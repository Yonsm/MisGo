// Package local provides direct LAN UDP (port 54321) control for MiIO and
// local MIoT devices with zero net/http or cloud account dependencies.
package local

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	localMagic      = 0x2131
	localHeaderSize = 32
	localMaxPacket  = 65507 // Maximum IPv4 UDP payload.
	localHello      = "\x21\x31\x00\x20\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
)

// Options configures each UDP exchange. Zero values select a three-second
// timeout per attempt and three total attempts. Only timeouts are retried.
type Options struct {
	Timeout time.Duration
	Retries int
}

// IID identifies a MIoT property (SIID, PIID) or action (SIID, AIID).
type IID struct{ SIID, PIID int }

// String formats IID as "siid-piid".
func (id IID) String() string {
	return strconv.Itoa(id.SIID) + "-" + strconv.Itoa(id.PIID)
}

// ParseIID parses siid[-piid]; the default PIID is 1.
func ParseIID(s string) (IID, error) {
	service, instance, found := strings.Cut(s, "-")
	if !found {
		instance = "1"
	}
	siid, serr := strconv.ParseUint(service, 10, strconv.IntSize-1)
	piid, perr := strconv.ParseUint(instance, 10, strconv.IntSize-1)
	if serr != nil || perr != nil {
		return IID{}, fmt.Errorf("invalid MIoT instance ID %q; want siid[-piid]", s)
	}
	return IID{int(siid), int(piid)}, nil
}

// Property pairs a legacy MiIO property name or numeric MIoT IID with its value.
type Property struct {
	Name  string
	Value any
}

// MIoTProperty pairs a numeric MIoT IID with its new value.
type MIoTProperty struct {
	IID   IID
	Value any
}

// Service controls a single MiIO/MIoT device directly over LAN UDP.
// It is safe for concurrent use and must not be copied.
type Service struct {
	addr    string
	token   []byte
	block   cipher.Block
	iv      [aes.BlockSize]byte
	options Options

	busy                chan struct{}
	deviceID, stamp, id uint32
	synced              time.Time
}

// New creates a LAN client for a 16-byte hexadecimal token.
// The host may include a port; otherwise the MiIO port 54321 is used.
func New(host, token string, options ...Options) (*Service, error) {
	var opts Options
	if len(options) > 1 {
		return nil, errors.New("miio: expected at most one local options value")
	}
	if len(options) == 1 {
		opts = options[0]
	}
	if opts.Timeout < 0 || opts.Retries < 0 {
		return nil, errors.New("miio: local timeout and retries cannot be negative")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Retries == 0 {
		opts.Retries = 3
	}

	host = strings.TrimSpace(host)
	port := "54321"
	if h, p, err := net.SplitHostPort(host); err == nil {
		host, port = h, p
	} else if strings.ContainsAny(host, ":[]") {
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, fmt.Errorf("miio: invalid local address %q", host)
		}
	}
	if n, err := strconv.ParseUint(port, 10, 16); host == "" || err != nil || n == 0 {
		return nil, errors.New("miio: expected a local host and a valid UDP port")
	}

	t, err := hex.DecodeString(strings.Join(strings.Fields(token), ""))
	if err != nil || len(t) != aes.BlockSize {
		return nil, errors.New("miio: local token must contain 32 hexadecimal digits")
	}
	key := md5.Sum(t)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &Service{
		addr:    net.JoinHostPort(host, port),
		token:   t,
		block:   block,
		iv:      md5.Sum(append(key[:], t...)),
		options: opts,
		busy:    make(chan struct{}, 1),
	}, nil
}

func (d *Service) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case d.busy <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-d.busy
			return err
		}
		return nil
	}
}

// Hello refreshes the device ID and its clock. Send does this automatically
// before the first request and retries once after a stale-session failure.
func (d *Service) Hello(ctx context.Context) error {
	if d == nil {
		return errors.New("miio: local command requires a device service")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.busy }()
	return d.hello(ctx)
}

func (d *Service) hello(ctx context.Context) error {
	d.synced = time.Time{}
	packet, err := d.exchange(ctx, []byte(localHello))
	if err != nil {
		return fmt.Errorf("miio: hello: %w", err)
	}
	d.deviceID = binary.BigEndian.Uint32(packet[8:12])
	d.stamp = binary.BigEndian.Uint32(packet[12:16])
	d.synced = time.Now()
	return nil
}

func (d *Service) exchange(ctx context.Context, request []byte) ([]byte, error) {
	conn, err := (&net.Dialer{Timeout: d.options.Timeout}).DialContext(ctx, "udp", d.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	response := make([]byte, localMaxPacket+1)
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(d.options.Timeout)
		if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
			deadline = limit
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		var n int
		if _, err = conn.Write(request); err == nil {
			n, err = conn.Read(response)
		}
		if err == nil {
			if n < localHeaderSize || n > localMaxPacket || binary.BigEndian.Uint16(response) != localMagic || int(binary.BigEndian.Uint16(response[2:4])) != n {
				return nil, errors.New("invalid MiIO packet header")
			}
			return response[:n], nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			return nil, err
		}
		if limit, ok := ctx.Deadline(); ok && !time.Now().Before(limit) {
			return nil, context.DeadlineExceeded
		}
		if attempt == d.options.Retries-1 {
			return nil, fmt.Errorf("No response from %s: %w", d.addr, err)
		}
	}
}

func (d *Service) checksum(packet []byte) []byte {
	h := md5.New()
	h.Write(packet[:16])
	h.Write(d.token)
	h.Write(packet[localHeaderSize:])
	return h.Sum(nil)
}

// Send invokes a raw MiIO method and returns its decoded JSON result, using
// json.Number for numbers. Nil or JSON null params are sent as an empty array.
// If a cached handshake stamp has drifted or the device rebooted, Send refreshes
// the handshake and retries once automatically.
func (d *Service) Send(ctx context.Context, method string, params any) (any, error) {
	if d == nil {
		return nil, errors.New("miio: local command requires a device service")
	}
	if method == "" {
		return nil, errors.New("miio: missing local method")
	}
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer func() { <-d.busy }()

	arg, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("miio: encode %s parameters: %w", method, err)
	}
	if bytes.Equal(arg, []byte("null")) {
		arg = []byte("[]")
	}

	hadSession := !d.synced.IsZero()
	if !hadSession {
		if err := d.hello(ctx); err != nil {
			return nil, err
		}
	}

	for attempt := 0; ; attempt++ {
		id := d.id + 1
		payload, err := json.Marshal(struct {
			ID     uint32          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}{id, method, arg})
		if err != nil {
			return nil, fmt.Errorf("miio: encode %s request: %w", method, err)
		}
		padding := aes.BlockSize - len(payload)%aes.BlockSize
		length := localHeaderSize + len(payload) + padding
		if length > localMaxPacket {
			return nil, errors.New("miio: local request exceeds UDP packet size")
		}
		d.id = id
		packet := make([]byte, length)
		binary.BigEndian.PutUint16(packet, localMagic)
		binary.BigEndian.PutUint16(packet[2:4], uint16(length))
		binary.BigEndian.PutUint32(packet[8:12], d.deviceID)
		binary.BigEndian.PutUint32(packet[12:16], d.stamp+uint32(time.Since(d.synced)/time.Second))
		body := packet[localHeaderSize:]
		copy(body, payload)
		for i := len(payload); i < len(body); i++ {
			body[i] = byte(padding)
		}
		cipher.NewCBCEncrypter(d.block, d.iv[:]).CryptBlocks(body, body)
		copy(packet[16:localHeaderSize], d.checksum(packet))

		response, err := d.exchange(ctx, packet)
		if err == nil {
			result, remoteError, decodeErr := d.decodeResponse(response, id)
			if decodeErr == nil {
				if len(remoteError) != 0 && !bytes.Equal(remoteError, []byte("null")) {
					return nil, fmt.Errorf("miio: %s: device returned error %s", method, remoteError)
				}
				return result, nil
			}
			err = decodeErr
		}
		d.synced = time.Time{}
		if !hadSession || attempt > 0 || ctx.Err() != nil {
			return nil, fmt.Errorf("miio: %s: %w", method, err)
		}
		if helloErr := d.hello(ctx); helloErr != nil {
			return nil, fmt.Errorf("miio: %s: %w", method, err)
		}
	}
}

func (d *Service) decodeResponse(packet []byte, id uint32) (any, json.RawMessage, error) {
	body := packet[localHeaderSize:]
	if binary.BigEndian.Uint32(packet[8:12]) != d.deviceID {
		return nil, nil, errors.New("response device ID does not match")
	}
	if len(body) == 0 {
		return nil, nil, errors.New("device did not acknowledge the command")
	}
	if len(body)%aes.BlockSize != 0 || !bytes.Equal(packet[16:localHeaderSize], d.checksum(packet)) {
		return nil, nil, errors.New("invalid encrypted response")
	}
	cipher.NewCBCDecrypter(d.block, d.iv[:]).CryptBlocks(body, body)
	padding := int(body[len(body)-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, nil, errors.New("invalid response padding")
	}
	for _, b := range body[len(body)-padding:] {
		if int(b) != padding {
			return nil, nil, errors.New("invalid response padding")
		}
	}
	var response struct {
		ID     *uint32         `json:"id"`
		Result any             `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	data := bytes.TrimRight(body[:len(body)-padding], "\x00")
	if !json.Valid(data) {
		return nil, nil, errors.New("invalid JSON response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return nil, nil, fmt.Errorf("decode response: %w", err)
	}
	if response.ID == nil || *response.ID != id {
		return nil, nil, errors.New("response request ID does not match")
	}
	return response.Result, response.Error, nil
}

// GetProps reads legacy MiIO properties in the supplied order.
func (d *Service) GetProps(ctx context.Context, props []string) ([]any, error) {
	if len(props) == 0 {
		return []any{}, nil
	}
	result, err := d.Send(ctx, "get_prop", props)
	if err != nil || result == nil {
		return nil, err
	}
	if values, ok := result.([]any); ok {
		return values, nil
	}
	return nil, errors.New("miio: get_prop did not return a list")
}

// GetProp reads a single legacy MiIO property.
func (d *Service) GetProp(ctx context.Context, prop string) (any, error) {
	values, err := d.GetProps(ctx, []string{prop})
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("miio: no value for property %q", prop)
	}
	return values[0], nil
}

// SetProps writes legacy MiIO properties in order, stopping on the first error.
func (d *Service) SetProps(ctx context.Context, props []Property) ([]any, error) {
	results := make([]any, 0, len(props))
	for _, prop := range props {
		value, err := d.SetProp(ctx, prop.Name, prop.Value)
		if err != nil {
			return nil, err
		}
		results = append(results, value)
	}
	return results, nil
}

// SetProp writes a legacy MiIO property. JSON arrays supply the method arguments
// directly; other values are wrapped in a list. A response starting with "ok"
// is returned as 0.
func (d *Service) SetProp(ctx context.Context, prop string, value any) (any, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	params := json.RawMessage(payload)
	if bytes.TrimSpace(payload)[0] != '[' {
		params = append(append([]byte{'['}, payload...), ']')
	}
	result, err := d.Send(ctx, "set_"+prop, params)
	if values, ok := result.([]any); ok && len(values) > 0 && values[0] == "ok" {
		return 0, nil
	}
	return result, err
}

// MIoTGetProps reads MIoT properties locally using get_properties, matching
// returned items by (siid, piid) or did so out-of-order responses remain aligned.
func (d *Service) MIoTGetProps(ctx context.Context, iids []IID) ([]any, error) {
	if len(iids) == 0 {
		return []any{}, nil
	}
	params := make([]map[string]any, len(iids))
	for i, id := range iids {
		params[i] = map[string]any{"did": id.String(), "siid": id.SIID, "piid": id.PIID}
	}
	raw, err := d.Send(ctx, "get_properties", params)
	if err != nil {
		return nil, err
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("miio: get_properties did not return a list")
	}
	return matchMIoTValues(list, iids)
}

// MIoTGetProp reads a single MIoT property locally.
func (d *Service) MIoTGetProp(ctx context.Context, id IID) (any, error) {
	values, err := d.MIoTGetProps(ctx, []IID{id})
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("miio: no value for MIoT property %s", id)
	}
	return values[0], nil
}

// MIoTSetProps writes MIoT properties locally using set_properties and returns
// each property's status code (0 on success).
func (d *Service) MIoTSetProps(ctx context.Context, props []MIoTProperty) ([]int, error) {
	if len(props) == 0 {
		return []int{}, nil
	}
	params := make([]map[string]any, len(props))
	for i, p := range props {
		params[i] = map[string]any{"did": p.IID.String(), "siid": p.IID.SIID, "piid": p.IID.PIID, "value": p.Value}
	}
	raw, err := d.Send(ctx, "set_properties", params)
	if err != nil {
		return nil, err
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("miio: set_properties did not return a list")
	}
	out := make([]int, len(list))
	for i, item := range list {
		p, _ := item.(map[string]any)
		out[i] = localInt(p["code"], -1)
	}
	return out, nil
}

// MIoTSetProp writes a single MIoT property locally and returns its status code.
func (d *Service) MIoTSetProp(ctx context.Context, id IID, value any) (int, error) {
	codes, err := d.MIoTSetProps(ctx, []MIoTProperty{{IID: id, Value: value}})
	if err != nil {
		return -1, err
	}
	if len(codes) == 0 {
		return -1, fmt.Errorf("miio: set_properties returned no status for %s", id)
	}
	return codes[0], nil
}

// MIoTAction invokes a MIoT action locally and returns its status code.
func (d *Service) MIoTAction(ctx context.Context, id IID, args []any) (int, error) {
	if args == nil {
		args = []any{}
	}
	raw, err := d.Send(ctx, "action", map[string]any{
		"did": id.String(), "siid": id.SIID, "aiid": id.PIID, "in": args,
	})
	if err != nil {
		return -1, err
	}
	p, _ := raw.(map[string]any)
	return localInt(p["code"], -1), nil
}

// MiIOGetProps auto-dispatches numeric IIDs to MIoTGetProps and named properties to GetProps.
func (d *Service) MiIOGetProps(ctx context.Context, iids []string) ([]any, error) {
	if len(iids) == 0 {
		return []any{}, nil
	}
	for _, s := range iids {
		if s == "" {
			return nil, errors.New("miio: missing property identifier")
		}
	}
	if isNumeric(iids[0]) {
		parsed := make([]IID, len(iids))
		for i, s := range iids {
			id, err := ParseIID(s)
			if err != nil {
				return nil, err
			}
			parsed[i] = id
		}
		return d.MIoTGetProps(ctx, parsed)
	}
	return d.GetProps(ctx, iids)
}

// MiIOSetProps auto-dispatches numeric IIDs to MIoTSetProps and named properties to SetProps.
func (d *Service) MiIOSetProps(ctx context.Context, props []Property) ([]any, error) {
	if len(props) == 0 {
		return []any{}, nil
	}
	for _, p := range props {
		if p.Name == "" {
			return nil, errors.New("miio: missing property identifier")
		}
	}
	if isNumeric(props[0].Name) {
		parsed := make([]MIoTProperty, len(props))
		for i, p := range props {
			id, err := ParseIID(p.Name)
			if err != nil {
				return nil, err
			}
			parsed[i] = MIoTProperty{IID: id, Value: p.Value}
		}
		codes, err := d.MIoTSetProps(ctx, parsed)
		if err != nil {
			return nil, err
		}
		out := make([]any, len(codes))
		for i, c := range codes {
			out[i] = c
		}
		return out, nil
	}
	return d.SetProps(ctx, props)
}

func isNumeric(s string) bool {
	return len(s) != 0 && s[0] >= '0' && s[0] <= '9'
}

func localInt(v any, fallback int) int {
	switch n := v.(type) {
	case json.Number:
		if i, err := strconv.Atoi(string(n)); err == nil {
			return i
		}
	case float64:
		return int(n)
	case int:
		return n
	case bool:
		if !n {
			return 0
		}
	}
	return fallback
}

func localString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case json.Number:
		return string(s)
	case int, int64, uint64:
		return fmt.Sprint(s)
	}
	return ""
}

func matchMIoTValues(list []any, ids []IID) ([]any, error) {
	out := make([]any, len(ids))
	matched := false
	for n, id := range ids {
		expected := id.String()
		for i, raw := range list {
			p, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			siid, piid := localInt(p["siid"], 0), localInt(p["piid"], 0)
			did := localString(p["did"])
			switch {
			case siid != 0 || piid != 0:
				if siid != id.SIID || piid != id.PIID || (did != "" && did != expected) {
					continue
				}
			case did != "":
				if did != expected {
					continue
				}
			case i != n:
				continue
			}
			if localInt(p["code"], -1) == 0 {
				out[n], matched = p["value"], true
			}
			break
		}
	}
	if !matched {
		return nil, errors.New("miio: local device returned no successful MIoT properties")
	}
	return out, nil
}
