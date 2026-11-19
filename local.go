package misgo

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
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	localMagic      = 0x2131
	localHeaderSize = 32
	localMaxPacket  = 65507 // Maximum IPv4 UDP payload.
	localHello      = "\x21\x31\x00\x20\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
)

// LocalOptions configures each UDP exchange. Zero values select a three-second
// timeout per attempt and three total attempts. Only timeouts are retried.
type LocalOptions struct {
	Timeout time.Duration
	Retries int
}

// MiIOLocalService controls a single MiIO device directly over UDP.
// It is safe for concurrent use and must not be copied.
type MiIOLocalService struct {
	addr    string
	token   []byte
	block   cipher.Block
	iv      [aes.BlockSize]byte
	options LocalOptions

	busy                chan struct{}
	deviceID, stamp, id uint32
	synced              time.Time
}

// NewMiIOLocalService creates a LAN client for a 16-byte hexadecimal token.
// The host may include a port; otherwise the MiIO port 54321 is used.
func NewMiIOLocalService(host, token string, options ...LocalOptions) (*MiIOLocalService, error) {
	var opts LocalOptions
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
	return &MiIOLocalService{
		addr: net.JoinHostPort(host, port), token: t, block: block,
		iv: md5.Sum(append(key[:], t...)), options: opts, busy: make(chan struct{}, 1),
	}, nil
}

func (d *MiIOLocalService) lock(ctx context.Context) error {
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
// before the first request and after a failed exchange.
func (d *MiIOLocalService) Hello(ctx context.Context) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.busy }()
	return d.hello(ctx)
}

func (d *MiIOLocalService) hello(ctx context.Context) error {
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

func (d *MiIOLocalService) exchange(ctx context.Context, request []byte) ([]byte, error) {
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

func (d *MiIOLocalService) checksum(packet []byte) []byte {
	h := md5.New()
	h.Write(packet[:16])
	h.Write(d.token)
	h.Write(packet[localHeaderSize:])
	return h.Sum(nil)
}

// Send invokes a raw MiIO method and returns its decoded JSON result, using
// json.Number for numbers. Nil or JSON null params are sent as an empty array.
func (d *MiIOLocalService) Send(ctx context.Context, method string, params any) (any, error) {
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
	if d.synced.IsZero() {
		if err := d.hello(ctx); err != nil {
			return nil, err
		}
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
	if err != nil {
		d.synced = time.Time{}
		return nil, fmt.Errorf("miio: %s: %w", method, err)
	}
	result, remoteError, err := d.decodeResponse(response, id)
	if err != nil {
		d.synced = time.Time{}
		return nil, fmt.Errorf("miio: %s: %w", method, err)
	}
	if len(remoteError) != 0 && !bytes.Equal(remoteError, []byte("null")) {
		return nil, fmt.Errorf("miio: %s: device returned error %s", method, remoteError)
	}
	return result, nil
}

func (d *MiIOLocalService) decodeResponse(packet []byte, id uint32) (any, json.RawMessage, error) {
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
	data := body[:len(body)-padding]
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
func (d *MiIOLocalService) GetProps(ctx context.Context, props []string) ([]any, error) {
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
func (d *MiIOLocalService) GetProp(ctx context.Context, prop string) (any, error) {
	values, err := d.GetProps(ctx, []string{prop})
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("miio: no value for property %q", prop)
	}
	return values[0], nil
}

// LocalProperty pairs a legacy MiIO property name with its new value.
type LocalProperty struct {
	Name  string
	Value any
}

// SetProps writes legacy MiIO properties in order, stopping on the first error.
func (d *MiIOLocalService) SetProps(ctx context.Context, props []LocalProperty) ([]any, error) {
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

// SetProp writes a legacy MiIO property. An array or slice supplies the method
// arguments directly (except byte slices); other values are wrapped in a list.
// A response starting with "ok" is returned as 0.
func (d *MiIOLocalService) SetProp(ctx context.Context, prop string, value any) (any, error) {
	params := any([]any{value})
	if t := reflect.TypeOf(value); t != nil && (t.Kind() == reflect.Array || (t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8)) {
		params = value
	}
	result, err := d.Send(ctx, "set_"+prop, params)
	if values, ok := result.([]any); ok && len(values) > 0 && values[0] == "ok" {
		return 0, nil
	}
	return result, err
}

// LocalCommandHelp returns usage for the local command syntax.
func LocalCommandHelp(prefix ...string) string {
	return fmt.Sprintf(`Get Props: %[1]s<prop>[,...]
           %[1]spower,brightness
Set Props: %[1]s<prop=value>[,...]
           %[1]spower=on,brightness=80

Call Method: %[1]s/<method> [params_json]
             %[1]s/miIO.info
             %[1]s/set_power ["on"]
`, commandPrefix(prefix))
}

// LocalCommand executes a property read, property write, or raw MiIO method.
// The caller should remove any command prefix from text before passing it in.
func LocalCommand(ctx context.Context, service *MiIOLocalService, text string, prefix ...string) (any, error) {
	cmd, arg := strings.TrimSpace(text), ""
	if i := strings.IndexFunc(cmd, unicode.IsSpace); i >= 0 {
		cmd, arg = cmd[:i], strings.TrimSpace(cmd[i:])
	}
	switch cmd {
	case "", "?", "？", "help", "-h", "--help":
		return LocalCommandHelp(prefix...), nil
	}
	if method, ok := strings.CutPrefix(cmd, "/"); ok {
		if arg == "" {
			return service.Send(ctx, method, nil)
		}
		params := json.RawMessage(arg)
		if !json.Valid(params) {
			return nil, fmt.Errorf("miio: invalid JSON parameters for %s", method)
		}
		return service.Send(ctx, method, params)
	}
	items := strings.Split(cmd, ",")
	if !strings.Contains(items[0], "=") {
		return service.GetProps(ctx, items)
	}
	props := make([]LocalProperty, 0, len(items))
	for _, item := range items {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			return "Invalid command: " + cmd, nil
		}
		props = append(props, LocalProperty{name, parseCommandValue(value)})
	}
	return service.SetProps(ctx, props)
}
