package misgo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const miIOSID = "xiaomiio"

// MiIOService provides cloud access to MiIO device RPCs and MIoT properties.
type MiIOService struct {
	Account *MiAccount
	server  string
	region  string
}

func NewMiIOService(account *MiAccount, region string) *MiIOService {
	host := "api.io.mi.com"
	if region != "" && region != "cn" {
		host = region + "." + host
	}
	return &MiIOService{Account: account, region: region, server: "https://" + host + "/app"}
}

func validMiIORegion(region string) bool {
	if region == "" {
		return true
	}
	if len(region) > 63 || region[0] == '-' || region[len(region)-1] == '-' {
		return false
	}
	for _, ch := range region {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

func miIOSignedNonce(ssecurity, nonce string) ([sha256.Size]byte, error) {
	security, err := base64.StdEncoding.DecodeString(ssecurity)
	if err != nil || len(security) == 0 {
		return [sha256.Size]byte{}, errors.New("invalid MiIO ssecurity")
	}
	decoded, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil || len(decoded) == 0 {
		return [sha256.Size]byte{}, errors.New("invalid MiIO nonce")
	}
	return sha256.Sum256(append(security, decoded...)), nil
}

// SignNonce derives the base64-encoded request key from the service security value and nonce.
func SignNonce(ssecurity, nonce string) (string, error) {
	key, err := miIOSignedNonce(ssecurity, nonce)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// SignData signs a raw JSON string or a JSON-serializable value for a MiIO URI.
func SignData(uri string, data any, ssecurity string) (url.Values, error) {
	payload, ok := data.(string)
	if !ok {
		b, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("encode MiIO request data: %w", err)
		}
		payload = string(b)
	}
	var n [12]byte
	if _, err := rand.Read(n[:8]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(n[8:], uint32(time.Now().Unix()/60))
	enc := base64.StdEncoding
	nonce := enc.EncodeToString(n[:])
	key, err := miIOSignedNonce(ssecurity, nonce)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key[:])
	io.WriteString(mac, uri+"&"+enc.EncodeToString(key[:])+"&"+nonce+"&data="+payload)
	return url.Values{"_nonce": {nonce}, "data": {payload}, "signature": {enc.EncodeToString(mac.Sum(nil))}}, nil
}

// MiIORequest sends a signed cloud request and returns the result field.
func (m *MiIOService) MiIORequest(ctx context.Context, uri string, data any) (any, error) {
	if m == nil || m.Account == nil {
		return nil, errors.New("MiIO cloud requests require an account")
	}
	if !validMiIORegion(m.region) {
		return nil, errors.New("invalid MiIO region")
	}
	srv := m.server
	if srv == "" {
		srv = "https://api.io.mi.com/app"
	}
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") || strings.ContainsAny(uri, "#\r\n") {
		return nil, errors.New("invalid MiIO request URI")
	}
	headers := make(http.Header)
	headers.Set("User-Agent", UAMiIO)
	headers.Set("x-xiaomi-protocal-flag-cli", "PROTOCAL-HTTP2")
	response, err := m.Account.MiRequestWith(ctx, miIOSID, srv+uri, headers, true, func(session MiRequestSession) (url.Values, []*http.Cookie, error) {
		form, err := SignData(uri, data, session.SSecurity)
		return form, []*http.Cookie{{Name: "PassportDeviceId", Value: session.DeviceID}}, err
	})
	if err != nil {
		return nil, err
	}
	result, ok := response["result"]
	if !ok {
		return nil, errors.New("MiIO response is missing result")
	}
	return result, nil
}

// IID identifies a MIoT property, or an action when passed to MIoTAction.
type IID struct{ SIID, PIID int }

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

// Property is a named MiIO or numeric MIoT property assignment.
type Property struct {
	IID   string
	Value any
}

type MIoTProperty struct {
	IID   IID
	Value any
}

func numericIID(iid string) bool {
	return len(iid) != 0 && iid[0] >= '0' && iid[0] <= '9'
}

func parsePropertyIDs(iids []string) ([]IID, bool, error) {
	if len(iids) == 0 {
		return nil, false, nil
	}
	for _, id := range iids {
		if id == "" {
			return nil, false, errors.New("missing MiIO/MIoT property identifier")
		}
	}
	if !numericIID(iids[0]) {
		return nil, false, nil
	}
	parsed := make([]IID, len(iids))
	for i, id := range iids {
		var err error
		parsed[i], err = ParseIID(id)
		if err != nil {
			return nil, false, err
		}
	}
	return parsed, true, nil
}

func (m *MiIOService) MiIOGetProps(ctx context.Context, did string, iids []string) ([]any, error) {
	ids, miot, err := parsePropertyIDs(iids)
	if err != nil {
		return nil, err
	}
	if miot {
		return m.MIoTGetProps(ctx, did, ids)
	}
	return m.HomeGetProps(ctx, did, iids)
}

func (m *MiIOService) MiIOSetProps(ctx context.Context, did string, props []Property) ([]any, error) {
	names := make([]string, len(props))
	for i, p := range props {
		names[i] = p.IID
	}
	ids, miot, err := parsePropertyIDs(names)
	if err != nil {
		return nil, err
	}
	if !miot {
		return m.HomeSetProps(ctx, did, props)
	}
	assignments := make([]MIoTProperty, len(props))
	for i, p := range props {
		assignments[i] = MIoTProperty{ids[i], p.Value}
	}
	result, err := m.MIoTSetProps(ctx, did, assignments)
	if err != nil {
		return nil, err
	}
	out := make([]any, len(result))
	for i, code := range result {
		out[i] = code
	}
	return out, nil
}

func firstProperty[T any](values []T, err error) (T, error) {
	var zero T
	if err != nil {
		return zero, err
	}
	if len(values) == 0 {
		return zero, errors.New("MiIO response is missing the requested property")
	}
	return values[0], nil
}

func (m *MiIOService) MiIOGetProp(ctx context.Context, did, iid string) (any, error) {
	return firstProperty(m.MiIOGetProps(ctx, did, []string{iid}))
}

func (m *MiIOService) MiIOSetProp(ctx context.Context, did, iid string, value any) (any, error) {
	return firstProperty(m.MiIOSetProps(ctx, did, []Property{{iid, value}}))
}

func (m *MiIOService) HomeRequest(ctx context.Context, did, method string, params any) (any, error) {
	return m.MiIORequest(ctx, "/home/rpc/"+url.PathEscape(did), map[string]any{
		"id": 1, "method": method, "accessKey": "IOS00026747c5acafc2", "params": params,
	})
}

func (m *MiIOService) HomeGetProps(ctx context.Context, did string, props []string) ([]any, error) {
	if len(props) == 0 {
		return []any{}, nil
	}
	result, err := m.HomeRequest(ctx, did, "get_prop", props)
	return miIOListResult(result, err)
}

func (m *MiIOService) HomeSetProps(ctx context.Context, did string, props []Property) ([]any, error) {
	out := make([]any, 0, len(props))
	for _, p := range props {
		result, err := m.HomeSetProp(ctx, did, p.IID, p.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, result)
	}
	return out, nil
}

func (m *MiIOService) HomeGetProp(ctx context.Context, did, prop string) (any, error) {
	return firstProperty(m.HomeGetProps(ctx, did, []string{prop}))
}

// legacySetParams normalizes the JSON representation, not the Go representation:
// only an array supplies the entire argument list.
func legacySetParams(value any) (json.RawMessage, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if bytes.TrimSpace(payload)[0] == '[' {
		return payload, nil
	}
	return append(append([]byte{'['}, payload...), ']'), nil
}

func (m *MiIOService) HomeSetProp(ctx context.Context, did, prop string, value any) (any, error) {
	params, err := legacySetParams(value)
	if err != nil {
		return nil, err
	}
	result, err := firstProperty(miIOListResult(m.HomeRequest(ctx, did, "set_"+prop, params)))
	if result == "ok" {
		return 0, nil
	}
	return result, err
}

func (m *MiIOService) MIoTRequest(ctx context.Context, cmd string, params any) (any, error) {
	return m.MiIORequest(ctx, "/miotspec/"+cmd, map[string]any{"params": params})
}

func (m *MiIOService) MIoTGetProps(ctx context.Context, did string, iids []IID) ([]any, error) {
	if len(iids) == 0 {
		return []any{}, nil
	}
	params := make([]map[string]any, len(iids))
	for i, id := range iids {
		params[i] = map[string]any{"did": did, "siid": id.SIID, "piid": id.PIID}
	}
	result, err := miIOListResult(m.MIoTRequest(ctx, "prop/get", params))
	if err != nil {
		return nil, err
	}
	out := make([]any, len(result))
	for i, v := range result {
		p, _ := v.(map[string]any)
		if miIOCode(p["code"]) == 0 {
			out[i] = p["value"]
		}
	}
	return out, nil
}

func (m *MiIOService) MIoTSetProps(ctx context.Context, did string, props []MIoTProperty) ([]int, error) {
	if len(props) == 0 {
		return []int{}, nil
	}
	params := make([]map[string]any, len(props))
	for i, p := range props {
		params[i] = map[string]any{"did": did, "siid": p.IID.SIID, "piid": p.IID.PIID, "value": p.Value}
	}
	result, err := miIOListResult(m.MIoTRequest(ctx, "prop/set", params))
	if err != nil {
		return nil, err
	}
	out := make([]int, len(result))
	for i, v := range result {
		p, _ := v.(map[string]any)
		out[i] = miIOCode(p["code"])
	}
	return out, nil
}

func (m *MiIOService) MIoTGetProp(ctx context.Context, did string, id IID) (any, error) {
	return firstProperty(m.MIoTGetProps(ctx, did, []IID{id}))
}

func (m *MiIOService) MIoTSetProp(ctx context.Context, did string, id IID, value any) (int, error) {
	return firstProperty(m.MIoTSetProps(ctx, did, []MIoTProperty{{id, value}}))
}

func (m *MiIOService) MIoTAction(ctx context.Context, did string, id IID, args []any) (int, error) {
	if args == nil {
		args = []any{}
	}
	result, err := m.MIoTRequest(ctx, "action", map[string]any{
		"did": did, "siid": id.SIID, "aiid": id.PIID, "in": args,
	})
	if err != nil {
		return -1, err
	}
	r, _ := result.(map[string]any)
	return miIOCode(r["code"]), nil
}

func miIOCode(v any) int {
	if isZeroCode(v) {
		return 0
	}
	if n, ok := v.(json.Number); ok {
		if code, err := strconv.Atoi(string(n)); err == nil {
			return code
		}
	}
	return -1
}

func miIOListResult(v any, err error) ([]any, error) {
	if err != nil {
		return nil, err
	}
	if list, ok := v.([]any); ok {
		return list, nil
	}
	return nil, errors.New("MiIO result is not a list")
}

func miIOObjectList(v any) ([]map[string]any, error) {
	if v == nil {
		return []map[string]any{}, nil
	}
	list, err := miIOListResult(v, nil)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, len(list))
	for i, v := range list {
		obj, ok := v.(map[string]any)
		if !ok || obj == nil {
			return nil, errors.New("MiIO list entry is not an object")
		}
		out[i] = obj
	}
	return out, nil
}

func (m *MiIOService) DeviceList(ctx context.Context, name string, getVirtualModel bool, getHuamiDevices int) ([]map[string]any, error) {
	result, err := m.MiIORequest(ctx, "/home/device_list", map[string]any{
		"getVirtualModel": getVirtualModel, "getHuamiDevices": getHuamiDevices,
	})
	if err != nil {
		return nil, err
	}
	r, _ := result.(map[string]any)
	list, err := miIOObjectList(r["list"])
	if err != nil || name == "full" {
		return list, err
	}
	out := make([]map[string]any, 0, len(list))
	for _, d := range list {
		if strings.Contains(accountString(d["name"]), name) {
			out = append(out, map[string]any{"name": d["name"], "model": d["model"], "did": d["did"], "token": d["token"]})
		}
	}
	return out, nil
}

func (m *MiIOService) HomeList(ctx context.Context, name string) ([]map[string]any, error) {
	result, err := m.MiIORequest(ctx, "/homeroom/gethome", struct{}{})
	if err != nil {
		return nil, err
	}
	if obj, ok := result.(map[string]any); ok {
		result = obj["homelist"]
		if list, _ := result.([]any); len(list) == 0 {
			result = obj["list"]
		}
	}
	list, err := miIOObjectList(result)
	if err != nil || name == "full" {
		return list, err
	}
	out := make([]map[string]any, 0, len(list))
	for _, h := range list {
		if !strings.Contains(accountString(h["name"]), name) {
			continue
		}
		roomList := h["roomlist"]
		if roomList == nil {
			roomList = h["rooms"]
		}
		rooms, err := miIOObjectList(roomList)
		if err != nil {
			return nil, err
		}
		summary := make([]map[string]any, len(rooms))
		for i, room := range rooms {
			dids := room["dids"]
			if dids == nil {
				dids = room["device_list"]
			}
			if dids == nil {
				dids = []any{}
			}
			summary[i] = map[string]any{"id": room["id"], "name": room["name"], "dids": dids}
		}
		out = append(out, map[string]any{"id": h["id"], "name": h["name"], "rooms": summary})
	}
	return out, nil
}
