// Package miio provides cloud access to Xiaomi MiIO device RPCs, MIoT
// properties/actions, and device/home lists.
package miio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Yonsm/misgo/account"
	"github.com/Yonsm/misgo/miio/sign"
)

const (
	SID = "xiaomiio"
	UA  = "iOS-14.4-6.0.103-iPhone12,3--D7744744F7AF32F0544445285880DD63E47D9BE9-8816080-84A3F44E137B71AE-iPhone"
)

// Service provides cloud access to MiIO device RPCs and MIoT properties.
type Service struct {
	Account *account.MiAccount
	server  string
	region  string
}

// New creates a cloud MiIO Service. An empty region or "cn" uses China mainland.
func New(acct *account.MiAccount, region string) *Service {
	host := "api.io.mi.com"
	if region != "" && region != "cn" {
		host = region + "." + host
	}
	return &Service{Account: acct, region: region, server: "https://" + host + "/app"}
}

func validRegion(region string) bool {
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

// SignNonce derives the base64-encoded request key from the service security value and nonce.
func SignNonce(ssecurity, nonce string) (string, error) { return sign.EncodedNonce(ssecurity, nonce) }

// SignData signs a raw JSON string or a JSON-serializable value for a MiIO URI.
func SignData(uri string, data any, ssecurity string) (url.Values, error) {
	return sign.Data(uri, data, ssecurity)
}

// MiIORequest sends a signed cloud request and returns the result field.
func (m *Service) MiIORequest(ctx context.Context, uri string, data any) (any, error) {
	if m == nil || m.Account == nil {
		return nil, errors.New("MiIO cloud requests require an account")
	}
	if !validRegion(m.region) {
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
	headers.Set("User-Agent", UA)
	headers.Set("x-xiaomi-protocal-flag-cli", "PROTOCAL-HTTP2")
	response, err := m.Account.MiRequestWith(ctx, SID, srv+uri, headers, true, func(session account.MiRequestSession) (url.Values, []*http.Cookie, error) {
		form, err := sign.Data(uri, data, session.SSecurity)
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

// Property is a named MiIO or numeric MIoT property assignment.
type Property struct {
	IID   string
	Value any
}

// MIoTProperty pairs a numeric MIoT IID with its new value.
type MIoTProperty struct {
	IID   IID
	Value any
}

// Device is a typed summary of a Xiaomi cloud device entry.
type Device struct {
	DID     string
	Name    string
	Model   string
	LocalIP string
	Token   string
	Members []string
}

// ParseDevice extracts typed fields from a raw DeviceList("full") record.
func ParseDevice(raw map[string]any) Device {
	v := Device{
		DID:     account.String(raw["did"]),
		Name:    account.String(raw["name"]),
		Model:   account.String(raw["model"]),
		LocalIP: account.String(raw["localip"]),
		Token:   account.String(raw["token"]),
	}
	extra, _ := raw["extra"].(map[string]any)
	list, _ := extra["member_list"].(map[string]any)
	switch members := list["member_ship"].(type) {
	case map[string]any:
		for did := range members {
			v.Members = append(v.Members, did)
		}
		sort.Strings(v.Members)
	case []any:
		for _, item := range members {
			if did := account.String(item); did != "" {
				v.Members = append(v.Members, did)
			}
		}
	}
	return v
}

// Room is a typed summary of a Xiaomi home room.
type Room struct {
	ID   string
	Name string
	DIDs []string
}

// Home is a typed summary of a Xiaomi home entry.
type Home struct {
	ID    string
	Name  string
	Rooms []Room
}

// DIDs returns all device IDs across all rooms in this home.
func (h Home) DIDs() []string {
	var out []string
	for _, r := range h.Rooms {
		out = append(out, r.DIDs...)
	}
	return out
}

// ParseHome extracts typed fields from a raw HomeList("full") record.
func ParseHome(raw map[string]any) Home {
	h := Home{
		ID:   account.String(raw["id"]),
		Name: account.String(raw["name"]),
	}
	roomsRaw, ok := raw["roomlist"].([]any)
	if !ok {
		roomsRaw, _ = raw["rooms"].([]any)
	}
	for _, r := range roomsRaw {
		rm, _ := r.(map[string]any)
		if rm == nil {
			continue
		}
		room := Room{
			ID:   account.String(rm["id"]),
			Name: account.String(rm["name"]),
		}
		didsRaw, ok := rm["dids"].([]any)
		if !ok {
			didsRaw, _ = rm["device_list"].([]any)
		}
		for _, item := range didsRaw {
			if did := account.String(item); did != "" {
				room.DIDs = append(room.DIDs, did)
			}
		}
		h.Rooms = append(h.Rooms, room)
	}
	return h
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

func (m *Service) MiIOGetProps(ctx context.Context, did string, iids []string) ([]any, error) {
	ids, miot, err := parsePropertyIDs(iids)
	if err != nil {
		return nil, err
	}
	if miot {
		return m.MIoTGetProps(ctx, did, ids)
	}
	return m.HomeGetProps(ctx, did, iids)
}

func (m *Service) MiIOSetProps(ctx context.Context, did string, props []Property) ([]any, error) {
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

func (m *Service) MiIOGetProp(ctx context.Context, did, iid string) (any, error) {
	return firstProperty(m.MiIOGetProps(ctx, did, []string{iid}))
}

func (m *Service) MiIOSetProp(ctx context.Context, did, iid string, value any) (any, error) {
	return firstProperty(m.MiIOSetProps(ctx, did, []Property{{iid, value}}))
}

func (m *Service) HomeRequest(ctx context.Context, did, method string, params any) (any, error) {
	return m.MiIORequest(ctx, "/home/rpc/"+url.PathEscape(did), map[string]any{
		"id": 1, "method": method, "accessKey": "IOS00026747c5acafc2", "params": params,
	})
}

func (m *Service) HomeGetProps(ctx context.Context, did string, props []string) ([]any, error) {
	if len(props) == 0 {
		return []any{}, nil
	}
	result, err := m.HomeRequest(ctx, did, "get_prop", props)
	return miIOListResult(result, err)
}

func (m *Service) HomeSetProps(ctx context.Context, did string, props []Property) ([]any, error) {
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

func (m *Service) HomeGetProp(ctx context.Context, did, prop string) (any, error) {
	return firstProperty(m.HomeGetProps(ctx, did, []string{prop}))
}

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

func (m *Service) HomeSetProp(ctx context.Context, did, prop string, value any) (any, error) {
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

func (m *Service) MIoTRequest(ctx context.Context, cmd string, params any) (any, error) {
	return m.MiIORequest(ctx, "/miotspec/"+cmd, map[string]any{"params": params})
}

// MIoTGetProps reads MIoT properties from the cloud, matching returned items by
// (siid, piid, did) when present so out-of-order responses remain aligned.
func (m *Service) MIoTGetProps(ctx context.Context, did string, iids []IID) ([]any, error) {
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
	out := make([]any, len(iids))
	for n, id := range iids {
		for i, v := range result {
			p, ok := v.(map[string]any)
			if !ok {
				continue
			}
			siid := miIOInt(p["siid"], 0)
			piid := miIOInt(p["piid"], 0)
			respDID := account.String(p["did"])
			if siid != 0 || piid != 0 {
				if siid != id.SIID || piid != id.PIID || (respDID != "" && did != "" && respDID != did) {
					continue
				}
			} else if i != n {
				continue
			}
			if miIOCode(p["code"]) == 0 {
				out[n] = p["value"]
			}
			break
		}
	}
	return out, nil
}

func (m *Service) MIoTSetProps(ctx context.Context, did string, props []MIoTProperty) ([]int, error) {
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

func (m *Service) MIoTGetProp(ctx context.Context, did string, id IID) (any, error) {
	return firstProperty(m.MIoTGetProps(ctx, did, []IID{id}))
}

func (m *Service) MIoTSetProp(ctx context.Context, did string, id IID, value any) (int, error) {
	return firstProperty(m.MIoTSetProps(ctx, did, []MIoTProperty{{id, value}}))
}

func (m *Service) MIoTAction(ctx context.Context, did string, id IID, args []any) (int, error) {
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
	if account.IsZeroCode(v) {
		return 0
	}
	return miIOInt(v, -1)
}

func miIOInt(v any, fallback int) int {
	switch n := v.(type) {
	case json.Number:
		if code, err := strconv.Atoi(string(n)); err == nil {
			return code
		}
	case float64:
		return int(n)
	case int:
		return n
	}
	return fallback
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

func (m *Service) DeviceList(ctx context.Context, name string, getVirtualModel bool, getHuamiDevices int) ([]map[string]any, error) {
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
		if strings.Contains(account.String(d["name"]), name) {
			out = append(out, map[string]any{"name": d["name"], "model": d["model"], "did": d["did"], "token": d["token"]})
		}
	}
	return out, nil
}

// Devices returns typed device records from /home/device_list.
func (m *Service) Devices(ctx context.Context, getVirtualModel bool, getHuamiDevices int) ([]Device, error) {
	raw, err := m.DeviceList(ctx, "full", getVirtualModel, getHuamiDevices)
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(raw))
	for _, d := range raw {
		out = append(out, ParseDevice(d))
	}
	return out, nil
}

func (m *Service) HomeList(ctx context.Context, name string) ([]map[string]any, error) {
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
		if !strings.Contains(account.String(h["name"]), name) {
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

// Homes returns typed home records from /homeroom/gethome.
func (m *Service) Homes(ctx context.Context) ([]Home, error) {
	raw, err := m.HomeList(ctx, "full")
	if err != nil {
		return nil, err
	}
	out := make([]Home, 0, len(raw))
	for _, h := range raw {
		out = append(out, ParseHome(h))
	}
	return out, nil
}
