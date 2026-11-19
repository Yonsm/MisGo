package misgo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// CommandCloud is the cloud service used by the command interpreter.
type CommandCloud interface {
	MiIORequest(ctx context.Context, uri string, data any) (any, error)
	MIoTRequest(ctx context.Context, cmd string, params any) (any, error)
	DeviceList(ctx context.Context, name string, virtual bool, huami int) ([]map[string]any, error)
	HomeList(ctx context.Context, name string) ([]map[string]any, error)
	MiIOGetProps(ctx context.Context, did string, iids []string) ([]any, error)
	MiIOSetProps(ctx context.Context, did string, props []Property) ([]any, error)
	MIoTAction(ctx context.Context, did string, iid IID, args []any) (int, error)
}

// Command executes a MiIO/MIoT command, using the public registry for spec lookups.
// A nil cloud is sufficient for help, spec, and decode commands.
func Command(ctx context.Context, cloud CommandCloud, did, text string, prefix ...string) (any, error) {
	return defaultSpecs.Command(ctx, cloud, did, text, prefix...)
}

// Command executes a MiIO/MIoT command with this client's spec registry.
func (s *SpecClient) Command(ctx context.Context, cloud CommandCloud, did, text string, prefix ...string) (any, error) {
	cmd, arg, hasArg := strings.Cut(text, " ")
	var argv []string
	if arg != "" {
		argv = strings.Split(arg, " ")
	}
	at := func(i int) string {
		if i < len(argv) {
			return argv[i]
		}
		return ""
	}

	switch cmd {
	case "", "?", "？", "help", "-h", "--help":
		return CommandHelp(did, prefix...), nil
	case "spec":
		return s.Spec(ctx, at(0), at(1))
	case "decode":
		if len(argv) < 3 || at(0) == "" || at(1) == "" || at(2) == "" {
			return nil, errors.New("usage: decode <ssecurity> <nonce> <data> [gzip]")
		}
		return Decode(at(0), at(1), at(2), at(3) == "gzip")
	}

	rawMiIO := strings.HasPrefix(cmd, "/")
	rawMIoT := strings.HasPrefix(cmd, "prop") || cmd == "action"
	if did == "" && !rawMiIO && !rawMIoT && cmd != "list" && cmd != "home" {
		return CommandHelp(did, prefix...), nil
	}
	if cloud == nil {
		return nil, errors.New("MiIO command requires a cloud service")
	}

	switch {
	case rawMiIO:
		var data any
		if hasArg {
			data = arg
		}
		return cloud.MiIORequest(ctx, cmd, data)
	case rawMIoT:
		var params any
		if arg != "" {
			var err error
			if params, err = commandJSON([]byte(arg)); err != nil {
				return nil, fmt.Errorf("invalid %s JSON parameters: %w", cmd, err)
			}
		}
		return cloud.MIoTRequest(ctx, cmd, params)
	case cmd == "list":
		var huami int
		if at(2) != "" {
			var err error
			if huami, err = strconv.Atoi(at(2)); err != nil {
				return nil, fmt.Errorf("invalid getHuamiDevices: %w", err)
			}
		}
		return cloud.DeviceList(ctx, at(0), commandTruthy(parseCommandValue(at(1))), huami)
	case cmd == "home":
		return cloud.HomeList(ctx, at(0))
	}

	if !commandDigits(did) {
		devices, err := cloud.DeviceList(ctx, did, false, 0)
		if err != nil {
			return nil, err
		}
		if len(devices) == 0 {
			return "Device not found: " + did, nil
		}
		switch id := devices[0]["did"].(type) {
		case string:
			did = id
		case json.Number:
			did = id.String()
		case int, int64, uint64:
			did = fmt.Sprint(id)
		default:
			did = ""
		}
		if did == "" {
			return nil, errors.New("device has no valid DID")
		}
	}

	items := strings.Split(cmd, ",")
	ids := make([]string, len(items))
	var props []Property
	miot := commandStartsDigit(items[0])
	write := strings.Contains(items[0], "=")
	for i, item := range items {
		key, value, hasValue := strings.Cut(item, "=")
		if hasValue != write {
			return "Invalid command: " + cmd, nil
		}
		if key == "" {
			return nil, fmt.Errorf("missing property identifier in %q", cmd)
		}
		ids[i] = key
		if write {
			props = append(props, Property{IID: key, Value: parseCommandValue(value)})
		}
	}
	switch {
	case write:
		return cloud.MiIOSetProps(ctx, did, props)
	case miot && arg != "":
		id, err := ParseIID(ids[0])
		if err != nil {
			return nil, err
		}
		args := []any{}
		if arg != "[]" {
			for _, value := range argv {
				args = append(args, parseCommandValue(value))
			}
		}
		return cloud.MIoTAction(ctx, did, id, args)
	default:
		return cloud.MiIOGetProps(ctx, did, ids)
	}
}

func commandPrefix(prefix []string) string {
	if len(prefix) == 0 {
		return "?"
	}
	return prefix[0]
}

// CommandHelp returns help text for the cloud command syntax.
func CommandHelp(did string, prefixes ...string) string {
	prefix := commandPrefix(prefixes)
	quote := "'"
	if prefix == "?" {
		quote = ""
	}
	if did == "" {
		did = "267090026"
	}
	return fmt.Sprintf(`Get Props: %[1]s<siid[-piid]>[,...]
           %[1]s1,1-2,1-3,1-4,2-1,2-2,3
Set Props: %[1]s<siid[-piid]=[#]value>[,...]
           %[1]s2=60,2-1=#60,2-2=false,2-3="null",3=test
Do Action: %[1]s<siid[-piid]> <arg1|[]> [...]
           %[1]s2 []
           %[1]s5 Hello
           %[1]s5-4 Hello 1

Call MIoT: %[1]s<cmd=prop/get|/prop/set|action> <params>
           %[1]saction %[2]s{"did":%[3]q,"siid":5,"aiid":1,"in":["Hello"]}%[2]s

Call MiIO: %[1]s/<uri> <data>
           %[1]s/home/device_list %[2]s{"getVirtualModel":false,"getHuamiDevices":1}%[2]s

Devs List: %[1]slist [name_keyword|full] [getVirtualModel=false|true] [getHuamiDevices=0|1]
           %[1]slist Light true 0
           %[1]slist full

Home List: %[1]shome [name_keyword|full]
           %[1]shome
           %[1]shome full
           %[1]shome 我的家

MIoT Spec: %[1]sspec [model_keyword|type_urn] [text|python]
           %[1]sspec
           %[1]sspec speaker
           %[1]sspec xiaomi.wifispeaker.lx04
           %[1]sspec urn:miot-spec-v2:device:speaker:0000A015:xiaomi-lx04:1

MIoT Decode: %[1]sdecode <ssecurity> <nonce> <data> [gzip]
`, prefix, quote, did)
}

func commandStartsDigit(text string) bool {
	return text != "" && text[0] >= '0' && text[0] <= '9'
}

func commandDigits(text string) bool {
	return text != "" && strings.IndexFunc(text, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func parseCommandValue(text string) any {
	if text != "" && strings.ContainsRune(`"'#`, rune(text[0])) {
		text = text[1:]
		if text != "" && strings.ContainsRune(`"'#`, rune(text[len(text)-1])) {
			text = text[:len(text)-1]
		}
		return text
	}
	switch text {
	case "null":
		return nil
	case "true":
		return true
	case "false":
		return false
	}
	if commandDigits(text) {
		if n, err := strconv.ParseInt(text, 10, 64); err == nil {
			return n
		}
		return json.Number(strings.TrimLeft(text, "0"))
	}
	if value, err := strconv.ParseFloat(strings.TrimSpace(text), 64); err == nil &&
		!strings.ContainsAny(text, "xX") && !math.IsNaN(value) && !math.IsInf(value, 0) {
		return value
	}
	return text
}

func commandTruthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return v != ""
	case bool:
		return v
	case int64:
		return v != 0
	case float64:
		return v != 0
	default:
		return true
	}
}

func commandJSON(data []byte) (any, error) {
	if !json.Valid(data) {
		return nil, errors.New("expected a single JSON value")
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	err := d.Decode(&value)
	return value, err
}
