package miio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Yonsm/misgo/command"
)

// Command parses and runs a cloud MiIO/MIoT text command.
// A nil service is sufficient for help.
func (m *Service) Command(ctx context.Context, did, text string, prefix ...string) (any, error) {
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
		return Help(did, prefix...), nil
	}

	rawMiIO := strings.HasPrefix(cmd, "/")
	rawMIoT := strings.HasPrefix(cmd, "prop") || cmd == "action"
	if did == "" && !rawMiIO && !rawMIoT && cmd != "list" && cmd != "home" {
		return Help(did, prefix...), nil
	}
	if m == nil {
		return nil, errors.New("MiIO command requires a cloud service")
	}

	switch {
	case rawMiIO:
		var data any
		if hasArg {
			data = arg
		}
		return m.MiIORequest(ctx, cmd, data)
	case rawMIoT:
		var params any
		if arg != "" {
			var err error
			if params, err = commandJSON([]byte(arg)); err != nil {
				return nil, fmt.Errorf("invalid %s JSON parameters: %w", cmd, err)
			}
		}
		return m.MIoTRequest(ctx, cmd, params)
	case cmd == "list":
		var huami int
		if at(2) != "" {
			var err error
			if huami, err = strconv.Atoi(at(2)); err != nil {
				return nil, fmt.Errorf("invalid getHuamiDevices: %w", err)
			}
		}
		return m.DeviceList(ctx, at(0), commandTruthy(command.ParseValue(at(1))), huami)
	case cmd == "home":
		return m.HomeList(ctx, at(0))
	}

	if strings.Trim(did, "0123456789") != "" {
		devices, err := m.DeviceList(ctx, did, false, 0)
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
	miot := numericIID(items[0])
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
			props = append(props, Property{IID: key, Value: command.ParseValue(value)})
		}
	}
	switch {
	case write:
		return m.MiIOSetProps(ctx, did, props)
	case miot && arg != "":
		id, err := ParseIID(ids[0])
		if err != nil {
			return nil, err
		}
		args := []any{}
		if arg != "[]" {
			for _, value := range argv {
				args = append(args, command.ParseValue(value))
			}
		}
		return m.MIoTAction(ctx, did, id, args)
	default:
		return m.MiIOGetProps(ctx, did, ids)
	}
}

// Help returns help text for the cloud command syntax.
func Help(did string, prefixes ...string) string {
	prefix := command.Prefix(prefixes)
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
	case json.Number:
		n, _ := v.Float64()
		return n != 0
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
