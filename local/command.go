package local

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/Yonsm/misgo/command"
)

// Help returns usage for the local LAN command syntax.
func Help(prefix ...string) string {
	return fmt.Sprintf(`Get Props: %[1]s<prop|siid[-piid]>[,...]
           %[1]spower,brightness
           %[1]s2-1,2-2
Set Props: %[1]s<prop=value|siid[-piid]=value>[,...]
           %[1]spower=on,brightness=80
           %[1]s2-1=true

Call Method: %[1]s/<method> [params_json]
             %[1]s/miIO.info
             %[1]s/set_power ["on"]
`, command.Prefix(prefix))
}

// Command executes a property read, property write, MIoT action, or raw MiIO method
// against the device.
func (s *Service) Command(ctx context.Context, text string, prefix ...string) (any, error) {
	cmd, arg := strings.TrimSpace(text), ""
	if i := strings.IndexFunc(cmd, unicode.IsSpace); i >= 0 {
		cmd, arg = cmd[:i], strings.TrimSpace(cmd[i:])
	}
	switch cmd {
	case "", "?", "？", "help", "-h", "--help":
		return Help(prefix...), nil
	}
	if method, ok := strings.CutPrefix(cmd, "/"); ok {
		if arg == "" {
			return s.Send(ctx, method, nil)
		}
		params := json.RawMessage(arg)
		if !json.Valid(params) {
			return nil, fmt.Errorf("miio: invalid JSON parameters for %s", method)
		}
		return s.Send(ctx, method, params)
	}
	items := strings.Split(cmd, ",")
	if !strings.Contains(items[0], "=") {
		if isNumeric(items[0]) && arg != "" {
			id, err := ParseIID(items[0])
			if err != nil {
				return nil, err
			}
			args := []any{}
			if arg != "[]" {
				for _, value := range strings.Fields(arg) {
					args = append(args, command.ParseValue(value))
				}
			}
			return s.MIoTAction(ctx, id, args)
		}
		return s.MiIOGetProps(ctx, items)
	}
	props := make([]Property, 0, len(items))
	for _, item := range items {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			return "Invalid command: " + cmd, nil
		}
		props = append(props, Property{Name: name, Value: command.ParseValue(value)})
	}
	return s.MiIOSetProps(ctx, props)
}
