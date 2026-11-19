package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/Yonsm/misgo"
)

var minaHelp = [...]struct{ command, description string }{
	{"", "# List MiNA devices"},
	{"<text>", "# TTS broadcast to all devices"},
	{"pause", "# Pause playback"},
	{"stop", "# Stop playback"},
	{"play", "# Resume playback"},
	{"play <url>", "# Play audio from URL"},
	{"loop <url>", "# Play URL on single-track loop"},
	{"volume <n>", "# Set volume (0-100)"},
	{"status", "# Get playback status"},
	{"ask", "# Get latest AI response"},
}

type minaDeviceService interface {
	DeviceList(context.Context, ...int) ([]map[string]any, error)
	SendMessage(context.Context, []map[string]any, int, string, *int) (bool, error)
	PlayerPause(context.Context, string) (bool, error)
	PlayerStop(context.Context, string) (bool, error)
	PlayerPlay(context.Context, string) (bool, error)
	PlayByURL(context.Context, string, string, ...int) (bool, error)
	PlayerSetLoop(context.Context, string, ...int) (bool, error)
	PlayerSetVolume(context.Context, string, int) (bool, error)
	PlayerGetStatus(context.Context, string) (any, error)
	GetLatestAsk(context.Context, string) ([]map[string]any, error)
}

var _ minaDeviceService = (*misgo.MiNAService)(nil)

func runMina(ctx context.Context, service minaDeviceService, text, did string, stdout, stderr io.Writer) (int, error) {
	devices, err := service.DeviceList(ctx)
	if err != nil {
		return 1, err
	}
	if devices == nil || len(devices) == 0 && strings.TrimSpace(text) == "" {
		fmt.Fprintln(stderr, "No devices found")
		return 1, nil
	}
	text = strings.TrimSpace(text)
	if text == "" {
		for _, d := range devices {
			fmt.Fprintf(stdout, "%-40s %-12s %-20s %s\n", minaDeviceField(d, "deviceID"), minaDeviceField(d, "miotDID"), minaDeviceField(d, "name"), minaDeviceField(d, "hardware"))
		}
		return 0, nil
	}

	cmd, arg := text, ""
	if i := strings.IndexFunc(text, unicode.IsSpace); i >= 0 {
		cmd, arg = text[:i], strings.TrimLeftFunc(text[i:], unicode.IsSpace)
	}
	switch cmd {
	case "pause", "stop", "play", "loop", "volume", "status", "ask":
	default:
		ok, err := service.SendMessage(ctx, devices, -1, text, nil)
		return minaExit(ok, err)
	}
	if did == "" {
		fmt.Fprintln(stderr, "Error: MI_DID environment variable required for device-specific commands")
		return 1, nil
	}
	deviceID := findMinaDevice(devices, did)
	if deviceID == "" {
		return 1, fmt.Errorf("Device not found with miotDID/name=%s. Use 'misgo mina' to list devices.", did)
	}

	switch cmd {
	case "pause":
		return minaExit(service.PlayerPause(ctx, deviceID))
	case "stop":
		return minaExit(service.PlayerStop(ctx, deviceID))
	case "play", "loop":
		loop := 1
		if cmd == "loop" {
			loop = 0
			if arg == "" {
				fmt.Fprintln(stderr, "Error: loop requires a URL argument")
				return 1, nil
			}
		} else if arg == "" {
			return minaExit(service.PlayerPlay(ctx, deviceID))
		}
		ok, err := service.PlayByURL(ctx, deviceID, arg)
		if err == nil && ok {
			_, err = service.PlayerSetLoop(ctx, deviceID, loop)
		}
		return minaExit(ok, err)
	case "volume":
		if arg == "" {
			fmt.Fprintln(stderr, "Error: volume requires a value (0-100)")
			return 1, nil
		}
		// Python int accepts underscores between digits and treats very large
		// integers as out of range rather than malformed.
		n, err := parseMinaVolume(arg)
		if err != nil {
			fmt.Fprintln(stderr, "Error: volume must be an integer (0-100)")
			return 1, nil
		}
		if n < 0 || n > 100 {
			fmt.Fprintln(stderr, "Error: volume must be 0-100")
			return 1, nil
		}
		return minaExit(service.PlayerSetVolume(ctx, deviceID, n))
	case "status":
		value, err := service.PlayerGetStatus(ctx, deviceID)
		if err != nil {
			return 1, err
		}
		if value == nil {
			fmt.Fprintln(stderr, "Failed to get playback status")
			return 1, nil
		}
		return minaExit(true, printJSON(stdout, value))
	case "ask":
		messages, err := service.GetLatestAsk(ctx, deviceID)
		if err != nil {
			return 1, err
		}
		if len(messages) == 0 {
			fmt.Fprintln(stdout, "No recent AI responses")
			return 0, nil
		}
		return minaExit(true, printJSON(stdout, messages))
	}
	panic("unreachable MiNA command")
}

func minaExit(ok bool, err error) (int, error) {
	if err != nil || !ok {
		return 1, err
	}
	return 0, nil
}

func minaDeviceField(d map[string]any, key string) string {
	if v, ok := d[key]; ok {
		return minaString(v)
	}
	return "?"
}

func minaString(v any) string {
	switch v {
	case nil:
		return "None"
	case true:
		return "True"
	case false:
		return "False"
	default:
		return fmt.Sprint(v)
	}
}

func findMinaDevice(devices []map[string]any, target string) string {
	for _, d := range devices {
		if v, ok := d["miotDID"]; ok && minaString(v) == target {
			if id, _ := d["deviceID"].(string); id != "" {
				return id
			}
		}
	}
	for _, d := range devices {
		if name, _ := d["name"].(string); name == target {
			if id, _ := d["deviceID"].(string); id != "" {
				return id
			}
		}
	}
	return ""
}

func parseMinaVolume(s string) (int, error) {
	var b strings.Builder
	digitBefore := false
	for i, ch := range s {
		switch {
		case i == 0 && (ch == '+' || ch == '-'):
			b.WriteRune(ch)
		case ch == '_' && digitBefore:
			digitBefore = false
		case unicode.IsDigit(ch):
			// Decimal Unicode numerals occur in groups of ten.
			base := ch
			for base > 0 && unicode.IsDigit(base-1) {
				base--
			}
			b.WriteByte(byte('0' + (ch-base)%10))
			digitBefore = true
		default:
			return 0, strconv.ErrSyntax
		}
	}
	if !digitBefore {
		return 0, strconv.ErrSyntax
	}
	n, err := strconv.Atoi(b.String())
	if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
		return 101, nil
	}
	return n, err
}
