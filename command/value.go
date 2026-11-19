// Package command implements the shared MiService text command syntax.
package command

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// Prefix returns the supplied command prefix, or "?" when omitted.
func Prefix(prefix []string) string {
	if len(prefix) == 0 {
		return "?"
	}
	return prefix[0]
}

// ParseValue converts a CLI token into nil, bool, int64, json.Number, or string.
func ParseValue(text string) any {
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
	if text != "" && strings.Trim(text, "0123456789") == "" {
		if n, err := strconv.ParseInt(text, 10, 64); err == nil {
			return n
		}
		return json.Number(strings.TrimLeft(text, "0"))
	}
	if value, err := strconv.ParseFloat(strings.TrimSpace(text), 64); err == nil &&
		!strings.ContainsAny(text, "xX") && !math.IsNaN(value) && !math.IsInf(value, 0) {
		s := strconv.FormatFloat(value, 'g', -1, 64)
		if !strings.ContainsAny(s, ".eE") {
			s += ".0"
		}
		return json.Number(s)
	}
	return text
}
