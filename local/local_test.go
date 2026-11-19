package local

import (
	"encoding/json"
	"testing"
)

func TestParseIID(t *testing.T) {
	id, err := ParseIID("2")
	if err != nil || id != (IID{SIID: 2, PIID: 1}) {
		t.Fatalf("ParseIID(\"2\") = %v, %v", id, err)
	}
	id, err = ParseIID("3-5")
	if err != nil || id != (IID{SIID: 3, PIID: 5}) {
		t.Fatalf("ParseIID(\"3-5\") = %v, %v", id, err)
	}
	if _, err := ParseIID("power"); err == nil {
		t.Fatal("expected error for non-numeric IID")
	}
}

func TestMatchMIoTValuesOutOfOrder(t *testing.T) {
	ids := []IID{{2, 1}, {2, 2}, {3, 1}}
	resp := []any{
		map[string]any{"did": "3-1", "siid": json.Number("3"), "piid": json.Number("1"), "code": json.Number("0"), "value": json.Number("42")},
		map[string]any{"did": "2-2", "siid": json.Number("2"), "piid": json.Number("2"), "code": json.Number("-4004")},
		map[string]any{"did": "2-1", "siid": json.Number("2"), "piid": json.Number("1"), "code": json.Number("0"), "value": true},
	}
	got, err := matchMIoTValues(resp, ids)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0] != true || got[1] != nil || got[2] != json.Number("42") {
		t.Fatalf("unexpected values: %#v", got)
	}
}

func TestMatchMIoTValuesAllFailed(t *testing.T) {
	ids := []IID{{2, 1}}
	resp := []any{
		map[string]any{"did": "2-1", "siid": json.Number("2"), "piid": json.Number("1"), "code": json.Number("-4004")},
	}
	if _, err := matchMIoTValues(resp, ids); err == nil {
		t.Fatal("expected error when all MIoT properties fail")
	}
}
