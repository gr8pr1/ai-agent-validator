package deny

import (
	"encoding/binary"
	"testing"
)

func TestParseVerdict(t *testing.T) {
	raw := make([]byte, verdictSize)
	binary.LittleEndian.PutUint64(raw[0:8], 123456789)
	binary.LittleEndian.PutUint32(raw[8:12], 42)
	binary.LittleEndian.PutUint32(raw[12:16], 0xdeadbeef)
	raw[16] = ActionOpen
	copy(raw[20:], "/etc/shadow")

	v, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.PID != 42 || v.RuleIDHash != 0xdeadbeef || v.Action != ActionOpen {
		t.Fatalf("unexpected verdict: %+v", v)
	}
	if v.Path != "/etc/shadow" {
		t.Fatalf("path=%q", v.Path)
	}
	if ActionName(v.Action) != "open" {
		t.Fatalf("action name=%q", ActionName(v.Action))
	}
}

func TestParseVerdictTooShort(t *testing.T) {
	_, err := Parse([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error")
	}
}
