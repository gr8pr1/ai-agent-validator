package deny

import (
	"encoding/binary"
	"testing"
)

func TestParseVerdictOpen(t *testing.T) {
	raw := make([]byte, verdictSize)
	binary.LittleEndian.PutUint64(raw[0:8], 123456789)
	binary.LittleEndian.PutUint32(raw[8:12], 42)
	binary.LittleEndian.PutUint32(raw[12:16], 0xdeadbeef)
	raw[16] = ActionOpen
	copy(raw[offsetPath:], "/etc/shadow")

	v, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.PID != 42 || v.RuleIDHash != 0xdeadbeef || v.Action != ActionOpen {
		t.Fatalf("unexpected verdict: %+v", v)
	}
	if v.Path != "/etc/shadow" || v.Target() != "/etc/shadow" {
		t.Fatalf("path=%q target=%q", v.Path, v.Target())
	}
}

func TestParseVerdictConnect(t *testing.T) {
	raw := make([]byte, verdictSize)
	raw[16] = ActionConnect
	raw[17] = 4 // IPv4
	binary.LittleEndian.PutUint16(raw[18:20], 443)
	copy(raw[offsetDestIP:offsetDestIP+4], []byte{8, 8, 8, 8})
	binary.LittleEndian.PutUint32(raw[8:12], 99)

	v, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.DestIP != "8.8.8.8" || v.DestPort != 443 {
		t.Fatalf("dest=%q port=%d", v.DestIP, v.DestPort)
	}
	if v.Target() != "8.8.8.8:443" {
		t.Fatalf("target=%q", v.Target())
	}
}

func TestParseVerdictTooShort(t *testing.T) {
	_, err := Parse([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveTargetFromCache(t *testing.T) {
	cache := NewConnectCache()
	cache.Record(7, "1.2.3.4", 53)
	v := Verdict{Action: ActionConnect, PID: 7}
	if got := resolveTarget(v, cache); got != "1.2.3.4:53" {
		t.Fatalf("target=%q", got)
	}
}
