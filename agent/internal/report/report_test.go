package report

import (
	"strings"
	"testing"
	"time"
)

func TestRenderShadowDenyText(t *testing.T) {
	r, err := New("text", "")
	if err != nil {
		t.Fatal(err)
	}
	line := r.render(Record{
		Time:          time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Event:         "shadow_deny",
		PID:           42,
		AgentID:       "ci-runner",
		RuleID:        "deny-etc",
		ShadowSource:  "shadow",
		PolicyVersion: 3,
		Reason:        "no etc access",
		Path:          "/etc/shadow",
	})
	if !strings.Contains(line, "SHADOW_DENY") {
		t.Fatalf("line: %s", line)
	}
	if !strings.Contains(line, "rule=deny-etc") || !strings.Contains(line, "source=shadow") {
		t.Fatalf("line: %s", line)
	}
}

func TestRenderShadowDenyJSON(t *testing.T) {
	r, err := New("json", "")
	if err != nil {
		t.Fatal(err)
	}
	line := r.render(Record{
		Event:         "shadow_deny",
		RuleID:        "deny-port",
		ShadowSource:  "live_preview",
		PolicyVersion: 1,
		Dest:          "8.8.8.8",
		DestPort:      53,
	})
	if !strings.Contains(line, `"event":"shadow_deny"`) {
		t.Fatalf("line: %s", line)
	}
	if !strings.Contains(line, `"shadow_source":"live_preview"`) {
		t.Fatalf("line: %s", line)
	}
}
