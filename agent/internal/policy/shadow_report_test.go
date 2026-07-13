package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShadowReportFromReader(t *testing.T) {
	fixture := `{"event":"connect","agent_id":"claude-code","time":"2026-01-01T12:00:00Z"}
{"event":"shadow_deny","rule_id":"deny-port","shadow_source":"shadow","agent_id":"claude-code","time":"2026-01-01T12:00:01Z"}
{"event":"shadow_deny","rule_id":"deny-port","shadow_source":"shadow","agent_id":"claude-code","time":"2026-01-01T12:00:02Z"}
{"event":"shadow_deny","rule_id":"deny-etc","shadow_source":"live_preview","agent_id":"ci-runner","time":"2026-01-01T12:00:03Z"}
`
	rows, err := ShadowReportFromReader(strings.NewReader(fixture), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d %+v", len(rows), rows)
	}
	var total int
	for _, r := range rows {
		total += r.Count
	}
	if total != 3 {
		t.Fatalf("total count=%d", total)
	}
	out := FormatShadowReport(rows)
	if !strings.Contains(out, "deny-port") {
		t.Fatalf("output: %s", out)
	}
}

func TestShadowReportSinceFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	lines := `{"event":"shadow_deny","rule_id":"old","shadow_source":"shadow","agent_id":"a","time":"2026-01-01T10:00:00Z"}
{"event":"shadow_deny","rule_id":"new","shadow_source":"shadow","agent_id":"a","time":"2026-01-02T10:00:00Z"}
`
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	since, _ := time.Parse(time.RFC3339, "2026-01-02T00:00:00Z")
	rows, err := ShadowReport(path, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].RuleID != "new" {
		t.Fatalf("rows=%+v", rows)
	}
}
