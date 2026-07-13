package enroll

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/config"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enricher"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/event"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

func newTestEngineWithPolicy(t *testing.T, agentID string, cp *policy.CompiledPolicy) (*Engine, *proctable.Table, string) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tbl := proctable.New()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	rep, err := report.New("json", auditPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	holder := policy.NewHolder()
	holder.Swap(cp, policy.VersionMeta{Version: 1, AgentScope: agentID})
	return New(cfg, enricher.New(), nil, tbl, rep, NoopTagger{}, holder, log), tbl, auditPath
}

func readAuditEvents(t *testing.T, path string) []report.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []report.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec report.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func TestHandleActionEmitsShadowDeny(t *testing.T) {
	cp := &policy.CompiledPolicy{
		AgentScope: "claude-code",
		Shadow: []policy.CompiledRule{{
			ID: "deny-weird-port", Rationale: "unusual port", Decision: policy.DecisionDeny,
			Action: "connect", DestPortNotIn: []uint16{443, 80}, Specificity: 16,
		}},
	}
	eng, tbl, auditPath := newTestEngineWithPolicy(t, "claude-code", cp)
	tagProc(tbl, 42, 100)

	eng.Handle(&event.Event{Type: event.TypeConnect, PID: 42, StartTimeNs: 100, DestIP: "8.8.8.8", DestPort: 53})

	events := readAuditEvents(t, auditPath)
	var actionCount, shadowCount int
	for _, e := range events {
		switch e.Event {
		case "connect":
			actionCount++
		case "shadow_deny":
			shadowCount++
			if e.RuleID != "deny-weird-port" || e.ShadowSource != policy.ShadowSourceShadow {
				t.Fatalf("shadow record: %+v", e)
			}
		}
	}
	if actionCount != 1 || shadowCount != 1 {
		t.Fatalf("action=%d shadow=%d events=%+v", actionCount, shadowCount, events)
	}
}

func TestHandleActionShadowScopeMismatch(t *testing.T) {
	cp := &policy.CompiledPolicy{
		AgentScope: "other-agent",
		Live: []policy.CompiledRule{{
			ID: "deny-open", Rationale: "deny", Decision: policy.DecisionDeny,
			Action: "open", PathIn: []string{"/etc/*"}, Specificity: 5,
		}},
	}
	eng, tbl, auditPath := newTestEngineWithPolicy(t, "other-agent", cp)
	tagProc(tbl, 42, 100)

	eng.Handle(&event.Event{Type: event.TypeOpen, PID: 42, StartTimeNs: 100, Path: "/etc/shadow", OpenFlags: 1})

	events := readAuditEvents(t, auditPath)
	for _, e := range events {
		if e.Event == "shadow_deny" {
			t.Fatalf("unexpected shadow_deny for scope mismatch: %+v", e)
		}
	}
}

func TestHandleActionAllowOnlyNoShadowDeny(t *testing.T) {
	cp := &policy.CompiledPolicy{
		AgentScope: "claude-code",
		Live: []policy.CompiledRule{{
			ID: "allow-tmp", Rationale: "allow tmp", Decision: policy.DecisionAllow,
			Action: "open", PathIn: []string{"/tmp/*"}, Specificity: 5,
		}},
	}
	eng, tbl, auditPath := newTestEngineWithPolicy(t, "claude-code", cp)
	tagProc(tbl, 42, 100)

	eng.Handle(&event.Event{Type: event.TypeOpen, PID: 42, StartTimeNs: 100, Path: "/tmp/foo", OpenFlags: 1})

	events := readAuditEvents(t, auditPath)
	for _, e := range events {
		if e.Event == "shadow_deny" {
			t.Fatalf("allow-only policy should not emit shadow_deny: %+v", e)
		}
	}
}

func TestHandleActionLivePreviewShadowDeny(t *testing.T) {
	cp := &policy.CompiledPolicy{
		AgentScope: "claude-code",
		Live: []policy.CompiledRule{{
			ID: "deny-shadow-file", Rationale: "no shadow reads", Decision: policy.DecisionDeny,
			Action: "open", PathIn: []string{"/etc/shadow"}, Specificity: 12,
		}},
	}
	eng, tbl, auditPath := newTestEngineWithPolicy(t, "claude-code", cp)
	tagProc(tbl, 42, 100)

	eng.Handle(&event.Event{Type: event.TypeOpen, PID: 42, StartTimeNs: 100, Path: "/etc/shadow", OpenFlags: 1})

	events := readAuditEvents(t, auditPath)
	found := false
	for _, e := range events {
		if e.Event == "shadow_deny" && e.ShadowSource == policy.ShadowSourceLivePreview {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected live_preview shadow_deny in %+v", events)
	}
}
