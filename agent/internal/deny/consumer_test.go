package deny

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

func TestConsumerEmitKernelDeny(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	rep, err := report.New("text", auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	tbl := proctable.New()
	now := time.Now()
	tbl.OnExec(42, 1, 1, "test", "/usr/bin/test", now)
	tbl.Tag(42, "agent", proctable.ModeA, "test")
	holder := policy.NewHolder()
	cp := &policy.CompiledPolicy{
		Version: 1,
		Live: []policy.CompiledRule{{
			ID: "deny-etc-shadow", Rationale: "no shadow reads",
			Decision: policy.DecisionDeny, Action: "open",
		}},
	}
	holder.Swap(cp, policy.VersionMeta{Version: 1})

	c := NewConsumer(rep, tbl, holder, slog.Default())
	hash := policy.RuleIDHash("deny-etc-shadow")
	c.emit(Verdict{
		TimestampNS: 100,
		PID:         42,
		RuleIDHash:  hash,
		Action:      ActionOpen,
		Path:        "/etc/shadow",
	})

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec report.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Event != "kernel_deny" {
		t.Fatalf("event=%q", rec.Event)
	}
	if rec.RuleID != "deny-etc-shadow" || rec.Reason != "no shadow reads" {
		t.Fatalf("rule=%q reason=%q", rec.RuleID, rec.Reason)
	}
	if rec.PolicyVersion != 1 || rec.Action != "open" || rec.Path != "/etc/shadow" {
		t.Fatalf("version=%d action=%q path=%q", rec.PolicyVersion, rec.Action, rec.Path)
	}
	if rec.AgentID != "agent" || rec.Mode != proctable.ModeA {
		t.Fatalf("agent=%q mode=%q", rec.AgentID, rec.Mode)
	}
}

func TestConsumerEmitUnknownHash(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	rep, err := report.New("json", auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	c := NewConsumer(rep, proctable.New(), policy.NewHolder(), slog.Default())
	c.emit(Verdict{
		TimestampNS: 1,
		PID:         99,
		RuleIDHash:  0xdeadbeef,
		Action:      ActionConnect,
	})

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec report.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.RuleID != "hash:deadbeef" {
		t.Fatalf("rule=%q", rec.RuleID)
	}
	if rec.Action != "connect" {
		t.Fatalf("action=%q", rec.Action)
	}
}
