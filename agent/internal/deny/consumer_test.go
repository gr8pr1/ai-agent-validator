package deny

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/feedback"
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

	hub, err := feedback.NewHub("", 8)
	if err != nil {
		t.Fatal(err)
	}
	c := NewConsumer(rep, tbl, holder, hub, slog.Default())
	hash := policy.RuleIDHash("deny-etc-shadow")
	c.emit(Verdict{
		TimestampNS: 100,
		PID:         42,
		RuleIDHash:  hash,
		Action:      ActionOpen,
		Path:        "/etc/shadow",
	})

	lines, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var kernelRec, fbRec report.Record
	for _, line := range splitJSONL(lines) {
		var rec report.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatal(err)
		}
		switch rec.Event {
		case "kernel_deny":
			kernelRec = rec
		case "policy_feedback":
			fbRec = rec
		}
	}
	if kernelRec.Event != "kernel_deny" {
		t.Fatalf("kernel event=%q", kernelRec.Event)
	}
	if kernelRec.RuleID != "deny-etc-shadow" || kernelRec.Reason != "no shadow reads" {
		t.Fatalf("rule=%q reason=%q", kernelRec.RuleID, kernelRec.Reason)
	}
	if fbRec.Feedback == nil || fbRec.Feedback.Retry != feedback.RetryDoNot {
		t.Fatalf("feedback=%+v", fbRec.Feedback)
	}
	if fbRec.Feedback.Target != "/etc/shadow" {
		t.Fatalf("target=%q", fbRec.Feedback.Target)
	}
	got := hub.ForAgent("agent")
	if len(got) != 1 || got[0].MatchedRule != "deny-etc-shadow" {
		t.Fatalf("hub=%+v", got)
	}
}

func splitJSONL(b []byte) [][]byte {
	var out [][]byte
	for _, line := range bytesSplit(b) {
		if len(line) > 0 {
			out = append(out, line)
		}
	}
	return out
}

func bytesSplit(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			lines = append(lines, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}

func TestConsumerEmitUnknownHash(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	rep, err := report.New("json", auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rep.Close() })

	c := NewConsumer(rep, proctable.New(), policy.NewHolder(), nil, slog.Default())
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
