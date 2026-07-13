package enroll

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/config"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enricher"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/event"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

func newTestEngine(cfg config.Config) (*Engine, *proctable.Table) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tbl := proctable.New()
	rep, err := report.New("json", "")
	if err != nil {
		panic(err)
	}
	return New(cfg, enricher.New(), nil, tbl, rep, NoopTagger{}, nil, log), tbl
}

func tagProc(tbl *proctable.Table, pid uint32, startNS uint64) {
	now := time.Now()
	tbl.OnExec(pid, startNS, 1, "node", "/tmp/node", now)
	tbl.Tag(pid, "claude-code", proctable.ModeB, "test")
}

func agentConnectCount(eng *Engine) uint64 {
	_, _, agents := eng.Stats().Snapshot()
	for _, a := range agents {
		if a.AgentID == "claude-code" {
			return a.Connect
		}
	}
	return 0
}

func agentOpenCount(eng *Engine) uint64 {
	_, _, agents := eng.Stats().Snapshot()
	for _, a := range agents {
		if a.AgentID == "claude-code" {
			return a.Open
		}
	}
	return 0
}

func agentUnlinkCount(eng *Engine) uint64 {
	_, _, agents := eng.Stats().Snapshot()
	for _, a := range agents {
		if a.AgentID == "claude-code" {
			return a.Unlink
		}
	}
	return 0
}

func TestHandleActionRequiresTaggedProc(t *testing.T) {
	cfg := config.Default()
	eng, tbl := newTestEngine(cfg)
	tagProc(tbl, 42, 100)

	eng.Handle(&event.Event{Type: event.TypeConnect, PID: 42, StartTimeNs: 100, DestIP: "127.0.0.1", DestPort: 9})
	if got := agentConnectCount(eng); got != 1 {
		t.Fatalf("tagged connect count: got %d want 1", got)
	}

	eng.Handle(&event.Event{Type: event.TypeConnect, PID: 99, StartTimeNs: 1, DestIP: "127.0.0.1", DestPort: 9})
	if got := agentConnectCount(eng); got != 1 {
		t.Fatalf("untagged pid should not increment connect: got %d", got)
	}

	eng.Handle(&event.Event{Type: event.TypeConnect, PID: 42, StartTimeNs: 999, DestIP: "127.0.0.1", DestPort: 9})
	if got := agentConnectCount(eng); got != 1 {
		t.Fatalf("start_time mismatch should drop event: got %d", got)
	}
}

func TestHandleActionDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Actions.Enabled = false
	eng, tbl := newTestEngine(cfg)
	tagProc(tbl, 1, 10)

	eng.Handle(&event.Event{Type: event.TypeUnlink, PID: 1, StartTimeNs: 10, Path: "/tmp/x"})
	if got := agentUnlinkCount(eng); got != 0 {
		t.Fatalf("disabled actions should not count unlink: got %d", got)
	}
}

func TestHandleActionOpenWritesOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Actions.OpenWritesOnly = true
	eng, tbl := newTestEngine(cfg)
	tagProc(tbl, 5, 50)

	eng.Handle(&event.Event{Type: event.TypeOpen, PID: 5, StartTimeNs: 50, Path: "/tmp/r.txt", OpenFlags: 0})
	if got := agentOpenCount(eng); got != 0 {
		t.Fatalf("read-only open should be filtered: got %d", got)
	}

	eng.Handle(&event.Event{Type: event.TypeOpen, PID: 5, StartTimeNs: 50, Path: "/tmp/w.txt", OpenFlags: 1})
	if got := agentOpenCount(eng); got != 1 {
		t.Fatalf("write open should be counted: got %d", got)
	}
}

func TestHandleActionCaptureFilter(t *testing.T) {
	cfg := config.Default()
	cfg.Actions.Capture = []string{"connect"}
	eng, tbl := newTestEngine(cfg)
	tagProc(tbl, 7, 70)

	eng.Handle(&event.Event{Type: event.TypeUnlink, PID: 7, StartTimeNs: 70, Path: "/tmp/x"})
	if got := agentUnlinkCount(eng); got != 0 {
		t.Fatalf("unlink not in capture list: got %d", got)
	}

	eng.Handle(&event.Event{Type: event.TypeConnect, PID: 7, StartTimeNs: 70, DestIP: "10.0.0.1", DestPort: 443})
	if got := agentConnectCount(eng); got != 1 {
		t.Fatalf("connect in capture list: got %d", got)
	}
}

func TestActionsCaptureEnabledDefault(t *testing.T) {
	cfg := config.Default()
	for _, name := range []string{"connect", "open", "unlink", "rename"} {
		if !cfg.Actions.CaptureEnabled(name) {
			t.Fatalf("expected %q enabled by default", name)
		}
	}
	cfg.Actions.Capture = []string{"open"}
	if cfg.Actions.CaptureEnabled("connect") {
		t.Fatal("connect should be disabled when not in capture list")
	}
}
