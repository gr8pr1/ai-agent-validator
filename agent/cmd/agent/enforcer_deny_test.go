package main

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	cringbuf "github.com/cilium/ebpf/ringbuf"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/deny"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/ebpfloader"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
)

const testDenyRuleID = "deny-etc-shadow"

// TestEnforcerDenyOpenEPERM loads policy, tags the test process, and expects
// opening /etc/shadow to fail with EPERM/EACCES and emit a deny_verdict.
// Requires root and amd64 fmod_ret support.
func TestEnforcerDenyOpenEPERM(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root; run: sudo -E go test ./cmd/agent -run TestEnforcerDenyOpenEPERM")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("fmod_ret openat hook is amd64-only in the BPF object")
	}
	if len(enforcerObject) == 0 || len(bpfObject) == 0 {
		t.Fatal("embedded BPF objects empty; run `make bpf` first")
	}

	enrollLoader, err := ebpfloader.Load(bpfObject)
	if err != nil {
		t.Fatalf("load enroll BPF: %v", err)
	}
	defer enrollLoader.Close()

	if _, err := enrollLoader.Attach(); err != nil {
		t.Fatalf("attach enroll tracepoints: %v", err)
	}

	replacements := map[string]*ebpf.Map{
		"tagged_pids":         enrollLoader.TaggedPidsMap(),
		"pending_open_paths":  enrollLoader.PendingOpenPathsMap(),
		"pending_connects":    enrollLoader.PendingConnectsMap(),
		"pending_open_cpu":    enrollLoader.PendingOpenCPUMap(),
		"pending_connect_cpu": enrollLoader.PendingConnectCPUMap(),
	}
	enforcer, err := ebpfloader.LoadEnforcer(enforcerObject, replacements)
	if err != nil {
		t.Fatalf("load enforcer BPF: %v", err)
	}
	defer enforcer.Close()

	if _, err := enforcer.AttachSyscallEnforcement(); err != nil {
		t.Fatalf("attach syscall fmod_ret: %v", err)
	}

	cp := &policy.CompiledPolicy{
		Version: 1,
		Live: []policy.CompiledRule{{
			ID: testDenyRuleID, Rationale: "test deny shadow reads",
			Decision: policy.DecisionDeny, Action: "open",
			PathIn: []string{"/etc/shadow"}, Specificity: 12,
		}},
	}
	if _, err := enforcer.LoadLivePolicy(cp, policy.PolicyCtrlValues{
		EnforcementActive: true,
		PolicyVersion:     1,
	}); err != nil {
		t.Fatalf("load live policy: %v", err)
	}

	pid := uint32(os.Getpid())
	if err := enrollLoader.TagPID(pid); err != nil {
		t.Fatalf("tag pid: %v", err)
	}

	denyReader, err := enforcer.DenyReader()
	if err != nil {
		t.Fatalf("open deny ringbuf: %v", err)
	}
	defer denyReader.Close()

	_, err = os.Open("/etc/shadow")
	if err == nil {
		t.Fatal("expected EPERM/EACCES opening /etc/shadow")
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("expected EPERM/EACCES, got %v", err)
	}

	v := readDenyVerdict(t, denyReader, 3*time.Second)
	if v.Action != deny.ActionOpen {
		t.Fatalf("action=%d want open", v.Action)
	}
	if v.PID != pid {
		t.Fatalf("pid=%d want %d", v.PID, pid)
	}
	wantHash := policy.RuleIDHash(testDenyRuleID)
	if v.RuleIDHash != wantHash {
		t.Fatalf("rule hash=%#x want %#x", v.RuleIDHash, wantHash)
	}
	if v.Path != "/etc/shadow" {
		t.Fatalf("path=%q want /etc/shadow", v.Path)
	}
}

func readDenyVerdict(t *testing.T, r *cringbuf.Reader, timeout time.Duration) deny.Verdict {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, cringbuf.ErrClosed) {
				t.Fatal("deny ringbuf closed")
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		v, err := deny.Parse(rec.RawSample)
		if err != nil {
			t.Fatalf("parse deny verdict: %v", err)
		}
		return v
	}
	t.Fatal("timeout waiting for deny verdict")
	return deny.Verdict{} // unreachable; satisfies compiler after t.Fatal
}
