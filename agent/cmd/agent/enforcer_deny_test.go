package main

import (
	"errors"
	"fmt"
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

const testDenyRuleID = "deny-open-test"

// TestEnforcerDenyOpenEPERM loads policy, tags the test process, and expects
// opening a world-readable temp file to fail with EPERM and emit a deny_verdict.
// Uses a dedicated path (not /etc/shadow) so root-only DAC does not mask a
// missing enforcement hook. Requires root and amd64 fmod_ret support.
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

	target, err := os.CreateTemp("", "aiblocker-deny-test-*")
	if err != nil {
		t.Fatal(err)
	}
	targetPath := target.Name()
	target.Close()
	defer os.Remove(targetPath)
	if err := os.Chmod(targetPath, 0o644); err != nil {
		t.Fatal(err)
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
			ID: testDenyRuleID, Rationale: "test deny open",
			Decision: policy.DecisionDeny, Action: "open",
			PathIn: []string{targetPath}, Specificity: 12,
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

	_, err = syscall.Open(targetPath, syscall.O_RDONLY, 0)
	if err == nil {
		stats, _ := enforcer.EnforceStats()
		t.Fatalf("expected EPERM opening %s (enforce_stats=%+v)", targetPath, stats)
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM, got %v", err)
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
	if v.Path != targetPath {
		t.Fatalf("path=%q want %s", v.Path, targetPath)
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
	t.Fatal(fmt.Sprintf("timeout waiting for deny verdict"))
	return deny.Verdict{} // unreachable; satisfies compiler after t.Fatal
}
