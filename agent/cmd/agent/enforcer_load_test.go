package main

import (
	"os"
	"testing"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/ebpfloader"
)

// TestEnforcerBPFSkeleton loads the enforcer object and attaches LSM programs.
// Requires root and CONFIG_BPF_LSM (lsm=...,bpf). Skipped otherwise.
func TestEnforcerBPFSkeleton(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load eBPF; run: sudo -E go test ./cmd/agent -run TestEnforcerBPFSkeleton")
	}
	if len(enforcerObject) == 0 {
		t.Fatal("embedded enforcer BPF object is empty; run `make bpf` first")
	}

	loader, err := ebpfloader.LoadEnforcer(enforcerObject)
	if err != nil {
		t.Fatalf("load enforcer BPF: %v", err)
	}
	defer loader.Close()

	attached, err := loader.AttachLSM()
	if err != nil {
		t.Fatalf("attach LSM: %v", err)
	}
	if len(attached) != 4 {
		t.Fatalf("expected 4 LSM programs attached, got %d: %v", len(attached), attached)
	}

	if err := loader.SetPolicyCtrl(ebpfloader.PolicyCtrl{
		EnforcementActive: 0,
		PolicyVersion:     1,
	}); err != nil {
		t.Fatalf("set policy_ctrl: %v", err)
	}

	if _, err := loader.DenyReader(); err != nil {
		t.Fatalf("open deny ringbuf: %v", err)
	}

	for _, name := range []string{"policy_ctrl", "tagged_pids", "path_deny", "path_allow", "ip_deny", "ip_allow", "port_deny", "port_allow", "deny_verdicts"} {
		if loader.Maps()[name] == nil {
			t.Fatalf("map %q not found", name)
		}
	}
}
