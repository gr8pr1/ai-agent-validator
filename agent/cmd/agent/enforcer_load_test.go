package main

import (
	"os"
	"runtime"
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

	loader, err := ebpfloader.LoadEnforcer(enforcerObject, ebpfloader.EnforcerLoadOptions{})
	if err != nil {
		t.Fatalf("load enforcer BPF: %v", err)
	}
	defer loader.Close()

	syscallAttached, err := loader.AttachSyscallEnforcement()
	if err != nil {
		t.Fatalf("attach syscall fmod_ret: %v", err)
	}
	if runtime.GOARCH == "amd64" && len(syscallAttached) < 4 {
		t.Fatalf("expected fmod_ret openat+connect+unlinkat+renameat2 on amd64, got %d: %v", len(syscallAttached), syscallAttached)
	}

	attached, err := loader.AttachLSM(true)
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

	for _, name := range []string{"policy_ctrl", "tagged_pids", "pending_open_paths", "pending_connects", "pending_unlink_paths", "pending_unlink_cpu", "pending_rename_paths", "pending_rename_cpu", "path_deny", "path_allow", "inode_deny", "inode_allow", "ip_deny", "ip_allow", "port_deny", "port_allow", "deny_verdicts"} {
		if loader.Maps()[name] == nil {
			t.Fatalf("map %q not found", name)
		}
	}
	for _, name := range []string{"enforce_cgroup_connect4", "enforce_cgroup_connect6"} {
		if loader.Program(name) == nil {
			t.Fatalf("program %q not found", name)
		}
	}
}
