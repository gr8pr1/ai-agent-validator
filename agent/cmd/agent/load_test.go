package main

import (
	"os"
	"testing"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/ebpfloader"
)

// TestBPFLoadAndAttach loads the embedded BPF object into the kernel and
// attaches the tracepoints. It is a verifier/attach smoke test and requires
// root (CAP_BPF + CAP_PERFMON). It is skipped otherwise so `go test ./...`
// stays green for unprivileged users and CI without a kernel.
func TestBPFLoadAndAttach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load eBPF; run: sudo -E go test ./cmd/agent -run TestBPFLoadAndAttach")
	}
	if len(bpfObject) == 0 {
		t.Fatal("embedded BPF object is empty; run `make bpf` first")
	}

	loader, err := ebpfloader.Load(bpfObject)
	if err != nil {
		t.Fatalf("load BPF: %v", err)
	}
	defer loader.Close()

	attached, err := loader.Attach()
	if err != nil {
		t.Fatalf("attach tracepoints: %v", err)
	}
	if len(attached) != 7 {
		t.Fatalf("expected 7 tracepoints attached, got %d: %v", len(attached), attached)
	}

	if _, err := loader.Reader(); err != nil {
		t.Fatalf("open ringbuf: %v", err)
	}
}
