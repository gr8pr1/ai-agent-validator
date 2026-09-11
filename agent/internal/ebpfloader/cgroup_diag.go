package ebpfloader

import (
	"bytes"
	"log/slog"
	"os/exec"
	"strings"
)

const expectedCgroupConnectProgs = 2 // connect4 + connect6

// WarnExtraCgroupPrograms uses bpftool to detect stale cgroup BPF attachments.
// Orphaned programs from a prior agent (e.g. SIGKILL without link.Close) can
// still deny connects while the running agent's stats stay at zero.
func WarnExtraCgroupPrograms(cgroupPath string, log *slog.Logger) {
	if log == nil || cgroupPath == "" {
		return
	}
	out, err := exec.Command("bpftool", "cgroup", "show", cgroupPath).CombinedOutput()
	if err != nil {
		log.Debug("bpftool cgroup show unavailable", "cgroup", cgroupPath, "err", err)
		return
	}
	n := countAttachedPrograms(out)
	if n <= expectedCgroupConnectProgs {
		return
	}
	log.Warn("extra cgroup BPF programs attached; orphaned enforcer from a prior run can block connects with stale policy — reboot or detach stale links before testing",
		"cgroup", cgroupPath,
		"attached_programs", n,
		"expected", expectedCgroupConnectProgs,
		"hint", "stop agent gracefully, run: bpftool cgroup show "+cgroupPath)
}

func countAttachedPrograms(bpftoolOut []byte) int {
	n := 0
	for _, line := range bytes.Split(bpftoolOut, []byte("\n")) {
		trim := bytes.TrimSpace(line)
		if len(trim) == 0 {
			continue
		}
		if bytes.HasPrefix(trim, []byte("ID ")) || bytes.HasPrefix(trim, []byte("id ")) {
			n++
		}
	}
	if n > 0 {
		return n
	}
	// Fallback: count non-empty lines that look like program listings.
	for _, line := range strings.Split(string(bpftoolOut), "\n") {
		if strings.Contains(line, "prog_id") {
			n++
		}
	}
	return n
}
