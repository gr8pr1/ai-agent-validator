package enroll

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/fingerprint"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
)

// BootstrapRunning enrolls already-running processes (Mode A cgroup / Mode B
// fingerprint) and tags their full descendant trees in the kernel map. This
// closes the gap when the agent starts after an AI runtime is already up.
func (e *Engine) BootstrapRunning() (enrolled, kernelTagged int) {
	ppids := listProcesses()
	now := time.Now()
	for pass := 0; pass < 3; pass++ {
		for pid, ppid := range ppids {
			if e.bootstrapPID(pid, ppid, now) {
				enrolled++
			}
		}
	}
	kernelTagged = e.propagateKernelDescendants(ppids)
	return enrolled, kernelTagged
}

func (e *Engine) bootstrapPID(pid, ppid uint32, now time.Time) bool {
	if p, ok := e.tbl.Get(pid); ok && p.Tagged() {
		e.tagKernel(pid)
		return false
	}
	binary := e.enr.Binary(pid)
	if binary == "" {
		return false
	}
	comm := readProcComm(pid)
	pp, alreadyTagged := e.tbl.OnExec(pid, 0, ppid, comm, binary, now)
	if alreadyTagged {
		e.tagKernel(pid)
		return false
	}
	if e.tryEnrollObs(pid, ppid, binary) {
		if np, ok := e.tbl.Get(pid); ok {
			*pp = np
		}
		e.tagKernel(pid)
		return true
	}
	return false
}

func (e *Engine) tryEnrollObs(pid, ppid uint32, binary string) bool {
	if e.cfg.ModeA.Enabled {
		if id, cg, ok := e.matchCgroup(pid); ok {
			e.tbl.Tag(pid, id, proctable.ModeA, "cgroup:"+cg)
			return true
		}
	}
	if e.cfg.ModeB.Enabled && e.fps != nil {
		res := e.fps.Evaluate(fingerprint.Observation{
			BinaryPath: binary,
			Argv:       readProcCmdline(pid),
			EnvKeys:    readProcEnvKeys(pid),
		})
		if e.debug {
			for _, t := range res.Trace {
				e.log.Debug("bootstrap fingerprint", "pid", pid, "try", t)
			}
		}
		if res.Matched {
			e.tbl.Tag(pid, res.Fingerprint.AgentID, proctable.ModeB, "fingerprint:"+res.Fingerprint.ID)
			return true
		}
	}
	// Inherit from tagged parent already in proctable (e.g. partial bootstrap order).
	if parent, ok := e.tbl.Get(ppid); ok && parent.Tagged() {
		e.tbl.OnFork(pid, ppid, readProcComm(pid), time.Now())
		if child, ok := e.tbl.Get(pid); ok && child.Tagged() {
			return true
		}
	}
	return false
}

func (e *Engine) propagateKernelDescendants(ppids map[uint32]uint32) int {
	children := make(map[uint32][]uint32, len(ppids))
	for pid, ppid := range ppids {
		children[ppid] = append(children[ppid], pid)
	}
	seen := make(map[uint32]struct{})
	seeds := make(map[uint32]struct{})
	for _, p := range e.tbl.TaggedSnapshot() {
		seeds[p.PID] = struct{}{}
		if p.RootPID != 0 {
			seeds[p.RootPID] = struct{}{}
		}
	}
	count := 0
	for seed := range seeds {
		stack := []uint32{seed}
		for len(stack) > 0 {
			pid := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if _, ok := seen[pid]; ok {
				continue
			}
			seen[pid] = struct{}{}
			e.tagKernel(pid)
			count++
			stack = append(stack, children[pid]...)
		}
	}
	return count
}

func listProcesses() map[uint32]uint32 {
	ppids := make(map[uint32]uint32)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ppids
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		n, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(n)
		ppid := readProcPPID(pid)
		if ppid == 0 {
			continue
		}
		ppids[pid] = ppid
	}
	return ppids
}

func readProcPPID(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				n, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					return uint32(n)
				}
			}
			break
		}
	}
	return 0
}

func readProcComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcCmdline(pid uint32) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}
	parts := bytes.Split(data, []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			out = append(out, string(p))
		}
	}
	return out
}

func readProcEnvKeys(pid uint32) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil
	}
	parts := bytes.Split(data, []byte{0})
	keys := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		if i := bytes.IndexByte(p, '='); i > 0 {
			keys = append(keys, string(p[:i]))
		}
	}
	return keys
}
