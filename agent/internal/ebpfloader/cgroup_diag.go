package ebpfloader

import (
	"bytes"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

const expectedCgroupConnectProgs = 2 // connect4 + connect6 per cgroup dir

// CgroupAttachedProg is one row from bpftool cgroup show.
type CgroupAttachedProg struct {
	ID         uint32
	AttachType string
	Name       string
}

// ParseCgroupShow parses bpftool cgroup show/list output.
func ParseCgroupShow(out []byte) []CgroupAttachedProg {
	var progs []CgroupAttachedProg
	for _, line := range bytes.Split(out, []byte("\n")) {
		trim := bytes.TrimSpace(line)
		if len(trim) == 0 {
			continue
		}
		fields := strings.Fields(string(trim))
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "ID" {
			continue
		}
		id64, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			continue
		}
		p := CgroupAttachedProg{
			ID:         uint32(id64),
			AttachType: fields[1],
			Name:       fields[len(fields)-1],
		}
		progs = append(progs, p)
	}
	return progs
}

// ListCgroupPrograms runs bpftool cgroup show on path. When effective is true,
// inherited programs from ancestor cgroups are included.
func ListCgroupPrograms(cgroupPath string, effective bool) ([]CgroupAttachedProg, error) {
	args := []string{"cgroup", "show", cgroupPath}
	if effective {
		args = append(args, "effective")
	}
	out, err := exec.Command("bpftool", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("bpftool cgroup show %s: %w (%s)", cgroupPath, err, bytes.TrimSpace(out))
	}
	return ParseCgroupShow(out), nil
}

func countConnectHooks(progs []CgroupAttachedProg) (connect4, connect6 int) {
	for _, p := range progs {
		switch p.AttachType {
		case "connect4":
			connect4++
		case "connect6":
			connect6++
		}
	}
	return connect4, connect6
}

// LogCgroupConnectPrograms logs effective connect hooks for path and its parent.
func LogCgroupConnectPrograms(cgroupPath string, log *slog.Logger) {
	if log == nil || cgroupPath == "" {
		return
	}
	paths := []string{cgroupPath}
	if parent := parentCgroupPath(cgroupPath); parent != "" {
		paths = append(paths, parent)
	}
	for _, p := range paths {
		progs, err := ListCgroupPrograms(p, true)
		if err != nil {
			log.Debug("bpftool cgroup show unavailable", "cgroup", p, "err", err)
			continue
		}
		c4, c6 := countConnectHooks(progs)
		if c4+c6 == 0 {
			continue
		}
		log.Info("cgroup connect hooks (effective)", "cgroup", p, "connect4", c4, "connect6", c6, "programs", connectHookSummary(progs))
	}
}

func connectHookSummary(progs []CgroupAttachedProg) []string {
	var out []string
	for _, p := range progs {
		if p.AttachType != "connect4" && p.AttachType != "connect6" {
			continue
		}
		out = append(out, fmt.Sprintf("%s:id=%d:%s", p.AttachType, p.ID, p.Name))
	}
	return out
}

func parentCgroupPath(path string) string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		return ""
	}
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return ""
	}
	return path[:i]
}

// WarnExtraCgroupPrograms detects stale cgroup/connect BPF attachments.
// Orphaned programs from a prior agent (e.g. SIGKILL without link.Close) can
// still deny connects while the running agent's stats stay at zero.
func WarnExtraCgroupPrograms(cgroupPath string, log *slog.Logger) {
	if log == nil || cgroupPath == "" {
		return
	}
	paths := []string{cgroupPath}
	if parent := parentCgroupPath(cgroupPath); parent != "" {
		paths = append(paths, parent)
	}
	for _, p := range paths {
		progs, err := ListCgroupPrograms(p, true)
		if err != nil {
			log.Debug("bpftool cgroup show unavailable", "cgroup", p, "err", err)
			continue
		}
		c4, c6 := countConnectHooks(progs)
		total := c4 + c6
		if total <= expectedCgroupConnectProgs {
			continue
		}
		log.Warn("extra effective cgroup connect BPF programs; orphaned enforcer from a prior run can block connects with stale policy while current agent stats stay zero",
			"cgroup", p,
			"connect4", c4,
			"connect6", c6,
			"expected_each", 1,
			"programs", connectHookSummary(progs),
			"cleanup", fmt.Sprintf("bpftool cgroup show %s effective  # then: bpftool cgroup detach %s connect4 id <ID>", p, p))
	}
}
