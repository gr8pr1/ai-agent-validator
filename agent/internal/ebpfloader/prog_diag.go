package ebpfloader

import (
	"bytes"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

// BPFProgSummary is a parsed row from bpftool prog list/show.
type BPFProgSummary struct {
	ID   uint32
	Type string
	Name string
}

var enforcerProgNames = []string{
	"enforce_connect_entry",
	"enforce_openat_entry",
	"enforce_cgroup_connect4",
	"enforce_cgroup_connect6",
}

// ListEnforcerProgs returns loaded BPF programs whose names match our enforcer.
func ListEnforcerProgs() []BPFProgSummary {
	out, err := exec.Command("bpftool", "prog", "list").CombinedOutput()
	if err != nil {
		return nil
	}
	var progs []BPFProgSummary
	for _, line := range bytes.Split(out, []byte("\n")) {
		text := string(bytes.TrimSpace(line))
		if text == "" {
			continue
		}
		// Example: "123: tracing  name enforce_connect_entry  tag ..."
		if !strings.Contains(text, "name ") {
			continue
		}
		colon := strings.IndexByte(text, ':')
		if colon <= 0 {
			continue
		}
		id64, err := strconv.ParseUint(text[:colon], 10, 32)
		if err != nil {
			continue
		}
		name := progNameFromListLine(text)
		if name == "" {
			continue
		}
		for _, want := range enforcerProgNames {
			if name == want {
				typ := strings.TrimSpace(text[colon+1 : strings.Index(text, "name ")])
				progs = append(progs, BPFProgSummary{
					ID:   uint32(id64),
					Type: typ,
					Name: name,
				})
				break
			}
		}
	}
	return progs
}

func progNameFromListLine(line string) string {
	const marker = "name "
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[i+len(marker):])
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		return rest[:j]
	}
	return rest
}

func countProgsNamed(progs []BPFProgSummary, name string) int {
	n := 0
	for _, p := range progs {
		if p.Name == name {
			n++
		}
	}
	return n
}

// WarnExtraEnforcerProgs warns when orphaned fmod_ret/cgroup programs remain loaded.
func WarnExtraEnforcerProgs(log *slog.Logger, phase string) {
	if log == nil {
		return
	}
	progs := ListEnforcerProgs()
	if len(progs) == 0 {
		return
	}
	connectN := countProgsNamed(progs, "enforce_connect_entry")
	openatN := countProgsNamed(progs, "enforce_openat_entry")
	if connectN <= 1 && openatN <= 1 {
		return
	}
	log.Warn("multiple enforcer syscall BPF programs loaded; orphaned fmod_ret from a prior agent run can deny connects while current agent enforce_connect_deny stays zero",
		"phase", phase,
		"enforce_connect_entry", connectN,
		"enforce_openat_entry", openatN,
		"programs", progs,
		"cleanup", "reboot, or stop all agents gracefully; bpftool prog list | grep enforce_")
}
