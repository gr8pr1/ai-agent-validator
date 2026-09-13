package ebpfloader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// DefaultPinRoot is the bpffs directory for persisted enforcer policy maps.
const DefaultPinRoot = "/sys/fs/bpf/ai-agent-validator"

// policyMapNames are enforcer maps persisted across agent restarts (P3.7).
var policyMapNames = []string{
	"policy_ctrl",
	"path_deny",
	"path_allow",
	"inode_deny",
	"inode_allow",
	"ip_deny",
	"ip_allow",
	"port_deny",
	"port_allow",
}

// PinPolicyMaps writes policy maps to pinPath/<map_name> under bpffs.
func PinPolicyMaps(pinPath string, maps map[string]*ebpf.Map) error {
	if pinPath == "" {
		return nil
	}
	if err := os.MkdirAll(pinPath, 0o755); err != nil {
		return fmt.Errorf("mkdir pin root: %w", err)
	}
	for _, name := range policyMapNames {
		m := maps[name]
		if m == nil {
			return fmt.Errorf("map %q missing from collection", name)
		}
		dest := filepath.Join(pinPath, name)
		if err := m.Pin(dest); err != nil {
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}
	return nil
}

// LoadPinnedPolicyMaps returns all policy maps from pinPath, or nil when the
// set is incomplete (partial pins are discarded).
func LoadPinnedPolicyMaps(pinPath string) (map[string]*ebpf.Map, error) {
	if pinPath == "" {
		return nil, nil
	}
	out := make(map[string]*ebpf.Map, len(policyMapNames))
	for _, name := range policyMapNames {
		path := filepath.Join(pinPath, name)
		if _, err := os.Stat(path); err != nil {
			closePinnedMaps(out)
			ClearPinnedPolicyMaps(pinPath)
			return nil, nil
		}
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			closePinnedMaps(out)
			ClearPinnedPolicyMaps(pinPath)
			return nil, nil
		}
		out[name] = m
	}
	return out, nil
}

// ClearPinnedPolicyMaps removes persisted policy map pins (best-effort).
func ClearPinnedPolicyMaps(pinPath string) {
	if pinPath == "" {
		return
	}
	for _, name := range policyMapNames {
		_ = os.Remove(filepath.Join(pinPath, name))
	}
}

func closePinnedMaps(maps map[string]*ebpf.Map) {
	for _, m := range maps {
		_ = m.Close()
	}
}

func mergeReplacements(base, extra map[string]*ebpf.Map) map[string]*ebpf.Map {
	out := make(map[string]*ebpf.Map, len(base)+len(extra))
	for k, v := range extra {
		out[k] = v
	}
	for k, v := range base {
		out[k] = v
	}
	return out
}
