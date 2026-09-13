package ebpfloader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyMapNamesComplete(t *testing.T) {
	want := []string{
		"policy_ctrl", "path_deny", "path_allow", "inode_deny", "inode_allow",
		"ip_deny", "ip_allow", "port_deny", "port_allow",
	}
	if len(policyMapNames) != len(want) {
		t.Fatalf("len=%d want=%d", len(policyMapNames), len(want))
	}
	for i, name := range want {
		if policyMapNames[i] != name {
			t.Fatalf("policyMapNames[%d]=%q want %q", i, policyMapNames[i], name)
		}
	}
}

func TestLoadPinnedPolicyMapsIncomplete(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadPinnedPolicyMaps(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestClearPinnedPolicyMaps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_ctrl")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ClearPinnedPolicyMaps(dir)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stat=%v", err)
	}
}
