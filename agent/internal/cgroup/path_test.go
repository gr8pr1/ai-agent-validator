package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveV2DirWalk(t *testing.T) {
	root := t.TempDir()
	slice := filepath.Join(root, "system.slice", "ai-agents.slice")
	if err := os.MkdirAll(filepath.Join(slice, "session.scope"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveV2Dir(root, []string{"ai-agents.slice"})
	if err != nil {
		t.Fatal(err)
	}
	if got != slice {
		t.Fatalf("got %q want %q", got, slice)
	}
}

func TestResolveV2DirMissing(t *testing.T) {
	root := t.TempDir()
	_, err := resolveV2Dir(root, []string{"missing.slice"})
	if err == nil {
		t.Fatal("expected error")
	}
}
