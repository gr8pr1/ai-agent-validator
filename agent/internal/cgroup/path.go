// Package cgroup resolves cgroup v2 paths for Mode A enforcement attach.
package cgroup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const cgroupV2Root = "/sys/fs/cgroup"

// ResolveV2Dir returns the shortest cgroup v2 directory under /sys/fs/cgroup
// whose path contains one of the substrings (e.g. "ai-agents.slice").
func ResolveV2Dir(contains []string) (string, error) {
	return resolveV2Dir(cgroupV2Root, contains)
}

func resolveV2Dir(root string, contains []string) (string, error) {
	if len(contains) == 0 {
		return "", fmt.Errorf("no cgroup substrings configured")
	}
	if _, err := os.Stat(root); err != nil {
		return "", fmt.Errorf("cgroup v2 root %s: %w", root, err)
	}

	var best string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || rel == "." {
			return nil
		}
		rel = "/" + rel
		for _, sub := range contains {
			if sub != "" && strings.Contains(rel, sub) {
				if best == "" || len(path) < len(best) {
					best = path
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if best == "" {
		return "", fmt.Errorf("no cgroup v2 dir matching %v under %s", contains, root)
	}
	return best, nil
}
