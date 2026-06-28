// Package enricher resolves userspace context for a pid: the real binary path,
// the owning username, and the cgroup-v2 path (used for Mode A enrollment).
package enricher

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
)

// Enricher caches uid->username lookups; /proc reads are done on demand.
type Enricher struct {
	mu    sync.RWMutex
	users map[uint32]string
}

func New() *Enricher {
	return &Enricher{users: make(map[uint32]string)}
}

// Binary returns the resolved executable path for pid via /proc/<pid>/exe.
// Returns "" if the process already exited.
func (e *Enricher) Binary(pid uint32) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	// Readlink may append " (deleted)" for replaced binaries.
	return strings.TrimSuffix(path, " (deleted)")
}

// User resolves a uid to a username, falling back to the numeric uid.
func (e *Enricher) User(uid uint32) string {
	e.mu.RLock()
	name, ok := e.users[uid]
	e.mu.RUnlock()
	if ok {
		return name
	}
	name = strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	e.mu.Lock()
	e.users[uid] = name
	e.mu.Unlock()
	return name
}

// CgroupPath returns the cgroup-v2 path for pid (the "0::" line of
// /proc/<pid>/cgroup), e.g. "/system.slice/ai-agents.slice/...". Returns ""
// if unavailable (process exited or cgroup v1 only).
func (e *Enricher) CgroupPath(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		// cgroup v2 unified hierarchy line looks like "0::/path".
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}
