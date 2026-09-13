package deny

import (
	"sync"
	"time"
)

const connectCacheTTL = 30 * time.Second

type connectEntry struct {
	ip   string
	port uint16
	at   time.Time
}

// ConnectCache stores recent connect destinations by PID for deny enrichment
// when the kernel verdict lacks dest (race with action stream).
type ConnectCache struct {
	mu sync.RWMutex
	m  map[uint32]connectEntry
}

func NewConnectCache() *ConnectCache {
	return &ConnectCache{m: make(map[uint32]connectEntry)}
}

// Record stores the connect destination for pid.
func (c *ConnectCache) Record(pid uint32, ip string, port uint16) {
	if c == nil || ip == "" {
		return
	}
	c.mu.Lock()
	c.m[pid] = connectEntry{ip: ip, port: port, at: time.Now()}
	c.mu.Unlock()
}

// Forget removes pid (call on process exit).
func (c *ConnectCache) Forget(pid uint32) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.m, pid)
	c.mu.Unlock()
}

// Lookup returns the most recent connect dest for pid within TTL.
func (c *ConnectCache) Lookup(pid uint32) (ip string, port uint16, ok bool) {
	if c == nil {
		return "", 0, false
	}
	c.mu.RLock()
	e, found := c.m[pid]
	c.mu.RUnlock()
	if !found || time.Since(e.at) > connectCacheTTL {
		return "", 0, false
	}
	return e.ip, e.port, true
}
