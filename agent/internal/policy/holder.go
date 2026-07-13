package policy

import "sync"

// Holder holds the current compiled policy for hot reload (P2 shadow mode).
type Holder struct {
	mu sync.RWMutex
	cp *CompiledPolicy
	meta VersionMeta
}

// NewHolder returns an empty holder.
func NewHolder() *Holder {
	return &Holder{}
}

// Swap atomically replaces the loaded policy.
func (h *Holder) Swap(cp *CompiledPolicy, meta VersionMeta) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cp = cp
	h.meta = meta
}

// Get returns the current policy snapshot (may be nil if never loaded).
func (h *Holder) Get() (*CompiledPolicy, VersionMeta) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cp, h.meta
}
