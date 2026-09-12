package feedback

import (
	"encoding/json"
	"os"
	"sync"
)

const defaultMaxPerAgent = 32

// Hub stores recent policy feedback decisions for runtime/shim consumption.
type Hub struct {
	mu          sync.RWMutex
	maxPerAgent int
	byAgent     map[string][]Decision
	recent      []Decision
	maxRecent   int
	file        *os.File
}

// NewHub builds a feedback hub. path is an optional append-only JSONL sink for shims.
func NewHub(path string, maxPerAgent int) (*Hub, error) {
	if maxPerAgent <= 0 {
		maxPerAgent = defaultMaxPerAgent
	}
	h := &Hub{
		maxPerAgent: maxPerAgent,
		byAgent:     make(map[string][]Decision),
		maxRecent:   maxPerAgent * 4,
	}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		h.file = f
	}
	return h, nil
}

// Record stores a decision and appends to the optional feedback file.
func (h *Hub) Record(d Decision) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	key := d.AgentID
	if key == "" {
		key = "_unknown"
	}
	list := append(h.byAgent[key], d)
	if len(list) > h.maxPerAgent {
		list = list[len(list)-h.maxPerAgent:]
	}
	h.byAgent[key] = list

	h.recent = append(h.recent, d)
	if len(h.recent) > h.maxRecent {
		h.recent = h.recent[len(h.recent)-h.maxRecent:]
	}

	if h.file != nil {
		b, _ := json.Marshal(d)
		h.file.Write(b)
		h.file.Write([]byte{'\n'})
	}
}

// ForAgent returns recent decisions for agentID (newest last).
func (h *Hub) ForAgent(agentID string) []Decision {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Decision, len(h.byAgent[agentID]))
	copy(out, h.byAgent[agentID])
	return out
}

// Recent returns the most recent decisions across all agents.
func (h *Hub) Recent(limit int) []Decision {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if limit <= 0 || limit > len(h.recent) {
		limit = len(h.recent)
	}
	start := len(h.recent) - limit
	out := make([]Decision, limit)
	copy(out, h.recent[start:])
	return out
}

// Close flushes the optional feedback file.
func (h *Hub) Close() error {
	if h == nil || h.file == nil {
		return nil
	}
	return h.file.Close()
}
