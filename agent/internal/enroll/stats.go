package enroll

import (
	"sort"
	"sync"
	"time"
)

// AgentStat holds per-agent event counters.
type AgentStat struct {
	AgentID   string    `json:"agent_id"`
	Exec      uint64    `json:"exec"`
	Fork      uint64    `json:"fork"`
	Exit      uint64    `json:"exit"`
	Connect   uint64    `json:"connect"`
	Open      uint64    `json:"open"`
	Unlink    uint64    `json:"unlink"`
	Rename    uint64    `json:"rename"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Stats aggregates pipeline and per-agent counters.
type Stats struct {
	mu          sync.Mutex
	TotalEvents uint64
	Enrollments uint64
	perAgent    map[string]*AgentStat
}

func newStats() *Stats {
	return &Stats{perAgent: make(map[string]*AgentStat)}
}

func (s *Stats) count(kind, agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalEvents++
	if agentID == "" {
		return
	}
	a := s.perAgent[agentID]
	if a == nil {
		a = &AgentStat{AgentID: agentID, FirstSeen: time.Now()}
		s.perAgent[agentID] = a
	}
	a.LastSeen = time.Now()
	switch kind {
	case "exec":
		a.Exec++
	case "fork":
		a.Fork++
	case "exit":
		a.Exit++
	case "connect":
		a.Connect++
	case "open":
		a.Open++
	case "unlink":
		a.Unlink++
	case "rename":
		a.Rename++
	}
}

func (s *Stats) enrolled() {
	s.mu.Lock()
	s.Enrollments++
	s.mu.Unlock()
}

// Snapshot returns a stable copy of the per-agent stats, sorted by agent id.
func (s *Stats) Snapshot() (total, enrollments uint64, agents []AgentStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	total = s.TotalEvents
	enrollments = s.Enrollments
	for _, a := range s.perAgent {
		agents = append(agents, *a)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].AgentID < agents[j].AgentID })
	return
}
