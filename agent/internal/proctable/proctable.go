// Package proctable tracks process lineage and propagates the agent_id tag
// across a process tree. It is the userspace source of truth for "which pid
// belongs to which enrolled agent" in P0 (no in-kernel tag map yet).
package proctable

import (
	"sync"
	"time"
)

// Enroll modes.
const (
	ModeNone      = ""
	ModeA         = "A"         // controlled-spawn cgroup
	ModeB         = "B"         // exec-time fingerprint
	ModeInherited = "inherited" // descendant of a tagged process
)

// Proc is one tracked process.
type Proc struct {
	PID       uint32
	StartNS   uint64
	PPID      uint32
	Comm      string
	Binary    string
	AgentID   string // "" when untagged
	Mode      string
	Reason    string
	RootPID   uint32 // pid of the lineage anchor that was enrolled
	FirstSeen time.Time
	LastSeen  time.Time
	Exited    bool
}

// Tagged reports whether this process belongs to an enrolled agent.
func (p *Proc) Tagged() bool { return p.AgentID != "" }

// Table is a concurrency-safe pid -> Proc map.
type Table struct {
	mu    sync.RWMutex
	byPID map[uint32]*Proc
}

func New() *Table {
	return &Table{byPID: make(map[uint32]*Proc)}
}

// OnFork records a child and, if the parent is tagged, propagates the tag.
// Returns the child Proc (already tagged if inheritance applied).
func (t *Table) OnFork(child, parent uint32, comm string, now time.Time) *Proc {
	t.mu.Lock()
	defer t.mu.Unlock()

	c := &Proc{PID: child, PPID: parent, Comm: comm, FirstSeen: now, LastSeen: now}
	if p, ok := t.byPID[parent]; ok && p.Tagged() {
		c.AgentID = p.AgentID
		c.Mode = ModeInherited
		c.Reason = "forked by " + p.Comm
		c.RootPID = p.RootPID
		t.byPID[child] = c
	}
	// Untagged forks are intentionally NOT stored: the exec path re-creates an
	// entry when needed and recovers the parent via real_parent->tgid, so
	// storing every host-wide fork (including thread creation, whose exit we
	// skip) would only leak memory.
	return c
}

// OnExec updates (or creates) a process at exec time, carrying over any tag the
// pid already holds (from a prior fork) or inheriting from a tagged parent.
// Returns the Proc and whether it is already tagged (inherited).
func (t *Table) OnExec(pid uint32, startNS uint64, ppid uint32, comm, binary string, now time.Time) (*Proc, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	p, ok := t.byPID[pid]
	// Reuse-safe identity: if the stored entry has a different start time, the
	// PID was reused and we missed the exit (e.g. a dropped ringbuf record).
	// Discard the stale entry so an unrelated process is not misattributed.
	if ok && p.StartNS != 0 && startNS != 0 && p.StartNS != startNS {
		ok = false
	}
	if !ok {
		p = &Proc{PID: pid, FirstSeen: now}
		t.byPID[pid] = p
	}
	p.StartNS = startNS
	p.PPID = ppid
	p.Comm = comm
	p.Binary = binary
	p.LastSeen = now
	p.Exited = false

	if !p.Tagged() {
		if parent, ok := t.byPID[ppid]; ok && parent.Tagged() {
			p.AgentID = parent.AgentID
			p.Mode = ModeInherited
			p.Reason = "child of " + parent.Comm
			p.RootPID = parent.RootPID
		}
	}
	return p, p.Tagged()
}

// Tag marks a process as a freshly enrolled anchor (Mode A or B).
func (t *Table) Tag(pid uint32, agentID, mode, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.byPID[pid]; ok {
		p.AgentID = agentID
		p.Mode = mode
		p.Reason = reason
		p.RootPID = pid
	}
}

// OnExit marks a process exited (pruned later).
func (t *Table) OnExit(pid uint32, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.byPID[pid]; ok {
		p.Exited = true
		p.LastSeen = now
	}
}

// Get returns a copy of the Proc for pid.
func (t *Table) Get(pid uint32) (Proc, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.byPID[pid]
	if !ok {
		return Proc{}, false
	}
	return *p, true
}

// TaggedSnapshot returns copies of all currently-tagged, non-exited processes.
func (t *Table) TaggedSnapshot() []Proc {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []Proc
	for _, p := range t.byPID {
		if p.Tagged() && !p.Exited {
			out = append(out, *p)
		}
	}
	return out
}

// Len returns the number of tracked processes.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byPID)
}

// Prune drops stale entries older than maxAge: exited processes, and untagged
// processes (whose exit we may have missed to a dropped ringbuf record). Live
// tagged processes are kept until their exit is observed.
func (t *Table) Prune(maxAge time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	n := 0
	for pid, p := range t.byPID {
		if p.LastSeen.Before(cutoff) && (p.Exited || !p.Tagged()) {
			delete(t.byPID, pid)
			n++
		}
	}
	return n
}
