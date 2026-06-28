// Package enroll is the P0 enrollment engine: it consumes decoded lifecycle
// events, decides AI-agent membership (Mode A cgroup / Mode B fingerprint),
// propagates the tag across the process tree, and reports tagged activity.
package enroll

import (
	"log/slog"
	"strings"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/config"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enricher"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/event"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/fingerprint"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

// Engine wires the enrollment pipeline together.
type Engine struct {
	cfg   config.Config
	enr   *enricher.Enricher
	fps   *fingerprint.Set
	tbl   *proctable.Table
	rep   *report.Reporter
	log   *slog.Logger
	stats *Stats
	debug bool
}

// New constructs an Engine. fps may be nil when Mode B is disabled.
func New(cfg config.Config, enr *enricher.Enricher, fps *fingerprint.Set, tbl *proctable.Table, rep *report.Reporter, log *slog.Logger) *Engine {
	return &Engine{
		cfg:   cfg,
		enr:   enr,
		fps:   fps,
		tbl:   tbl,
		rep:   rep,
		log:   log,
		stats: newStats(),
		debug: cfg.Debug.Enabled || strings.EqualFold(cfg.LogLevel, "debug"),
	}
}

// Table exposes the proctable (for the debug server).
func (e *Engine) Table() *proctable.Table { return e.tbl }

// Fingerprints exposes the loaded set (for the debug server).
func (e *Engine) Fingerprints() *fingerprint.Set { return e.fps }

// Stats exposes the counters (for the debug server).
func (e *Engine) Stats() *Stats { return e.stats }

// Handle processes one decoded event.
func (e *Engine) Handle(ev *event.Event) {
	now := time.Now()
	switch ev.Type {
	case event.TypeFork:
		e.handleFork(ev, now)
	case event.TypeExec:
		e.handleExec(ev, now)
	case event.TypeExit:
		e.handleExit(ev, now)
	}
}

func (e *Engine) handleFork(ev *event.Event, now time.Time) {
	child := e.tbl.OnFork(ev.PID, ev.PPID, ev.Comm, now)
	e.stats.count("fork", child.AgentID)
	if e.debug {
		e.log.Debug("fork", "pid", ev.PID, "ppid", ev.PPID, "comm", ev.Comm, "tagged", child.Tagged())
	}
	if child.Tagged() {
		e.rep.Emit(report.Record{
			Event: "fork", PID: child.PID, PPID: child.PPID, RootPID: child.RootPID,
			AgentID: child.AgentID, Mode: child.Mode, Reason: child.Reason, Comm: child.Comm,
		})
	}
}

func (e *Engine) handleExec(ev *event.Event, now time.Time) {
	binary := ev.Filename
	if binary == "" {
		binary = e.enr.Binary(ev.PID)
	}
	pp, alreadyTagged := e.tbl.OnExec(ev.PID, ev.StartTimeNs, ev.PPID, ev.Comm, binary, now)
	p := *pp

	newlyEnrolled := false
	if !alreadyTagged {
		newlyEnrolled = e.tryEnroll(ev, binary)
		if np, ok := e.tbl.Get(ev.PID); ok {
			p = np
		}
	}

	e.stats.count("exec", p.AgentID)
	if newlyEnrolled {
		e.stats.enrolled()
	}

	if e.debug {
		e.log.Debug("exec", "pid", ev.PID, "ppid", ev.PPID, "comm", ev.Comm,
			"bin", binary, "argv", ev.Argv, "tagged", p.Tagged(), "mode", p.Mode)
	}

	if p.Tagged() {
		e.rep.Emit(report.Record{
			Event: "exec", Enrolled: newlyEnrolled, PID: p.PID, PPID: p.PPID, RootPID: p.RootPID,
			AgentID: p.AgentID, Mode: p.Mode, Reason: p.Reason, Comm: p.Comm, Binary: p.Binary, Argv: ev.Argv,
		})
	} else if e.cfg.Report.AllEvents {
		e.rep.Emit(report.Record{Event: "exec", PID: p.PID, PPID: p.PPID, Comm: p.Comm, Binary: binary, Argv: ev.Argv})
	}
}

func (e *Engine) handleExit(ev *event.Event, now time.Time) {
	if p, ok := e.tbl.Get(ev.PID); ok && p.Tagged() {
		e.stats.count("exit", p.AgentID)
		e.rep.Emit(report.Record{Event: "exit", PID: p.PID, RootPID: p.RootPID, AgentID: p.AgentID, Comm: p.Comm})
	}
	e.tbl.OnExit(ev.PID, now)
}

// tryEnroll attempts Mode A then Mode B and tags the pid on success.
func (e *Engine) tryEnroll(ev *event.Event, binary string) bool {
	if e.cfg.ModeA.Enabled {
		if id, cg, ok := e.matchCgroup(ev.PID); ok {
			e.tbl.Tag(ev.PID, id, proctable.ModeA, "cgroup:"+cg)
			return true
		}
	}
	if e.cfg.ModeB.Enabled && e.fps != nil {
		res := e.fps.Evaluate(fingerprint.Observation{
			BinaryPath: binary,
			Argv:       ev.Argv,
			EnvKeys:    envKeys(ev.Env),
		})
		if e.debug {
			for _, t := range res.Trace {
				e.log.Debug("fingerprint", "pid", ev.PID, "try", t)
			}
		}
		if res.Matched {
			e.tbl.Tag(ev.PID, res.Fingerprint.AgentID, proctable.ModeB, "fingerprint:"+res.Fingerprint.ID)
			return true
		}
	}
	return false
}

// matchCgroup returns an agent id when the pid's cgroup path matches a Mode A
// substring.
func (e *Engine) matchCgroup(pid uint32) (agentID, cgPath string, ok bool) {
	cg := e.enr.CgroupPath(pid)
	if cg == "" {
		return "", "", false
	}
	for _, sub := range e.cfg.ModeA.CgroupContains {
		if sub != "" && strings.Contains(cg, sub) {
			id := e.cfg.ModeA.DefaultAgentID
			if id == "" {
				id = "agent"
			}
			return id, cg, true
		}
	}
	return "", "", false
}

// envKeys extracts variable names from raw KEY=VALUE entries.
func envKeys(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			keys = append(keys, kv[:i])
		} else if kv != "" {
			keys = append(keys, kv)
		}
	}
	return keys
}
