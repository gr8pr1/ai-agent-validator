package enroll

import (
	"log/slog"
	"strings"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/config"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enricher"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/event"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/fingerprint"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

// KernelTagger writes the advisory in-kernel tagged_pids map.
type KernelTagger interface {
	TagPID(pid uint32) error
	UntagPID(pid uint32) error
}

// NoopTagger is a no-op KernelTagger for tests.
type NoopTagger struct{}

func (NoopTagger) TagPID(uint32) error   { return nil }
func (NoopTagger) UntagPID(uint32) error { return nil }

// Engine wires the enrollment pipeline together.
type Engine struct {
	cfg          config.Config
	enr          *enricher.Enricher
	fps          *fingerprint.Set
	tbl          *proctable.Table
	rep          *report.Reporter
	tagger       KernelTagger
	policy       *policy.Holder
	policyScope  string // optional config override for agent_scope matching
	log          *slog.Logger
	stats        *Stats
	debug        bool
}

// New constructs an Engine. fps may be nil when Mode B is disabled; tagger may
// be nil (treated as no-op). policy may be nil when shadow mode is disabled.
func New(cfg config.Config, enr *enricher.Enricher, fps *fingerprint.Set, tbl *proctable.Table, rep *report.Reporter, tagger KernelTagger, pol *policy.Holder, log *slog.Logger) *Engine {
	if tagger == nil {
		tagger = NoopTagger{}
	}
	return &Engine{
		cfg:         cfg,
		enr:         enr,
		fps:         fps,
		tbl:         tbl,
		rep:         rep,
		tagger:      tagger,
		policy:      pol,
		policyScope: cfg.Policy.Scope,
		log:         log,
		stats:       newStats(),
		debug:       cfg.Debug.Enabled || strings.EqualFold(cfg.LogLevel, "debug"),
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
	case event.TypeConnect, event.TypeOpen, event.TypeUnlink, event.TypeRename:
		e.handleAction(ev)
	}
}

func (e *Engine) tagKernel(pid uint32) {
	if err := e.tagger.TagPID(pid); err != nil && e.debug {
		e.log.Debug("tag pid in kernel map", "pid", pid, "err", err)
	}
}

func (e *Engine) untagKernel(pid uint32) {
	if err := e.tagger.UntagPID(pid); err != nil && e.debug {
		e.log.Debug("untag pid in kernel map", "pid", pid, "err", err)
	}
}

func (e *Engine) handleFork(ev *event.Event, now time.Time) {
	child := e.tbl.OnFork(ev.PID, ev.PPID, ev.Comm, now)
	e.stats.count("fork", child.AgentID)
	if child.Tagged() {
		e.tagKernel(child.PID)
	}
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

	if p.Tagged() {
		e.tagKernel(ev.PID)
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
		e.untagKernel(ev.PID)
	}
	e.tbl.OnExit(ev.PID, now)
}

func (e *Engine) handleAction(ev *event.Event) {
	if !e.cfg.Actions.Enabled {
		return
	}
	name := ev.TypeString()
	if !e.cfg.Actions.CaptureEnabled(name) {
		return
	}
	p, ok := e.tbl.Get(ev.PID)
	if !ok || !p.Tagged() {
		return
	}
	if ev.StartTimeNs != 0 && p.StartNS != 0 && ev.StartTimeNs != p.StartNS {
		return
	}
	if ev.Type == event.TypeOpen && e.cfg.Actions.OpenWritesOnly && !event.IsOpenWriteIntent(ev.OpenFlags) {
		return
	}

	rec := report.Record{
		Event: name, PID: p.PID, RootPID: p.RootPID,
		AgentID: p.AgentID, Mode: p.Mode, Comm: p.Comm,
	}
	switch ev.Type {
	case event.TypeConnect:
		rec.Dest = ev.DestIP
		rec.DestPort = ev.DestPort
	case event.TypeOpen:
		rec.Path = ev.Path
		rec.Write = event.IsOpenWriteIntent(ev.OpenFlags)
	case event.TypeUnlink:
		rec.Path = ev.Path
	case event.TypeRename:
		rec.Path = ev.Path
		rec.NewPath = ev.Path2
	}

	e.stats.count(name, p.AgentID)
	if e.debug {
		e.log.Debug("action", "event", name, "pid", ev.PID, "agent", p.AgentID, "path", ev.Path)
	}
	e.rep.Emit(rec)
	e.evaluateShadow(ev, p, rec)
}

func (e *Engine) evaluateShadow(ev *event.Event, p proctable.Proc, actionRec report.Record) {
	if e.policy == nil {
		return
	}
	cp, meta := e.policy.Get()
	if cp == nil {
		return
	}
	scope := cp.AgentScope
	if e.policyScope != "" {
		scope = e.policyScope
	}
	if !policy.ScopeMatches(p.AgentID, scope) {
		return
	}

	uid := ev.UID
	in := policy.ActionInput{
		Action:      ev.TypeString(),
		Path:        ev.Path,
		NewPath:     ev.Path2,
		DestIP:      ev.DestIP,
		DestPort:    ev.DestPort,
		WriteIntent: ev.Type == event.TypeOpen && event.IsOpenWriteIntent(ev.OpenFlags),
		UID:         &uid,
		Binary:      p.Binary,
		Cgroup:      e.enr.CgroupPath(ev.PID),
	}
	for _, hit := range policy.EvaluateShadowAndLive(cp, in) {
		shadowRec := report.Record{
			Event:         "shadow_deny",
			PID:           p.PID,
			RootPID:       p.RootPID,
			AgentID:       p.AgentID,
			Mode:          p.Mode,
			Comm:          p.Comm,
			Reason:        hit.Rationale,
			RuleID:        hit.RuleID,
			PolicyVersion: meta.Version,
			ShadowSource:  hit.Source,
			Path:          actionRec.Path,
			NewPath:       actionRec.NewPath,
			Dest:          actionRec.Dest,
			DestPort:      actionRec.DestPort,
			Write:         actionRec.Write,
		}
		e.rep.Emit(shadowRec)
		if e.debug {
			e.log.Debug("shadow_deny", "agent", p.AgentID, "rule", hit.RuleID, "source", hit.Source)
		}
	}
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
