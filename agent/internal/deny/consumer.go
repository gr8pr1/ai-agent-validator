package deny

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	cringbuf "github.com/cilium/ebpf/ringbuf"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/feedback"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

// Consumer turns kernel deny_verdict ringbuf records into audit events.
type Consumer struct {
	rep *report.Reporter
	tbl *proctable.Table
	pol *policy.Holder
	hub *feedback.Hub
	log *slog.Logger
}

// NewConsumer builds a deny ringbuf consumer.
func NewConsumer(rep *report.Reporter, tbl *proctable.Table, pol *policy.Holder, hub *feedback.Hub, log *slog.Logger) *Consumer {
	return &Consumer{rep: rep, tbl: tbl, pol: pol, hub: hub, log: log}
}

// Run reads deny verdicts until ctx is cancelled or the reader closes.
func (c *Consumer) Run(ctx context.Context, reader *cringbuf.Reader) {
	for ctx.Err() == nil {
		rec, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || isClosed(err) {
				return
			}
			c.log.Warn("deny ringbuf read", "err", err)
			continue
		}
		v, err := Parse(rec.RawSample)
		if err != nil {
			c.log.Warn("deny verdict parse", "err", err, "len", len(rec.RawSample))
			continue
		}
		c.emit(v)
	}
}

func (c *Consumer) emit(v Verdict) {
	action := ActionName(v.Action)
	rec := report.Record{
		Time:   time.Unix(0, int64(v.TimestampNS)),
		Event:  "kernel_deny",
		Action: action,
		PID:    v.PID,
		Path:   v.Path,
	}
	if c.pol != nil {
		if cp, meta := c.pol.Get(); cp != nil {
			rec.PolicyVersion = meta.Version
			if r, ok := policy.RuleByHash(cp, v.RuleIDHash); ok {
				rec.RuleID = r.ID
				rec.Reason = r.Rationale
			}
		}
	}
	if rec.RuleID == "" {
		rec.RuleID = formatHash(v.RuleIDHash)
	}
	if p, ok := c.tbl.Get(v.PID); ok {
		rec.AgentID = p.AgentID
		rec.Mode = p.Mode
		rec.RootPID = p.RootPID
		rec.Comm = p.Comm
	}
	if c.rep != nil {
		c.rep.Emit(rec)
	}
	if c.hub != nil {
		fd := feedback.NewDecision(time.Now(), v.PID, action, v.Path, rec.AgentID, rec.RuleID, rec.Reason, rec.PolicyVersion)
		c.hub.Record(fd)
		if c.rep != nil {
			c.rep.Emit(report.Record{
				Time:     fd.Time,
				Event:    "policy_feedback",
				PID:      fd.PID,
				AgentID:  fd.AgentID,
				RuleID:   fd.MatchedRule,
				Reason:   fd.Reason,
				Feedback: &fd,
			})
		}
	}
	c.log.Debug("kernel_deny", "pid", v.PID, "rule", rec.RuleID, "action", action, "path", v.Path)
}

func formatHash(hash uint32) string {
	return fmt.Sprintf("hash:%08x", hash)
}

func isClosed(err error) bool {
	return errors.Is(err, cringbuf.ErrClosed) || errors.Is(err, os.ErrClosed)
}
