package deny

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	cringbuf "github.com/cilium/ebpf/ringbuf"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/feedback"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

// Consumer turns kernel deny_verdict ringbuf records into audit events.
type Consumer struct {
	rep      *report.Reporter
	tbl      *proctable.Table
	pol      *policy.Holder
	hub      *feedback.Hub
	connects *ConnectCache
	log      *slog.Logger
}

// NewConsumer builds a deny ringbuf consumer.
func NewConsumer(rep *report.Reporter, tbl *proctable.Table, pol *policy.Holder, hub *feedback.Hub, connects *ConnectCache, log *slog.Logger) *Consumer {
	return &Consumer{rep: rep, tbl: tbl, pol: pol, hub: hub, connects: connects, log: log}
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
	target := resolveTarget(v, c.connects)
	rec := report.Record{
		Time:   time.Unix(0, int64(v.TimestampNS)),
		Event:  "kernel_deny",
		Action: action,
		PID:    v.PID,
		Path:   v.Path,
	}
	if v.Action == ActionConnect {
		rec.Dest = v.DestIP
		rec.DestPort = v.DestPort
		if rec.Dest == "" && target != "" {
			rec.Dest, rec.DestPort = splitConnectTarget(target)
		}
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
		fd := feedback.NewDecision(time.Now(), v.PID, action, target, rec.AgentID, rec.RuleID, rec.Reason, rec.PolicyVersion)
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
	c.log.Debug("kernel_deny", "pid", v.PID, "rule", rec.RuleID, "action", action, "target", target)
}

func resolveTarget(v Verdict, cache *ConnectCache) string {
	if t := v.Target(); t != "" {
		return t
	}
	if v.Action != ActionConnect || cache == nil {
		return v.Path
	}
	ip, port, ok := cache.Lookup(v.PID)
	if !ok {
		return v.Path
	}
	return FormatConnectTarget(ip, port)
}

func splitConnectTarget(target string) (ip string, port uint16) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 0 || p > 65535 {
		return host, 0
	}
	return host, uint16(p)
}

func formatHash(hash uint32) string {
	return fmt.Sprintf("hash:%08x", hash)
}

func isClosed(err error) bool {
	return errors.Is(err, cringbuf.ErrClosed) || errors.Is(err, os.ErrClosed)
}
