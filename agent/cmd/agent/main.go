// Command agent is the P0 "enroll & observe" agent for ebpf-ai-blocker.
//
// It loads the enrollment BPF program, attaches the process-lifecycle
// tracepoints, and reports the tagged AI-agent process stream. It is
// observe-only: it never blocks or kills anything.
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	cringbuf "github.com/cilium/ebpf/ringbuf"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/config"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/debugsrv"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/ebpfloader"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enricher"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enroll"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/event"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/fingerprint"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/logging"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

//go:embed bpf/enroll.bpf.o
var bpfObject []byte

func main() {
	var (
		configPath = flag.String("config", "config.yaml", "path to config file")
		debug      = flag.Bool("debug", false, "enable debug logging + debug HTTP server")
		logLevel   = flag.String("log-level", "", "override log level (debug|info|warn|error)")
		logFormat  = flag.String("log-format", "", "override log format (text|json)")
	)
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log, _ := logging.Setup("info", "text", "")
		log.Error("loading config", "err", err)
		os.Exit(1)
	}
	if *debug {
		cfg.Debug.Enabled = true
		cfg.LogLevel = "debug"
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if *logFormat != "" {
		cfg.LogFormat = *logFormat
	}

	log, err := logging.Setup(cfg.LogLevel, cfg.LogFormat, cfg.LogFile)
	if err != nil {
		fallback, _ := logging.Setup("info", "text", "")
		fallback.Error("setup logging", "err", err)
		os.Exit(1)
	}
	log.Info("starting ebpf-ai-blocker agent", "mode_a", cfg.ModeA.Enabled, "mode_b", cfg.ModeB.Enabled, "policy", cfg.Policy.Enabled)
	if cfg.LogFile != "" {
		log.Info("slog output also written to log_file", "path", cfg.LogFile)
	}

	// Load Mode B fingerprints.
	var fps *fingerprint.Set
	if cfg.ModeB.Enabled {
		fps, err = fingerprint.Load(cfg.ModeB.FingerprintsPath)
		if err != nil {
			log.Error("loading fingerprints", "path", cfg.ModeB.FingerprintsPath, "err", err)
			os.Exit(1)
		}
		log.Info("loaded fingerprints", "count", len(fps.Fingerprints), "path", cfg.ModeB.FingerprintsPath)
	}

	// Load + attach BPF.
	loader, err := ebpfloader.Load(bpfObject)
	if err != nil {
		log.Error("loading BPF", "err", err)
		os.Exit(1)
	}
	defer loader.Close()

	attached, err := loader.Attach()
	if err != nil {
		log.Error("attaching tracepoints", "err", err)
		os.Exit(1)
	}
	log.Info("attached tracepoints", "tracepoints", attached)

	reader, err := loader.Reader()
	if err != nil {
		log.Error("opening ringbuf", "err", err)
		os.Exit(1)
	}

	// Build the pipeline.
	rep, err := report.New(cfg.Report.Format, cfg.Report.AuditLog)
	if err != nil {
		log.Error("building reporter", "err", err)
		os.Exit(1)
	}
	defer rep.Close()

	if cfg.Report.AuditLog != "" {
		log.Info("audit log enabled (tagged enroll/events only; debug traces stay in slog)", "path", cfg.Report.AuditLog)
		rep.EmitAuditOnly(report.Record{Event: "session_start"})
	}

	tbl := proctable.New()

	var polHolder *policy.Holder
	if cfg.Policy.Enabled {
		pub, err := policy.LoadPublicKey(cfg.Policy.PubKeyPath)
		if err != nil {
			log.Error("loading policy public key", "path", cfg.Policy.PubKeyPath, "err", err)
			os.Exit(1)
		}
		store, err := policy.OpenStore(cfg.Policy.StorePath)
		if err != nil {
			log.Error("opening policy store", "path", cfg.Policy.StorePath, "err", err)
			os.Exit(1)
		}
		polHolder = policy.NewHolder()
		cp, meta, err := policy.LoadCurrent(store, pub)
		if err != nil {
			log.Error("loading current policy", "err", err)
			os.Exit(1)
		}
		polHolder.Swap(cp, meta)
		log.Info("policy shadow mode enabled",
			"version", meta.Version, "scope", cp.AgentScope,
			"live_rules", len(cp.Live), "shadow_rules", len(cp.Shadow),
			"reload_sec", cfg.Policy.ReloadSec)
	}

	eng := enroll.New(cfg, enricher.New(), fps, tbl, rep, loader, polHolder, log)

	// Signals + lifecycle.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.Debug.Enabled {
		dbg := debugsrv.New(eng, log).Start(cfg.Debug.HTTPAddr)
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = dbg.Shutdown(shutCtx)
		}()
	}

	go backgroundTasks(ctx, eng, loader, tbl, cfg, polHolder, log)

	var closeReader sync.Once
	closeRingbuf := func() {
		closeReader.Do(func() {
			_ = reader.Close()
		})
	}
	defer closeRingbuf()

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		closeRingbuf()
	}()

	log.Info("observing (press Ctrl-C to stop)")
	consume(ctx, reader, eng, log)
}

// consume reads ringbuf records until shutdown or the reader is closed.
func consume(ctx context.Context, reader *cringbuf.Reader, eng *enroll.Engine, log *slog.Logger) {
	for {
		if ctx.Err() != nil {
			return
		}
		rec, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || isRingbufClosed(err) {
				return
			}
			log.Warn("ringbuf read", "err", err)
			continue
		}
		ev, err := event.Parse(rec.RawSample)
		if err != nil {
			log.Warn("event parse", "err", err, "len", len(rec.RawSample))
			continue
		}
		eng.Handle(ev)
	}
}

func isRingbufClosed(err error) bool {
	return errors.Is(err, cringbuf.ErrClosed) || errors.Is(err, os.ErrClosed)
}

// backgroundTasks runs the periodic snapshot report, proctable pruning, and policy reload.
func backgroundTasks(ctx context.Context, eng *enroll.Engine, loader *ebpfloader.Loader, tbl *proctable.Table, cfg config.Config, polHolder *policy.Holder, log *slog.Logger) {
	snapEvery := time.Duration(cfg.Report.SnapshotSec) * time.Second
	if snapEvery <= 0 {
		snapEvery = time.Hour
	}
	snap := time.NewTicker(snapEvery)
	prune := time.NewTicker(time.Minute)
	defer snap.Stop()
	defer prune.Stop()

	var reload *time.Ticker
	var reloadCh <-chan time.Time
	if cfg.Policy.Enabled && polHolder != nil && cfg.Policy.ReloadSec > 0 {
		reloadEvery := time.Duration(cfg.Policy.ReloadSec) * time.Second
		reload = time.NewTicker(reloadEvery)
		defer reload.Stop()
		reloadCh = reload.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-snap.C:
			total, enrollments, agents := eng.Stats().Snapshot()
			drops, _ := loader.Drops()
			log.Info("snapshot",
				"total_events", total, "enrollments", enrollments,
				"tagged_agents", len(agents), "tracked_pids", tbl.Len(), "ringbuf_drops", drops)
			for _, a := range agents {
				log.Info("agent", "id", a.AgentID, "exec", a.Exec, "fork", a.Fork, "exit", a.Exit,
					"connect", a.Connect, "open", a.Open, "unlink", a.Unlink, "rename", a.Rename)
			}
		case <-prune.C:
			tbl.Prune(2 * time.Minute)
		case <-reloadCh:
			reloadPolicy(cfg, polHolder, log)
		}
	}
}

func reloadPolicy(cfg config.Config, holder *policy.Holder, log *slog.Logger) {
	pub, err := policy.LoadPublicKey(cfg.Policy.PubKeyPath)
	if err != nil {
		log.Warn("policy reload: load pubkey", "err", err)
		return
	}
	store, err := policy.OpenStore(cfg.Policy.StorePath)
	if err != nil {
		log.Warn("policy reload: open store", "err", err)
		return
	}
	cp, meta, err := policy.LoadCurrent(store, pub)
	if err != nil {
		log.Warn("policy reload: load current", "err", err)
		return
	}
	prev, _ := holder.Get()
	if prev != nil && prev.Version == cp.Version {
		return
	}
	holder.Swap(cp, meta)
	log.Info("policy reloaded", "version", meta.Version, "live_rules", len(cp.Live), "shadow_rules", len(cp.Shadow))
}
