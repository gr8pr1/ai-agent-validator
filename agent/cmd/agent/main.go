// Command agent is the P0 "enroll & observe" agent for ebpf-ai-blocker.
//
// It loads the enrollment BPF program, attaches the process-lifecycle
// tracepoints, and reports the tagged AI-agent process stream. It is
// observe-only: it never blocks or kills anything.
package main

import (
	"context"
	_ "embed"
	"flag"
	"log/slog"
	"os"
	"os/signal"
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
		// Logger not up yet; use a default one.
		logging.Setup("info", "text").Error("loading config", "err", err)
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

	log := logging.Setup(cfg.LogLevel, cfg.LogFormat)
	log.Info("starting ebpf-ai-blocker P0 agent", "mode_a", cfg.ModeA.Enabled, "mode_b", cfg.ModeB.Enabled)

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
	defer reader.Close()

	// Build the pipeline.
	rep, err := report.New(cfg.Report.Format, cfg.Report.AuditLog)
	if err != nil {
		log.Error("building reporter", "err", err)
		os.Exit(1)
	}
	defer rep.Close()

	tbl := proctable.New()
	eng := enroll.New(cfg, enricher.New(), fps, tbl, rep, log)

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

	go backgroundTasks(ctx, eng, loader, tbl, cfg, log)

	// Closing the reader on ctx cancel unblocks Read().
	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		_ = reader.Close()
	}()

	log.Info("observing (press Ctrl-C to stop)")
	consume(reader, eng, log)
}

// consume reads ringbuf records until the reader is closed.
func consume(reader *cringbuf.Reader, eng *enroll.Engine, log *slog.Logger) {
	for {
		rec, err := reader.Read()
		if err != nil {
			if err == cringbuf.ErrClosed {
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

// backgroundTasks runs the periodic snapshot report and proctable pruning.
func backgroundTasks(ctx context.Context, eng *enroll.Engine, loader *ebpfloader.Loader, tbl *proctable.Table, cfg config.Config, log *slog.Logger) {
	snapEvery := time.Duration(cfg.Report.SnapshotSec) * time.Second
	if snapEvery <= 0 {
		snapEvery = time.Hour
	}
	snap := time.NewTicker(snapEvery)
	prune := time.NewTicker(time.Minute)
	defer snap.Stop()
	defer prune.Stop()

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
				log.Info("agent", "id", a.AgentID, "exec", a.Exec, "fork", a.Fork, "exit", a.Exit)
			}
		case <-prune.C:
			tbl.Prune(2 * time.Minute)
		}
	}
}
