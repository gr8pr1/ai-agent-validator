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
	"fmt"
	"log/slog"
	"os"
	"strings"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	cringbuf "github.com/cilium/ebpf/ringbuf"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/cgroup"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/config"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/deny"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/debugsrv"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/ebpfloader"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enricher"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enroll"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/feedback"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/event"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/fingerprint"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/logging"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/proctable"
	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/report"
)

//go:embed bpf/enroll.bpf.o
var bpfObject []byte

//go:embed bpf/enforcer.bpf.o
var enforcerObject []byte

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
	policyMode := cfg.Policy.EffectiveMode()
	log.Info("starting ebpf-ai-blocker agent",
		"mode_a", cfg.ModeA.Enabled, "mode_b", cfg.ModeB.Enabled, "policy_mode", policyMode)
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

	var enforcer *ebpfloader.EnforcerLoader
	if policyMode == config.PolicyModeEnforce {
		if len(enforcerObject) == 0 {
			log.Error("embedded enforcer BPF object is empty; run `make bpf` first")
			os.Exit(1)
		}
		tagMap := loader.TaggedPidsMap()
		if tagMap == nil {
			log.Error("enroll tagged_pids map missing; cannot wire kernel enforcement")
			os.Exit(1)
		}
		pendingOpenMap := loader.PendingOpenPathsMap()
		if pendingOpenMap == nil {
			log.Error("enroll pending_open_paths map missing; cannot wire kernel enforcement")
			os.Exit(1)
		}
		pendingConnectMap := loader.PendingConnectsMap()
		if pendingConnectMap == nil {
			log.Error("enroll pending_connects map missing; cannot wire kernel enforcement")
			os.Exit(1)
		}
		pendingOpenCPUMap := loader.PendingOpenCPUMap()
		if pendingOpenCPUMap == nil {
			log.Error("enroll pending_open_cpu map missing; cannot wire kernel enforcement")
			os.Exit(1)
		}
		pendingConnectCPUMap := loader.PendingConnectCPUMap()
		if pendingConnectCPUMap == nil {
			log.Error("enroll pending_connect_cpu map missing; cannot wire kernel enforcement")
			os.Exit(1)
		}
		enforcer, err = ebpfloader.LoadEnforcer(enforcerObject, map[string]*ebpf.Map{
			"tagged_pids":         tagMap,
			"pending_open_paths":  pendingOpenMap,
			"pending_connects":    pendingConnectMap,
			"pending_open_cpu":    pendingOpenCPUMap,
			"pending_connect_cpu": pendingConnectCPUMap,
		})
		if err != nil {
			log.Error("loading enforcer BPF", "err", err)
			os.Exit(1)
		}
		defer enforcer.Close()
		bpfInLSM := logKernelLSMStack(log)
		ebpfloader.WarnExtraEnforcerProgs(log, "before_attach")
		syscallAttached, err := enforcer.AttachSyscallEnforcement()
		if err != nil {
			log.Error("attaching syscall fmod_ret enforcer", "err", err)
			os.Exit(1)
		}
		if len(syscallAttached) > 0 {
			log.Info("attached syscall enforcer", "programs", syscallAttached)
		} else if !bpfInLSM {
			log.Error("no enforcement hooks active: fmod_ret programs missing from BPF object and bpf is not in the kernel LSM stack")
			os.Exit(1)
		}
		lsmAttached, err := enforcer.AttachLSM(bpfInLSM)
		if err != nil {
			log.Error("attaching LSM enforcer (requires root and CONFIG_BPF_LSM)", "err", err)
			os.Exit(1)
		}
		if !bpfInLSM {
			log.Info("attached LSM enforcer (socket_connect skipped; bpf not in active LSM stack)", "programs", lsmAttached)
		} else {
			log.Info("attached LSM enforcer", "programs", lsmAttached)
		}

		if cfg.ModeA.Enabled {
			cgPath, err := cgroup.ResolveV2Dir(cfg.ModeA.CgroupContains)
			if err != nil {
				log.Error("Mode A cgroup egress required but cgroup dir not found", "err", err)
				os.Exit(1)
			}
			cgroupAttached, err := enforcer.AttachCgroupEgress(cgPath)
			if err != nil {
				log.Error("attaching cgroup egress enforcer", "cgroup", cgPath, "err", err)
				os.Exit(1)
			}
			if len(cgroupAttached) < 2 {
				log.Error("expected cgroup connect4+connect6 programs", "attached", cgroupAttached)
				os.Exit(1)
			}
			log.Info("attached cgroup egress enforcer", "cgroup", cgPath, "programs", cgroupAttached)
			ebpfloader.LogCgroupConnectPrograms(cgPath, log)
			ebpfloader.WarnExtraCgroupPrograms(cgPath, log)
			ebpfloader.WarnExtraEnforcerProgs(log, "after_attach")
		}
	}

	reader, err := loader.Reader()
	if err != nil {
		log.Error("opening ringbuf", "err", err)
		os.Exit(1)
	}

	var denyReader *cringbuf.Reader
	var fbHub *feedback.Hub
	if enforcer != nil {
		denyReader, err = enforcer.DenyReader()
		if err != nil {
			log.Error("opening deny ringbuf", "err", err)
			os.Exit(1)
		}
		log.Info("kernel deny ringbuf consumer enabled")
		fbHub, err = feedback.NewHub(cfg.Feedback.Path, cfg.Feedback.MaxPerAgent)
		if err != nil {
			log.Error("opening feedback sink", "path", cfg.Feedback.Path, "err", err)
			os.Exit(1)
		}
		defer fbHub.Close()
		if cfg.Feedback.Path != "" {
			log.Info("denial feedback JSONL enabled", "path", cfg.Feedback.Path)
		}
		log.Info("denial feedback channel enabled")
	}

	// Build the pipeline.
	rep, err := report.New(cfg.Report.Format, cfg.Report.AuditLog)
	if err != nil {
		log.Error("building reporter", "err", err)
		os.Exit(1)
	}
	defer rep.Close()

	if cfg.Report.AuditLog != "" {
		log.Info("audit log enabled (tagged enroll/events + kernel_deny; debug traces stay in slog)", "path", cfg.Report.AuditLog)
		rep.EmitAuditOnly(report.Record{Event: "session_start"})
	}

	tbl := proctable.New()

	var polHolder *policy.Holder
	if cfg.Policy.Active() {
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
		if enforcer != nil {
			stats, err := applyLivePolicy(enforcer, cp, true, log)
			if err != nil {
				log.Error("loading live policy into kernel maps", "err", err)
				os.Exit(1)
			}
			log.Info("kernel enforcement maps loaded", "stats", stats, "enforcement_active", true)
		}
		polHolder.Swap(cp, meta)
		log.Info("policy enabled",
			"mode", policyMode,
			"version", meta.Version, "scope", cp.AgentScope,
			"live_rules", len(cp.Live), "shadow_rules", len(cp.Shadow),
			"reload_sec", cfg.Policy.ReloadSec)
	}

	var tagger enroll.KernelTagger = loader
	if enforcer != nil {
		tagger = enroll.MultiTagger{loader, enforcer}
	}
	connectCache := deny.NewConnectCache()
	eng := enroll.New(cfg, enricher.New(), fps, tbl, rep, tagger, polHolder, log)
	eng.SetConnectCache(connectCache)

	// Signals + lifecycle.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.Debug.Enabled {
		dbg := debugsrv.New(eng, fbHub, log).Start(cfg.Debug.HTTPAddr)
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = dbg.Shutdown(shutCtx)
		}()
	}

	go backgroundTasks(ctx, eng, loader, tbl, cfg, polHolder, enforcer, log)

	var closeReaders sync.Once
	closeRingbufs := func() {
		closeReaders.Do(func() {
			_ = reader.Close()
			if denyReader != nil {
				_ = denyReader.Close()
			}
		})
	}
	defer closeRingbufs()

	if denyReader != nil {
		go deny.NewConsumer(rep, tbl, polHolder, fbHub, connectCache, log).Run(ctx, denyReader)
	}

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		closeRingbufs()
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
func backgroundTasks(ctx context.Context, eng *enroll.Engine, loader *ebpfloader.Loader, tbl *proctable.Table, cfg config.Config, polHolder *policy.Holder, enforcer *ebpfloader.EnforcerLoader, log *slog.Logger) {
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
	if cfg.Policy.Active() && polHolder != nil && cfg.Policy.ReloadSec > 0 {
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
			eng.ResyncKernelTags()
			total, enrollments, agents := eng.Stats().Snapshot()
			drops, _ := loader.Drops()
			fields := []any{
				"total_events", total, "enrollments", enrollments,
				"tagged_agents", len(agents), "tracked_pids", tbl.Len(), "ringbuf_drops", drops,
			}
			fields = append(fields, enforceSnapshotFields(enforcer)...)
			log.Info("snapshot", fields...)
			for _, a := range agents {
				log.Info("agent", "id", a.AgentID, "exec", a.Exec, "fork", a.Fork, "exit", a.Exit,
					"connect", a.Connect, "open", a.Open, "unlink", a.Unlink, "rename", a.Rename)
			}
		case <-prune.C:
			tbl.Prune(2 * time.Minute)
		case <-reloadCh:
			reloadPolicy(cfg, polHolder, enforcer, log)
		}
	}
}

func reloadPolicy(cfg config.Config, holder *policy.Holder, enforcer *ebpfloader.EnforcerLoader, log *slog.Logger) {
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
	prev, prevMeta := holder.Get()
	if prev != nil && prev.Version == cp.Version {
		return
	}
	if enforcer != nil {
		stats, err := applyLivePolicy(enforcer, cp, true, log)
		if err != nil {
			log.Warn("policy reload: kernel map load failed, keeping previous policy", "err", err)
			if prev == nil {
				return
			}
			if _, restoreErr := applyLivePolicy(enforcer, prev, true, log); restoreErr != nil {
				log.Error("policy reload: failed to restore previous kernel maps", "err", restoreErr)
				return
			}
			log.Info("policy reload: restored previous kernel maps", "version", prevMeta.Version)
			return
		}
		log.Info("policy reload: kernel maps updated", "stats", stats)
	}
	holder.Swap(cp, meta)
	log.Info("policy reloaded", "version", meta.Version, "live_rules", len(cp.Live), "shadow_rules", len(cp.Shadow))
}

func applyLivePolicy(enforcer *ebpfloader.EnforcerLoader, cp *policy.CompiledPolicy, active bool, log *slog.Logger) (policy.LoadStats, error) {
	deactivate := policyCtrlFromCompiled(cp, false)
	if err := enforcer.SetPolicyCtrl(deactivate); err != nil {
		return policy.LoadStats{}, fmt.Errorf("deactivate policy_ctrl: %w", err)
	}
	stats, err := enforcer.LoadLivePolicy(cp, policy.PolicyCtrlValues{
		EnforcementActive: active,
		PolicyVersion:     uint32(cp.Version),
	})
	if err != nil {
		return stats, err
	}
	if stats.Skipped > 0 {
		log.Warn("kernel map load skipped rules with uid/binary/cgroup predicates", "skipped", stats.Skipped)
	}
	if len(cp.Live) > 0 && stats.PathDeny+stats.PathAllow+stats.InodeDeny+stats.InodeAllow+stats.IPDeny+stats.IPAllow+stats.PortDeny+stats.PortAllow == 0 {
		log.Warn("kernel enforcement maps are empty despite live rules; ensure rules use state: enforced and kernel-loadable predicates")
	}
	return stats, nil
}

func policyCtrlFromCompiled(cp *policy.CompiledPolicy, active bool) ebpfloader.PolicyCtrl {
	var failClosed, defaultDeny, enforcementActive uint8
	if active {
		enforcementActive = 1
	}
	if cp.FailDirection == policy.FailDirectionClosed {
		failClosed = 1
	}
	if cp.DefaultAction == policy.DefaultActionDeny {
		defaultDeny = 1
	}
	return ebpfloader.PolicyCtrl{
		EnforcementActive: enforcementActive,
		FailClosed:        failClosed,
		DefaultDeny:       defaultDeny,
		PolicyVersion:     uint32(cp.Version),
	}
}

func logKernelLSMStack(log *slog.Logger) bool {
	lsmList, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	active := strings.TrimSpace(string(lsmList))
	if active == "" {
		return false
	}
	log.Info("kernel LSM stack", "lsm", active)
	bpfActive := stringsContainsLSM(active, "bpf")
	if !bpfActive {
		log.Warn("bpf is not in the active LSM stack; LSM hooks may not run (add lsm=...,bpf at boot). Syscall fmod_ret hooks are the primary block path.")
	}
	return bpfActive
}

func enforceSnapshotFields(enforcer *ebpfloader.EnforcerLoader) []any {
	if enforcer == nil {
		return nil
	}
	est, err := enforcer.EnforceStats()
	if err != nil {
		return nil
	}
	return []any{
		"enforce_file_open", est.FileOpenCalls,
		"enforce_gate_pass", est.GatePass,
		"enforce_openat_fmod", est.OpenatFmod,
		"enforce_openat_deny", est.OpenatDeny,
		"enforce_connect_fmod", est.ConnectFmod,
		"enforce_connect_deny", est.ConnectDeny,
		"enforce_cgroup_connect", est.CgroupConnect,
	}
}

func stringsContainsLSM(lsmList, name string) bool {
	for _, part := range strings.Split(lsmList, ",") {
		if strings.TrimSpace(part) == name {
			return true
		}
	}
	return false
}
