# State

## Active Task
Reshaped `architecture.md` to the owner's v1 vision: a **policy-strict** enforcement agent
(track AI procs → check vs defined policies → block → comprehensible denial feedback). Learning
baseline, LLM authoring, and intent correlation moved to §14 Future directions.

## To-Do
1. Owner resolves remaining open decisions D2, D3, D5, D6 in `architecture.md` §12.
2. After decisions land, revise `architecture.md` to prune unchosen options.
3. (Later) Transition to an implementation plan once design is approved.

## Issues / Blockers
- D1 RESOLVED → hybrid enrollment (Mode A controlled-spawn cgroup + Mode B eBPF exec-time
  fingerprint; anchor + cgroup/lineage propagation). See §5.1.1.
- Five open architectural decisions remain, awaiting owner input:
  - D2 kernel enforcement mechanism (LSM + cgroup-egress + tracepoints mix recommended)
  - D3 enforcement actions (full set assumed, gated by rollout)
  - D4 LLM location (local self-hosted assumed)
  - D5 fail direction (per-scope configurable, fail-open prod default assumed)
  - D6 v1 scope (full design documented; build can start single-host)
- No git remote configured yet (push deferred until remote exists).

## Completed
- 2026-06-17 — Explored sibling `ebpf-host-monitor` (observe-only eBPF agent) to reuse its
  observation/enrichment/baseline/MITRE/OTel machinery as this project's foundation.
- 2026-06-17 — Wrote `architecture.md`: two-plane model (slow AI control plane / fast kernel
  data plane), component architecture, policy lifecycle + schema, enforcement mechanism
  candidates, trust/safety + threat model, open decisions D1–D6, phased build plan P0–P6.
- 2026-06-17 — Sub-agent review pass (code-reviewer + docs). Docs agent CONFIRMED all
  eBPF/LSM/seccomp/verifier facts. Incorporated reviewer findings into `architecture.md`:
  direct-map-write/TCB caveat + signing-key custody (§10), self-reported-intent untrusted-hint
  caveat (§5.2), task-relative vs weekly-seasonal baseline (§5.4), LSM restrict-only allow/deny
  semantics + rule precedence (§8), cgroup-egress + `bpf_send_signal` enforcement candidates
  and USER_NOTIF TOCTOU note (§9), and two new threat-model rows.
- 2026-06-27 — Owner Q&A refinements to `architecture.md`: resolved D1 with hybrid enrollment
  + new §5.1.1 (anchor + cgroup/lineage propagation, Mode A controlled-spawn / Mode B eBPF
  exec-time fingerprint); elevated argv capture to P0 (§5.1); added §5.10 denial-feedback
  channel (model-comprehensible do-not-retry signal) + escalation ladder deny→freeze→kill
  (§5.8); updated data-flow diagram, threat model (enrollment evasion, retry loop), build plan
  P0/P1/P5, component summary, and glossary.
- 2026-06-27 — Sub-agent review pass (code-reviewer + docs, 6/7 claims CONFIRMED). Applied
  accuracy fixes: Mode B uses `sched_process_exec` tracepoint (not `bprm_check`) to keep P0
  free of the BPF-LSM dependency; per-mode propagation/enforcement (Mode A cgroup-BPF+LSM,
  Mode B tagged-PID-map+LSM, no cgroup-egress on shared cgroups); argv/env via bounded
  `bpf_probe_read_user` prefix scan (env unindexed → binary-identity backstop, `codex`
  name-match FP risk); `cgroup.freeze` clarified as userspace cgroup-v2 action;
  `bpf_send_signal` targets current task only; §5.10 `correlation_id` reconstructed in
  userspace via cgroup/(pid,start_ns) join; cgroup-delegation lockdown note for Mode A.
- 2026-06-27 — Settled: **enforcement is action-only**; no intent-vs-action comparison in the
  hot path. Intent demoted to observability/logging + slow-plane detection + denial-feedback
  reason. Reframed §5.2 (intent role), §5.3 (correlator = detection/observability only, never
  feeds enforcer), §5.8 (action-only verdict), §6 diagram, glossary. Expanded §5.9 into the
  concrete observability data path: ringbuf → enrich → SQLite (state only, not a firehose) →
  OTLP push (logs/traces/metrics; enforcement decisions at 100%); Prometheus pull = health
  only; local append-only tamper-evident audit log; backend owns full-event retention.
  Retention default = push-only + local audit log (optional local full-event sink off by
  default).
- 2026-06-27 — Sub-agent review (code-reviewer) of action-only/observability edits: no
  Critical. Applied fixes: `task_class` is learning/authoring-only and never a kernel match
  field (compiles to `agent_scope`) — §5.4 + §8; ringbuf audit-durability caveat (reserved
  verdict channel; else best-effort under backpressure) — §5.9; corrected §4 overclaim
  (monitor OTLP metrics are planned, not done) + flagged net-new metrics/audit-log;
  schema example rationale reworded ("divergence from the learned baseline", agent_scope
  note); §5.2 `reason` sourced from rule rationale not intent; §10.7 task_class as untrusted
  learning/poisoning vector.
- 2026-06-27 — **Major reshape** of `architecture.md` to the owner's v1 vision: a policy-strict
  enforcement agent. New thesis ("define policy once; kernel enforces on AI procs; tell the
  agent comprehensibly to stop"). Core v1 components: enrollment/attribution, observation,
  policy model (curated allow/deny), trusted loader, enforcement, denial feedback (the
  differentiator), audit/observability, human authoring + shadow→enforce lifecycle. Demoted to
  §14 Future directions: behavioral baseline/learning, LLM policy authoring, intent capture +
  correlation, automated promotion gate, anomaly-detection alerting. D1 resolved, D4 deferred
  (LLM is future); D2/D3/D5/D6 remain. Decision rationale: enforcement (block) needs crisp
  deterministic reasons; agents are novelty machines so a learned baseline is a poor + poisonable
  authorization boundary; curated policy matches industry practice (Falco/Tetragon/AppArmor).
- 2026-06-27 — Sub-agent review of the reshape (code-reviewer + docs). Reviewer: no Critical,
  zero dangling refs. Applied fixes: added system-path destructive-op protection to curated core
  + §8 example (`rm -rf` motivation now actually covered; arbitrary user-file deletion explicitly
  NOT deny-listed); tightened threat-row 1 (novel bad action is allowed under deny-list default);
  removed stale "detection state" from §5.7; freeze-only-for-dedicated-cgroup caveat in goal 4 +
  P3; §9 note that Mode-B egress rides LSM `socket_connect` and D2 couples with Mode A/B. Docs
  agent CONFIRMED new LSM hook claims (socket_connect, path/inode unlink+rename, file_open;
  write via file_permission MAY_WRITE; all need CONFIG_BPF_LSM + lsm=bpf, kernel >= 5.7).

## Decisions
- Build on `ebpf-host-monitor` rather than rebuild; reuse it as the observation layer.
- Leaning toward a separate `enforcer` daemon (small auditable TCB) consuming the monitor's
  telemetry, rather than folding enforcement into the existing agent binary.
- Hard invariant: the LLM never writes enforcement state; only a trusted loader writes
  kernel maps, and only for signed bundles that passed the promotion gate.
- New deny rules are shadow-by-default; enforcement (P5) is sequenced last, after
  observe/correlate/learn/author/shadow are proven.
- Enforcement is action-only; intent is never a hot-path input (trust + determinism). Intent
  serves observability, slow-plane detection, and the denial-feedback `reason` only.
- Observability is push-first (OTLP) for detection/enforcement/audit, pull (Prometheus) for
  health only; local disk is state-only (SQLite) plus a tamper-evident audit log; full-event
  retention is delegated to the backend.

## Open / Undecided
- Policy authoring source SETTLED for v1: human-authored curated allow/deny policy (no LLM, no
  learning baseline). AI authoring + learning-assisted allow-list generation are future (§14).
- Default posture: `default_action: allow` (deny-list) recommended for v1; `default_action: deny`
  (allow-list) reserved for high-security tier + future learning assist.
