# State

## Active Task
§14 Future directions reprioritized per owner: AI/learning ranked last. Next: transition to an
implementation plan once design is approved.

## To-Do
1. (Later) Transition to an implementation plan once design is approved.
2. (Later) Begin P0 — enroll & observe on `ebpf-host-monitor` foundation.

## Issues / Blockers
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
- 2026-06-27 — Owner Q&A resolved **D2–D3, D5–D6** in `architecture.md` §12. **D2:** LSM +
  cgroup-BPF egress + tracepoints. **D3:** deny-only in v1 P3; full escalation ladder +
  terminal `decision: kill` planned (Mode B kill-only, no freeze). **D4:** deferred (§14).
  **D5:** operator-configurable `fail_direction` per scope. **D6:** single-host v1, fleet-ready
  loader contract. Pruned §9 unchosen mechanisms; updated §5.4/§5.5/§8/§10/§11/§13 and status
  footer.
- 2026-06-27 — Reprioritized §14 (Future directions) per owner: reordered by priority with the
  AI/learning idea **last**. Kept LLM/learning-assisted **allow-list generation** as the only
  AI control-plane item, marked *planned, distant-future, lowest-priority* (revisit only once the
  deterministic product is mature; output always a human-approved proposal, never on the
  enforcement path). Folded the former standalone "AI policy authoring" bullet into it and added
  an *explicitly-not-planned* note for LLM-authored deny-lists (curated human packs preferred).
  Demoted intent correlation + anomaly alerting to deterministic/detection-only near-term items.

## Decisions
- Build on `ebpf-host-monitor` rather than rebuild; reuse it as the observation layer.
- Separate `enforcer` daemon (small auditable TCB) consuming the monitor's telemetry, rather
  than folding enforcement into the monitor binary.
- Hard invariant: the LLM never writes enforcement state; only a trusted loader writes kernel
  maps, and only for signed bundles.
- New deny rules are shadow-by-default; enforcement (P3) follows observe + policy + shadow.
- Enforcement is action-only; intent is never a hot-path input.
- Observability is push-first (OTLP) for detection/enforcement/audit, pull (Prometheus) for
  health only; local disk is state-only (SQLite) plus a tamper-evident audit log.
- **D1:** Hybrid enrollment — Mode A (controlled-spawn cgroup) + Mode B (exec-time fingerprint).
- **D2:** LSM + cgroup-BPF egress + tracepoints (§9).
- **D3:** Full action set designed; **v1 P3 = deny-only**. Escalation ladder + terminal kill
  rules planned for P3+; Mode B skips freeze.
- **D4:** Deferred — LLM location irrelevant until AI authoring (§14).
- **D5:** Fail direction is **operator config** (`fail_direction: open|closed` per bundle).
- **D6:** Open-source v1 **must** be single-host; architecture **must not block** a future host
  management platform (pluggable bundle source on loader).
- Policy authoring for v1: human-authored curated allow/deny (no LLM, no learning baseline).
- Recommended default posture: `default_action: allow` (deny-list); allow-list for
  high-security scopes + future learning assist.

## Open / Undecided
- None — all v1 architectural decisions resolved. D4 deferred to §14 by design.
