# State

## Active Task
Refine `architecture.md` per owner Q&A: resolve D1 (enrollment/attribution), elevate argv
capture, add denial-feedback channel.

## To-Do
1. Owner resolves remaining open decisions D2–D6 in `architecture.md` §12.
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

## Decisions
- Build on `ebpf-host-monitor` rather than rebuild; reuse it as the observation layer.
- Leaning toward a separate `enforcer` daemon (small auditable TCB) consuming the monitor's
  telemetry, rather than folding enforcement into the existing agent binary.
- Hard invariant: the LLM never writes enforcement state; only a trusted loader writes
  kernel maps, and only for signed bundles that passed the promotion gate.
- New deny rules are shadow-by-default; enforcement (P5) is sequenced last, after
  observe/correlate/learn/author/shadow are proven.
