# State

## Active Task
Draft `architecture.md` for the eBPF AI-action blocker (monitor + block suspicious AI-agent
actions on Linux; AI in slow control plane authors rules, kernel enforces in fast data plane).

## To-Do
1. Owner resolves open decisions D1–D6 in `architecture.md` §12.
2. After decisions land, revise `architecture.md` to prune unchosen options.
3. (Later) Transition to an implementation plan once design is approved.

## Issues / Blockers
- Six open architectural decisions (D1–D6) are unresolved by design, awaiting owner input:
  - D1 monitoring/enforcement target (cgroup-scoped agent tree assumed)
  - D2 kernel enforcement mechanism (LSM+tracepoints mix recommended to evaluate first)
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

## Decisions
- Build on `ebpf-host-monitor` rather than rebuild; reuse it as the observation layer.
- Leaning toward a separate `enforcer` daemon (small auditable TCB) consuming the monitor's
  telemetry, rather than folding enforcement into the existing agent binary.
- Hard invariant: the LLM never writes enforcement state; only a trusted loader writes
  kernel maps, and only for signed bundles that passed the promotion gate.
- New deny rules are shadow-by-default; enforcement (P5) is sequenced last, after
  observe/correlate/learn/author/shadow are proven.
