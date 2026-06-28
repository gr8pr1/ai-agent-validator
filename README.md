# AI Agent Validator

Policy-strict, kernel-enforced guardrails for AI agents on Linux (`ai-agent-validator`).

AI coding agents now run real commands on real machines. **AI Agent Validator** watches
those agents from the kernel, attributes every action to the agent that caused it,
and (in later phases) blocks actions that violate a deterministic, human-authored
policy — returning a model-comprehensible "do not retry" signal.

The design follows a two-plane model: a **slow control plane** where humans author
and version policy, and a **fast data plane** where the kernel enforces it
deterministically with no model in the decision path. See
[architecture.md](architecture.md) for the full design.

> Status: early. The design is complete; the first code milestone, **P0 (enroll &
> observe)**, is implemented and observe-only — it never blocks anything yet.

## What works today (P0)

P0 identifies AI-agent processes and emits a structured, debuggable stream of their
process-lifecycle activity. Two enrollment modes:

- **Mode A — controlled spawn:** any process whose cgroup-v2 path matches a
  configured slice (e.g. `ai-agents.slice`) is enrolled. Launch agents under a
  dedicated slice and inheritance does the rest.
- **Mode B — exec-time fingerprint:** processes are matched at exec against a
  fingerprint set (binary identity + argv + env markers). This is the common path
  for agents you don't control the launch of (e.g. a developer running `claude`).

Once a process is enrolled, the tag propagates across its whole process tree, so a
`bash -> curl -> sh` subtree spawned by an agent is all attributed to that agent.

Not in P0: any blocking/enforcement, file/network action capture, and the in-kernel
tag map — those arrive in later phases (see [architecture.md](architecture.md) §13).

## Quickstart

Requirements: Linux 5.8+ with BTF (`/sys/kernel/btf/vmlinux`), `clang`/LLVM, libbpf
headers, and Go 1.24+.

```bash
cd agent
make            # compiles the BPF object and builds the agent
sudo ./aiblocker-agent --config config.yaml --debug
```

In another terminal, start a process that matches a fingerprint to see it enrolled.
See [agent/README.md](agent/README.md) for build details, flags, the debug HTTP
endpoints, and the integration test.

## Adding a fingerprint (Mode B)

Fingerprints are data, not code — add an entry to
[`agent/fingerprints.yaml`](agent/fingerprints.yaml) and reload. For interpreted
agents (Claude Code, Cursor) the kernel-visible binary is the interpreter (`node`),
so argv + env markers are the discriminators; for compiled agents, the binary path
is. See [CONTRIBUTING.md](CONTRIBUTING.md) for the derive-and-test workflow.

## Repository layout

- [`architecture.md`](architecture.md) — full system design and rationale.
- [`agent/`](agent) — the P0 enroll-and-observe agent (Go + eBPF).

## License

Apache-2.0. See [LICENSE](LICENSE).
