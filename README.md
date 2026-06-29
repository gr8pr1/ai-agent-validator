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

> Status: **P0 + P0.5 implemented**, observe-only (never blocks). P1 policy loader
> and P3 enforcement are planned. See [architecture.md](architecture.md) §13.

## What works today

### P0 — enroll & observe

Identifies AI-agent processes and emits a structured stream of their process-lifecycle
activity. Two enrollment modes:

- **Mode A — controlled spawn:** any process whose cgroup-v2 path matches a
  configured slice (e.g. `ai-agents.slice`) is enrolled. Launch agents under a
  dedicated slice and inheritance does the rest.
- **Mode B — exec-time fingerprint:** processes are matched at exec against a
  fingerprint set (binary identity + argv + env markers). This is the common path
  for agents you don't control the launch of (e.g. a developer running `claude`).

Once a process is enrolled, the tag propagates across its whole process tree, so a
`bash -> curl -> sh` subtree spawned by an agent is all attributed to that agent.

### P0.5 — action capture

For enrolled agents only, the agent also records **connect**, **open**,
**unlink**, and **rename** syscalls (observe-only). See
[agent/config.md](agent/config.md) for tuning (`actions.open_writes_only`, etc.).

Not yet: blocking/enforcement and the in-kernel enforcement tag map (P3).

## Quickstart

Requirements: Linux 5.8+ with BTF (`/sys/kernel/btf/vmlinux`), `clang`/LLVM, libbpf
headers, and Go 1.24+.

```bash
cd agent
make                              # compiles the BPF object and builds the agent
cp config.yaml.example config.yaml  # first time; edit as needed
cp fingerprints.yaml.example fingerprints.yaml  # if using Mode B defaults
sudo ./aiblocker-agent --config config.yaml --debug
```

In another terminal, start a process that matches a fingerprint to see it enrolled.
See [agent/README.md](agent/README.md) for build details, configuration, debug HTTP
endpoints, and the integration test.

## Adding a fingerprint (Mode B)

Fingerprints are data, not code — copy
[`agent/fingerprints.yaml.example`](agent/fingerprints.yaml.example) to
`agent/fingerprints.yaml` (or point `mode_b.fingerprints_path` at the example) and
add entries as needed. For interpreted
agents (Claude Code, Cursor) the kernel-visible binary is the interpreter (`node`),
so argv + env markers are the discriminators; for compiled agents, the binary path
is. See [CONTRIBUTING.md](CONTRIBUTING.md) for the derive-and-test workflow.

## Repository layout

| Path | Description |
|------|-------------|
| [architecture.md](architecture.md) | Full system design and phased roadmap |
| [agent/](agent/) | Go + eBPF agent (enroll, observe, action capture) |
| [agent/config.md](agent/config.md) | Agent configuration reference |
| [agent/config.yaml.example](agent/config.yaml.example) | Starter config file |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Fingerprints, dev setup, PR guidelines |

## License

Apache-2.0. See [LICENSE](LICENSE).
