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

> Status: **P0 + P0.5 + P1 + P2 implemented** (observe agent + policy loader + shadow mode).
> P3 kernel enforcement is planned. See [architecture.md](architecture.md) §13.

## What works today

### P0 — enroll & observe

Identifies AI-agent processes and emits a structured stream of their process-lifecycle
activity. Two enrollment modes:

- **Mode A — controlled spawn:** any process whose cgroup-v2 path matches a
  configured slice (e.g. `ai-agents.slice`) is enrolled.
- **Mode B — exec-time fingerprint:** processes are matched at exec against a
  fingerprint set (binary identity + argv + env markers).

Once enrolled, the tag propagates across the whole process tree.

### P0.5 — action capture

For enrolled agents only, records **connect**, **open**, **unlink**, and **rename**
syscalls (observe-only). See [agent/config.md](agent/config.md).

### P1 — policy model + loader

Signed, versioned policy bundles with a trusted `policyctl` CLI: schema validation,
deterministic compiler, Ed25519 signing, file-backed version store, and instant
rollback. See [agent/policy.md](agent/policy.md).

### P2 — shadow mode

When `policy.enabled` in the agent config, evaluates captured actions against
shadow and enforced rules in userspace and emits `shadow_deny` "would-have-blocked"
events to the audit log. Nothing is blocked. Use `policyctl shadow-report` to
summarize hits before promoting rules. See [agent/config.md](agent/config.md) and
[agent/policy.md](agent/policy.md).

Not yet: kernel enforcement (P3), denial feedback (P4).

## Quickstart

Requirements: Linux 5.8+ with BTF, `clang`/LLVM, libbpf headers, Go 1.24+.

```bash
cd agent
make                              # agent + policyctl
cp config.yaml.example config.yaml
cp fingerprints.yaml.example fingerprints.yaml
sudo ./aiblocker-agent --config config.yaml --debug

# Policy loader (no root):
cp policy.yaml.example policy.yaml
make policy-test
```

See [agent/README.md](agent/README.md) for build details, tests, and debug endpoints.

## Repository layout

| Path | Description |
|------|-------------|
| [architecture.md](architecture.md) | Full system design and phased roadmap |
| [agent/](agent/) | Go + eBPF observe agent + policy loader |
| [agent/config.md](agent/config.md) | Agent configuration reference |
| [agent/policy.md](agent/policy.md) | Policy bundle schema + `policyctl` |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Fingerprints, policy, dev setup |

## License

Apache-2.0. See [LICENSE](LICENSE).
