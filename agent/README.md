# AI Agent Validator — agent

A self-contained Go + eBPF agent that enrolls AI-agent processes (Mode A cgroup /
Mode B fingerprint), propagates the `agent_id` tag across the process tree,
reports tagged lifecycle and action events, and **enforces signed policy in the
kernel** when `policy.mode: enforce`.

Current milestones: **P0** (enroll & observe), **P0.5** (action capture),
**P1** (policy schema + trusted loader via `policyctl`), **P2** (shadow-mode
evaluation in userspace), **P3** (kernel deny via fmod_ret + Mode A cgroup
egress), and **P4** (denial feedback channel). See [architecture.md](../architecture.md) §13.

## Build

Requirements: Linux 5.8+ with BTF, `clang`/LLVM, libbpf headers
(`/usr/include/bpf`), and Go 1.24+.

```bash
make                 # bpf + aiblocker-agent + policyctl
make bpf             # compile bpf/enroll.bpf.c -> staged for go:embed
make build           # go build -> ./aiblocker-agent
make build-policyctl # go build -> ./policyctl
make test            # unit tests (BPF load test auto-skips unless root)
make vet
make policy-test     # P1 loader smoke test (no root)
```

The compiled BPF object is embedded via `go:embed`, so `make bpf` must run before
`go build`/`go test` of `./cmd/agent`. The object is git-ignored and regenerated.

## Run

eBPF load + attach needs root (CAP_BPF + CAP_PERFMON):

```bash
cp config.yaml.example config.yaml   # first time only
cp fingerprints.yaml.example fingerprints.yaml   # if mode_b enabled
sudo ./aiblocker-agent --config config.yaml
```

### Enforce mode (P3)

Set `policy.mode: enforce` in `config.yaml`, load a signed bundle with `policyctl
load`, then start the agent. Mode A processes in `mode_a.cgroup_contains` (e.g.
`ai-agents.slice`) get egress enforcement via cgroup/connect; tagged agents also
get open/connect enforcement via syscall fmod_ret hooks.

Policy maps persist under `bpf.pin_path` (default `/sys/fs/bpf/ai-agent-validator`)
across agent restarts (P3.7). Ensure the AI cgroup slice exists before starting
the agent in Mode A (`systemd-run --slice=ai-agents.slice sleep infinity`).

AI agent shell (Mode A):

```bash
sudo systemd-run --slice=ai-agents.slice --pty bash
```

Enforce smoke test (root; builds temp policy + config):

```bash
sudo ./scripts/enforce-test.sh
```

Flags (override config):

| Flag | Meaning |
|------|---------|
| `--config PATH` | config file (default `config.yaml`) |
| `--debug` | enable debug logging + the debug HTTP server |
| `--log-level` | `debug`\|`info`\|`warn`\|`error` |
| `--log-format` | `text`\|`json` |

## Policy loader (P1) + shadow / enforce (P2/P3)

`policyctl` is a separate trusted loader for signed policy bundles. It does not
require root. When `policy.mode` is `shadow` or `enforce`, the agent loads the
current bundle from the store, re-verifies the signature, and evaluates captured
actions against shadow rules (`shadow_deny` audit events). In `enforce` mode,
`state: enforced` rules are compiled into kernel BPF maps and block matching
actions with `-EPERM` plus `kernel_deny` audit events.

See [policy.md](policy.md) and [policy.yaml.example](policy.yaml.example).

```bash
cp policy.yaml.example policy.yaml
policyctl keygen --key policy.key --pub policy.pub
policyctl sign --key policy.key policy.yaml
policyctl load --pub policy.pub --store ./policy-store policy.yaml
policyctl shadow-report --audit audit.jsonl   # summarize would-have-blocked hits
```

Enable shadow evaluation in `config.yaml` (`policy.enabled: true`, matching
`agent_scope` to enrolled `agent_id`). Requires action capture (`actions.enabled`).

## Configuration

| File | Purpose |
|------|---------|
| [config.md](config.md) | Agent configuration reference |
| [config.yaml.example](config.yaml.example) | Starter config — copy to `config.yaml` |
| [policy.md](policy.md) | Policy bundle schema + `policyctl` reference |
| [policy.yaml.example](policy.yaml.example) | Starter policy bundle |
| [fingerprints.yaml.example](fingerprints.yaml.example) | Mode B fingerprint set — copy to `fingerprints.yaml` |

## Output

- **stdout** — one line per tagged event (`text`) or JSON (`json`). Enrollment
  decisions are prefixed `ENROLL`; shadow verdicts are prefixed `SHADOW_DENY`;
  kernel blocks are prefixed `KERNEL_DENY` in text mode (also in audit JSONL).
- **stderr (slog)** — startup, snapshots, warnings, and with `--debug` the
  fingerprint match trace. Set `log_file` to duplicate slog to a file.
- **audit log** — append-only JSONL when `report.audit_log` is set. Tagged
  lifecycle events (`exec`, `fork`, `exit`), action events (`connect`, `open`,
  `unlink`, `rename`), and P2 `shadow_deny` verdicts. Does not include debug traces.
- **snapshot** — periodic per-agent counters in the logs (`report.snapshot_sec`).

## Debug mode

`--debug` raises log level to `debug` and starts a read-only HTTP server
(`debug.http_addr`, default `127.0.0.1:9230`):

| Endpoint | Shows |
|----------|-------|
| `/debug/agents` | live tagged process trees |
| `/debug/fingerprints` | the loaded fingerprint set |
| `/debug/stats` | lifecycle + action counters, tracked pids |
| `/debug/feedback` | recent `policy_feedback` records (`?agent_id=` or `?limit=`) |
| `/healthz` | liveness |

When `policy.mode: enforce`, kernel denies also emit structured `policy_feedback`
records (stdout, audit JSONL, optional `feedback.path`). See architecture §5.6.

## Policy shim (P4.2)

`aiblocker-shim` wraps a subprocess and, when the command fails under enforcement,
looks up the matching `policy_feedback` record and prints it on stderr for the
agent runtime to inject into model context.

```bash
make build-shim

# Agent config: feedback.path must match shim source (or use HTTP).
export AIBLOCKER_FEEDBACK_FILE=/tmp/aiblocker-feedback.jsonl
export AIBLOCKER_AGENT_ID=agent

sudo systemd-run --slice=ai-agents.slice --pty bash
# inside slice:
aiblocker-shim cat /etc/shadow
# stderr includes:
#   AIBLOCKER_POLICY_FEEDBACK:{"decision":"denied",...}
#   Policy blocked action "open" on "/etc/shadow" ...
```

Environment variables (override with flags):

| Variable | Purpose |
|----------|---------|
| `AIBLOCKER_FEEDBACK_FILE` | JSONL path (`feedback.path` in agent config) |
| `AIBLOCKER_FEEDBACK_URL` | e.g. `http://127.0.0.1:9230/debug/feedback` |
| `AIBLOCKER_AGENT_ID` | filter HTTP lookup by enrolled agent |

## Tests

| Script | Requires root | What it verifies |
|--------|---------------|------------------|
| `./scripts/policy-test.sh` | no | P1: sign, load, rollback |
| `./scripts/integration-test.sh` | yes | P0/P0.5: enroll + action capture |
| `./scripts/enforce-test.sh` | yes | P3: localhost allow + egress/file deny |
| `./scripts/pack-test.sh` | no | P5: compile curated policy packs |
| `./scripts/pack-install.sh` | no | P5: sign + load a pack (needs policy.key) |
| `go test ./internal/enroll/...` | no | P2 shadow evaluation (engine_shadow_test.go) |
| `go test ./internal/policy/...` | no | P2 evaluator + shadow-report |

```bash
make policy-test
sudo ./scripts/integration-test.sh
```

## Package layout

| Package / file | Responsibility |
|----------------|----------------|
| `bpf/enroll.bpf.c` | lifecycle tracepoints + action syscalls; advisory tag map |
| `cmd/policyctl` | P1 trusted policy loader CLI; P2 `shadow-report`; P5 `promote` |
| `packs/` | P5 curated policy packs + carve-out examples |
| `internal/policy` | schema, compiler, signing, store, loader, evaluator, holder, shadow-report |
| `internal/ebpfloader` | load object, attach 7 tracepoints, ringbuf, tag map |
| `internal/event` | decode ringbuf records (lifecycle + action layouts) |
| `internal/enricher` | resolve binary / user / cgroup path from `/proc` |
| `internal/fingerprint` | Mode B fingerprint schema, load, match (+ trace) |
| `internal/proctable` | lineage + `agent_id` tag propagation (source of truth) |
| `internal/enroll` | enrollment engine, action handling, P2 shadow evaluation |
| `internal/report` | stdout/audit sinks (OTLP seam, inert) |
| `internal/debugsrv` | read-only debug HTTP endpoints |
| `internal/config`, `internal/logging` | config + slog setup |
