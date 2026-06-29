# AI Agent Validator — agent

A self-contained Go + eBPF agent that enrolls AI-agent processes (Mode A cgroup /
Mode B fingerprint), propagates the `agent_id` tag across the process tree, and
reports tagged lifecycle and action events. **Observe-only** — it never blocks.

Current milestones: **P0** (enroll & observe), **P0.5** (action capture), and
**P1** (policy schema + trusted loader via `policyctl`). See
[architecture.md](../architecture.md) §13 for the full roadmap.

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

## Run (observe agent)

eBPF load + attach needs root (CAP_BPF + CAP_PERFMON):

```bash
cp config.yaml.example config.yaml   # first time only
cp fingerprints.yaml.example fingerprints.yaml   # if mode_b enabled
sudo ./aiblocker-agent --config config.yaml
```

Flags (override config):

| Flag | Meaning |
|------|---------|
| `--config PATH` | config file (default `config.yaml`) |
| `--debug` | enable debug logging + the debug HTTP server |
| `--log-level` | `debug`\|`info`\|`warn`\|`error` |
| `--log-format` | `text`\|`json` |

## Policy loader (P1)

`policyctl` is a separate trusted loader for signed policy bundles. It does not
require root. See [policy.md](policy.md) and [policy.yaml.example](policy.yaml.example).

```bash
cp policy.yaml.example policy.yaml
policyctl keygen --key policy.key --pub policy.pub
policyctl sign --key policy.key policy.yaml
policyctl load --pub policy.pub --store ./policy-store policy.yaml
```

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
  decisions are prefixed `ENROLL`.
- **stderr (slog)** — startup, snapshots, warnings, and with `--debug` the
  fingerprint match trace. Set `log_file` to duplicate slog to a file.
- **audit log** — append-only JSONL when `report.audit_log` is set. Tagged
  lifecycle events (`exec`, `fork`, `exit`) and action events (`connect`, `open`,
  `unlink`, `rename`). Does not include debug traces.
- **snapshot** — periodic per-agent counters in the logs (`report.snapshot_sec`).

## Debug mode

`--debug` raises log level to `debug` and starts a read-only HTTP server
(`debug.http_addr`, default `127.0.0.1:9230`):

| Endpoint | Shows |
|----------|-------|
| `/debug/agents` | live tagged process trees |
| `/debug/fingerprints` | the loaded fingerprint set |
| `/debug/stats` | lifecycle + action counters, tracked pids |
| `/healthz` | liveness |

## Tests

| Script | Requires root | What it verifies |
|--------|---------------|------------------|
| `./scripts/policy-test.sh` | no | P1: sign, load, rollback |
| `./scripts/integration-test.sh` | yes | P0/P0.5: enroll + action capture |

```bash
make policy-test
sudo ./scripts/integration-test.sh
```

## Package layout

| Package / file | Responsibility |
|----------------|----------------|
| `bpf/enroll.bpf.c` | lifecycle tracepoints + action syscalls; advisory tag map |
| `cmd/policyctl` | P1 trusted policy loader CLI |
| `internal/policy` | schema, compiler, signing, version store, loader |
| `internal/ebpfloader` | load object, attach 7 tracepoints, ringbuf, tag map |
| `internal/event` | decode ringbuf records (lifecycle + action layouts) |
| `internal/enricher` | resolve binary / user / cgroup path from `/proc` |
| `internal/fingerprint` | Mode B fingerprint schema, load, match (+ trace) |
| `internal/proctable` | lineage + `agent_id` tag propagation (source of truth) |
| `internal/enroll` | enrollment engine, action handling, per-agent stats |
| `internal/report` | stdout/audit sinks (OTLP seam, inert) |
| `internal/debugsrv` | read-only debug HTTP endpoints |
| `internal/config`, `internal/logging` | config + slog setup |
