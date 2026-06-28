# AI Agent Validator — agent (P0: enroll & observe)

A self-contained Go + eBPF agent that enrolls AI-agent processes (Mode A cgroup /
Mode B fingerprint), propagates the `agent_id` tag across the process tree, and
reports the tagged process-lifecycle stream. Observe-only — it never blocks.

## Build

Requirements: Linux 5.8+ with BTF, `clang`/LLVM, libbpf headers
(`/usr/include/bpf`), and Go 1.24+.

```bash
make        # = make bpf + make build
make bpf    # compile bpf/enroll.bpf.c -> staged for go:embed
make build  # go build -> ./aiblocker-agent
make test   # unit tests (BPF load test auto-skips unless root)
make vet
```

The compiled BPF object is embedded via `go:embed`, so `make bpf` must run before
`go build`/`go test` of `./cmd/agent`. The object is git-ignored and regenerated.

## Run

eBPF load + attach needs root (CAP_BPF + CAP_PERFMON):

```bash
sudo ./aiblocker-agent --config config.yaml
```

Flags (override config):

| Flag | Meaning |
|------|---------|
| `--config PATH` | config file (default `config.yaml`) |
| `--debug` | enable debug logging + the debug HTTP server |
| `--log-level` | `debug`\|`info`\|`warn`\|`error` |
| `--log-format` | `text`\|`json` |

## Configuration

See [config.yaml](config.yaml). Key sections: `mode_a` (cgroup substrings +
default agent id), `mode_b` (fingerprints path), `report` (format, audit log,
snapshot interval), and `debug`.

Fingerprints live in [fingerprints.yaml](fingerprints.yaml); each entry's `match`
block is an AND of `interpreter_basename` / `interpreter_path` / `argv_contains`
(wildcard globs where `*` spans any characters) / `env_markers.any_of`.

## Output

- **stdout** — one line per tagged event (`text`) or JSON (`json`). Enrollment
  decisions are prefixed `ENROLL`.
- **audit log** — append-only JSONL when `report.audit_log` is set.
- **snapshot** — periodic per-agent counters in the logs (`report.snapshot_sec`).

## Debug mode

`--debug` raises log level to `debug` and starts a read-only HTTP server
(`debug.http_addr`, default `127.0.0.1:9230`):

| Endpoint | Shows |
|----------|-------|
| `/debug/agents` | live tagged process trees |
| `/debug/fingerprints` | the loaded fingerprint set |
| `/debug/stats` | event/enrollment counters + tracked pids |
| `/healthz` | liveness |

Debug logs include per-event traces and, crucially, **fingerprint match tracing**
(which entries were tried and exactly why each did/didn't match) — the primary tool
for debugging Mode B.

## Integration smoke test

```bash
sudo ./scripts/integration-test.sh
```

Spawns a fake agent (node basename + `CLAUDECODE` marker) plus a control process and
asserts the agent is enrolled (recall) while the control is not (precision).

## Package layout

| Package | Responsibility |
|---------|----------------|
| `bpf/enroll.bpf.c` | tracepoints (exec/fork/exit), argv+env capture |
| `internal/ebpfloader` | load object, attach tracepoints, ringbuf + drops |
| `internal/event` | decode ringbuf records (header + argv/env tail) |
| `internal/enricher` | resolve binary / user / cgroup path from `/proc` |
| `internal/fingerprint` | Mode B fingerprint schema, load, match (+ trace) |
| `internal/proctable` | lineage + `agent_id` tag propagation |
| `internal/enroll` | enrollment engine + per-agent stats |
| `internal/report` | stdout/audit sinks (OTLP seam, inert in P0) |
| `internal/debugsrv` | read-only debug HTTP endpoints |
| `internal/config`, `internal/logging` | config + slog setup |
