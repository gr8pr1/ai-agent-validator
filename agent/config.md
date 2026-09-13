# Agent configuration reference

The agent reads a YAML file (default: `config.yaml` in the working directory). If the
file is missing, built-in defaults apply (see [config.yaml.example](config.yaml.example)).

Copy the example to get started:

```bash
cp config.yaml.example config.yaml
# edit config.yaml, then:
sudo ./aiblocker-agent --config config.yaml
```

CLI flags (`--debug`, `--log-level`, `--log-format`) override matching config fields at
startup.

---

## Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_level` | string | `info` | slog level: `debug`, `info`, `warn`, `error` |
| `log_format` | string | `text` | slog format: `text` or `json` |
| `log_file` | string | `""` | Optional path; duplicates slog output to this file |

---

## `mode_a` — controlled-spawn enrollment

Enroll any process whose cgroup-v2 path contains one of the configured substrings.
Useful when you launch agents under a dedicated systemd slice (e.g.
`Slice=ai-agents.slice`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable Mode A |
| `cgroup_contains` | list of strings | `["ai-agents.slice"]` | Substrings matched against `/proc/<pid>/cgroup` |
| `default_agent_id` | string | `"agent"` | `agent_id` assigned on cgroup match |

At least one of `mode_a` or `mode_b` must be enabled.

---

## `mode_b` — exec-time fingerprint enrollment

Enroll processes at exec when they match an entry in the fingerprint set. This is the
usual path for agents you do not control the launch of (e.g. a developer running
`claude` or `cursor-agent`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable Mode B |
| `fingerprints_path` | string | `"fingerprints.yaml"` | Path to the fingerprint YAML file |

See [fingerprints.yaml.example](fingerprints.yaml.example) and
[CONTRIBUTING.md](../CONTRIBUTING.md) for how to add entries.

---

## `actions` — file/network action capture (P0.5)

Observe-only capture of per-agent **connect**, **open**, **unlink**, and **rename**
syscalls for enrolled processes. Does not block anything.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch for action capture |
| `capture` | list of strings | all four types | Subset to record: `connect`, `open`, `unlink`, `rename` |
| `open_writes_only` | bool | `true` | When true, report only open-for-write intent (see below) |

### Action event types

| Event | Source syscall | Audit fields |
|-------|----------------|--------------|
| `connect` | `sys_enter_connect` | `dest`, `dest_port` |
| `open` | `sys_enter_openat` | `path`, `write` |
| `unlink` | `sys_enter_unlinkat`, `sys_enter_unlink` | `path` |
| `rename` | `sys_enter_renameat2` | `path`, `new_path` |

**Open / write intent:** P0.5 does not hook raw `write()`. When `open_writes_only:
true` (default), only `openat` calls with write-related flags are reported
(`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC` — see `event.IsOpenWriteIntent`).
When `open_writes_only: false`, read-only opens are reported too (expect high
volume). The audit field `write` reflects flag-based write intent on each emitted
open; many runtimes (e.g. Bun) open files with `O_RDWR` even for reads, so
`"write": true` does **not** always mean the file was modified.

**Capture list:** If `capture` is omitted or empty, all four action types are enabled.
Set `capture: []` explicitly only when you intend this; to disable a type, list the
types you want instead of leaving an empty array.

**Read-only opens:** With the default `open_writes_only: true`, read-only file access
is filtered out in userspace and will not appear in the audit log. Set
`open_writes_only: false` while testing read visibility.

Action events are gated in the kernel by an advisory `tagged_pids` map; userspace
re-checks every event against the process table before reporting.

---

## `policy` — shadow (P2) and enforce (P3)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `off` | `off` \| `shadow` \| `enforce` — preferred control |
| `enabled` | bool | `false` | Deprecated alias: `true` with empty `mode` → `shadow` |
| `store_path` | string | `./policy-store` | Policy version store (from `policyctl load`) |
| `pub_key_path` | string | `""` | Ed25519 public key for bundle verification (required when active) |
| `reload_sec` | int | `15` | Poll store `current` for hot reload; `0` disables polling |
| `scope` | string | `""` | Optional override for `agent_scope` matching (default: bundle scope) |

### Modes

| Mode | Kernel maps | Userspace shadow | Blocks |
|------|-------------|------------------|--------|
| `off` | not loaded | no | no |
| `shadow` | not loaded | yes (`shadow_deny`) | no |
| `enforce` | yes (`state: enforced` rules) | yes | yes (`-EPERM`, `kernel_deny`) |

**Enforce hooks:** tagged agents — syscall fmod_ret (`openat`, `connect`, `unlinkat`,
`unlink`, `renameat2` on amd64). Enroll tracepoints stage paths/destinations into
per-PID maps before the syscall runs. Mode A cgroup (`mode_a.cgroup_contains`) —
cgroup/connect4+6 for all processes in the slice (egress). LSM `socket_connect`
attaches only when `bpf` is in the kernel LSM stack (`lsm=...,bpf` at boot);
otherwise fmod_ret is the connect path for tagged processes.

**Kernel tag sync:** the in-kernel `tagged_pids` map is updated on exec/fork/exit,
propagates from tagged ancestors, and is bootstrapped from `/proc` at agent startup
for already-running enrolled processes.

**Unlink/rename fail-closed:** when a tagged agent reaches an unlink or rename `fmod_ret`
hook without resolvable staged paths (e.g. fd-based `unlinkat` with `AT_EMPTY_PATH`), the
enforcer returns `-EPERM` rather than allowing the operation.

**Multi-action path rules:** rules that share the same path prefix but different verbs
(e.g. write+unlink+rename on `/etc/*`) are merged into one kernel map entry with an
action bitmask at load time.

**Cgroup connect return codes:** `1` = allow, `0` = deny (unlike fmod_ret `-EPERM`).

**Fail direction:** bundle `fail_direction: open|closed` is stored in the
`policy_ctrl` BPF map. When `enforcement_active` is clear (e.g. during policy
reload), `closed` denies tagged/slice traffic until maps are live again; `open`
allows (default).

When enabled, the agent loads the store's current signed bundle on startup and on
each reload, **re-verifies the signature**, recompiles, and evaluates each captured
action against **shadow** and **live (enforced)** rule sets. Matching deny rules
emit a separate `shadow_deny` audit event (dual emit with the original action).

**Prerequisites:** `actions.enabled` must be true and the action type must appear
in `actions.capture`. P2 evaluates only captured P0.5 actions (`connect`, `open`,
`unlink`, `rename`) — not exec lifecycle events. `match.action: write` matches
`open` events with write intent, not raw `write()` syscalls.

**Shadow sources:** `state: shadow` rules emit `shadow_source: "shadow"`; `state:
enforced` rules emit `shadow_source: "live_preview"`. Both can fire on one action.

**Startup:** invalid/missing store or bad signature → agent exits. **Reload:** failures
log a warning and keep the previous policy; reload is skipped when version unchanged.
`reload_sec: 0` disables polling.

`agent_scope` matches enrolled `agent_id` by exact equality (optional `agent:`
prefix stripped on both sides). `policy.enabled` requires `policy.pub_key_path`.

**Predicate availability:** path, dest IP/port, uid, binary, and cgroup are
evaluated when present on the action/enrollment record. Predicates referencing
missing fields are treated as non-matching.

Example:

```yaml
policy:
  enabled: true
  store_path: "./policy-store"
  pub_key_path: "policy.pub"
  reload_sec: 15
```

---

## `feedback` — denial feedback channel (P4)

Structured do-not-retry records for agent runtimes when `policy.mode: enforce`.
Each kernel deny emits a `policy_feedback` audit event with rule rationale,
`retry: do-not-retry`, and appeal text (architecture §5.6).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | `""` | Optional append-only JSONL sink for shims |
| `max_per_agent` | int | `32` | Ring buffer size per `agent_id` in memory |

Query recent feedback via debug HTTP: `GET /debug/feedback?agent_id=agent` or
`GET /debug/feedback?limit=20` (requires `debug.enabled: true`).

### Shim integration (P4.2)

Build `aiblocker-shim` (`make build-shim`) and wrap agent tool calls:

```bash
export AIBLOCKER_FEEDBACK_FILE=/tmp/aiblocker-feedback.jsonl
aiblocker-shim curl -s https://example.com
```

On policy block, stderr includes a machine-readable line prefixed with
`AIBLOCKER_POLICY_FEEDBACK:` (JSON decision) plus a human-readable summary.
Point `feedback.path` at the same JSONL file, or set `AIBLOCKER_FEEDBACK_URL`
to the debug endpoint instead.

---

## `report` — output sinks

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `format` | string | `text` | Stdout format: `text` or `json` |
| `audit_log` | string | `""` | Append-only JSONL path; empty disables file audit |
| `all_events` | bool | `false` | Also report untagged exec events (very noisy) |
| `snapshot_sec` | int | `30` | Periodic counter snapshot interval; `0` disables |

### What goes where

| Sink | Contents |
|------|----------|
| **stdout** | Tagged lifecycle + action + `shadow_deny` events (`text` or `json`; shadow prefix `SHADOW_DENY`) |
| **stderr (slog)** | Startup, snapshots, warnings; with `--debug`, fingerprint traces |
| **`log_file`** | Duplicate of slog when set |
| **`audit_log`** | Tagged events only: `exec`, `fork`, `exit`, `connect`, `open`, `unlink`, `rename`, `shadow_deny`, `kernel_deny`, `policy_feedback`, plus `session_start` marker |

Enrollment decisions on stdout are prefixed `ENROLL` in text mode.

### Example audit records

Lifecycle:

```json
{"event":"exec","enrolled":true,"pid":7240,"agent_id":"claude-code","mode":"B","binary":"/root/.local/bin/claude"}
```

Action:

```json
{"event":"open","pid":12427,"agent_id":"claude-code","path":"/root/ai-agent-validator/agent/config.yaml","write":true}
```

Shadow verdict (P2, when `policy.enabled`):

```json
{"event":"shadow_deny","pid":12427,"agent_id":"claude-code","rule_id":"deny-cred-file-read","shadow_source":"shadow","policy_version":1,"reason":"AI agents never need credential files","path":"/etc/shadow","write":true}
```

---

## `bpf` — pinned policy maps (P3.7)

When `policy.mode: enforce`, policy maps can persist under bpffs across agent
restarts so live rules and `policy_ctrl` survive process exit.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pin_path` | string | `/sys/fs/bpf/ai-agent-validator` | bpffs directory; `""` disables pinning |

Pinned maps: `policy_ctrl`, `path_deny/allow`, `ip_deny/allow`, `port_deny/allow`,
`inode_deny/allow`. Ringbufs and per-CPU scratch maps are not pinned.

Inspect: `ls /sys/fs/bpf/ai-agent-validator/` or `bpftool map show pinned
/sys/fs/bpf/ai-agent-validator/policy_ctrl`.

On startup the agent logs `reusing pinned policy maps` when pins from a prior run
are loaded. Stale or incompatible pins are cleared and recreated automatically.

---

## `debug` — debug HTTP server

Enabled automatically when you pass `--debug` (also forces log level to `debug`), or
when `debug.enabled: true` in YAML.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Start the debug HTTP server |
| `http_addr` | string | `127.0.0.1:9230` | Listen address |

| Endpoint | Shows |
|----------|-------|
| `/debug/agents` | Live tagged process trees |
| `/debug/fingerprints` | Loaded fingerprint set |
| `/debug/stats` | Event/enrollment/action counters |
| `/debug/feedback` | Recent `policy_feedback` records (`?agent_id=`, `?limit=`) |
| `/healthz` | Liveness |

---

## Example configuration

```yaml
log_level: info
log_format: text
log_file: "log.txt"

mode_a:
  enabled: true
  cgroup_contains:
    - "ai-agents.slice"
  default_agent_id: "agent"

mode_b:
  enabled: true
  fingerprints_path: "fingerprints.yaml"

actions:
  enabled: true
  capture: [connect, open, unlink, rename]
  open_writes_only: false   # true in production to reduce noise

report:
  format: text
  audit_log: "report-audit.jsonl"
  all_events: false
  snapshot_sec: 30

debug:
  enabled: false
  http_addr: "127.0.0.1:9230"
```

---

## Validation rules

- `report.format` must be `text` or `json`.
- At least one of `mode_a.enabled` or `mode_b.enabled` must be `true`.
- Unknown YAML keys are ignored by the parser.
- A missing config file is not an error; defaults are used.
