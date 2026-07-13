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
| `unlink` | `sys_enter_unlinkat` | `path` |
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

## `policy` — shadow-mode evaluation (P2)

Log-only "would have blocked" evaluation against captured actions. **Does not
block anything** — kernel enforcement is P3.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable shadow evaluation |
| `store_path` | string | `./policy-store` | Policy version store (from `policyctl load`) |
| `pub_key_path` | string | `""` | Ed25519 public key for bundle verification (required when enabled) |
| `reload_sec` | int | `15` | Poll store `current` for hot reload; `0` disables polling |
| `scope` | string | `""` | Optional override for `agent_scope` matching (default: bundle scope) |

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
| **`audit_log`** | Tagged events only: `exec`, `fork`, `exit`, `connect`, `open`, `unlink`, `rename`, `shadow_deny`, plus `session_start` marker |

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
