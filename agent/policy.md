# Policy bundle reference

Policy bundles are declarative, signed YAML documents that define allow/deny rules
for AI-agent processes. P1 provides the schema, compiler, signing, and trusted loader
(`policyctl`). **Enforcement is P3** — P1 compiles and stores policy but does not
wire it into the running eBPF agent yet.

See [architecture.md](../architecture.md) §8 for design rationale and
[policy.yaml.example](policy.yaml.example) for a starter bundle.

## Quickstart

```bash
make build-policyctl          # or: go build -o policyctl ./cmd/policyctl

cp policy.yaml.example policy.yaml   # edit rules
policyctl keygen --key policy.key --pub policy.pub
policyctl sign --key policy.key policy.yaml
policyctl verify --pub policy.pub policy.yaml
policyctl load --pub policy.pub --store ./policy-store policy.yaml
policyctl history --store ./policy-store
```

Flags must appear **before** positional arguments.

## Bundle schema

Top-level envelope:

```yaml
policy_bundle:
  version: 1                    # required, monotonic integer
  agent_scope: "agent:ci-runner" # cgroup / label / tag selector
  signed_by: "ops-team"         # metadata; signature covers whole file bytes
  default_action: allow         # allow | deny (deny-list vs allow-list posture)
  fail_direction: open          # open | closed (§10 — used when enforcer unavailable)
  rules: [...]
```

### Rule fields

| Field | Required | Values | Description |
|-------|----------|--------|-------------|
| `id` | yes | string | Unique rule identifier |
| `rationale` | yes | string | Human-readable reason (becomes denial feedback in P4) |
| `match` | yes | object | Closed-vocabulary predicates (see below) |
| `decision` | yes | `allow`, `deny`, `kill` | `kill` parses but compiler rejects (P3+ planned) |
| `state` | no | `draft`, `shadow`, `enforced`, `retired`, `rollback` | Default `draft` |

### Match fields (closed vocabulary)

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | **Required.** One or more of `connect`, `open`, `write`, `unlink`, `rename`, `exec` separated by `\|` |
| `path_in` | list | Path globs (`*` wildcard); match if path matches any entry |
| `path_not_in` | list | Exclude paths matching any entry |
| `dest_ip_in` | list | CIDR/IP allow list for `connect` |
| `dest_ip_not_in` | list | CIDR/IP deny list for `connect` |
| `dest_port_in` | list | Allowed destination ports |
| `dest_port_not_in` | list | Denied destination ports |
| `uid` | int | Match specific UID |
| `binary` | string | Resolved binary path identity |
| `cgroup` | string | Cgroup path substring |

At least one match field besides `action` is recommended; `match.action` is always required.

### Compiler behavior

- **`enforced`** rules → `live` set (future kernel enforcement).
- **`shadow`** rules → `shadow` set (P2 log-only evaluation).
- **`draft`**, **`retired`**, **`rollback`** → skipped.
- **Conflict resolution:** deny beats allow; higher specificity wins among same decision;
  ambiguous overlapping deny rules at the same specificity are rejected.
- Output: JSON `CompiledPolicy` with `live` and `shadow` rule arrays.

## Signing

Ed25519 detached signatures over the **exact bundle file bytes** (no re-serialization).

| File | Purpose |
|------|---------|
| `policy.key` | Private signing key (`0600`) — authoring host only |
| `policy.pub` | Public verification key — policed hosts |
| `policy.yaml.sig` | Base64 detached signature sidecar |

The private key never belongs on monitored hosts (§10).

## Version store

`policyctl load` writes to a file-backed store (default `./policy-store`):

```
policy-store/
  manifest.json       # all version metadata
  current             # active version number
  versions/
    1/
      bundle.yaml
      bundle.yaml.sig
      meta.json       # signed_by, bundle_sha256, loaded_at, state
      compiled.json   # map-ready artifact
```

Rollback is instant: `policyctl rollback --store ./policy-store <version>`.

## policyctl commands

| Command | Description |
|---------|-------------|
| `keygen [--key PATH] [--pub PATH]` | Generate Ed25519 key pair |
| `sign [--key PATH] <bundle.yaml>` | Sign bundle, write `.sig` sidecar |
| `verify [--pub PATH] <bundle.yaml>` | Verify signature |
| `compile <bundle.yaml>` | Dry-run compile; print JSON to stdout |
| `load [--pub PATH] [--store DIR] <bundle.yaml>` | Verify, compile, store, set current |
| `history [--store DIR]` | List stored versions |
| `rollback [--store DIR] <version>` | Set current version |
| `show [--store DIR] [version]` | Print compiled policy (current if version omitted) |

## Smoke test

No root required:

```bash
make policy-test
# or: ./scripts/policy-test.sh
```

## Relationship to the observe agent

| Component | Phase | Role |
|-----------|-------|------|
| `aiblocker-agent` | P0/P0.5 | Enroll + observe (unchanged in P1) |
| `policyctl` | P1 | Sign, compile, load policy bundles |
| Kernel enforcer | P3 | Consumes compiled policy from store |

Agent-side `policy:` config wiring is deferred to P3.
