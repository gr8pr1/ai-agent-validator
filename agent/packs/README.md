# Curated policy packs (P5)

Ready-to-sign policy bundles for common AI-agent deployments. Start with
**shadow** egress rules, review hits, then promote to **enforced**.

## Packs

| File | Purpose |
|------|---------|
| `generic-agent.yaml` | Default deny-list: cred reads, enforcer tamper, system-path write/unlink/rename, shadow public egress |
| `carve-out.example.yaml` | Example with internal registry allow rule (copy pattern into your bundle) |

## agent_scope

`policy_bundle.agent_scope` must **exactly match** the enrolled `agent_id`
(Mode A `default_agent_id`, fingerprint tag, or `policy.scope` override in
`config.yaml`). The default pack uses `"agent"` — change it if your agents
enroll as `claude-code`, `agent:ci-runner`, etc.

## Quick install

From `agent/`:

```bash
# one-time keys
policyctl keygen --key policy.key --pub policy.pub

# compile-check, sign, load
./scripts/pack-install.sh packs/generic-agent.yaml
```

Set `policy.pub_key_path: policy.pub` and `policy.store_path: ./policy-store` in
`config.yaml`, then start the agent with `policy.mode: enforce` (or `shadow` first).

## Shadow → enforce workflow

1. Load pack with egress rules in `state: shadow`.
2. Run agents under enrollment (Mode A slice or Mode B fingerprint).
3. Review shadow hits:

   ```bash
   policyctl shadow-report --audit report-audit.jsonl --since 24h
   ```

4. Promote a rule when clean:

   ```bash
   policyctl promote --state enforced --bump packs/generic-agent.yaml shadow-public-egress
   policyctl sign --key policy.key packs/generic-agent.yaml
   policyctl load --pub policy.pub --store ./policy-store packs/generic-agent.yaml
   ```

5. Roll back if needed: `policyctl rollback --store ./policy-store <version>`

## Carve-outs

Copy allow rules from `carve-out.example.yaml` into your working bundle. Allow
rules must be **more specific** than broad deny rules (see architecture §8).
Always **bump `version`**, re-sign, and `policyctl load`.

## Compiler constraints

- Do not add overlapping `connect` deny rules at the same specificity — merge
  predicates (e.g. `dest_ip_not_in` + `dest_port_not_in`) into one rule. The
  compiler rejects ambiguous overlaps regardless of `state`.
- Kernel path rules support exact paths and trailing `/*` only. The pack uses
  `/home/*/.ssh/*`; the agent expands that to `/home/USER/.ssh/*` for each home
  directory at load time (restart or policy reload after new users are created).
- Rules with multiple verbs on the same path prefix (e.g. write+unlink+rename on
  `/etc/*`) are merged into one kernel entry with an action bitmask — do not split
  them into separate rules with the same prefix unless you intend different specificity.
- Run `policyctl compile packs/your.yaml` before sign/load to catch conflicts.
