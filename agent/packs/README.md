# Curated policy packs (P5)

Ready-to-sign policy bundles for common AI-agent deployments. Start with
**shadow** egress rules, review hits, then promote to **enforced**.

## Packs

| File | Purpose |
|------|---------|
| `generic-agent.yaml` | Default deny-list: cred reads, enforcer tamper, system-path writes, shadow public egress |
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

- Only one shadow `connect` deny rule at the same specificity — do not add
  overlapping `dest_port_not_in` and `dest_ip_not_in` shadow denies without
  merging them into a single rule.
- Run `policyctl compile packs/your.yaml` before sign/load to catch conflicts.
