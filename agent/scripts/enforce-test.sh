#!/usr/bin/env bash
# P3 enforce smoke test (requires root).
#
# Builds a temp signed policy (localhost allow + public egress deny + /etc/shadow
# deny), starts the agent in enforce mode, and runs checks inside ai-agents.slice.
#
# Usage: sudo ./scripts/enforce-test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $EUID -ne 0 ]]; then
  echo "must run as root: sudo $0" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null || true' EXIT

echo "== build =="
make bpf all >/dev/null

echo "== temp policy =="
cat >"$TMP/policy.yaml" <<'EOF'
policy_bundle:
  version: 1
  agent_scope: "agent"
  signed_by: "enforce-test"
  default_action: allow
  fail_direction: open
  rules:
    - id: deny-public-egress
      rationale: "block public egress"
      match:
        action: connect
        dest_ip_not_in: ["10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
      decision: deny
      state: enforced
    - id: allow-localhost
      rationale: "loopback ok"
      match:
        action: connect
        dest_ip_in: ["127.0.0.0/8"]
      decision: allow
      state: enforced
    - id: deny-etc-shadow
      rationale: "no shadow file"
      match:
        action: open
        path_in: ["/etc/shadow"]
      decision: deny
      state: enforced
    - id: deny-etc-unlink
      rationale: "no etc deletes"
      match:
        action: unlink
        path_in: ["/etc/*"]
      decision: deny
      state: enforced
EOF

./policyctl keygen --key "$TMP/policy.key" --pub "$TMP/policy.pub"
./policyctl sign --key "$TMP/policy.key" "$TMP/policy.yaml"
./policyctl load --pub "$TMP/policy.pub" --store "$TMP/policy-store" "$TMP/policy.yaml"

cat >"$TMP/config.yaml" <<EOF
log_level: info
mode_a:
  enabled: true
  cgroup_contains: ["ai-agents.slice"]
  default_agent_id: agent
mode_b:
  enabled: false
actions:
  enabled: true
  capture: [connect, open, unlink]
policy:
  mode: enforce
  store_path: "$TMP/policy-store"
  pub_key_path: "$TMP/policy.pub"
  reload_sec: 0
report:
  format: text
  snapshot_sec: 0
debug:
  enabled: false
EOF

run_in_slice() {
  systemd-run --quiet --wait --pipe --slice=ai-agents.slice -- "$SHELL" -lc "$1"
}

echo "== start agent =="
./aiblocker-agent -config "$TMP/config.yaml" &
AGENT_PID=$!
sleep 2

echo "== localhost connect (expect success) =="
if run_in_slice 'nc -z -w2 127.0.0.1 22'; then
  echo "OK localhost connect allowed"
else
  echo "FAIL localhost connect blocked" >&2
  exit 1
fi

echo "== public egress (expect block) =="
if run_in_slice 'nc -z -w2 8.8.8.8 443' 2>/dev/null; then
  echo "FAIL public egress allowed" >&2
  exit 1
else
  echo "OK public egress blocked"
fi

echo "== /etc/shadow open (expect block) =="
if run_in_slice 'cat /etc/shadow' 2>/dev/null; then
  echo "FAIL /etc/shadow readable" >&2
  exit 1
else
  echo "OK /etc/shadow blocked"
fi

echo "== /etc unlink (expect block) =="
TEST_FILE="/etc/aiblocker-enforce-test-$$"
run_in_slice "touch '$TEST_FILE'"
if run_in_slice "rm '$TEST_FILE'" 2>/dev/null; then
  echo "FAIL /etc unlink allowed" >&2
  rm -f "$TEST_FILE"
  exit 1
else
  echo "OK /etc unlink blocked"
  rm -f "$TEST_FILE"
fi

echo "== all enforce checks passed =="
