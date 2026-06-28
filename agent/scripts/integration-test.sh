#!/usr/bin/env bash
# P0 integration smoke test (requires root for eBPF).
#
# Verifies the two enrollment failure modes that matter most:
#   - RECALL: a fake "agent" (node basename + CLAUDECODE marker) gets enrolled and tagged.
#   - PRECISION: an unrelated control process is NOT tagged.
#
# Usage: sudo ./scripts/integration-test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (eBPF load needs CAP_BPF/CAP_PERFMON): sudo $0" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null || true' EXIT

echo "== building =="
make all >/dev/null

# A fake agent whose resolved binary basename is "node" (matches the
# claude-code fingerprint when CLAUDECODE is set). Use a copy of sleep so it
# blocks while we observe it.
cp "$(command -v sleep)" "$TMP/node"

cat >"$TMP/config.yaml" <<EOF
log_level: info
log_format: text
mode_a:
  enabled: true
  cgroup_contains: ["ai-agents.slice"]
  default_agent_id: agent
mode_b:
  enabled: true
  fingerprints_path: "$(pwd)/fingerprints.yaml"
report:
  format: json
  audit_log: "$TMP/audit.jsonl"
  snapshot_sec: 0
debug:
  enabled: false
EOF

echo "== starting agent =="
./aiblocker-agent --config "$TMP/config.yaml" >"$TMP/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1.5

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
  echo "FAIL: agent exited during startup (BPF load/attach failed?)"
  cat "$TMP/agent.log"
  exit 1
fi

echo "== spawning control (should NOT enroll) =="
sleep 4 &
CONTROL_PID=$!

echo "== spawning fake agent (should enroll) =="
# Use a minimal env so CLAUDECODE lands inside the BPF env prefix (MAX_ENV=512).
# On a full inherited shell env, CLAUDECODE=1 is appended late and the marker is missed.
env -i CLAUDECODE=1 PATH="${PATH:-/usr/bin:/bin}" "$TMP/node" 4 &
FAKE_PID=$!

sleep 2

echo "== results =="
fail=0

if grep -q '"agent_id":"claude-code"' "$TMP/audit.jsonl" 2>/dev/null; then
  echo "PASS: fake agent enrolled as claude-code"
else
  echo "FAIL: fake agent was not enrolled"; fail=1
  echo "--- agent.log (last 30 lines) ---"
  tail -30 "$TMP/agent.log" 2>/dev/null || echo "(no agent log)"
fi

if grep -q "\"pid\":$CONTROL_PID" "$TMP/audit.jsonl" 2>/dev/null; then
  echo "FAIL: control pid $CONTROL_PID was tagged (false positive)"; fail=1
else
  echo "PASS: control process not tagged"
fi

wait "$FAKE_PID" "$CONTROL_PID" 2>/dev/null || true

echo "--- audit.jsonl ---"
cat "$TMP/audit.jsonl" 2>/dev/null || echo "(empty)"

exit $fail
