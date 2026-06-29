#!/usr/bin/env bash
# P0/P0.5 integration smoke test (requires root for eBPF).
#
# Verifies enrollment and action capture:
#   - RECALL: a fake "agent" (node basename + CLAUDECODE marker) gets enrolled and tagged.
#   - PRECISION: an unrelated control process is NOT tagged.
#   - ACTIONS: the fake agent's connect/open/unlink/rename syscalls are captured with agent_id.
#   - ACTION PRECISION: control process syscalls are NOT reported as agent actions.
#
# Usage: sudo ./scripts/integration-test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

FP="fingerprints.yaml"
if [[ ! -f "$FP" ]]; then
  FP="fingerprints.yaml.example"
fi

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (eBPF load needs CAP_BPF/CAP_PERFMON): sudo $0" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null || true' EXIT

echo "== building =="
make all >/dev/null

# Fake agent: copy bash as "node" so resolved basename matches claude-code fingerprint.
cp "$(command -v bash)" "$TMP/node"

cat >"$TMP/agent-actions.sh" <<'SCRIPT'
set -euo pipefail
TMP="$1"
# Let userspace populate the kernel tag map before syscalls fire.
sleep 1
echo x >"$TMP/w.txt"
touch "$TMP/del.txt"
rm "$TMP/del.txt"
touch "$TMP/a.txt"
mv "$TMP/a.txt" "$TMP/b.txt"
exec 3<>/dev/tcp/127.0.0.1/9 || true
sleep 2
SCRIPT
chmod +x "$TMP/agent-actions.sh"

cat >"$TMP/control-actions.sh" <<'SCRIPT'
set -euo pipefail
TMP="$1"
touch "$TMP/control.txt"
exec 3<>/dev/tcp/127.0.0.1/8 || true
sleep 4
SCRIPT
chmod +x "$TMP/control-actions.sh"

cat >"$TMP/config.yaml" <<EOF
log_level: info
log_format: text
mode_a:
  enabled: true
  cgroup_contains: ["ai-agents.slice"]
  default_agent_id: agent
mode_b:
  enabled: true
  fingerprints_path: "$(pwd)/$FP"
actions:
  enabled: true
  capture: [connect, open, unlink, rename]
  open_writes_only: true
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

echo "== spawning control (should NOT enroll or emit actions) =="
env -i PATH="${PATH:-/usr/bin:/bin}" "$TMP/control-actions.sh" "$TMP" &
CONTROL_PID=$!

echo "== spawning fake agent (should enroll + emit actions) =="
# Minimal env so CLAUDECODE lands inside the BPF env prefix (MAX_ENV=512).
env -i CLAUDECODE=1 PATH="${PATH:-/usr/bin:/bin}" "$TMP/node" "$TMP/agent-actions.sh" "$TMP" &
FAKE_PID=$!

sleep 4

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

# Action capture: fake agent should produce connect/open/unlink/rename records.
if grep -q '"event":"connect"' "$TMP/audit.jsonl" && \
   grep -q '"agent_id":"claude-code"' "$TMP/audit.jsonl" && \
   grep -q '"dest":"127.0.0.1"' "$TMP/audit.jsonl" && \
   grep -q '"dest_port":9' "$TMP/audit.jsonl"; then
  echo "PASS: connect action captured for claude-code"
else
  echo "FAIL: connect action not captured"; fail=1
fi

if grep -q '"event":"open"' "$TMP/audit.jsonl" && \
   grep -q "w.txt" "$TMP/audit.jsonl" && \
   grep -q '"write":true' "$TMP/audit.jsonl"; then
  echo "PASS: open-for-write action captured"
else
  echo "FAIL: open-for-write action not captured"; fail=1
fi

if grep -q '"event":"unlink"' "$TMP/audit.jsonl" && \
   grep -q "del.txt" "$TMP/audit.jsonl"; then
  echo "PASS: unlink action captured"
else
  echo "FAIL: unlink action not captured"; fail=1
fi

if grep -q '"event":"rename"' "$TMP/audit.jsonl" && \
   grep -q "a.txt" "$TMP/audit.jsonl" && \
   grep -q "b.txt" "$TMP/audit.jsonl"; then
  echo "PASS: rename action captured"
else
  echo "FAIL: rename action not captured"; fail=1
fi

# Action precision: no connect/open/unlink/rename records for the control pid.
for ev in connect open unlink rename; do
  if grep -E "\"event\":\"$ev\".*\"pid\":$CONTROL_PID|\"pid\":$CONTROL_PID.*\"event\":\"$ev\"" \
     "$TMP/audit.jsonl" 2>/dev/null; then
    echo "FAIL: control pid $CONTROL_PID has $ev action (false positive)"; fail=1
  fi
done
if [[ $fail -eq 0 ]]; then
  echo "PASS: control process has no action events"
fi

wait "$FAKE_PID" "$CONTROL_PID" 2>/dev/null || true

echo "--- audit.jsonl ---"
cat "$TMP/audit.jsonl" 2>/dev/null || echo "(empty)"

exit $fail
