#!/usr/bin/env bash
# P1 policy loader smoke test (no root required).
#
# Verifies keygen → sign → verify → compile → load → history → show → rollback
# and that tampered bundles fail verification.
#
# Usage: ./scripts/policy-test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== building policyctl =="
go build -o "$TMP/policyctl" ./cmd/policyctl

POLICY="$TMP/policy.yaml"
cp policy.yaml.example "$POLICY"
KEY="$TMP/policy.key"
PUB="$TMP/policy.pub"
STORE="$TMP/store"

echo "== keygen =="
"$TMP/policyctl" keygen --key "$KEY" --pub "$PUB"

echo "== sign =="
"$TMP/policyctl" sign --key "$KEY" "$POLICY"

echo "== verify =="
"$TMP/policyctl" verify --pub "$PUB" "$POLICY"

echo "== compile =="
"$TMP/policyctl" compile "$POLICY" | grep -q '"live"'

echo "== load =="
"$TMP/policyctl" load --pub "$PUB" --store "$STORE" "$POLICY"

echo "== history =="
"$TMP/policyctl" history --store "$STORE" | grep -q 'v1'

echo "== show =="
"$TMP/policyctl" show --store "$STORE" | grep -q 'deny-cred-file-read'

echo "== tamper detect =="
echo "# tampered" >>"$POLICY"
if "$TMP/policyctl" verify --pub "$PUB" "$POLICY" 2>/dev/null; then
  echo "FAIL: tampered bundle verified"
  exit 1
fi

echo "== rollback (reload v1 after fixing tamper) =="
head -n -1 "$POLICY" >"$POLICY.fixed"
mv "$POLICY.fixed" "$POLICY"
"$TMP/policyctl" sign --key "$KEY" "$POLICY"
"$TMP/policyctl" load --pub "$PUB" --store "$STORE" "$POLICY"
# bump version in policy for second load
sed 's/version: 1/version: 2/' policy.yaml.example >"$POLICY"
"$TMP/policyctl" sign --key "$KEY" "$POLICY"
"$TMP/policyctl" load --pub "$PUB" --store "$STORE" "$POLICY"
"$TMP/policyctl" rollback --store "$STORE" 1
CUR=$("$TMP/policyctl" history --store "$STORE" | grep 'current' || true)
if ! echo "$CUR" | grep -q 'v1'; then
  echo "FAIL: rollback did not set v1 current"
  echo "$CUR"
  exit 1
fi

echo "PASS: policy loader round-trip"
