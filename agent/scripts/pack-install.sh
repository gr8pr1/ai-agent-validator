#!/usr/bin/env bash
# Sign and load a curated policy pack (P5).
#
# Usage: ./scripts/pack-install.sh [pack.yaml]
# Env:   POLICY_KEY, POLICY_PUB, POLICY_STORE
set -euo pipefail

cd "$(dirname "$0")/.."

PACK="${1:-packs/generic-agent.yaml}"
KEY="${POLICY_KEY:-policy.key}"
PUB="${POLICY_PUB:-policy.pub}"
STORE="${POLICY_STORE:-./policy-store}"

if [[ ! -f "$KEY" ]]; then
  echo "missing $KEY — run: policyctl keygen --key $KEY --pub $PUB" >&2
  exit 1
fi

make build-policyctl >/dev/null

echo "== compile $PACK =="
./policyctl compile "$PACK" >/dev/null

echo "== sign =="
./policyctl sign --key "$KEY" "$PACK"

echo "== load =="
./policyctl load --pub "$PUB" --store "$STORE" "$PACK"

echo "OK loaded $(basename "$PACK") into $STORE"
