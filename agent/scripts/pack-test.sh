#!/usr/bin/env bash
# P5 pack compile smoke test (no root).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== build policyctl =="
go build -o /tmp/policyctl-pack-test ./cmd/policyctl

echo "== compile generic-agent pack =="
/tmp/policyctl-pack-test compile packs/generic-agent.yaml | grep -q '"live"'

echo "== compile carve-out example =="
/tmp/policyctl-pack-test compile packs/carve-out.example.yaml | grep -q allow-internal-registry

echo "PASS pack compile"
