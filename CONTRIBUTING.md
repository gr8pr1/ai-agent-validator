# Contributing

Thanks for your interest in **AI Agent Validator** (`ai-agent-validator`). The project is early; the most
valuable contributions right now are **agent fingerprints** and feedback on the
[architecture](architecture.md).

## Dev setup

Requirements: Linux 5.8+ with BTF (`/sys/kernel/btf/vmlinux`), `clang`/LLVM, libbpf
headers, and Go 1.24+.

```bash
cd agent
make            # compile BPF + build
make test       # unit tests (BPF load test auto-skips unless root)
make vet
gofmt -l .      # must be empty
```

The BPF load/verify test and the integration smoke test need root:

```bash
sudo -E go test ./cmd/agent -run TestBPFLoadAndAttach
sudo ./scripts/integration-test.sh
```

## Contributing a fingerprint (Mode B)

Fingerprints are data in [`agent/fingerprints.yaml.example`](agent/fingerprints.yaml.example),
not code. Copy to `fingerprints.yaml` (or set `mode_b.fingerprints_path`) before running. To add support for a new agent:

1. **Observe.** Run the validator agent with `--debug`. Watch the
   `fingerprint` match-trace logs and the `exec` events to see the real
   `interpreter_basename`, argv, and env vars.
2. **Derive discriminators.** Pick a *stable, unique* tuple:
   - interpreted agents (node/python): `interpreter_basename` + an `env_markers`
     entry and/or `argv_contains` glob for the script/module path;
   - compiled agents: `interpreter_path`.
   Avoid bare common names (e.g. matching `node` alone) — they cause false
   positives. argv/env are captured as a bounded prefix, so keep markers early.
3. **Shadow-test.** Confirm both directions:
   - recall: the whole agent process subtree gets tagged;
   - precision: unrelated `node`/`python` processes are **not** tagged.

   The integration script spawns a fake agent (bash as `node` + `CLAUDECODE`) that
   exercises connect/open/unlink/rename, plus a control process. Requires root:

   ```bash
   cp fingerprints.yaml.example fingerprints.yaml   # if not already present
   sudo ./scripts/integration-test.sh
   ```

   For deployments, configure the `actions:` section in `config.yaml` — see
   [agent/config.md](agent/config.md).
4. **Open a PR.** Include the agent name/version you tested against and how you
   verified precision/recall.

## Code

- Keep packages small and single-purpose; mirror the existing layout.
- `gofmt`-clean, `go vet`-clean, tests passing.
- BPF changes: keep the verifier happy and document any kernel-version assumptions.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not file public issues for
vulnerabilities.
