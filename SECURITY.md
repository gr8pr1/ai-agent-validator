# Security Policy

**AI Agent Validator** (`ai-agent-validator`) is a security tool that loads eBPF programs into the kernel and is
intended (in later phases) to make allow/deny decisions about process behavior. We
take its correctness and safety seriously.

## Reporting a vulnerability

Please report vulnerabilities **privately**. Do not open a public issue or PR for a
security problem.

- Use GitHub's "Report a vulnerability" (Security Advisories) on this repository, or
- contact the maintainers privately and allow reasonable time to respond before any
  public disclosure.

When reporting, include: affected version/commit, kernel version, a description of
the issue and its impact, and reproduction steps or a proof of concept if available.

## Scope notes

- A host-root or `CAP_BPF` attacker is explicitly part of the trusted computing base
  and is **out of scope** (they can manipulate any eBPF state). See the trust and
  threat-model sections of [architecture.md](architecture.md).
- P0 is observe-only: it does not block, kill, or modify any process. Enforcement
  and its associated threat surface arrive in later phases.

## Supported versions

The project is pre-1.0; only the latest `main` is supported. Security fixes land on
`main`.
