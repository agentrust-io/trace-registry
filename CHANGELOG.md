# Changelog

Notable changes to the TRACE Registry and the `trace-verify` package. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/).

Two different things are versioned here and they move independently:

- **The registry** is append-only and has no version. Entries under `registry/`
  are never rewritten; see [GOVERNANCE.md](GOVERNANCE.md).
- **`trace-verify`**, the packaged verifier, uses semantic-ish versioning while
  pre-1.0 and is published to PyPI.

## Unreleased

- Public-readiness pass: governance, maintainers, roadmap, this changelog,
  `NOTICE`, `CODEOWNERS`, Dependabot config, and issue/PR templates.

## trace-verify

### 0.2.0
- Producer signatures are **verified before anchoring**, and verification is on by
  default rather than opt-in. Adds an SSRF allowlist for producer key fetching.
  Anchoring an unverified claim would have let a producer put anything into the
  record, which is the one thing the registry must not permit.
- Anchor commits are signed and verified in CI, and the checkout in the anchor
  pipeline is pinned by SHA.
- Schema fix: batch entries without `entry_type` no longer trigger the checkpoint
  required-fields branch.

### 0.1.0
- `trace-verify` packaged as an installable CLI and published to PyPI via trusted
  publishing.

## Registry

### 2026-08
- Anchor pipeline runs on a 15-minute schedule. It has produced no new entries
  since the June entry below, because there is no production claim volume yet;
  a run with nothing to anchor is a no-op by design, not a failure.

### 2026-06
- Log aggregator service and the checkpoint architecture
  ([docs/checkpoint-architecture.md](docs/checkpoint-architecture.md)) designed for
  the volumes that would make one-line-per-batch impractical. Designed, not yet
  needed: the thresholds that would trigger it are in that document.
- Automated anchoring pipeline.
- Mirror network: [MIRRORS.md](MIRRORS.md), `check-mirrors` workflow, and
  [docs/mirroring.md](docs/mirroring.md) for running an independent copy.
- Producer key registry with Ed25519 signature verification.
- CI enforces append-only, monotonic timestamps, and producer ID format. This is
  the mechanical half of the append-only rule; the governance half is in
  GOVERNANCE.md.
- Anchor format specified ([docs/anchor-format.md](docs/anchor-format.md)), verifier
  tooling shipped, and the first real entry landed
  (`registry/2026/06/12.ndjson`).
