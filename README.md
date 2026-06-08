[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](LICENSE)
[![TRACE Spec](https://img.shields.io/badge/TRACE-Spec_v0.1-0ea5e9)](https://github.com/agentrust-io/trace-spec)

# TRACE Registry

The public accountability layer for TRACE claim anchors. Each entry records a TRACE claim anchor: the Merkle root hash, timestamp, and block number, committed to this repository as a permanent, independently-verifiable record.

Git's immutable commit history is the append-only proof. Any tampering with registry entries is detectable via commit hash divergence.

## Why this exists

Anyone holding a TRACE trust record can independently verify that it was anchored in this registry without trusting the operator who issued it. TRACE claim anchors are published here so that verification is always possible by a third party, using only this public git history. This is the transparency guarantee: no single operator controls the audit trail.

## Registry Format

Each daily file in `registry/YYYY/MM/` is a newline-delimited JSON file where each line is one anchor entry:

```json
{"ts": "2026-06-23T09:15:42Z", "merkle_root": "sha256:a3f8d2...", "block": 1, "producer": "cmcp-gateway/0.1.0"}
```

## Verification

**Manual verification (available now):** Clone this repository and audit the Merkle root hashes directly against your TRACE claim receipts.

```bash
git clone https://github.com/agentrust-io/trace-registry.git
# Compare merkle_root values in registry/YYYY/MM/ against your TRACE claim receipts
```

> **Note:** A `trace-verify` CLI is planned but not yet published to PyPI. The commands below show the intended interface once it ships.
>
> ```bash
> pip install trace-verify
> trace-verify registry check --since 2026-06-23 --registry https://github.com/agentrust-io/trace-registry
> ```

## Canonical Registry

This mirror exists for independence. Anyone can verify TRACE claim anchors without trusting any single operator's infrastructure. The mirror and its git history are independently auditable.

## License

Creative Commons Attribution 4.0 International (CC BY 4.0). See [LICENSE](LICENSE).
