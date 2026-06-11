[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](LICENSE)
[![TRACE Spec](https://img.shields.io/badge/TRACE-Spec_v0.1-0ea5e9)](https://github.com/agentrust-io/trace-spec)

# TRACE Registry

The public accountability layer for TRACE claim anchors. Each entry will record a TRACE claim anchor: the Merkle root hash, timestamp, and block number, committed to this repository as a permanent record.

Git's immutable commit history is the append-only proof. Any tampering with registry entries is detectable via commit hash divergence.

> **Status: pre-launch.** The registry contains no entries yet, and the anchor construction (how a Merkle root is derived from TRACE Trust Records, leaf hashing, inclusion proofs) is not yet specified. Until that specification and a published verifier ship, third-party verification is a design goal, not an operational guarantee. Track progress in [#5](https://github.com/agentrust-io/trace-registry/issues/5).

## Why this exists

The goal: anyone holding a TRACE trust record can verify that it was anchored in this registry without trusting the operator who issued it, using only this public git history. No single operator controls the audit trail. The sections below describe the intended mechanism.

## Registry Format

Each daily file in `registry/YYYY/MM/` is a newline-delimited JSON file where each line is one anchor entry:

```json
{"ts": "2026-06-23T09:15:42Z", "merkle_root": "sha256:a3f8d2...", "block": 1, "producer": "cmcp-gateway/0.1.0"}
```

## Verification (intended interface)

Once entries exist and the anchor format is specified, manual verification will be: clone this repository and audit the Merkle root hashes against your TRACE claim receipts.

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

This mirror exists for independence: once operational, TRACE claim anchors can be checked without trusting any single operator's infrastructure, and the git history is auditable by anyone.

## License

Creative Commons Attribution 4.0 International (CC BY 4.0). See [LICENSE](LICENSE).
