# TRACE Registry

Append-only public mirror of the TRACE Merkle registry. Each entry records a TRACE claim anchor — the Merkle root hash, timestamp, and block number — committed to this repository as a permanent, independently-verifiable record.

Git's immutable commit history is the append-only proof. Any tampering with registry entries is detectable via commit hash divergence.

## Registry Format

Each daily file in `registry/YYYY/MM/` is a newline-delimited JSON file where each line is one anchor entry:

```json
{"ts": "2026-06-23T09:15:42Z", "merkle_root": "sha256:a3f8d2...", "block": 1, "producer": "cmcp-gateway/0.1.0"}
```

## Verification

```bash
# trace-verify CLI (planned — not yet published to PyPI)
pip install trace-verify
trace-verify registry check --since 2026-06-23 --registry https://github.com/agentrust-io/trace-registry
```

Until `trace-verify` is published, verification can be done by cloning this repository and auditing the Merkle root hashes directly against your TRACE claim receipts.

## Canonical Registry

This mirror exists for independence — anyone can verify TRACE claim anchors without trusting any single operator's infrastructure. The mirror and its git history are independently auditable.

## License

Creative Commons Attribution 4.0 International (CC BY 4.0). See [LICENSE](LICENSE).
