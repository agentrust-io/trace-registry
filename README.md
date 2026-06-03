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
pip install trace-verify
trace-verify registry check --since 2026-06-23 --registry https://github.com/agentrust-io/trace-registry
```

## Canonical Registry

This is a mirror. The canonical TRACE registry with verification API and SLAs runs at [api.trace.opaque.com](https://api.trace.opaque.com).

The mirror exists for independence — anyone can verify the registry without trusting Opaque infrastructure.

## Status

Private. First entries committed at CC Summit June 23, 2026 when cMCP goes live.

## License

Creative Commons Attribution 4.0 International (CC BY 4.0)