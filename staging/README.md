# Staging area

This directory is the intake point for TRACE Trust Records awaiting anchoring.

## How it works

1. **`staging/incoming/`** -- drop signed Trust Record JSON files here, one per file.
2. The [automated anchor pipeline](../.github/workflows/anchor-pipeline.yml) runs every 15 minutes, picks up all pending files, groups them by `producer`, builds a Merkle batch per group, and writes:
   - One NDJSON line to `registry/YYYY/MM/DD.ndjson`
   - One inclusion proof per claim to `proofs/YYYY/MM/DD/<batch_id>/<claim-stem>.proof.json`
3. Processed files are moved to **`staging/processed/<batch_id>/`** after a successful anchor.

## Submitting a Trust Record

A Trust Record is a JSON file with at minimum:

```json
{
  "fmt": 1,
  "producer": "your-component/1.0.0",
  "ts": "2026-06-22T12:00:00Z",
  "hash": "sha256:<64-hex-chars>",
  "signature": "<base64url-encoded Ed25519 signature>"
}
```

To submit:

1. Name the file anything unique -- e.g. `<producer_id>-<session_id>.json`.
2. Commit it to `staging/incoming/` via a pull request.
3. Wait up to 15 minutes for the pipeline to anchor and push proofs.
4. Retrieve your proof from `proofs/YYYY/MM/DD/<batch_id>/<your-stem>.proof.json`.

## Retrieving your inclusion proof

After anchoring, proofs are committed to `proofs/` and accessible via the GitHub API:

```
https://raw.githubusercontent.com/agentrust-io/trace-registry/main/proofs/YYYY/MM/DD/<batch_id>/<claim-stem>.proof.json
```

You can also verify end-to-end with `trace-verify`:

```bash
pip install trace-verify
trace-verify \
  --claim your-claim.json \
  --proof proofs/YYYY/MM/DD/<batch_id>/your-claim.proof.json \
  --entry registry/YYYY/MM/DD.ndjson \
  --batch-id <batch_id>
```

## Batch cadence

The pipeline anchors whatever is in `staging/incoming/` at the time it runs. All claims from the same `producer` are placed in a single batch per run. If you need claims from a single session to be in the same batch, ensure they are all committed before the next pipeline run.

Maximum claims per batch defaults to unlimited. Large submissions are handled in a single Merkle tree.

## Idempotency

Batch IDs are derived deterministically from the content of the claims. If the pipeline is re-run on the same input (e.g. after a transient failure), it detects the existing batch_id in the registry and skips without creating a duplicate.
