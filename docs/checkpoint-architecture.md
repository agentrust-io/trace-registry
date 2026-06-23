# Checkpoint log pattern for high-volume anchoring

**Status: architecture decision -- not yet implemented**

This document captures the design decision described in issue #17. No implementation work is required until the simpler batch-per-commit model shows strain at production volume.

## The problem

The current design writes one NDJSON line per anchor batch directly to git. At low volume this is fine. At high volume (millions of claims/day across many producers) two problems emerge:

1. **Repo size**: at ~200 bytes per line, a git repo approaches the 1-2 GB practical clone limit at roughly 5-10 million entries.
2. **Writer contention**: even with the log aggregator (issue #16) handling concurrent producers, the aggregator itself is still a single writer committing to git. Very high throughput may make it impossible to commit fast enough.

## The certificate transparency analogy

Certificate Transparency (RFC 6962) solved the same problem at web-PKI scale:

1. A high-throughput log backend (Trillian, Rekor) handles raw ingestion and inclusion proof issuance at speed.
2. Periodically, a **signed tree head** is published as a checkpoint to the append-only public log.
3. The public log contains checkpoint entries -- one per time window -- rather than one entry per certificate.

The inclusion proof chain is: `certificate → batch Merkle root → checkpoint Merkle root → public log history`.

## What this means for this registry

### New entry type: checkpoint

The registry entry format gains an optional `entry_type` field:

| `entry_type` | Meaning |
|---|---|
| `batch` (default, omitted) | One Merkle tree over a single producer batch. Current behavior. |
| `checkpoint` | A Merkle tree over the roots of multiple batches anchored during a time window. |

A checkpoint entry has additional fields:

```json
{
  "ts": "2026-06-23T12:00:00Z",
  "entry_type": "checkpoint",
  "merkle_root": "sha256:<root over batch roots>",
  "leaf_count": 240,
  "batch_count": 12,
  "first_batch_ts": "2026-06-23T11:00:00Z",
  "last_batch_ts": "2026-06-23T11:58:32Z",
  "producer": "trace-aggregator/1.0.0",
  "batch_id": "2026-06-23T12:00:00Z-checkpoint"
}
```

The `leaf_count` is the total number of claims across all batches in the checkpoint window.

### Two-step inclusion proof

Under the checkpoint model, an auditor verifying a claim must:

1. **Batch proof**: verify the claim is included in its batch Merkle tree (existing algorithm, unchanged).
2. **Checkpoint proof**: verify the batch root is included in the checkpoint Merkle tree.
3. **Registry proof**: verify the checkpoint entry is committed in the registry git history (existing algorithm, unchanged).

The `trace-verify` CLI will gain a `--checkpoint-proof` flag alongside `--proof` to supply the second step. The first step proof format is identical to today's.

### Backward compatibility

- Existing `batch` entries require no change to verify -- `entry_type` is optional, defaults to `batch`.
- Verifiers that do not understand `checkpoint` entries will skip them (or error, depending on configuration).
- The breaking change is in the proof artifact: a claim anchored under a checkpoint produces two proof files instead of one. This is a new proof format, not a schema change to the registry entry.

## Decision threshold

The simpler (batch-per-commit) model is adequate until:

- Daily claim volume exceeds ~50,000 claims/day across all producers, **and**
- The git repo size exceeds 500 MB, **or**
- Proof delivery SLA cannot be met with a 15-minute flush cycle.

Below those thresholds, the aggregator from issue #16 handles contention without the additional proof complexity.

## What triggers this transition

1. Run the aggregator (issue #16) in production.
2. Monitor daily claim volume and repo size.
3. When the thresholds above are hit, implement the checkpoint writer as a new mode of the aggregator (flag: `--checkpoint-interval SECONDS`).
4. Existing batch entries remain valid indefinitely; the checkpoint mode is additive.

## Implementation sketch (future work)

When implemented, the aggregator gains a second-level flush:

```
inner loop (batch flush, every 15 min):
  anchor pending claims into batch trees
  store batch roots in a "pending checkpoints" queue

outer loop (checkpoint flush, every N hours):
  take all pending batch roots
  build a checkpoint Merkle tree over them
  write one checkpoint NDJSON line to the registry
  commit to git
```

The `trace-verify` package gains `verify_checkpoint_inclusion()` and the CLI gains `--checkpoint-proof FILE`.
