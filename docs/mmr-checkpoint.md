# CLL checkpoint chain: cryptographic consistency between anchoring runs

**Status: implemented.** Conforms to `draft-mih-scitt-checkpointed-local-log`
(CLL) and its companion MMR/COSE-Receipts mechanism. See
`aggregator/_mmr_log.py`, `src/trace_verify/_mmr.py`,
`src/trace_verify/_checkpoint.py`, and `tools/verify_checkpoint_chain.py`.

## The problem this solves

The registry's tamper-evidence today is git commit history: a rewrite is
only caught if an auditor kept the old commit hashes. A per-batch RFC 6962
Merkle root (`merkle_root` on each entry) proves one claim is included in
*its own* batch, but says nothing about whether the registry as a whole was
honestly extended between one anchoring run and the next. There is no
cryptographic link *between* batch N and batch N+1 -- only the social
convention that nobody rewrote git history in between.

## This is a different problem from docs/checkpoint-architecture.md

`docs/checkpoint-architecture.md` (issue #17, not yet implemented) proposes a
second-level Merkle tree over batch roots, to solve *repo-size and write-
contention at high volume* -- the Certificate Transparency "signed tree head
over a time window" pattern. It is complementary to this document, not
superseded by it, and can still be built:

| | docs/checkpoint-architecture.md (#17) | This document (CLL/MMR) |
|---|---|---|
| Problem | Repo size / writer contention at high volume | Cryptographic consistency between anchoring runs |
| Mechanism | A second Merkle tree over N batch roots per time window | An append-only MMR + signed checkpoint per entry |
| What it proves | A batch root was included in a checkpoint window | Checkpoint N+1 provably, mathematically extends checkpoint N |
| Entry cadence | One new `entry_type: checkpoint` line per time window | Every existing batch entry, unchanged cadence |
| Status | Architecture decision, not implemented | Implemented (this PR) |

Both can coexist: a future `entry_type: checkpoint` entry (#17) would itself
be just another leaf in this MMR, checkpointed the same way. Implementing
#17 is still real future work if repo size becomes the binding constraint;
implementing this document does not require it and does not block it.

## How it works

Every anchored batch entry (`aggregator/_core.py`'s existing per-batch
NDJSON write, unchanged cadence, unchanged batch Merkle root) additionally
folds as one leaf into a single, aggregator-wide, append-only **Merkle
Mountain Range (MMR)** and carries a signed **checkpoint**:

```json
{
  "v": 1,
  "kind": "mmr_checkpoint",
  "log_id": "trace-registry/v1",
  "mmr_size": 15,
  "root": "<64 hex chars>",
  "prev_size": 11,
  "prev_root": "<64 hex chars>",
  "key_id": "<64 hex chars -- raw Ed25519 public key>",
  "timestamp": "2026-08-26T00:00:00Z",
  "signature": "<128 hex chars -- Ed25519 signature>",
  "consistency_proof": {
    "v": 1, "kind": "consistency",
    "size_a": 11, "size_b": 15,
    "old_peaks": ["..."], "witness": [["..."]], "new_peaks": ["..."]
  }
}
```

attached to the same entry under `entry["mmr_checkpoint"]`
(`schema/registry-entry.schema.json`). This is additive: the entry's own
`merkle_root`/`leaf_count`/`batch_id` and the existing per-claim inclusion
proof (`trace_verify.verify_inclusion`, `tools/verify_inclusion.py`) are
completely unchanged. `entry_type: checkpoint` (the separate #17 concept
above) is unrelated and unaffected.

`mmr_size`/`root` describe the MMR's state (bagged-peaks root,
`trace_verify._mmr.root_from_peaks`) as of this entry; `prev_size`/
`prev_root` name the previous checkpoint's state; `consistency_proof` is a
real MMR consistency (extension) proof tying the two together
mathematically -- see "Why field equality is not enough" below. Checkpoints
are constant-size (a handful of 32-byte hashes, `O(log n)` in the number of
old peaks) regardless of total log volume, and each append is `O(log n)` --
no per-batch tree rebuild (`trace_verify._mmr.add_leaf` never rewrites an
existing node).

`key_id` is the signer's raw 32-byte Ed25519 public key, hex-encoded --
self-contained; a verifier needs no separate key-registry lookup to check a
checkpoint's own signature (though key *trust*, as always, is a separate,
out-of-band question -- same caveat as the existing producer-signature
scheme in `docs/anchor-format.md`).

## Why field equality is not enough

A verifier that only checks `curr.prev_size == prev.mmr_size and
curr.prev_root == prev.root` is checking that two JSON strings/integers
match -- which proves nothing, because both are simply values in a
JSON document an attacker with write access to storage can set to whatever
they like. `trace_verify._checkpoint.verify_checkpoint_link` requires, in
addition, a genuine `ConsistencyProof`
(`trace_verify._mmr.ConsistencyProof`/`verify_consistency`): it recomputes
`root_a` from the proof's own `old_peaks` and confirms it equals the real
`prev.root`, recomputes `root_b` from `new_peaks` and confirms it equals
`curr.root`, then re-derives every old peak's path into the new tree with
the production hash function and confirms it lands on the claimed new peak.
A forged pair of matching field values cannot satisfy this unless the
forger also holds the genuine intervening node data -- seeing
`tests/test_mmr_checkpoint_adversarial.py` for a live demonstration (a
forged continuation with copied `prev_size`/`prev_root` fields, backed by a
consistency proof from an entirely different, attacker-controlled tree,
passes a naive field-equality check and is rejected by the real one, with a
named reason).

## What this catches, and what it does not

Verifying the checkpoint chain alone (`trace_verify.verify_checkpoint_chain`)
catches:
- a **forged or rewritten continuation** (no genuine proof of extension);
- a **forked chain** (two checkpoints claiming the same `prev_size` with
  different `prev_root`, or a `prev_size` that never existed);
- a **non-monotonic or cross-log** checkpoint (wrong `log_id`, or `mmr_size`
  that does not strictly increase).

It does **not**, by itself, catch a quiet post-hoc edit to an
already-checkpointed entry's own content that leaves every checkpoint's
internal math untouched (nobody re-signed anything) -- that requires
cross-checking the chain against the raw entries, which
`tools/verify_checkpoint_chain.py` also does: it rebuilds the MMR from
scratch from the entries themselves (`trace_verify.entry_leaf_digest`) and
compares the recomputed root/size at each checkpoint against what that
checkpoint claims. A tampered entry changes its own leaf digest, which
propagates to every hash above it, so the recomputed root diverges from the
originally-signed one from that point forward -- caught and named at the
exact `batch_id`/`mmr_size` where it first becomes provable.

## Reference verifier

`pip install trace-verify` ships `trace_verify._mmr` and
`trace_verify._checkpoint` -- the same MMR/checkpoint algorithm this
registry's aggregator uses to produce checkpoints, reachable by any third
party independent of this repository. `tools/verify_checkpoint_chain.py` is
a CLI wrapper over that package:

```
python tools/verify_checkpoint_chain.py registry/2026/06/12.ndjson
```

Unlike `tools/verify_inclusion.py` (a deliberately hand-duplicated,
self-contained copy of the small RFC 6962 algorithm), this tool imports the
package rather than re-implementing the MMR math a second time: the
consistency-proof algorithm is intricate enough that an independently
maintained duplicate would risk silently drifting from the reference
implementation it exists to audit.

## Compatibility with capsule-emit / capsule-ledger

This is the same CLL checkpoint field set and MMR construction (leaf/
interior hash, peak bagging, consistency-proof shape) already shipped in
`capsule-emit`'s `capsule_emit.checkpoint` and `capsule-ledger`'s
`capsule_ledger.mmr`, deliberately -- not a divergent format. The hash
construction is pinned against the same 39-node MMRIVER-draft KAT vector
those packages use (`tests/test_mmr_kat39.py`), so this registry's
checkpoints are bit-for-bit compatible with that implementation lineage.
`log_id` is the one addition relative to the minimal `capsule-ledger` shape
(present in `capsule-emit`'s), naming which log a checkpoint belongs to --
relevant if this registry ever runs more than one aggregator instance.
