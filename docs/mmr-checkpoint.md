# CLL checkpoint chain: cryptographic consistency between anchoring runs

Each new registry entry carries a checkpoint: a signed summary of the whole log so far,
with a proof that it only adds to the previous summary and changes nothing before it.
This page explains how that works and what it does and does not catch. It is for
auditors and anyone writing their own verifier; to just run the check, use
`trace-verify chain` (see "Reference verifier" below). As of 2026-10-07 the registry
holds two checkpoints, in `registry/2026/09/01.ndjson` and `registry/2026/09/25.ndjson`.

**Status: implemented.** MMR construction per
[`draft-mih-scitt-checkpointed-local-log-02`](https://datatracker.ietf.org/doc/html/draft-mih-scitt-checkpointed-local-log-02)
(CLL), which builds on the MMR receipts profile (`draft-bryce-cose-receipts-mmr-profile-03`,
now [`draft-ietf-scitt-receipts-mmr-profile`](https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-mmr-profile/)
in the SCITT working group). The checkpoint is in the registry's JSON form, not -02's
COSE wire form; "Conformance to CLL -02" below has the field mapping and says what is
checked. See `aggregator/_mmr_log.py`, `src/trace_verify/_mmr.py`,
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
  that does not strictly increase);
- a **change of signer** mid-chain (`key_id` differs from the previous
  checkpoint's). The format has no rotation statement, so a new key is a
  break, not a continuation. Whether the one key is the registry's is still
  the out-of-band question above: pin it with `trace-verify chain
  --registry-key HEX` or `trace-verify receipt --registry-key HEX`.
  Obtain that key independently of the entries being verified. Without a pin,
  `chain` reports the signer as `key_id` in both text and `--json` output so
  you can compare it yourself; a self-consistent chain alone does not establish
  that its signer is the registry you trust.

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
party independent of this repository. Since 0.4.0 it also ships the command:

```
trace-verify chain registry/2026/06/12.ndjson
```

`tools/verify_checkpoint_chain.py` is the same code reached from a clone, and
takes the same arguments:

```
python tools/verify_checkpoint_chain.py registry/2026/06/12.ndjson
```

Unlike `tools/verify_inclusion.py` (a deliberately hand-duplicated,
self-contained copy of the small RFC 6962 algorithm), this tool imports the
package rather than re-implementing the MMR math a second time: the
consistency-proof algorithm is intricate enough that an independently
maintained duplicate would risk silently drifting from the reference
implementation it exists to audit.

## Conformance to CLL -02

The registry's MMR construction conforms to `draft-mih-scitt-checkpointed-local-log-02`.
Its checkpoint does not use -02's wire form. It is the JSON object in "How it works",
signed with Ed25519 over a JSON digest, where -02 specifies a COSE_Sign1 with CWT claims.
A CLL or SCITT verifier cannot check a registry checkpoint as published; the mapping
below shows how the fields correspond, and the registry does not emit the COSE form.

The -02 known-answer vectors are generated from the draft text, not from any
implementation, on top of the MMR profile (`draft-bryce-cose-receipts-mmr-profile-03`,
since adopted by the SCITT working group as `draft-ietf-scitt-receipts-mmr-profile`).
`tests/test_mmr_kat39.py` runs them against `trace_verify` in CI:

- the 21-entry log at every prefix: node count, peaks, the concatenated commitment and
  its SHA-256;
- the four-checkpoint chain, mapped into the JSON shape and run through
  `verify_checkpoint_link` and `verify_checkpoint_chain`, with the consistency proofs
  `trace_verify` generates compared to the vectors';
- the negative cases.

The pinned vectors are in `tests/fixtures/cll-02/`, with the upstream commit and the
steps to refresh them. When a CLL revision changes anything the registry depends on,
refresh the vectors and the revision named here together.

### Field mapping

| -02 claim | Registry field | Note |
|---|---|---|
| `kind` = `cll-checkpoint` | `kind` = `mmr_checkpoint`, `v` = 1 | |
| `log_size` | `mmr_size` | The MMR node count, a complete size, as in -02. |
| `commitment` | `root` | -02 commits the peaks concatenated, tallest first. The registry commits the bagged root of the same peaks (`root_from_peaks`). The full peak list is `consistency_proof.new_peaks`. |
| `prev_size` | `prev_size` | 0 on a first checkpoint. |
| `prev_commitment` | `prev_root` | Empty string on a first checkpoint. |
| `issued_at` | `timestamp` | |
| `consistency_proof`: `[tree-size-1, tree-size-2, consistency-paths, right-peaks]` | `consistency_proof`: `size_a`, `size_b`, `old_peaks`, `witness`, `new_peaks` | `witness` is the consistency-paths. `old_peaks` are the peaks of `prev_commitment`. `new_peaks` are the peaks the paths reach followed by the right-peaks, which is the whole accumulator at `mmr_size`. The registry's proof is outside its signature. |
| CWT claim `sub`, the log | `log_id` | |
| COSE `kid`, `alg` -19 | `key_id`, `signature` | Raw Ed25519 key. The signature covers the JSON signing body. |
| `cadence`, `leaf_count` | not carried | `leaf_count` is `trace_verify._mmr.leaf_count(mmr_size)`. |

### Where `trace_verify` differs from -02

- **No-growth checkpoints.** -02 allows `prev_size == log_size` with the same
  commitment and no proof. `verify_consistency` accepts that case, but
  `verify_checkpoint_link` requires `mmr_size` to strictly increase. The registry adds
  a leaf per checkpoint, so it never emits one, and a chain that contains one is refused.
- **A proof on a first checkpoint.** -02 refuses it. `verify_checkpoint_chain` does not
  read the proof of a first checkpoint: it is outside the signed body and the registry
  never emits one.
- **Wire encoding.** -02 requires the commitment to be one byte string and the proof to
  be the profile's CBOR array, and refuses the earlier CBOR-array commitment and
  `size_a`/`size_b`/`old_peaks`/`witness`/`new_peaks` map. Those rules have no
  counterpart for a JSON checkpoint, whose proof is that map in JSON.

`tests/test_mmr_kat39.py` pins each difference, so changing one is a decision that
updates this list. Every other negative vector is refused by `verify_checkpoint_chain`:
a wrong `log_size`, an incomplete size, a missing, tampered, mis-sized or mis-ordered
proof, a commitment that does not extend the previous one, a skipped registration and a
per-checkpoint log identity. The `leaf_count` rule is held by the MMR layer's arithmetic,
because the registry's checkpoint has no `leaf_count`.

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
