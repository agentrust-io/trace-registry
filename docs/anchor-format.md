# TRACE Registry Anchor Format v1

This page is a pointer. The anchor format defines exactly how the registry turns a
signed TRACE record into the fingerprint it logs, so that anyone can recompute it and
check a record's inclusion. The full definition lives in the TRACE specification
repository; this page keeps only the rule implementers most often get wrong.

**Moved. The normative document lives in the public spec repository:**
**[`trace-spec/spec/registry-anchor-v1.md`](https://github.com/agentrust-io/trace-spec/blob/main/spec/registry-anchor-v1.md)**

This file used to carry a second copy of the anchor format. That was a hazard
rather than a convenience: this repository was private at the time, so the copy that readers
of the published `trace-verify` package could actually reach was the one they
could not open, and the two copies had already begun to diverge. The public
document is now the more complete of the two, carrying the canonicalization
warning in §0, the relationship to the `transparency` claim in §6, the reference
implementations in §7 and the conformance requirements in §8.

One document, one place, and it is the one a package user can read.

## If you are here for the canonicalization rule

Canonicalization is the rule for writing a JSON record as one exact sequence of bytes,
so that two programs computing a signature or a hash over it get the same result.

TRACE uses **two different canonicalizations at two different layers and they
are not interchangeable**, which is the single most common way an implementation
of this format goes wrong:

| Layer | Canonicalization |
|---|---|
| Signing a Trust Record | RFC 8785 (JCS), per TRACE v0.2 §3.2 |
| Registry anchor leaf v1 | Sorted-key ASCII JSON, per registry-anchor-v1 §1 |

They agree on records whose keys and strings are pure ASCII and whose numbers
are integers, which is most records, which is exactly what makes the mistake
survivable in testing and fatal in production. Do not reuse the signing
canonicalizer at the leaf, or the leaf canonicalizer at the signature. See §0 of
the linked document for the three ways they diverge.

## Anchor-leaf construction is a declared, registered choice

Each registry entry says which of two byte-level methods was used to turn its records
into log entries ("leaves"), so a verifier never has to guess.

Registry entries carry a `canonicalization_id` field naming the anchor-leaf
construction used to build that entry's leaves (`schema/registry-entry.schema.json`).
Two constructions are registered, both first-class and permanently valid;
neither is a fallback or compatibility path for the other:

| `canonicalization_id` | Construction | Status |
|---|---|---|
| `sorted-key` | Sorted-key ASCII JSON (registry-anchor-v1 §1) | Default |
| `as-transmitted` | The exact signed bytes, no re-serialization | Offered on technical merit; not the default |

An entry with no `canonicalization_id` field predates this field and was built
under `sorted-key`, the only construction that existed at the time.
`tools/anchor.py`, `tools/batch_anchor.py`, and `tools/verify_inclusion.py`
all select the construction by this declared token rather than assuming one,
so a mismatched-layer request (naming a signing-layer algorithm such as `jcs`
where an anchor-leaf construction is expected) fails loudly with a named
error instead of a silent non-verify.

## Batch leaf subject

Every new batch entry declares `leaf_subject` beside `canonicalization_id`.
`envelope` denotes the producer transport envelope; `record` denotes the final
record or a direct record. The recognized transport envelope has exactly
`producer`, `trace`, and `signature`, with `trace` holding final signed record
JSON text or a signed record object. Subject and byte canonicalization are
independent; either subject supports both existing constructions.

The scheduled writer extracts the final record and declares `record`. HTTP
aggregation and manual anchoring retain their existing whole-object leaf bytes
and declare the supplied object's subject. HTTP aggregation separates subjects
into batches; manual anchoring refuses a mixed-subject batch. The marker is
written before MMR checkpoint construction and is covered by the existing entry
digest. Inclusion alone does not authenticate registry metadata; verifying the
checkpoint chain and pinning the registry key remain separate checks.

Legacy entries remain unchanged. Missing `leaf_subject` means unmarked, including
entries between the final-record change and this marker. With no retained input,
`resolve_leaf_subject(entry)` reports `unknown`. Inclusion verification accepts
one explicitly supplied retained subject file and checks exactly those bytes;
a successful proof establishes whether that retained file is an envelope or a
record. A failed legacy proof reports no established subject. Verifiers never
use timestamps to infer a subject, extract an alternate object on failure, or
try both objects. An explicit invalid marker or mismatch with the supplied file
refuses. Checkpoint/batch-of-batches entries do not use this batch-only field.
