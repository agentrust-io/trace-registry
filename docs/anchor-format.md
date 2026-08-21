# TRACE Registry Anchor Format v1

**Moved. The normative document lives in the public spec repository:**
**[`trace-spec/spec/registry-anchor-v1.md`](https://github.com/agentrust-io/trace-spec/blob/main/spec/registry-anchor-v1.md)**

This file used to carry a second copy of the anchor format. That was a hazard
rather than a convenience: this repository is private, so the copy that readers
of the published `trace-verify` package could actually reach was the one they
could not open, and the two copies had already begun to diverge. The public
document is now the more complete of the two, carrying the canonicalization
warning in §0, the relationship to the `transparency` claim in §6, the reference
implementations in §7 and the conformance requirements in §8.

One document, one place, and it is the one a package user can read.

## If you are here for the canonicalization rule

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
