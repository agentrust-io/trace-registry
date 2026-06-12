# TRACE Registry Anchor Format v1

This document is the normative specification for how TRACE Trust Records (signed
claims) are anchored into this registry and how a third party verifies, without
trusting the registry operator, that a given claim was included in an anchor.

The construction follows [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)
(Certificate Transparency) Merkle trees. A conforming verifier can be written
from this document alone; the reference tools in [`tools/`](../tools/) are one
implementation, not the definition.

## 1. Canonical claim bytes

The unit of anchoring is the COMPLETE signed claim object, signature included.
Anchoring binds the signed artifact, not a pre-signature payload: if either the
claim body or its signature changes, the anchor no longer matches.

`canonical_claim_bytes` is the canonical JSON serialization of the claim object:

- Object keys sorted lexicographically (by Unicode code point), recursively.
- Separators `","` and `":"` with no whitespace.
- Non-ASCII characters escaped (`ensure_ascii`); output encoded as ASCII bytes.
- No trailing newline.

In Python this is exactly:

```python
json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
```

Claims MUST be JSON objects. TRACE Trust Records contain only strings,
integers, booleans, nulls, arrays, and objects; claims containing non-integer
numbers are outside this profile because cross-language float serialization is
not canonical.

## 2. Leaf hash

```
leaf = SHA-256(0x00 || canonical_claim_bytes)
```

The `0x00` domain-separation prefix is the RFC 6962 leaf prefix. It prevents an
interior node from being presented as a leaf (second-preimage attack).

## 3. Merkle tree

The tree over the ordered list of leaves is the RFC 6962 Merkle Tree Hash:

- A tree of one leaf has root equal to that leaf hash.
- Interior nodes: `node = SHA-256(0x01 || left || right)` where `left` and
  `right` are the 32-byte child hashes and `0x01` is the interior prefix.
- Construction proceeds level by level over the ordered leaves: adjacent pairs
  are hashed together; when a level has an odd number of nodes, the final node
  is promoted unchanged to the next level (it is NOT duplicated). This yields
  the same tree as the RFC 6962 recursive split at the largest power of two.
- The empty batch (zero leaves) is invalid and MUST be rejected. This registry
  never anchors an empty tree.

The root is published hex-encoded, lowercase, prefixed with the algorithm:

```
sha256:<64 lowercase hex characters>
```

## 4. Registry entry format

Anchors are recorded in newline-delimited JSON files at
`registry/YYYY/MM/DD.ndjson` (UTC date of anchoring). Each line is one JSON
object with exactly these fields:

| field         | type    | meaning                                                       |
|---------------|---------|---------------------------------------------------------------|
| `ts`          | string  | Anchoring time, ISO-8601 UTC with `Z` suffix                  |
| `merkle_root` | string  | `sha256:<hex>` root of the batch tree (section 3)             |
| `leaf_count`  | integer | Number of leaves in the batch, >= 1                           |
| `producer`    | string  | Identifier of the party that produced and submitted the batch |
| `batch_id`    | string  | Producer-scoped unique identifier for the batch               |

Example:

```json
{"ts": "2026-06-12T18:30:00Z", "merkle_root": "sha256:9c4f...", "leaf_count": 1, "producer": "cmcp-gateway/0.1.0", "batch_id": "2026-06-12-001"}
```

Entries are append-only: lines are only ever added to the end of a day file,
and existing files are never rewritten. Git history is the tamper-evidence
layer; any rewrite of a published entry diverges the commit hashes that
auditors and mirrors have already observed. The machine-readable schema is
[`schema/registry-entry.schema.json`](../schema/registry-entry.schema.json)
and is enforced by CI on every line of every `registry/**/*.ndjson` file.

## 5. Inclusion proof

A producer gives each claim holder an inclusion proof:

```json
{"leaf_index": 0, "audit_path": ["sha256:<hex>", "sha256:<hex>"]}
```

- `leaf_index`: 0-based position of the claim's leaf in the batch.
- `audit_path`: the RFC 6962 audit path, ordered leaf-to-root: at each tree
  level the sibling hash needed to recompute the parent. A level where the
  node was promoted (no sibling) contributes no path element. A single-leaf
  batch has an empty `audit_path`.

### Verification algorithm

Inputs: the claim object, the proof (`leaf_index`, `audit_path`), and the
registry entry (`merkle_root`, `leaf_count`). All `sha256:<hex>` strings are
decoded to 32 raw bytes. The algorithm is the RFC 9162 inclusion-proof check:

```
1. If leaf_index >= leaf_count, reject.
2. r  = SHA-256(0x00 || canonical_claim_bytes)        # section 2
   fn = leaf_index
   sn = leaf_count - 1
3. For each p in audit_path, in order:
     a. If sn == 0, reject (path too long).
     b. If fn is odd, or fn == sn:
          r = SHA-256(0x01 || p || r)
          If fn is even:                  # fn == sn, right-edge promotion
              until fn is odd or fn == 0: fn = fn >> 1; sn = sn >> 1
        else:
          r = SHA-256(0x01 || r || p)
     c. fn = fn >> 1; sn = sn >> 1
4. Accept iff sn == 0 and r equals the entry's merkle_root.
```

Any failure (wrong root, leftover `sn`, malformed hash, out-of-range index)
means the claim is NOT proven included in that entry.

### What verification proves

A successful verification proves the exact signed claim bytes were part of the
batch whose root is committed in the public, append-only git history at the
entry's timestamp. It does not validate the claim's signature or semantics;
signature verification against the producer key is a separate TRACE step.

## 6. Reference tooling

- [`tools/anchor.py`](../tools/anchor.py): builds the tree over one or more
  claim files, emits the registry entry line and one inclusion proof per claim.
- [`tools/verify_inclusion.py`](../tools/verify_inclusion.py): standalone
  verifier (claim + proof + entry, exit 0/1). Deliberately self-contained so it
  can be copied and audited in isolation.

Both are Python 3 standard library only (`hashlib`, `json`).
