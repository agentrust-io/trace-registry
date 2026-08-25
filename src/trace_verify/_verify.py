"""Core TRACE inclusion-proof verification algorithm.

Implements the RFC 6962 Merkle tree and RFC 9162 inclusion-proof check
as specified in docs/anchor-format.md. Standard library only.

This module is the single source of truth for the algorithm. The standalone
script tools/verify_inclusion.py in the repository is an auditable copy of
this same logic kept in sync for third parties who want to inspect or
reimplement it without installing the package.
"""

from __future__ import annotations

import hashlib
import json
import re

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

ANCHOR_FORMAT_VERSION = 1

# CPB anchor-leaf canonicalization constructions this package supports, each
# selectable by the registry entry's declared `canonicalization_id`
# (docs/anchor-format.md section 0). Both are first-class and permanently
# valid -- neither is a fallback for the other.
CANONICALIZATION_SORTED_KEY = "sorted-key"
CANONICALIZATION_AS_TRANSMITTED = "as-transmitted"
ANCHOR_LEAF_CANONICALIZATIONS = frozenset(
    {CANONICALIZATION_SORTED_KEY, CANONICALIZATION_AS_TRANSMITTED}
)
# Content-digest (signing) layer algorithms -- real CPB constructions, but
# never valid as an anchor-leaf canonicalization_id.
CONTENT_DIGEST_CANONICALIZATIONS = frozenset({"jcs"})
# Vintage rule: entries anchored before canonicalization_id existed carry no
# such field. They were all built under sorted-key -- absence infers that
# token, never as-transmitted.
VINTAGE_CANONICALIZATION = CANONICALIZATION_SORTED_KEY


class UnknownCanonicalizationError(ValueError):
    """canonicalization_id does not name any registered CPB construction."""


class MismatchedCanonicalizationLayerError(ValueError):
    """canonicalization_id names a real CPB construction, but one that
    belongs to the content-digest (signing) layer, not the anchor-leaf
    layer -- the #111 trap this closes by declaration. See
    docs/anchor-format.md section 0."""


def canonical_claim_bytes(
    raw_bytes: bytes, claim: dict, canonicalization_id: str = VINTAGE_CANONICALIZATION
) -> bytes:
    """Anchor-leaf preimage bytes for *claim* under *canonicalization_id*
    (docs/anchor-format.md section 0)."""
    if canonicalization_id in CONTENT_DIGEST_CANONICALIZATIONS:
        raise MismatchedCanonicalizationLayerError(
            f"canonicalization_id {canonicalization_id!r} is a content-digest "
            "(signing) layer algorithm, not a registered anchor-leaf "
            f"construction. The anchor leaf accepts: "
            f"{sorted(ANCHOR_LEAF_CANONICALIZATIONS)}. See "
            "docs/anchor-format.md section 0."
        )
    if canonicalization_id == CANONICALIZATION_AS_TRANSMITTED:
        return raw_bytes
    if canonicalization_id == CANONICALIZATION_SORTED_KEY:
        if not isinstance(claim, dict):
            raise ValueError("claim must be a JSON object")
        return json.dumps(
            claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    raise UnknownCanonicalizationError(
        f"unknown canonicalization_id {canonicalization_id!r}; registered "
        f"anchor-leaf constructions: {sorted(ANCHOR_LEAF_CANONICALIZATIONS)}"
    )


def decode_hash(value: object) -> bytes:
    """Decode a 'sha256:<64 lowercase hex>' string to 32 raw bytes."""
    if not isinstance(value, str) or not _HASH_RE.match(value):
        raise ValueError(f"malformed hash value: {value!r}")
    return bytes.fromhex(value.split(":", 1)[1])


def verify_inclusion(
    raw_bytes: bytes,
    claim: dict,
    canonicalization_id: str,
    leaf_index: int,
    audit_path: list[bytes],
    leaf_count: int,
    merkle_root: bytes,
) -> bool:
    """Return True iff the claim's leaf is proven included under merkle_root.

    Implements RFC 9162 s2.1.3.2 over an RFC 6962 tree (anchor-format.md s5).
    Raises UnknownCanonicalizationError / MismatchedCanonicalizationLayerError
    (both ValueError subclasses) instead of returning False when
    *canonicalization_id* itself is invalid -- a construction mismatch is a
    distinct, named failure from "the proof does not verify".
    """
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        return False
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool):
        return False
    if leaf_index < 0 or leaf_count < 1 or leaf_index >= leaf_count:
        return False

    r = hashlib.sha256(
        LEAF_PREFIX + canonical_claim_bytes(raw_bytes, claim, canonicalization_id)
    ).digest()
    fn = leaf_index
    sn = leaf_count - 1

    for p in audit_path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = hashlib.sha256(NODE_PREFIX + p + r).digest()
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(NODE_PREFIX + r + p).digest()
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == merkle_root
