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


def canonical_claim_bytes(claim: dict) -> bytes:
    """Canonical JSON bytes of a signed claim object (anchor-format.md section 1)."""
    if not isinstance(claim, dict):
        raise ValueError("claim must be a JSON object")
    return json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def decode_hash(value: object) -> bytes:
    """Decode a 'sha256:<64 lowercase hex>' string to 32 raw bytes."""
    if not isinstance(value, str) or not _HASH_RE.match(value):
        raise ValueError(f"malformed hash value: {value!r}")
    return bytes.fromhex(value.split(":", 1)[1])


def verify_inclusion(
    claim: dict,
    leaf_index: int,
    audit_path: list[bytes],
    leaf_count: int,
    merkle_root: bytes,
) -> bool:
    """Return True iff the claim's leaf is proven included under merkle_root.

    Implements RFC 9162 s2.1.3.2 over an RFC 6962 tree (anchor-format.md s5).
    """
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        return False
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool):
        return False
    if leaf_index < 0 or leaf_count < 1 or leaf_index >= leaf_count:
        return False

    r = hashlib.sha256(LEAF_PREFIX + canonical_claim_bytes(claim)).digest()
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
