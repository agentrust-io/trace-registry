#!/usr/bin/env python3
"""Verify that a signed TRACE claim is included in a registry entry.

Standalone verifier for the format in docs/anchor-format.md. It recomputes the
claim's leaf hash and replays the inclusion proof's audit path using the
RFC 9162 inclusion-proof algorithm, then compares the result against the
merkle_root committed in the registry entry.

Deliberately self-contained (no import from anchor.py) so a third party can
audit or reimplement it in isolation. Standard library only.

Usage:
    python tools/verify_inclusion.py --claim CLAIM.json --proof PROOF.json \
        --entry ENTRY_OR_DAYFILE.ndjson [--batch-id ID]

--entry may be a single-entry JSON file or a registry day file (.ndjson); when
the file has more than one line, --batch-id selects the entry.

The registry entry's `canonicalization_id` field (docs/anchor-format.md
section 0) selects which anchor-leaf construction to recompute the claim's
leaf hash under. Entries anchored before this field existed carry none; the
vintage rule (VINTAGE_CANONICALIZATION below) infers `sorted-key` for those,
since that was the only construction that existed at the time -- it does not
infer `as-transmitted`, which is never assumed.

Exit status: 0 if the claim is proven included, 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# CPB anchor-leaf canonicalization constructions this tool supports, each
# selectable by the registry entry's declared `canonicalization_id`. Both are
# first-class and permanently valid -- neither is a compatibility-only
# fallback for the other. Duplicated from anchor.py deliberately (module
# docstring above): this verifier must be auditable in isolation.
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
# token, never as-transmitted. See docs/anchor-format.md section 0.
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


def _decode_hash(value: object) -> bytes:
    """Decode a 'sha256:<64 lowercase hex>' string to 32 raw bytes."""
    if not isinstance(value, str) or not _HASH_RE.match(value):
        raise ValueError(f"malformed hash value: {value!r}")
    return bytes.fromhex(value.split(":", 1)[1])


def verify_inclusion(
    raw_bytes: bytes, claim: dict, canonicalization_id: str,
    leaf_index: int, audit_path: list[bytes],
    leaf_count: int, merkle_root: bytes,
) -> bool:
    """Return True iff the claim's leaf is proven included under merkle_root.

    Implements the RFC 9162 section 2.1.3.2 inclusion-proof verification over
    an RFC 6962 tree (docs/anchor-format.md section 5). Raises
    UnknownCanonicalizationError / MismatchedCanonicalizationLayerError
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
            return False  # path longer than the tree height
        if fn & 1 or fn == sn:
            r = hashlib.sha256(NODE_PREFIX + p + r).digest()
            if not fn & 1:
                # Right edge of the tree: skip levels where the ancestor
                # was promoted without a sibling.
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(NODE_PREFIX + r + p).digest()
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == merkle_root


def _load_json(path: Path) -> object:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}")


def _load_entry(path: Path, batch_id: str | None) -> dict:
    """Load a registry entry from a single-entry file or an ndjson day file."""
    try:
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}")
    entries = []
    for ln in lines:
        try:
            entries.append(json.loads(ln))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"error: invalid JSON line in {path}: {exc}")
    if batch_id is not None:
        entries = [e for e in entries if isinstance(e, dict) and e.get("batch_id") == batch_id]
        if not entries:
            raise SystemExit(f"error: no entry with batch_id {batch_id!r} in {path}")
    if len(entries) != 1:
        raise SystemExit(
            f"error: {path} contains {len(entries)} entries; use --batch-id to select one"
        )
    if not isinstance(entries[0], dict):
        raise SystemExit(f"error: entry in {path} is not a JSON object")
    return entries[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a TRACE claim inclusion proof against a registry entry."
    )
    parser.add_argument("--claim", required=True, help="signed claim JSON file")
    parser.add_argument("--proof", required=True,
                        help='inclusion proof file: {"leaf_index": int, "audit_path": [...]}')
    parser.add_argument("--entry", required=True,
                        help="registry entry file (single JSON object or .ndjson day file)")
    parser.add_argument("--batch-id", default=None,
                        help="select the entry with this batch_id from a multi-line day file")
    args = parser.parse_args(argv)

    try:
        claim_raw = Path(args.claim).read_bytes()
        claim = json.loads(claim_raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: cannot read {args.claim}: {exc}")
    proof = _load_json(Path(args.proof))
    entry = _load_entry(Path(args.entry), args.batch_id)

    try:
        if not isinstance(claim, dict):
            raise ValueError("claim is not a JSON object")
        if not isinstance(proof, dict):
            raise ValueError("proof is not a JSON object")
        raw_path = proof.get("audit_path")
        if not isinstance(raw_path, list):
            raise ValueError("proof.audit_path must be a list")
        audit_path = [_decode_hash(h) for h in raw_path]
        merkle_root = _decode_hash(entry.get("merkle_root"))
        canonicalization_id = entry.get("canonicalization_id", VINTAGE_CANONICALIZATION)
        ok = verify_inclusion(
            claim_raw,
            claim,
            canonicalization_id,
            proof.get("leaf_index"),
            audit_path,
            entry.get("leaf_count"),
            merkle_root,
        )
    except ValueError as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if ok:
        print(
            f"OK: claim is included in batch {entry.get('batch_id')!r} "
            f"(root {entry.get('merkle_root')}, ts {entry.get('ts')}, "
            f"canonicalization_id {canonicalization_id!r})"
        )
        return 0
    print("FAIL: inclusion proof does not verify against the registry entry",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
