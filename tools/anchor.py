#!/usr/bin/env python3
"""Anchor TRACE Trust Records into a registry entry.

Builds an RFC 6962 Merkle tree over one or more signed claim files and emits:

  - the registry entry (one JSON object, printed to stdout) suitable for
    appending to registry/YYYY/MM/DD.ndjson, and
  - one inclusion proof per claim, written to --proof-dir as
    <claim-stem>.proof.json.

The construction is specified normatively in docs/anchor-format.md. Standard
library only.

Usage:
    python tools/anchor.py CLAIM.json [CLAIM2.json ...] \
        --producer cmcp-gateway/0.1.0 [--batch-id ID] [--ts ISO8601Z] \
        [--proof-dir DIR]

Append the printed entry to the day file for the (UTC) anchoring date:
    python tools/anchor.py claim.json --producer p >> registry/2026/06/12.ndjson
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def canonical_claim_bytes(claim: dict) -> bytes:
    """Serialize a claim object to canonical JSON bytes (sorted keys, compact
    separators, ASCII-only). See docs/anchor-format.md section 1."""
    if not isinstance(claim, dict):
        raise ValueError("claim must be a JSON object")
    return json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def leaf_hash(claim: dict) -> bytes:
    """SHA-256(0x00 || canonical_claim_bytes), the RFC 6962 leaf hash."""
    return hashlib.sha256(LEAF_PREFIX + canonical_claim_bytes(claim)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def build_tree(leaves: list[bytes]) -> tuple[bytes, list[list[str]]]:
    """Compute the RFC 6962 Merkle root and per-leaf audit paths.

    Levels are built bottom-up; an odd trailing node is promoted unchanged to
    the next level (equivalent to the RFC 6962 recursive construction).

    Returns (root_digest, audit_paths) where audit_paths[i] is the ordered
    leaf-to-root list of "sha256:<hex>" sibling hashes for leaf i.

    Raises ValueError for an empty batch: an empty tree is never anchored.
    """
    if not leaves:
        raise ValueError("empty batch: refusing to anchor zero leaves")

    paths: list[list[str]] = [[] for _ in leaves]
    # positions[i] = index of leaf i's ancestor in the current level
    positions = list(range(len(leaves)))
    level = list(leaves)

    while len(level) > 1:
        for i, pos in enumerate(positions):
            sibling = pos ^ 1
            if sibling < len(level):
                paths[i].append("sha256:" + level[sibling].hex())
            # A promoted node (no sibling) contributes no path element.
            positions[i] = pos // 2
        next_level = [
            _node_hash(level[k], level[k + 1]) for k in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            next_level.append(level[-1])
        level = next_level

    return level[0], paths


def make_entry(root: bytes, leaf_count: int, producer: str, batch_id: str, ts: str) -> dict:
    """Assemble a registry entry object (docs/anchor-format.md section 4)."""
    return {
        "ts": ts,
        "merkle_root": "sha256:" + root.hex(),
        "leaf_count": leaf_count,
        "producer": producer,
        "batch_id": batch_id,
    }


def _load_claim(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as fh:
            claim = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: cannot read claim {path}: {exc}")
    if not isinstance(claim, dict):
        raise SystemExit(f"error: claim {path} is not a JSON object")
    return claim


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Anchor signed TRACE claims: emit a registry entry and inclusion proofs."
    )
    parser.add_argument("claims", nargs="+", metavar="CLAIM.json",
                        help="signed claim file(s); leaf order is argument order")
    parser.add_argument("--producer", required=True,
                        help="identifier of the party producing this batch")
    parser.add_argument("--batch-id", default=None,
                        help="producer-scoped batch id (default: first 12 hex chars of the root)")
    parser.add_argument("--ts", default=None,
                        help="anchoring timestamp, ISO-8601 UTC with Z suffix (default: now)")
    parser.add_argument("--proof-dir", default=".", metavar="DIR",
                        help="directory for <claim-stem>.proof.json files (default: cwd)")
    args = parser.parse_args(argv)

    claim_paths = [Path(p) for p in args.claims]
    leaves = [leaf_hash(_load_claim(p)) for p in claim_paths]
    root, paths = build_tree(leaves)

    ts = args.ts or datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    batch_id = args.batch_id or root.hex()[:12]
    entry = make_entry(root, len(leaves), args.producer, batch_id, ts)

    proof_dir = Path(args.proof_dir)
    proof_dir.mkdir(parents=True, exist_ok=True)
    for index, claim_path in enumerate(claim_paths):
        proof = {"leaf_index": index, "audit_path": paths[index]}
        proof_path = proof_dir / (claim_path.stem + ".proof.json")
        proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {proof_path}", file=sys.stderr)

    print(json.dumps(entry, separators=(", ", ": ")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
