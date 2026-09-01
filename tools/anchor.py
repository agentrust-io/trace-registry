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
        [--canonicalization sorted-key|as-transmitted] [--proof-dir DIR]

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

# This tool is deliberately standalone (docs/anchor-format.md): it reimplements
# the leaf and tree math rather than importing trace_verify, so a third party
# can audit it in one file. The checkpoint path below is the one exception,
# because a second copy of MMR consistency math is exactly the kind of drift
# tools/verify_checkpoint_chain.py refuses to risk.
REPO_ROOT = Path(__file__).resolve().parents[1]

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# CPB anchor-leaf canonicalization constructions this tool supports, each
# selectable by a declared `canonicalization_id` (docs/anchor-format.md
# section 0). Both are first-class and permanently valid -- neither is a
# compatibility-only fallback for the other.
CANONICALIZATION_SORTED_KEY = "sorted-key"
CANONICALIZATION_AS_TRANSMITTED = "as-transmitted"
ANCHOR_LEAF_CANONICALIZATIONS = frozenset(
    {CANONICALIZATION_SORTED_KEY, CANONICALIZATION_AS_TRANSMITTED}
)
# Unchanged from before this construction was named: sorted-key remains the
# default when a caller does not declare one.
DEFAULT_CANONICALIZATION = CANONICALIZATION_SORTED_KEY

# Content-digest (signing) layer algorithms -- real CPB constructions, but
# never valid as an anchor-leaf canonicalization_id. Naming them here lets a
# mismatched-layer mistake (the #111 trap) fail with a specific diagnosis
# instead of a bare "unknown" error.
CONTENT_DIGEST_CANONICALIZATIONS = frozenset({"jcs"})


class UnknownCanonicalizationError(ValueError):
    """canonicalization_id does not name any registered CPB construction."""


class MismatchedCanonicalizationLayerError(ValueError):
    """canonicalization_id names a real CPB construction, but one that
    belongs to the content-digest (signing) layer, not the anchor-leaf
    layer -- the #111 trap this closes by declaration. See
    docs/anchor-format.md section 0."""


def canonical_claim_bytes(
    claim: dict,
    *,
    canonicalization_id: str = DEFAULT_CANONICALIZATION,
    raw_bytes: bytes | None = None,
) -> bytes:
    """Return the anchor-leaf preimage bytes for *claim* under *canonicalization_id*.

    Additive, not breaking: ``canonical_claim_bytes(claim)`` -- every
    existing call site -- returns byte-for-byte what it always has (the
    ``sorted-key`` construction below). ``canonicalization_id`` and
    ``raw_bytes`` are new, keyword-only, and opt-in.

    Both registered anchor-leaf constructions are first-class and permanent
    (docs/anchor-format.md section 0):

    - ``sorted-key`` (the default, unchanged): sort-keys ASCII JSON
      re-serialization of the complete signed claim.
    - ``as-transmitted``: the exact bytes as received, no re-serialization --
      offered as an option on technical merit (there is nothing to
      re-canonicalize at the anchor, so nothing to get wrong), never forced.
      Requires ``raw_bytes``; omitting it is a caller error, not a silent
      fallback to some other construction.
    """
    if canonicalization_id in CONTENT_DIGEST_CANONICALIZATIONS:
        raise MismatchedCanonicalizationLayerError(
            f"canonicalization_id {canonicalization_id!r} is a content-digest "
            "(signing) layer algorithm, not a registered anchor-leaf "
            f"construction. The anchor leaf accepts: "
            f"{sorted(ANCHOR_LEAF_CANONICALIZATIONS)}. See "
            "docs/anchor-format.md section 0."
        )
    if canonicalization_id == CANONICALIZATION_AS_TRANSMITTED:
        if raw_bytes is None:
            raise ValueError(
                "canonicalization_id='as-transmitted' requires raw_bytes "
                "(the producer's exact signed bytes) -- there is nothing to "
                "re-serialize at this layer, by design"
            )
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


def leaf_hash(
    claim: dict,
    *,
    canonicalization_id: str = DEFAULT_CANONICALIZATION,
    raw_bytes: bytes | None = None,
) -> bytes:
    """SHA-256(0x00 || canonical_claim_bytes), the RFC 6962 leaf hash.

    Additive, not breaking: see :func:`canonical_claim_bytes`.
    """
    return hashlib.sha256(
        LEAF_PREFIX
        + canonical_claim_bytes(
            claim, canonicalization_id=canonicalization_id, raw_bytes=raw_bytes
        )
    ).digest()


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


def make_entry(
    root: bytes,
    leaf_count: int,
    producer: str,
    batch_id: str,
    ts: str,
    canonicalization_id: str = DEFAULT_CANONICALIZATION,
) -> dict:
    """Assemble a registry entry object (docs/anchor-format.md section 4).

    ``canonicalization_id`` is always emitted, even for the default
    construction -- the fix this PR makes is that the construction is
    declared on every new entry, not assumed from context.
    """
    return {
        "ts": ts,
        "merkle_root": "sha256:" + root.hex(),
        "leaf_count": leaf_count,
        "producer": producer,
        "batch_id": batch_id,
        "canonicalization_id": canonicalization_id,
    }


def _load_claim(path: Path) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
        claim = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: cannot read claim {path}: {exc}")
    if not isinstance(claim, dict):
        raise SystemExit(f"error: claim {path} is not a JSON object")
    return claim, raw


def _registry_is_chained(registry_dir: Path) -> bool:
    """True if any published entry carries an mmr_checkpoint."""
    try:
        for path in registry_dir.rglob("*.ndjson"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    if isinstance(json.loads(line).get("mmr_checkpoint"), dict):
                        return True
                except json.JSONDecodeError:
                    continue
    except OSError:
        return False
    return False


def _checkpoint_and_append(
    entry: dict, registry_dir: Path, ts: str, no_checkpoint: bool
) -> None:
    """Fold the entry into the checkpoint chain and append it, in that order.

    These are one operation, not two. A checkpoint mints against the chain as
    published, so minting one and then not appending its entry, or minting twice
    before appending either, produces a chain nobody can reproduce from the
    registry. Requiring the registry directory here is what makes the printed
    entry and the published entry the same object.
    """
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import batch_anchor

    if not no_checkpoint:
        log = batch_anchor.open_checkpoint_log(registry_dir, log_id="trace-registry/v1")
        if log is None:
            raise SystemExit(
                f"error: {batch_anchor.CHECKPOINT_KEY_ENV} is not set, so this "
                "entry cannot be folded into the checkpoint chain. Set it, or "
                "pass --no-checkpoint to append an entry the chain will not cover."
            )
        entry["mmr_checkpoint"] = log.append_entry(entry, timestamp=ts).to_dict()

    year, month, day = ts[:10].split("-")
    day_file = registry_dir / year / month / (day + ".ndjson")
    day_file.parent.mkdir(parents=True, exist_ok=True)
    with day_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + chr(10))
    print(f"appended to {day_file}", file=sys.stderr)


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
    parser.add_argument("--canonicalization", default=DEFAULT_CANONICALIZATION,
                        choices=sorted(ANCHOR_LEAF_CANONICALIZATIONS),
                        help="CPB anchor-leaf construction (default: "
                             f"{DEFAULT_CANONICALIZATION}; both are permanent, "
                             "first-class options -- see docs/anchor-format.md "
                             "section 0)")
    parser.add_argument("--proof-dir", default=".", metavar="DIR",
                        help="directory for <claim-stem>.proof.json files (default: cwd)")
    parser.add_argument("--registry-dir", default=None, metavar="DIR",
                        help="registry root. Supplying it folds this entry into "
                             "the checkpoint chain AND appends it to the correct "
                             "day file, because the two must happen together. "
                             "Without it the entry is printed for you to redirect "
                             "and will sit OUTSIDE the chain.")
    parser.add_argument("--no-checkpoint", action="store_true",
                        help="with --registry-dir, append without checkpointing. "
                             "The entry will not be covered by the chain.")
    args = parser.parse_args(argv)

    claim_paths = [Path(p) for p in args.claims]
    loaded = [_load_claim(p) for p in claim_paths]
    leaves = [
        leaf_hash(claim, canonicalization_id=args.canonicalization, raw_bytes=raw)
        for claim, raw in loaded
    ]
    root, paths = build_tree(leaves)

    ts = args.ts or datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    batch_id = args.batch_id or root.hex()[:12]
    entry = make_entry(root, len(leaves), args.producer, batch_id, ts, args.canonicalization)

    proof_dir = Path(args.proof_dir)
    proof_dir.mkdir(parents=True, exist_ok=True)
    for index, claim_path in enumerate(claim_paths):
        proof = {"leaf_index": index, "audit_path": paths[index]}
        proof_path = proof_dir / (claim_path.stem + ".proof.json")
        proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {proof_path}", file=sys.stderr)

    if args.registry_dir is not None:
        _checkpoint_and_append(entry, Path(args.registry_dir), ts, args.no_checkpoint)
    elif _registry_is_chained(REPO_ROOT / "registry"):
        print(
            "WARNING: this registry publishes a checkpoint chain, and an entry "
            "appended by hand is NOT folded into it. The chain will still verify, "
            "because it only covers the entries it checkpointed, so nothing will "
            "tell you this entry is outside it. Pass --registry-dir to checkpoint "
            "and append in one step.",
            file=sys.stderr,
        )

    print(json.dumps(entry, separators=(", ", ": ")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
