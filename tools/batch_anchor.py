#!/usr/bin/env python3
"""Batch anchor pipeline for the TRACE Registry.

Scans staging/incoming/ for pending Trust Records, groups them by producer,
anchors each group as a separate Merkle batch, writes inclusion proofs to
proofs/YYYY/MM/DD/<batch_id>/, appends one NDJSON line per batch to the
registry day file, and moves processed files to staging/processed/<batch_id>/.

Idempotency guarantee: batch_id is derived deterministically from the sorted
canonical bytes of every claim in the group. Re-running on the same input
detects the existing batch_id in the registry and skips without writing.

Safe to retry after a partial failure: claims that were not yet moved to
staging/processed/ appear again on the next run and are re-processed.

Usage:
    python tools/batch_anchor.py [options]

Options:
    --staging-dir DIR   Root of the staging area (default: staging/ in repo root)
    --registry-dir DIR  Root of the registry (default: registry/ in repo root)
    --proofs-dir DIR    Root for proof output (default: proofs/ in repo root)
    --max-batch N       Maximum claims per batch; 0 = unlimited (default: 0)
    --ts ISO8601Z       Override anchoring timestamp (default: now)
    --canonicalization  Anchor-leaf construction: sorted-key (default) or
                        as-transmitted -- both first-class, see
                        docs/anchor-format.md section 0
    --dry-run           Compute and report without writing any files
    --json              Emit machine-readable JSON summary to stdout

Exit codes:
    0  All batches anchored (or nothing pending).
    1  One or more batches failed.
    2  Unrecoverable argument or I/O error.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Make the bundled trace_verify package importable for signature verification.
sys.path.insert(0, str(REPO_ROOT / "src"))

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# CPB anchor-leaf canonicalization constructions this pipeline supports, each
# selectable by a declared `canonicalization_id` (docs/anchor-format.md
# section 0). Both are first-class and permanently valid -- neither is a
# compatibility-only fallback for the other. Duplicated from anchor.py
# deliberately, for pipeline self-containment (module docstring above).
CANONICALIZATION_SORTED_KEY = "sorted-key"
CANONICALIZATION_AS_TRANSMITTED = "as-transmitted"
ANCHOR_LEAF_CANONICALIZATIONS = frozenset(
    {CANONICALIZATION_SORTED_KEY, CANONICALIZATION_AS_TRANSMITTED}
)
DEFAULT_CANONICALIZATION = CANONICALIZATION_SORTED_KEY
# Content-digest (signing) layer algorithms -- real CPB constructions, but
# never valid as an anchor-leaf canonicalization_id.
CONTENT_DIGEST_CANONICALIZATIONS = frozenset({"jcs"})


class UnknownCanonicalizationError(ValueError):
    """canonicalization_id does not name any registered CPB construction."""


class MismatchedCanonicalizationLayerError(ValueError):
    """canonicalization_id names a real CPB construction, but one that
    belongs to the content-digest (signing) layer, not the anchor-leaf
    layer -- the #111 trap this closes by declaration. See
    docs/anchor-format.md section 0."""


# ---------------------------------------------------------------------------
# Merkle tree (duplicated from anchor.py for pipeline self-containment)
# ---------------------------------------------------------------------------

def _canonical_claim_bytes(
    raw_bytes: bytes, claim: dict, canonicalization_id: str = DEFAULT_CANONICALIZATION
) -> bytes:
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
        return json.dumps(
            claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    raise UnknownCanonicalizationError(
        f"unknown canonicalization_id {canonicalization_id!r}; registered "
        f"anchor-leaf constructions: {sorted(ANCHOR_LEAF_CANONICALIZATIONS)}"
    )


def _leaf_hash(
    raw_bytes: bytes, claim: dict, canonicalization_id: str = DEFAULT_CANONICALIZATION
) -> bytes:
    return hashlib.sha256(
        LEAF_PREFIX + _canonical_claim_bytes(raw_bytes, claim, canonicalization_id)
    ).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _build_tree(leaves: list[bytes]) -> tuple[bytes, list[list[str]]]:
    if not leaves:
        raise ValueError("empty batch")
    paths: list[list[str]] = [[] for _ in leaves]
    positions = list(range(len(leaves)))
    level = list(leaves)
    while len(level) > 1:
        for i, pos in enumerate(positions):
            sibling = pos ^ 1
            if sibling < len(level):
                paths[i].append("sha256:" + level[sibling].hex())
            positions[i] = pos // 2
        next_level = [
            _node_hash(level[k], level[k + 1]) for k in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            next_level.append(level[-1])
        level = next_level
    return level[0], paths


# ---------------------------------------------------------------------------
# Staging helpers
# ---------------------------------------------------------------------------

def scan_staging(incoming_dir: Path) -> list[tuple[Path, dict, bytes]]:
    """Return (path, claim, raw_bytes) triples for all valid JSON files in incoming_dir."""
    records: list[tuple[Path, dict, bytes]] = []
    for path in sorted(incoming_dir.glob("*.json")):
        try:
            raw = path.read_bytes()
            claim = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: skipping {path.name}: {exc}", file=sys.stderr)
            continue
        if not isinstance(claim, dict):
            print(f"warning: skipping {path.name}: not a JSON object", file=sys.stderr)
            continue
        records.append((path, claim, raw))
    return records


def group_by_producer(
    records: list[tuple[Path, dict, bytes]], max_batch: int
) -> dict[str, list[tuple[Path, dict, bytes]]]:
    """Group records by the 'producer' field in each claim.

    Claims missing a 'producer' field are grouped under '__unknown__'.
    If max_batch > 0, each group is truncated to at most max_batch items.
    """
    groups: dict[str, list[tuple[Path, dict, bytes]]] = {}
    for path, claim, raw in records:
        producer = claim.get("producer", "__unknown__")
        groups.setdefault(producer, []).append((path, claim, raw))
    if max_batch > 0:
        groups = {p: items[:max_batch] for p, items in groups.items()}
    return groups


def _identity_bytes(claim: dict) -> bytes:
    """Sorted-key JSON bytes used ONLY to derive the idempotency batch_id below.

    Deliberately independent of the anchor-leaf `canonicalization_id` choice
    (`_canonical_claim_bytes`): re-running the same input under a different
    `--canonicalization` must still resolve to the same batch_id so the
    idempotency check in `is_already_anchored` keeps working either way.
    """
    return json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def batch_id_for(claims: list[dict]) -> str:
    """Deterministic batch_id: first 16 hex chars of SHA-256 over sorted canonical bytes."""
    h = hashlib.sha256()
    for claim in sorted(claims, key=_identity_bytes):
        h.update(_identity_bytes(claim))
    return h.hexdigest()[:16]


def is_already_anchored(batch_id: str, registry_dir: Path) -> bool:
    """Return True if any NDJSON file in the registry already contains batch_id."""
    for ndjson in registry_dir.rglob("*.ndjson"):
        try:
            for line in ndjson.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("batch_id") == batch_id:
                        return True
                except json.JSONDecodeError:
                    continue
        except OSError:
            continue
    return False


# ---------------------------------------------------------------------------
# Signature verification (fail-closed)
# ---------------------------------------------------------------------------

def verify_group(
    producer: str, records: list[tuple[Path, dict, bytes]], producers_dir: Path
) -> str | None:
    """Return None if every claim in the group verifies against the producer's
    registered key, else a string reason. Fail-closed: a missing key or a bad
    signature rejects the whole group so it is never anchored."""
    from trace_verify._signature import verify_claim_against_registry

    for _, claim, _ in records:
        ok, reason = verify_claim_against_registry(claim, producer, producers_dir)
        if not ok:
            return reason
    return None


# ---------------------------------------------------------------------------
# Anchoring
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Checkpoint chain
# ---------------------------------------------------------------------------

CHECKPOINT_KEY_ENV = "TRACE_CHECKPOINT_SIGNING_KEY"


def load_published_entries(registry_dir: Path) -> list[dict]:
    """Every published registry entry, in the order it was appended.

    Day files are named registry/YYYY/MM/DD.ndjson, so sorting paths sorts
    chronologically, and lines within a file are already in append order.
    """
    entries: list[dict] = []
    for path in sorted(registry_dir.rglob("*.ndjson")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
    return entries


def open_checkpoint_log(registry_dir: Path, *, log_id: str):
    """Open the registry-wide checkpoint log, resuming the published chain.

    The signing identity comes from the TRACE_CHECKPOINT_SIGNING_KEY
    environment variable (PEM). There is deliberately no on-disk fallback
    here: a scheduled run in a fresh checkout would silently generate a new
    identity, publish checkpoints under a key_id nobody has seen, and break
    the chain a witness is countersigning. No key means no checkpoint, said
    out loud, rather than a wrong one.
    """
    pem = os.environ.get(CHECKPOINT_KEY_ENV)
    if not pem:
        return None
    sys.path.insert(0, str(REPO_ROOT))
    from aggregator._mmr_log import CheckpointLog, Ed25519CheckpointSigner

    signer = Ed25519CheckpointSigner(None, pem=pem.encode("utf-8"))
    return CheckpointLog(
        None,
        log_id=log_id,
        signer=signer,
        replay_entries=load_published_entries(registry_dir),
    )


def anchor_group(
    producer: str,
    records: list[tuple[Path, dict, bytes]],
    ts: str,
    batch_id: str,
    registry_dir: Path,
    proofs_dir: Path,
    dry_run: bool,
    canonicalization_id: str = DEFAULT_CANONICALIZATION,
    checkpoint_log: object | None = None,
) -> dict:
    """Anchor one producer group. Returns a result dict with status and details."""
    leaves = [_leaf_hash(raw, claim, canonicalization_id) for _, claim, raw in records]
    root, paths = _build_tree(leaves)
    root_hex = "sha256:" + root.hex()

    entry = {
        "ts": ts,
        "merkle_root": root_hex,
        "leaf_count": len(leaves),
        "producer": producer,
        "batch_id": batch_id,
        "canonicalization_id": canonicalization_id,
    }

    # Destination paths
    date_parts = ts[:10].split("-")  # YYYY-MM-DD
    day_file = registry_dir / date_parts[0] / date_parts[1] / (date_parts[2] + ".ndjson")
    proof_batch_dir = proofs_dir / date_parts[0] / date_parts[1] / date_parts[2] / batch_id

    proof_files: list[tuple[Path, str]] = []
    for i, (claim_path, _, _raw) in enumerate(records):
        proof = {"leaf_index": i, "audit_path": paths[i]}
        proof_path = proof_batch_dir / (claim_path.stem + ".proof.json")
        proof_files.append((proof_path, json.dumps(proof, indent=2) + "\n"))

    checkpoint = None
    if checkpoint_log is not None and not dry_run:
        # Fold this entry into the registry-wide MMR and attach the signed
        # checkpoint proving it extends the previous one. Done before the
        # entry is written, because the entry we publish must be the entry
        # the checkpoint covers. entry_leaf_digest() excludes the
        # mmr_checkpoint field itself, so attaching it does not disturb the
        # leaf the checkpoint was just computed over.
        checkpoint = checkpoint_log.append_entry(entry, timestamp=ts)
        entry["mmr_checkpoint"] = checkpoint.to_dict()

    if not dry_run:
        proof_batch_dir.mkdir(parents=True, exist_ok=True)
        for proof_path, proof_content in proof_files:
            proof_path.write_text(proof_content, encoding="utf-8")

        day_file.parent.mkdir(parents=True, exist_ok=True)
        with day_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    return {
        "status": "dry_run" if dry_run else "anchored",
        "producer": producer,
        "batch_id": batch_id,
        "merkle_root": root_hex,
        "ts": ts,
        "leaf_count": len(leaves),
        "day_file": str(day_file),
        "proof_dir": str(proof_batch_dir),
        "proofs": [str(p) for p, _ in proof_files],
        "mmr_size": checkpoint.mmr_size if checkpoint is not None else None,
        "checkpoint_key_id": checkpoint.key_id if checkpoint is not None else None,
    }


def move_to_processed(
    records: list[tuple[Path, dict, bytes]],
    batch_id: str,
    processed_dir: Path,
    dry_run: bool,
) -> None:
    if dry_run:
        return
    dest = processed_dir / batch_id
    dest.mkdir(parents=True, exist_ok=True)
    for path, _, _raw in records:
        shutil.move(str(path), str(dest / path.name))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _now_ts() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Batch anchor pending Trust Records from staging/incoming/ into the registry."
    )
    parser.add_argument("--staging-dir", default=None, metavar="DIR",
                        help="staging root (default: staging/ in repo root)")
    parser.add_argument("--registry-dir", default=None, metavar="DIR",
                        help="registry root (default: registry/ in repo root)")
    parser.add_argument("--proofs-dir", default=None, metavar="DIR",
                        help="proofs output root (default: proofs/ in repo root)")
    parser.add_argument("--max-batch", type=int, default=0, metavar="N",
                        help="max claims per batch, 0=unlimited (default: 0)")
    parser.add_argument("--ts", default=None, metavar="ISO8601Z",
                        help="override anchoring timestamp (default: now)")
    parser.add_argument("--canonicalization", default=DEFAULT_CANONICALIZATION,
                        choices=sorted(ANCHOR_LEAF_CANONICALIZATIONS),
                        help="CPB anchor-leaf construction (default: "
                             f"{DEFAULT_CANONICALIZATION}; both are permanent, "
                             "first-class options -- see docs/anchor-format.md "
                             "section 0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="compute without writing any files")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit machine-readable JSON summary")
    parser.add_argument("--producers-dir", default=None, metavar="DIR",
                        help="producer key directory (default: producers/ in repo root)")
    parser.add_argument("--no-verify-signatures", action="store_true",
                        help="DANGEROUS: anchor claims without verifying producer "
                             "signatures (default: verify and reject unverified claims)")
    parser.add_argument("--log-id", default="trace-registry/v1", metavar="ID",
                        help="checkpoint chain identifier (default: trace-registry/v1)")
    parser.add_argument("--require-checkpoints", action="store_true",
                        help=f"fail if {CHECKPOINT_KEY_ENV} is unset, instead of "
                             "anchoring without a checkpoint")
    args = parser.parse_args(argv)

    staging_dir = Path(args.staging_dir) if args.staging_dir else REPO_ROOT / "staging"
    registry_dir = Path(args.registry_dir) if args.registry_dir else REPO_ROOT / "registry"
    proofs_dir = Path(args.proofs_dir) if args.proofs_dir else REPO_ROOT / "proofs"
    producers_dir = Path(args.producers_dir) if args.producers_dir else REPO_ROOT / "producers"
    incoming_dir = staging_dir / "incoming"
    processed_dir = staging_dir / "processed"

    if args.no_verify_signatures:
        print(
            "WARNING: --no-verify-signatures is set; claims will be anchored "
            "WITHOUT verifying producer signatures. Do not use in production.",
            file=sys.stderr,
        )

    if not incoming_dir.exists():
        msg = f"staging/incoming not found at {incoming_dir}"
        if args.as_json:
            print(json.dumps({"status": "no_staging_dir", "detail": msg}))
        else:
            print(msg)
        return 0

    ts = args.ts or _now_ts()
    records = scan_staging(incoming_dir)

    if not records:
        msg = "no pending records in staging/incoming"
        if args.as_json:
            print(json.dumps({"status": "nothing_to_anchor", "ts": ts}))
        else:
            print(msg)
        return 0

    groups = group_by_producer(records, args.max_batch)

    checkpoint_log = None
    if not args.dry_run:
        checkpoint_log = open_checkpoint_log(registry_dir, log_id=args.log_id)
        if checkpoint_log is None:
            msg = (
                f"{CHECKPOINT_KEY_ENV} is not set: anchoring WITHOUT signed "
                "checkpoints. Entries will carry batch inclusion proofs but "
                "nothing tying this run to the previous one."
            )
            if args.require_checkpoints:
                if args.as_json:
                    print(json.dumps({"status": "no_checkpoint_key", "detail": msg}))
                else:
                    print(f"FAIL  {msg}", file=sys.stderr)
                return 1
            print(f"WARNING: {msg}", file=sys.stderr)

    results = []
    failures = 0

    for producer, group_records in groups.items():
        claims = [c for _, c, _ in group_records]
        b_id = batch_id_for(claims)

        if not args.no_verify_signatures:
            reason = verify_group(producer, group_records, producers_dir)
            if reason is not None:
                result = {
                    "status": "rejected",
                    "producer": producer,
                    "batch_id": b_id,
                    "detail": reason,
                }
                failures += 1
                if not args.as_json:
                    print(f"REJECT {producer} batch {b_id}: {reason}", file=sys.stderr)
                results.append(result)
                continue

        if is_already_anchored(b_id, registry_dir):
            result = {
                "status": "skipped_duplicate",
                "producer": producer,
                "batch_id": b_id,
                "detail": "batch_id already in registry (idempotent skip)",
            }
            if not args.as_json:
                print(f"SKIP  {producer} batch {b_id} (already anchored)")
            results.append(result)
            continue

        try:
            result = anchor_group(
                producer, group_records, ts, b_id,
                registry_dir, proofs_dir, args.dry_run,
                canonicalization_id=args.canonicalization,
                checkpoint_log=checkpoint_log,
            )
            move_to_processed(group_records, b_id, processed_dir, args.dry_run)
            if not args.as_json:
                prefix = "DRY   " if args.dry_run else "OK    "
                print(f"{prefix}{producer} batch {b_id} ({result['leaf_count']} claims)")
        except Exception as exc:
            result = {
                "status": "failed",
                "producer": producer,
                "batch_id": b_id,
                "error": str(exc),
            }
            failures += 1
            if not args.as_json:
                print(f"FAIL  {producer} batch {b_id}: {exc}", file=sys.stderr)

        results.append(result)

    if args.as_json:
        print(json.dumps({
            "ts": ts,
            "batches": results,
            "ok": failures == 0,
            "dry_run": args.dry_run,
            "checkpoints": checkpoint_log is not None,
            "log_id": args.log_id if checkpoint_log is not None else None,
        }, indent=2))
    elif failures:
        print(f"\n{failures}/{len(results)} batch(es) failed", file=sys.stderr)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
