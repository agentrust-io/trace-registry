#!/usr/bin/env python3
"""Reference verifier for the CLL (Checkpointed Local Log) checkpoint chain.

Unlike tools/verify_inclusion.py, this tool is a thin CLI over the
`trace_verify` package rather than a hand-duplicated standalone
implementation: the MMR consistency-proof math (trace_verify._mmr) is
intricate enough that a second, independently-maintained copy would risk
silently drifting from the reference algorithm it is supposed to audit.
`pip install trace-verify` is the reference implementation reachable by any
third party (docs/mmr-checkpoint.md); this script is a convenience wrapper
around it, not an alternate implementation.

Two independent checks are run over the registry's entries, in order:

  1. Checkpoint-chain consistency (`trace_verify.verify_checkpoint_chain`):
     for every adjacent pair of checkpoints, is there a genuine MMR
     consistency proof tying the later root back to the earlier one? This
     catches a forged, rewritten, or forked checkpoint chain even without
     access to the raw entries -- see docs/mmr-checkpoint.md and
     tests/test_mmr_checkpoint_adversarial.py.

  2. From-scratch recomputation against the raw entries: this script rebuilds
     the MMR leaf by leaf from the entries themselves (via
     `trace_verify.entry_leaf_digest`) and compares the running root/size at
     each checkpoint against what that checkpoint actually claims. This is
     the check that catches a *quiet edit to an already-anchored entry* --
     tampering that leaves every checkpoint record's own internal math
     self-consistent (nothing in the checkpoint chain itself changed) but no
     longer matches what is actually stored under it.

Usage:
    python tools/verify_checkpoint_chain.py registry/2026/06/12.ndjson [MORE...]

Exit status: 0 if every entry with an mmr_checkpoint passes both checks
(or no entry carries one), 1 otherwise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from trace_verify import _mmr as core
from trace_verify._checkpoint import CheckpointRecord, entry_leaf_digest, verify_checkpoint_chain


def _load_entries(paths: list[Path]) -> list[dict]:
    entries: list[dict] = []
    for path in paths:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"error: {path}:{lineno}: invalid JSON: {exc}")
            if not isinstance(entry, dict):
                raise SystemExit(f"error: {path}:{lineno}: entry is not a JSON object")
            entries.append(entry)
    return entries


def verify_against_raw_entries(entries: list[dict]) -> list[str]:
    """From-scratch recompute: returns a list of named errors (empty = pass)."""
    errors: list[str] = []
    store = core.MemoryNodeStore()
    checkpointed = [e for e in entries if isinstance(e.get("mmr_checkpoint"), dict)]

    for entry in checkpointed:
        cp = entry["mmr_checkpoint"]
        core.add_leaf(store, core.leaf_hash(entry_leaf_digest(entry)))
        actual_size = store.size()
        actual_root = core.root_from_peaks(
            [store.node(p) for p in core.peaks(actual_size)]
        ).hex()

        claimed_size = cp.get("mmr_size")
        claimed_root = cp.get("root")
        batch_id = entry.get("batch_id", "?")

        if actual_size != claimed_size:
            errors.append(
                f"batch_id={batch_id!r}: recomputed MMR size {actual_size} != "
                f"checkpoint's claimed mmr_size {claimed_size!r} -- an entry was "
                "omitted, duplicated, or inserted out of order"
            )
            continue
        if actual_root != claimed_root:
            errors.append(
                f"batch_id={batch_id!r} (mmr_size={claimed_size}): recomputed "
                f"root {actual_root} != checkpoint's claimed root "
                f"{claimed_root!r} -- this entry's committed content was "
                "altered after it was checkpointed"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: verify_checkpoint_chain.py REGISTRY_NDJSON [MORE...]", file=sys.stderr)
        return 2

    paths = [Path(a) for a in argv]
    entries = _load_entries(paths)
    checkpointed = [e for e in entries if isinstance(e.get("mmr_checkpoint"), dict)]

    if not checkpointed:
        print("no entries with mmr_checkpoint found; nothing to verify")
        return 0

    checkpoints = [CheckpointRecord.from_dict(e["mmr_checkpoint"]) for e in checkpointed]
    chain_ok, chain_errors = verify_checkpoint_chain(checkpoints)
    raw_errors = verify_against_raw_entries(entries)

    all_errors = chain_errors + raw_errors
    if all_errors:
        for err in all_errors:
            print(f"FAIL: {err}", file=sys.stderr)
        print(f"FAIL: {len(all_errors)} problem(s) found across {len(checkpointed)} checkpoint(s)")
        return 1

    print(
        f"OK: {len(checkpointed)} checkpoint(s) verified -- chain-consistent "
        f"and matching the raw entries (mmr_size {checkpoints[-1].mmr_size}, "
        f"root {checkpoints[-1].root})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
