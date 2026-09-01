"""Core aggregator logic: queue, batch, anchor, notify.

Thread-safety model
-------------------
A single threading.Condition wraps the mutable state (_pending, _completed,
_proof_index). The flush thread holds the lock only long enough to swap the
pending queue; the Merkle construction and file I/O happen outside the lock.
Callers in submit() wait on the condition and are woken after each flush.

Anchor-leaf canonicalization
-----------------------------
submit() defaults to the sorted-key construction, unchanged. Passing
canonicalization_id='as-transmitted' (with one raw_bytes entry per claim)
commits the anchor leaf to each claim's exact transmitted bytes instead --
the registry never re-serializes it. See docs/anchor-format.md section 0.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# CPB anchor-leaf canonicalization constructions the aggregator supports, each
# selectable per submit() call by a declared canonicalization_id
# (docs/anchor-format.md section 0). Both are first-class and permanently
# valid -- neither is a fallback for the other. Mirrors tools/anchor.py's
# ANCHOR_LEAF_CANONICALIZATIONS; duplicated here deliberately so this module
# stays self-contained (same convention as tools/verify_inclusion.py).
_CANONICALIZATION_SORTED_KEY = "sorted-key"
_CANONICALIZATION_AS_TRANSMITTED = "as-transmitted"
_ANCHOR_LEAF_CANONICALIZATIONS = frozenset(
    {_CANONICALIZATION_SORTED_KEY, _CANONICALIZATION_AS_TRANSMITTED}
)
# Unchanged from before as-transmitted was wired in here: sorted-key remains
# the default when a caller does not declare one.
_CANONICALIZATION_ID = _CANONICALIZATION_SORTED_KEY


def _canonical(claim: dict) -> bytes:
    return json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _leaf_hash(
    claim: dict,
    *,
    canonicalization_id: str = _CANONICALIZATION_ID,
    raw_bytes: bytes | None = None,
) -> bytes:
    """SHA-256(0x00 || anchor-leaf preimage), the RFC 6962 leaf hash.

    Additive, not breaking: ``_leaf_hash(claim)`` -- every existing call
    site -- returns byte-for-byte what it always has. ``canonicalization_id``
    and ``raw_bytes`` are new, keyword-only, and opt-in.

    ``as-transmitted`` commits to *raw_bytes* verbatim -- the producer's exact
    signed bytes, no re-serialization -- and requires them; there is nothing
    to re-derive at this layer, by design.
    """
    if canonicalization_id == _CANONICALIZATION_AS_TRANSMITTED:
        if raw_bytes is None:
            raise ValueError(
                "canonicalization_id='as-transmitted' requires raw_bytes "
                "(the producer's exact signed bytes) -- there is nothing to "
                "re-serialize at this layer, by design"
            )
        body = raw_bytes
    elif canonicalization_id == _CANONICALIZATION_SORTED_KEY:
        body = _canonical(claim)
    else:
        raise ValueError(
            f"unsupported canonicalization_id {canonicalization_id!r}; "
            f"registered anchor-leaf constructions: "
            f"{sorted(_ANCHOR_LEAF_CANONICALIZATIONS)}"
        )
    return hashlib.sha256(LEAF_PREFIX + body).digest()


def _node_hash(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + a + b).digest()


def _build_tree(leaves: list[bytes]) -> tuple[bytes, list[list[str]]]:
    paths: list[list[str]] = [[] for _ in leaves]
    positions = list(range(len(leaves)))
    level = list(leaves)
    while len(level) > 1:
        for i, pos in enumerate(positions):
            sib = pos ^ 1
            if sib < len(level):
                paths[i].append("sha256:" + level[sib].hex())
            positions[i] = pos // 2
        nxt = [_node_hash(level[k], level[k + 1]) for k in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0], paths


def _batch_id(claims: list[dict]) -> str:
    h = hashlib.sha256()
    for c in sorted(claims, key=_canonical):
        h.update(_canonical(c))
    return h.hexdigest()[:16]


def _now_ts() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TRACEAggregator:
    """Single-writer aggregator: collects claims, batches by producer, anchors.

    Args:
        registry_dir: path to the registry/ tree (NDJSON day files written here)
        proofs_dir: path to the proofs/ tree (proof files written here)
        flush_interval: seconds between automatic flushes (default 15 min)
        max_batch_size: trigger an early flush when pending >= this (0 = never)
        git_commit: if True, run git add + git commit after each flush
        git_cwd: working directory for git commands (default: parent of registry_dir)
    """

    def __init__(
        self,
        registry_dir: Path,
        proofs_dir: Path,
        flush_interval: float = 900.0,
        max_batch_size: int = 0,
        git_commit: bool = False,
        git_cwd: Path | None = None,
        producers_dir: Path | None = None,
        verify_signatures: bool = True,
        checkpoints_dir: Path | None = None,
        enable_mmr_checkpoints: bool = True,
        now_ts: Callable[[], str] = _now_ts,
    ) -> None:
        self._registry_dir = registry_dir
        self._proofs_dir = proofs_dir
        self._flush_interval = flush_interval
        self._max_batch_size = max_batch_size
        self._git_commit = git_commit
        self._git_cwd = git_cwd or registry_dir.parent
        self._producers_dir = producers_dir or (registry_dir.parent / "producers")
        self._verify_signatures = verify_signatures
        # Injectable clock: production uses wall-clock _now_ts; tests pass a
        # fixed clock so the registry day-file path (derived from this ts) is
        # deterministic and can straddle a checkpoint/UTC-midnight boundary
        # without failing once a day (agentrust-io/trace-registry#51 review).
        self._now_ts = now_ts

        # CLL (Checkpointed Local Log) upgrade: every anchored entry also
        # folds into one aggregator-wide append-only MMR and carries a
        # signed checkpoint proving, by math, that it honestly extends the
        # previous entry -- not merely that git history was not rewritten.
        # See aggregator/_mmr_log.py and docs/mmr-checkpoint.md.
        self._checkpoint_log = None
        if enable_mmr_checkpoints:
            from aggregator._mmr_log import CheckpointLog

            self._checkpoint_log = CheckpointLog(
                checkpoints_dir or (registry_dir.parent / "checkpoints")
            )

        # Protected by _cond
        self._pending: list[tuple[str, dict, str, bytes | None]] = []
        # (job_id, claim, canonicalization_id, raw_bytes)
        self._completed: dict[str, dict] = {}       # job_id -> result
        self._proof_index: dict[tuple[str, int], dict] = {}  # (batch_id, leaf_index) -> proof
        self._cond = threading.Condition(threading.Lock())

        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(
        self,
        claims: list[dict],
        timeout: float = 120.0,
        *,
        canonicalization_id: str = _CANONICALIZATION_ID,
        raw_bytes: list[bytes] | None = None,
    ) -> list[dict]:
        """Submit claims for anchoring; block until proofs are ready.

        Returns a list of result dicts, one per claim, each containing:
            batch_id, leaf_index, audit_path, merkle_root, ts
        Raises TimeoutError if anchoring is not complete within `timeout` seconds.

        Additive, not breaking: ``submit(claims)`` -- every existing call
        site -- keeps building leaves under ``sorted-key``, unchanged.
        ``canonicalization_id`` and ``raw_bytes`` are new, keyword-only, and
        opt-in. Passing ``canonicalization_id='as-transmitted'`` commits the
        anchor leaf to each claim's exact transmitted bytes -- no
        re-serialization -- and requires *raw_bytes*, one entry per claim in
        *claims* order; a claim submitted this way registers and verifies
        without the registry ever recomputing its bytes (docs/anchor-format.md
        section 0).
        """
        if not claims:
            return []
        if canonicalization_id not in _ANCHOR_LEAF_CANONICALIZATIONS:
            raise ValueError(
                f"unsupported canonicalization_id {canonicalization_id!r}; "
                f"registered anchor-leaf constructions: "
                f"{sorted(_ANCHOR_LEAF_CANONICALIZATIONS)}"
            )
        if canonicalization_id == _CANONICALIZATION_AS_TRANSMITTED:
            if raw_bytes is None or len(raw_bytes) != len(claims):
                raise ValueError(
                    "canonicalization_id='as-transmitted' requires one "
                    "raw_bytes entry per claim -- there is nothing to "
                    "re-serialize at this layer, by design"
                )
        job_ids = [uuid.uuid4().hex for _ in claims]
        with self._cond:
            for i, (jid, claim) in enumerate(zip(job_ids, claims)):
                rb = raw_bytes[i] if raw_bytes is not None else None
                self._pending.append((jid, claim, canonicalization_id, rb))
            if self._max_batch_size > 0 and len(self._pending) >= self._max_batch_size:
                self._cond.notify_all()
            deadline = time.monotonic() + timeout
            while not all(jid in self._completed for jid in job_ids):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"anchoring timed out after {timeout}s")
                self._cond.wait(timeout=min(remaining, 1.0))
            return [self._completed[jid] for jid in job_ids]

    def get_proof(self, batch_id: str, leaf_index: int) -> dict | None:
        with self._cond:
            return self._proof_index.get((batch_id, leaf_index))

    def pending_count(self) -> int:
        with self._cond:
            return len(self._pending)

    def stats(self) -> dict:
        with self._cond:
            return {
                "pending": len(self._pending),
                "completed_jobs": len(self._completed),
                "proof_index_size": len(self._proof_index),
            }

    # ------------------------------------------------------------------
    # Flush loop
    # ------------------------------------------------------------------

    def _flush_loop(self) -> None:
        while True:
            with self._cond:
                self._cond.wait(timeout=self._flush_interval)
                if not self._pending:
                    continue
                batch = list(self._pending)
                self._pending.clear()

            completed, proof_index = self._anchor_batch(batch)

            with self._cond:
                self._completed.update(completed)
                self._proof_index.update(proof_index)
                self._cond.notify_all()

    # ------------------------------------------------------------------
    # Anchoring
    # ------------------------------------------------------------------

    def _anchor_batch(
        self, batch: list[tuple[str, dict, str, bytes | None]]
    ) -> tuple[dict[str, dict], dict[tuple[str, int], dict]]:
        """Group by (producer, canonicalization_id), build Merkle trees, write
        to disk. Thread-safe (runs outside the lock). Returns (completed,
        proof_index).

        Grouping includes canonicalization_id, not just producer: a registry
        entry declares one construction for all its leaves
        (schema/registry-entry.schema.json), so claims submitted under
        different constructions -- even from the same producer in the same
        flush window -- anchor as separate batches rather than mixing.
        """
        ts = self._now_ts()
        completed: dict[str, dict] = {}
        proof_index: dict[tuple[str, int], dict] = {}

        groups: dict[tuple[str, str], list[tuple[str, dict, bytes | None]]] = {}
        for jid, claim, canon_id, raw in batch:
            producer = claim.get("producer", "__unknown__")
            groups.setdefault((producer, canon_id), []).append((jid, claim, raw))

        for (producer, canon_id), group in groups.items():
            # Fail-closed: verify every claim's signature against the producer's
            # registered key before anchoring. Reject the whole group if the
            # producer has no active registered key, or any claim's signature
            # does not verify. Rejected claims are reported back to submit()
            # so callers are not left waiting, but nothing is anchored for them.
            if self._verify_signatures:
                rejection = self._reject_reason(
                    producer, [(jid, c) for jid, c, _ in group]
                )
                if rejection is not None:
                    for jid, _, _ in group:
                        completed[jid] = {"rejected": True, "reason": rejection,
                                          "producer": producer}
                    continue

            job_ids = [jid for jid, _, _ in group]
            claims = [c for _, c, _ in group]
            raws = [r for _, _, r in group]
            b_id = _batch_id(claims)

            leaves = [
                _leaf_hash(c, canonicalization_id=canon_id, raw_bytes=r)
                for c, r in zip(claims, raws)
            ]
            root, paths = _build_tree(leaves)
            root_hex = "sha256:" + root.hex()

            entry = {
                "ts": ts,
                "merkle_root": root_hex,
                "leaf_count": len(leaves),
                "producer": producer,
                "batch_id": b_id,
                "canonicalization_id": canon_id,
            }

            if self._checkpoint_log is not None:
                cp = self._checkpoint_log.append_entry(entry, timestamp=ts)
                entry["mmr_checkpoint"] = cp.to_dict()

            self._write_registry_entry(entry, ts)
            self._write_proofs(b_id, claims, paths, ts, raw_bytes=raws)

            for i, jid in enumerate(job_ids):
                result = {
                    "batch_id": b_id,
                    "leaf_index": i,
                    "audit_path": paths[i],
                    "merkle_root": root_hex,
                    "ts": ts,
                }
                completed[jid] = result
                proof_index[(b_id, i)] = {"leaf_index": i, "audit_path": paths[i]}

        if self._git_commit and any(
            not r.get("rejected") for r in completed.values()
        ):
            self._do_git_commit(ts, sum(
                1 for r in completed.values() if not r.get("rejected")
            ))

        return completed, proof_index

    def _reject_reason(
        self, producer: str, group: list[tuple[str, dict]]
    ) -> str | None:
        """Return None if every claim in the group verifies against the
        producer's registered key, else a string reason for rejection."""
        from trace_verify._signature import verify_claim_against_registry

        for _, claim in group:
            ok, reason = verify_claim_against_registry(
                claim, producer, self._producers_dir
            )
            if not ok:
                return reason
        return None

    def _write_registry_entry(self, entry: dict, ts: str) -> None:
        date_parts = ts[:10].split("-")
        day_file = (
            self._registry_dir / date_parts[0] / date_parts[1] / (date_parts[2] + ".ndjson")
        )
        day_file.parent.mkdir(parents=True, exist_ok=True)
        with day_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _write_proofs(
        self,
        batch_id: str,
        claims: list[dict],
        paths: list[list[str]],
        ts: str,
        raw_bytes: list[bytes | None] | None = None,
    ) -> None:
        """Write one proof file per claim, named by a content hash.

        For an as-transmitted claim the stem is derived from its raw bytes,
        not ``_canonical(claim)`` -- two claims that parse to the same dict
        but were transmitted with different byte-level formatting (key
        order, whitespace) are distinct under as-transmitted and must not
        collide on the same proof filename.
        """
        date_parts = ts[:10].split("-")
        proof_dir = (
            self._proofs_dir / date_parts[0] / date_parts[1] / date_parts[2] / batch_id
        )
        proof_dir.mkdir(parents=True, exist_ok=True)
        for i, claim in enumerate(claims):
            raw = raw_bytes[i] if raw_bytes is not None else None
            stem_bytes = raw if raw is not None else _canonical(claim)
            stem = hashlib.sha256(stem_bytes).hexdigest()[:12]
            proof = {"leaf_index": i, "audit_path": paths[i]}
            (proof_dir / f"{stem}.proof.json").write_text(
                json.dumps(proof, indent=2) + "\n", encoding="utf-8"
            )

    def _do_git_commit(self, ts: str, n_claims: int) -> None:
        try:
            subprocess.run(
                ["git", "add", "registry/", "proofs/"],
                cwd=self._git_cwd, check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-m",
                 f"chore(aggregator): anchor {n_claims} claim(s) at {ts} [skip ci]"],
                cwd=self._git_cwd, check=True, capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            # Log but do not crash the aggregator -- proofs are already in memory
            print(f"warning: git commit failed: {exc.stderr.decode()}", flush=True)
