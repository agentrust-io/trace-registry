# SPDX-License-Identifier: Apache-2.0
"""Signed MMR checkpoint chain: the CLL (Checkpointed Local Log) upgrade.

Per-batch anchoring (``trace_verify._verify``, RFC 6962/9162) proves a single
claim is included in the batch it was anchored with. It says nothing about
whether the registry as a whole was honestly extended between one anchoring
run and the next -- that guarantee came only from git commit history, which
is a social anchor: a rewrite is only caught if an auditor kept the old
commit hashes around.

A *checkpoint* closes that gap. Every registry entry, in addition to its own
batch Merkle root, commits a signed snapshot of one running MMR log's peak
set: ``{v, kind, log_id, mmr_size, root, prev_size, prev_root, key_id,
timestamp, signature}`` (the CLL shape ratified across ``capsule-emit`` and
``capsule-ledger`` -- this module intentionally uses the identical field set,
not a divergent one, per draft-mih-scitt-checkpointed-local-log). Checkpoint
N+1 also carries an MMR ``ConsistencyProof`` (``trace_verify._mmr
.ConsistencyProof``) proving, by math, that its tree structurally extends
checkpoint N's tree -- not merely that the two records' ``prev_root``/``root``
strings happen to match. See ``verify_checkpoint_link`` below and
``tests/test_mmr_checkpoint_adversarial.py`` for why field equality alone is
not this proof.

``key_id`` is the signer's raw 32-byte Ed25519 public key, hex-encoded --
the same self-contained convention capsule-emit uses (no separate key
registry lookup needed to verify a checkpoint's signature).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from trace_verify import _mmr

__all__ = [
    "CHECKPOINT_KIND",
    "CheckpointError",
    "RollbackError",
    "CheckpointRecord",
    "entry_leaf_digest",
    "verify_checkpoint_signature_offline",
    "verify_checkpoint_link",
    "verify_checkpoint_chain",
]

CHECKPOINT_KIND = "mmr_checkpoint"


def entry_leaf_digest(entry: dict) -> bytes:
    """The MMR leaf body_digest for one registry entry: sha256 of the
    entry's own canonical JSON (sorted keys, ASCII, no whitespace), computed
    over every field EXCEPT ``mmr_checkpoint`` itself -- a checkpoint can
    never cover its own field, only the batch fields it is checkpointing.

    Single source of truth for this leaf construction: the aggregator
    (``aggregator._mmr_log.CheckpointLog.append_entry``) and any external
    verifier (``tools/verify_checkpoint_chain.py``) both call this function
    rather than each re-deriving the same bytes, so the two sides cannot
    silently drift apart.
    """
    body = {k: v for k, v in entry.items() if k != "mmr_checkpoint"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).digest()


class CheckpointError(RuntimeError):
    """A checkpoint operation failed for a non-integrity reason."""


class RollbackError(RuntimeError):
    """A checkpoint is inconsistent with its claimed predecessor."""


@dataclass
class CheckpointRecord:
    """A signed snapshot of one log's MMR peak set at ``mmr_size``.

    ``signature`` covers the signing body (every field below except
    ``signature`` and ``consistency_proof``, serialised as deterministic
    JSON). ``consistency_proof`` is ``None`` only for the first checkpoint of
    a log (``prev_size == 0``); every later checkpoint MUST carry one.
    """

    v: int
    kind: str
    log_id: str
    mmr_size: int
    root: str  # hex: root_from_peaks at mmr_size (32B)
    prev_size: int  # 0 for the first checkpoint
    prev_root: str  # hex root at prev_size; empty string for the first checkpoint
    key_id: str  # raw Ed25519 public key, hex-encoded
    timestamp: str  # ISO 8601 UTC
    signature: str  # hex Ed25519 signature over signing_body
    consistency_proof: _mmr.ConsistencyProof | None = field(default=None)

    def signing_body(self) -> str:
        """Canonical JSON over the fields covered by the signature."""
        body = {
            "v": self.v,
            "kind": self.kind,
            "log_id": self.log_id,
            "mmr_size": self.mmr_size,
            "root": self.root,
            "prev_size": self.prev_size,
            "prev_root": self.prev_root,
            "key_id": self.key_id,
            "timestamp": self.timestamp,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """64-char lowercase hex: sha256 of the signing body (UTF-8 encoded)."""
        return hashlib.sha256(self.signing_body().encode()).hexdigest()

    def to_dict(self) -> dict:
        d = {
            "v": self.v,
            "kind": self.kind,
            "log_id": self.log_id,
            "mmr_size": self.mmr_size,
            "root": self.root,
            "prev_size": self.prev_size,
            "prev_root": self.prev_root,
            "key_id": self.key_id,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }
        if self.consistency_proof is not None:
            d["consistency_proof"] = self.consistency_proof.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CheckpointRecord":
        cp = d.get("consistency_proof")
        return cls(
            v=int(d["v"]),
            kind=d["kind"],
            log_id=d["log_id"],
            mmr_size=int(d["mmr_size"]),
            root=d["root"],
            prev_size=int(d["prev_size"]),
            prev_root=d.get("prev_root", ""),
            key_id=d["key_id"],
            timestamp=d["timestamp"],
            signature=d["signature"],
            consistency_proof=_mmr.ConsistencyProof.from_dict(cp) if cp is not None else None,
        )


def verify_checkpoint_signature_offline(cp: CheckpointRecord) -> bool:
    """Verify ``cp.signature`` using ONLY ``cp`` itself -- no network, no
    external key registry. Reconstructs the Ed25519 public key straight from
    ``cp.key_id`` (raw public key, hex-encoded) and verifies ``cp.signature``
    over ``cp.digest()``. Proves "the holder of this key signed this exact
    checkpoint"; does not prove who that key belongs to. Never raises -- any
    malformed input is a verification failure.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp.key_id))
        public_key.verify(bytes.fromhex(cp.signature), cp.digest().encode("ascii"))
        return True
    except Exception:
        return False


def verify_checkpoint_link(prev: CheckpointRecord, curr: CheckpointRecord) -> tuple[bool, str]:
    """The REAL consistency check between two adjacent checkpoints.

    Returns ``(ok, reason)`` -- never raises. ``reason`` is empty on success
    and a specific, named failure description on rejection, so a chain
    verifier can report exactly which checkpoint transition broke rather
    than a bare boolean.

    Deliberately more than field comparison. A verifier that only checked
    ``curr.prev_size == prev.mmr_size and curr.prev_root == prev.root`` would
    accept ANY pair of records whose four numbers/strings happen to match --
    including a `curr` built over an entirely different, rewritten tree that
    was never actually derived from `prev`'s tree, so long as whoever forged
    it copied the four field values across (see
    ``tests/test_mmr_checkpoint_adversarial.py`` for a live demonstration
    that this is a real, exploitable gap, not a hypothetical one). The fix is
    requiring `curr.consistency_proof` -- an ``_mmr.ConsistencyProof`` -- and
    verifying it with `_mmr.verify_consistency`, which recomputes both roots
    from the peaks the proof itself supplies and re-derives every old peak's
    path into the new tree with the production hash function. A forged or
    fabricated proof fails that recomputation with overwhelming probability;
    it cannot be satisfied by copying field values alone.
    """
    if curr.log_id != prev.log_id:
        return False, f"log_id mismatch: prev={prev.log_id!r} curr={curr.log_id!r}"
    if curr.mmr_size <= prev.mmr_size:
        return False, (
            f"non-monotonic mmr_size: prev.mmr_size={prev.mmr_size} "
            f"curr.mmr_size={curr.mmr_size} (must strictly increase)"
        )
    if curr.prev_size != prev.mmr_size:
        return False, (
            f"forked chain: curr.prev_size={curr.prev_size} does not match "
            f"prev.mmr_size={prev.mmr_size} -- curr does not claim to "
            "descend from prev at all"
        )
    if curr.prev_root != prev.root:
        return False, (
            f"forked chain: curr.prev_root={curr.prev_root!r} does not match "
            f"prev.root={prev.root!r} at the same prev_size={prev.mmr_size} -- "
            "two different histories claim the same size"
        )
    if curr.consistency_proof is None:
        return False, (
            "no consistency_proof on curr -- field equality of prev_root/"
            "prev_size is NOT sufficient evidence of an honest extension; "
            "a real MMR consistency proof is required"
        )
    try:
        root_a = bytes.fromhex(prev.root)
        root_b = bytes.fromhex(curr.root)
    except ValueError as exc:
        return False, f"malformed root hex: {exc}"
    ok = _mmr.verify_consistency(root_a, prev.mmr_size, root_b, curr.mmr_size, curr.consistency_proof)
    if not ok:
        return False, (
            f"MMR consistency proof does not verify between mmr_size="
            f"{prev.mmr_size} (root={prev.root}) and mmr_size={curr.mmr_size} "
            f"(root={curr.root}) -- the claimed extension is not "
            "cryptographically genuine (rewritten history, omitted entries, "
            "or a forged proof)"
        )
    if not verify_checkpoint_signature_offline(curr):
        return False, f"checkpoint signature does not verify at mmr_size={curr.mmr_size}"
    return True, ""


def verify_checkpoint_chain(
    checkpoints: list[CheckpointRecord],
) -> tuple[bool, list[str]]:
    """Walk a sequence of checkpoints (oldest first) and verify every link.

    Returns ``(ok, errors)``. ``ok`` is True iff every checkpoint's own
    signature verifies AND every adjacent pair passes
    ``verify_checkpoint_link``. Each entry in ``errors`` names the exact
    checkpoint transition (by ``mmr_size``/``timestamp``) that failed, so a
    tampered mid-stream entry is reported at the checkpoint boundary where
    the break becomes provable -- not as an undifferentiated "verification
    failed". Never raises.
    """
    if not checkpoints:
        return True, []

    errors: list[str] = []

    first = checkpoints[0]
    if first.prev_size == 0:
        if not verify_checkpoint_signature_offline(first):
            errors.append(f"checkpoint signature does not verify at mmr_size={first.mmr_size}")
    else:
        # Chain segment starts mid-log (caller supplied a suffix); at least
        # verify its own signature so a garbage first element is still caught.
        if not verify_checkpoint_signature_offline(first):
            errors.append(f"checkpoint signature does not verify at mmr_size={first.mmr_size}")

    for prev, curr in zip(checkpoints, checkpoints[1:]):
        ok, reason = verify_checkpoint_link(prev, curr)
        if not ok:
            errors.append(
                f"chain broken between checkpoint mmr_size={prev.mmr_size} "
                f"(ts={prev.timestamp}) and mmr_size={curr.mmr_size} "
                f"(ts={curr.timestamp}): {reason}"
            )

    return not errors, errors
