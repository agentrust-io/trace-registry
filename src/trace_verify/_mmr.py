# SPDX-License-Identifier: Apache-2.0
"""Merkle Mountain Range (MMR) core algorithm -- the CLL append-only log.

Ported from ``capsule_emit.checkpoint.core`` / ``capsule_ledger.mmr.core``
(both Apache-2.0, same authorship lineage) so the checkpoint chain this
package verifies is bit-for-bit compatible with the CLL implementation those
packages already ship, per draft-mih-scitt-checkpointed-local-log. This is a
deliberate reuse, not a reimplementation: a divergent hash construction here
would silently produce a checkpoint format only this repository could read.

Classic flat-array MMR: 0-indexed node positions, grown strictly left to
right, interior nodes appear immediately after both of their children. This
is a published, implementation-independent accumulator design (originally
described by Peter Todd) that predates any single implementation.

Hashing scheme -- MMRIVER-draft-compatible, position-committed:
    leaf_hash     = sha256(0x00 || body_digest)
    interior_hash = sha256(be64(position + 1) || left || right)
                    where `position` is the 0-based flat-array index the new
                    interior node occupies
    root          = bagged peaks, right-to-left, NO domain-separator byte:
                    pop the two rightmost peak hashes, combine as
                    sha256(right || left), push the result back, repeat
                    until one hash remains
    root of an empty MMR = 32 zero bytes

The interior-hash construction matches the MMRIVER IETF draft as implemented
by datatrails/go-datatrails-merklelog (`mmr/add.go`, `mmr/hashwritevalue.go`
-- MIT licensed), pinned against that repo's hardcoded 39-node KAT
(`mmr/draft_kat39_test.go`; see `tests/test_mmr_kat39.py`).

Position commitment (rather than a fixed-prefix scheme with no position) is
deliberate: a position-committed interior hash can only ever be valid at the
one array position it was computed for, closing an equivocation attack a
fixed-prefix scheme does not, and it keeps this module MMRIVER-conformant.

This is an internal accumulator for one local, append-only entry log; it is
not claimed to interoperate on the wire with any external MMR implementation.
The registry's separate RFC 6962/RFC 9162 per-batch inclusion proof
(`trace_verify._verify`) is unaffected by and unrelated to this module.

Verification functions (`verify_inclusion`/`verify_consistency`) are pure,
take no reader, and never raise -- any malformed input (wrong lengths, bad
hex, wrong type) is a verification *failure* (return False), not an
exception. A verifier is a total function from (possibly adversarial) bytes
to a boolean, never a partial one.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

DIGEST_LEN = 32
MAX_MMR_SIZE = 2**50

__all__ = [
    "DIGEST_LEN",
    "MAX_MMR_SIZE",
    "InvalidArgumentError",
    "IntegrityError",
    "NodeReader",
    "NodeAppender",
    "MemoryNodeStore",
    "InclusionProof",
    "ConsistencyProof",
    "leaf_hash",
    "interior_hash",
    "root_from_peaks",
    "height_at",
    "node_count",
    "leaf_count",
    "leaf_index_to_pos",
    "pos_to_leaf_index",
    "peaks",
    "add_leaf",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
]


class InvalidArgumentError(ValueError):
    """A caller-supplied argument (size, leaf_index, digest shape) is invalid."""


class IntegrityError(RuntimeError):
    """The node store cannot answer a request that should be structurally satisfiable."""


def _assert_digest(d: bytes, what: str = "digest") -> None:
    if not isinstance(d, (bytes, bytearray)) or len(d) != DIGEST_LEN:
        raise InvalidArgumentError(f"{what} must be {DIGEST_LEN} bytes")


def _require_nonneg_int(n: int, what: str) -> None:
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise InvalidArgumentError(f"{what} must be a non-negative integer: {n}")


# -- hashing -----------------------------------------------------------------


def leaf_hash(body_digest: bytes) -> bytes:
    """leaf_hash = sha256(0x00 || body_digest)."""
    _assert_digest(body_digest, "body_digest")
    return hashlib.sha256(b"\x00" + body_digest).digest()


def interior_hash(left: bytes, right: bytes, position: int) -> bytes:
    """interior_hash = sha256(be64(position+1) || left || right)."""
    _assert_digest(left, "left")
    _assert_digest(right, "right")
    _require_nonneg_int(position, "position")
    pos_bytes = (position + 1).to_bytes(8, "big")
    return hashlib.sha256(pos_bytes + left + right).digest()


def root_from_peaks(peak_hashes: list[bytes]) -> bytes:
    """Root = binary-tree bagging of the peaks, right-to-left pairwise
    folding with NO domain-separator byte: pop the two rightmost hashes,
    combine as sha256(right || left), push the result back, repeat until
    one hash remains. Root of an empty MMR is 32 zero bytes."""
    if not peak_hashes:
        return bytes(DIGEST_LEN)
    for p in peak_hashes:
        _assert_digest(p, "peak")
    hashes = list(peak_hashes)
    while len(hashes) > 1:
        right = hashes.pop()
        left = hashes.pop()
        hashes.append(hashlib.sha256(right + left).digest())
    return hashes[0]


# -- position math -------------------------------------------------------


def height_at(pos: int) -> int:
    """Height of the node at 0-indexed position `pos` (0 = leaf level)."""
    _require_nonneg_int(pos, "pos")
    pos1 = pos + 1
    h = 0
    while 2 ** (h + 1) - 1 < pos1:
        h += 1
    while h > 0:
        size = 2 ** (h + 1) - 1
        if pos1 == size:
            return h
        left_size = 2**h - 1
        if pos1 > left_size:
            pos1 -= left_size
        h -= 1
    return 0


def node_count(leaf_count_: int) -> int:
    """nodeCount(f) = 2f - popcount(f): total node count for `f` leaves."""
    _require_nonneg_int(leaf_count_, "leaf_count")
    return 2 * leaf_count_ - bin(leaf_count_).count("1")


def peaks(size: int) -> list[int]:
    """Peak positions (left to right) of an MMR with `size` nodes.

    A valid MMR size decomposes into a strictly-decreasing sequence of
    "mountain" sizes 2^(h+1)-1 (greedy, largest-fitting first) whose heights
    strictly decrease left to right. Any size that does not decompose this
    way (e.g. an in-progress/incomplete parent) is not a valid MMR size.
    """
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size >= MAX_MMR_SIZE:
        raise InvalidArgumentError(f"invalid MMR size: {size}")
    result: list[int] = []
    remaining = size
    offset = 0
    prev_height = float("inf")
    while remaining > 0:
        h = 0
        while 2 ** (h + 2) - 1 <= remaining:
            h += 1
        if h >= prev_height:
            raise InvalidArgumentError(f"invalid MMR size (not a valid node count): {size}")
        m_size = 2 ** (h + 1) - 1
        offset += m_size
        result.append(offset - 1)
        remaining -= m_size
        prev_height = h
    return result


def leaf_count(size: int) -> int:
    """Number of leaves in an MMR of `size` nodes. Raises on an invalid size."""
    pks = peaks(size)
    return sum(2 ** height_at(p) for p in pks)


def leaf_index_to_pos(leaf_index: int) -> int:
    """Position of the nth (0-indexed) leaf: node_count(leaf_index)."""
    _require_nonneg_int(leaf_index, "leaf_index")
    pos = node_count(leaf_index)
    if pos >= MAX_MMR_SIZE:
        raise InvalidArgumentError(f"leaf_index too large: {leaf_index}")
    return pos


def pos_to_leaf_index(pos: int) -> int:
    """Inverse of leaf_index_to_pos. Raises if `pos` is not a leaf position."""
    if height_at(pos) != 0:
        raise InvalidArgumentError(f"position {pos} is not a leaf")
    return leaf_count(pos)


# -- node storage protocol + appending ---------------------------------------


class NodeReader(Protocol):
    def size(self) -> int: ...
    def node(self, pos: int) -> bytes: ...


class NodeAppender(NodeReader, Protocol):
    def append_nodes(self, hashes: list[bytes]) -> None: ...


class MemoryNodeStore:
    """In-memory MMR node store. No persistence -- callers needing durability
    across restarts back this with their own append-only file (see
    ``aggregator._mmr_log.FileNodeStore``)."""

    def __init__(self) -> None:
        self._nodes: list[bytes] = []

    def size(self) -> int:
        return len(self._nodes)

    def node(self, pos: int) -> bytes:
        try:
            return self._nodes[pos]
        except IndexError as exc:
            raise IndexError(f"no node at position {pos}") from exc

    def append_nodes(self, hashes: list[bytes]) -> None:
        self._nodes.extend(hashes)


def add_leaf(nodes: NodeAppender, leaf: bytes) -> tuple[int, list[bytes]]:
    """Append `leaf` to the MMR exposed by `nodes`.

    Writes the leaf and any newly-completed parent nodes. Returns the leaf's
    position and all nodes appended (leaf first, then parents), in append
    order. No prior node's own bytes are ever recomputed or rewritten --
    this is what makes MMR appends streaming (O(log n) per append, no
    per-batch tree rebuild).
    """
    _assert_digest(leaf, "leaf_hash")
    size = nodes.size()
    leaf_pos = size
    new_nodes: list[bytes] = [leaf]

    existing_peaks = [] if size == 0 else peaks(size)
    peak_idx = len(existing_peaks) - 1

    height = 0
    cur_hash = leaf

    while peak_idx >= 0 and height_at(existing_peaks[peak_idx]) == height:
        left_pos = existing_peaks[peak_idx]
        left_hash = nodes.node(left_pos)
        parent_pos = leaf_pos + len(new_nodes)
        parent_hash = interior_hash(left_hash, cur_hash, parent_pos)
        new_nodes.append(parent_hash)
        cur_hash = parent_hash
        height += 1
        peak_idx -= 1

    nodes.append_nodes(new_nodes)
    return leaf_pos, new_nodes


# -- proof paths ---------------------------------------------------------


@dataclass(frozen=True)
class _PathStep:
    sibling_pos: int
    target_is_right: bool  # True if the node on the path-so-far is the RIGHT child here.
    parent_pos: int  # 0-based array position of the parent node produced by this fold step.


def _find_containing_peak(pos: int, peak_positions: list[int]) -> int:
    """Index of the peak whose mountain contains `pos`, or -1."""
    for i, peak_pos in enumerate(peak_positions):
        h = height_at(peak_pos)
        m_size = 2 ** (h + 1) - 1
        start = peak_pos - m_size + 1
        if start <= pos <= peak_pos:
            return i
    return -1


def _locate_path(root_pos: int, height: int, target_pos: int) -> list[_PathStep]:
    """Bottom-up sibling path from `target_pos` up to (but excluding) the
    mountain root at `root_pos` (height `height`).

    `target_pos` need not be a leaf: `consistency_proof` walks from an *old
    peak* (which may itself be an interior node of arbitrary height) up to
    the containing new peak, so this stops as soon as the current subtree
    root reaches the target, not only when height hits 0.
    """
    top_down: list[_PathStep] = []
    cur_root = root_pos
    cur_height = height
    while cur_height > 0 and cur_root != target_pos:
        parent_pos = cur_root
        left_size = 2**cur_height - 1
        left_child_root = cur_root - left_size - 1
        right_child_root = cur_root - 1
        if target_pos <= left_child_root:
            top_down.append(_PathStep(right_child_root, False, parent_pos))
            cur_root = left_child_root
        else:
            top_down.append(_PathStep(left_child_root, True, parent_pos))
            cur_root = right_child_root
        cur_height -= 1
    top_down.reverse()
    return top_down


def _parse_digest_hex(h: object) -> bytes:
    if not isinstance(h, str):
        raise InvalidArgumentError("proof element is not a hex string")
    b = bytes.fromhex(h)
    if len(b) != DIGEST_LEN:
        raise InvalidArgumentError(f"proof element has wrong digest length: {len(b)}")
    return b


# -- inclusion -------------------------------------------------------------


@dataclass(frozen=True)
class InclusionProof:
    """Sibling hashes up to the leaf's peak, then the *other peaks* needed to
    re-bag the root. Hex-encoded so the whole shape is JSON-serializable."""

    v: int
    kind: str  # "inclusion"
    size: int
    leaf_index: int
    witness: tuple[str, ...]
    peaks_left: tuple[str, ...]
    peaks_right: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "v": self.v,
            "kind": self.kind,
            "size": self.size,
            "leaf_index": self.leaf_index,
            "witness": list(self.witness),
            "peaks_left": list(self.peaks_left),
            "peaks_right": list(self.peaks_right),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InclusionProof":
        return cls(
            v=int(d["v"]),
            kind=d["kind"],
            size=int(d["size"]),
            leaf_index=int(d["leaf_index"]),
            witness=tuple(d["witness"]),
            peaks_left=tuple(d["peaks_left"]),
            peaks_right=tuple(d["peaks_right"]),
        )


def inclusion_proof(reader: NodeReader, leaf_index: int, size: int) -> InclusionProof:
    lc = leaf_count(size)
    if not isinstance(leaf_index, int) or leaf_index < 0 or leaf_index >= lc:
        raise InvalidArgumentError(f"leaf_index out of range: {leaf_index}")
    reader_size = reader.size()
    if reader_size < size:
        raise IntegrityError(f"reader size {reader_size} is smaller than requested size {size}")

    leaf_pos = leaf_index_to_pos(leaf_index)
    pks = peaks(size)
    peak_idx = _find_containing_peak(leaf_pos, pks)
    if peak_idx == -1:
        raise IntegrityError(f"leaf position {leaf_pos} not found under any peak")
    peak_pos = pks[peak_idx]
    peak_height = height_at(peak_pos)
    path = _locate_path(peak_pos, peak_height, leaf_pos)

    witness = tuple(reader.node(step.sibling_pos).hex() for step in path)
    peaks_left = tuple(reader.node(pks[i]).hex() for i in range(peak_idx))
    peaks_right = tuple(reader.node(pks[i]).hex() for i in range(peak_idx + 1, len(pks)))

    return InclusionProof(1, "inclusion", size, leaf_index, witness, peaks_left, peaks_right)


def verify_inclusion(
    root: bytes, size: int, leaf_index: int, body_digest: bytes, proof: InclusionProof
) -> bool:
    """Pure inclusion verification. No reader, never raises."""
    try:
        _assert_digest(root, "root")
        _assert_digest(body_digest, "body_digest")
        if proof is None or proof.v != 1 or proof.kind != "inclusion":
            return False
        if proof.size != size or proof.leaf_index != leaf_index:
            return False
        if not isinstance(size, int) or size < 0 or size >= MAX_MMR_SIZE:
            return False
        if not isinstance(leaf_index, int) or leaf_index < 0:
            return False
        if (
            not isinstance(proof.witness, (list, tuple))
            or not isinstance(proof.peaks_left, (list, tuple))
            or not isinstance(proof.peaks_right, (list, tuple))
        ):
            return False

        lc = leaf_count(size)
        if leaf_index >= lc:
            return False

        leaf_pos = leaf_index_to_pos(leaf_index)
        pks = peaks(size)
        peak_idx = _find_containing_peak(leaf_pos, pks)
        if peak_idx == -1:
            return False

        peak_pos = pks[peak_idx]
        peak_height = height_at(peak_pos)
        path = _locate_path(peak_pos, peak_height, leaf_pos)

        if len(proof.witness) != len(path):
            return False
        if len(proof.peaks_left) != peak_idx:
            return False
        if len(proof.peaks_right) != len(pks) - peak_idx - 1:
            return False

        witness_bytes = [_parse_digest_hex(w) for w in proof.witness]
        peaks_left_bytes = [_parse_digest_hex(w) for w in proof.peaks_left]
        peaks_right_bytes = [_parse_digest_hex(w) for w in proof.peaks_right]

        acc = leaf_hash(body_digest)
        for step, sib in zip(path, witness_bytes):
            acc = (
                interior_hash(sib, acc, step.parent_pos)
                if step.target_is_right
                else interior_hash(acc, sib, step.parent_pos)
            )

        all_peaks = [*peaks_left_bytes, acc, *peaks_right_bytes]
        computed_root = root_from_peaks(all_peaks)
        return computed_root == root
    except Exception:
        return False


# -- consistency (range proof) ------------------------------------------------


@dataclass(frozen=True)
class ConsistencyProof:
    """Lets a verifier holding only (root_a, size_a) confirm that the MMR at
    size_b >= size_a extends it: each old peak is proven contained in the new
    MMR and re-bags to root_b. MMR nodes are write-once, so old-peak positions
    carry identical hashes in the new log -- this proof never needs to
    recompute anything about the leaves under `size_a`.

    This is the object that makes checkpoint-chain consistency a MATH
    question, not a "the two records say the same string" question: a
    verifier who trusted only ``curr.prev_root == prev.root`` field equality
    would accept any forged pair of matching strings. This proof forces the
    claimed continuation to exhibit real, structurally-embedded internal
    nodes of the actual larger tree that fold up to both the old and the new
    root -- something a party without the genuine intervening leaf data
    cannot produce (see tests/test_mmr_checkpoint_adversarial.py).
    """

    v: int
    kind: str  # "consistency"
    size_a: int
    size_b: int
    old_peaks: tuple[str, ...]
    witness: tuple[tuple[str, ...], ...]
    new_peaks: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "v": self.v,
            "kind": self.kind,
            "size_a": self.size_a,
            "size_b": self.size_b,
            "old_peaks": list(self.old_peaks),
            "witness": [list(w) for w in self.witness],
            "new_peaks": list(self.new_peaks),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ConsistencyProof":
        return cls(
            v=int(d["v"]),
            kind=d["kind"],
            size_a=int(d["size_a"]),
            size_b=int(d["size_b"]),
            old_peaks=tuple(d["old_peaks"]),
            witness=tuple(tuple(w) for w in d["witness"]),
            new_peaks=tuple(d["new_peaks"]),
        )


def consistency_proof(reader: NodeReader, size_a: int, size_b: int) -> ConsistencyProof:
    if not isinstance(size_a, int) or size_a < 0:
        raise InvalidArgumentError(f"invalid size_a: {size_a}")
    if not isinstance(size_b, int) or size_b < size_a:
        raise InvalidArgumentError(f"invalid size_b: {size_b} (must be >= size_a={size_a})")
    reader_size = reader.size()
    if reader_size < size_b:
        raise IntegrityError(f"reader size {reader_size} is smaller than requested size_b {size_b}")

    old_peak_positions = peaks(size_a)
    new_peak_positions = peaks(size_b)

    old_peaks: list[str] = []
    witness: list[tuple[str, ...]] = []

    for p in old_peak_positions:
        h = reader.node(p)
        old_peaks.append(h.hex())

        containing_idx = _find_containing_peak(p, new_peak_positions)
        if containing_idx == -1:
            raise IntegrityError(f"old peak at position {p} not found in new MMR of size {size_b}")
        new_peak_pos = new_peak_positions[containing_idx]
        new_peak_height = height_at(new_peak_pos)
        path = _locate_path(new_peak_pos, new_peak_height, p)

        w = tuple(reader.node(step.sibling_pos).hex() for step in path)
        witness.append(w)

    new_peaks = tuple(reader.node(p).hex() for p in new_peak_positions)

    return ConsistencyProof(1, "consistency", size_a, size_b, tuple(old_peaks), tuple(witness), new_peaks)


def verify_consistency(
    root_a: bytes, size_a: int, root_b: bytes, size_b: int, proof: ConsistencyProof
) -> bool:
    """Pure consistency verification. No reader, never raises.

    This is the REAL check: it recomputes ``root_a`` from ``proof.old_peaks``
    and ``root_b`` from ``proof.new_peaks``, then re-derives every old peak's
    path up into the new tree with the production ``interior_hash`` and
    confirms it lands on the claimed new peak. Field equality between two
    checkpoint records' ``prev_root``/``root`` strings is NOT this check and
    is not a substitute for it -- see ``ConsistencyProof``'s docstring.
    """
    try:
        _assert_digest(root_a, "root_a")
        _assert_digest(root_b, "root_b")
        if proof is None or proof.v != 1 or proof.kind != "consistency":
            return False
        if proof.size_a != size_a or proof.size_b != size_b:
            return False
        if not isinstance(size_a, int) or size_a < 0:
            return False
        if not isinstance(size_b, int) or size_b < size_a:
            return False
        if (
            not isinstance(proof.old_peaks, (list, tuple))
            or not isinstance(proof.new_peaks, (list, tuple))
            or not isinstance(proof.witness, (list, tuple))
        ):
            return False

        old_peak_positions = peaks(size_a)
        new_peak_positions = peaks(size_b)

        if len(proof.old_peaks) != len(old_peak_positions):
            return False
        if len(proof.new_peaks) != len(new_peak_positions):
            return False
        if len(proof.witness) != len(old_peak_positions):
            return False

        old_peaks_bytes = [_parse_digest_hex(w) for w in proof.old_peaks]
        new_peaks_bytes = [_parse_digest_hex(w) for w in proof.new_peaks]

        computed_root_a = root_from_peaks(old_peaks_bytes)
        if computed_root_a != root_a:
            return False
        computed_root_b = root_from_peaks(new_peaks_bytes)
        if computed_root_b != root_b:
            return False

        for i, p in enumerate(old_peak_positions):
            containing_idx = _find_containing_peak(p, new_peak_positions)
            if containing_idx == -1:
                return False

            new_peak_pos = new_peak_positions[containing_idx]
            new_peak_height = height_at(new_peak_pos)
            path = _locate_path(new_peak_pos, new_peak_height, p)

            w = proof.witness[i]
            if not isinstance(w, (list, tuple)) or len(w) != len(path):
                return False
            w_bytes = [_parse_digest_hex(x) for x in w]

            acc = old_peaks_bytes[i]
            for step, sib in zip(path, w_bytes):
                acc = (
                    interior_hash(sib, acc, step.parent_pos)
                    if step.target_is_right
                    else interior_hash(acc, sib, step.parent_pos)
                )
            if acc != new_peaks_bytes[containing_idx]:
                return False

        return True
    except Exception:
        return False
