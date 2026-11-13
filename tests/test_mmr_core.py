# SPDX-License-Identifier: Apache-2.0
"""Property tests for trace_verify._mmr beyond the pinned KAT39 vector:
round-trip inclusion/consistency proofs over freshly-grown trees, and basic
negative cases for the two verifiers."""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trace_verify import _mmr as core


def _digest(tag: str) -> bytes:
    return hashlib.sha256(tag.encode()).digest()


def _grow(n: int, store: core.MemoryNodeStore | None = None, start: int = 0) -> core.MemoryNodeStore:
    store = store if store is not None else core.MemoryNodeStore()
    for i in range(start, start + n):
        core.add_leaf(store, core.leaf_hash(_digest(f"entry-{i}")))
    return store


class TestPeaksAndSizes(unittest.TestCase):
    def test_node_count_matches_peaks_leaf_count(self):
        for n in range(1, 60):
            store = _grow(n)
            size = store.size()
            self.assertEqual(core.node_count(n), size)
            self.assertEqual(core.leaf_count(size), n)

    def test_invalid_size_rejected(self):
        with self.assertRaises(core.InvalidArgumentError):
            core.peaks(2)  # 2 is not a valid MMR node count (no such decomposition)

    def test_empty_root_is_zero(self):
        self.assertEqual(core.root_from_peaks([]), bytes(32))


class TestInclusionRoundTrip(unittest.TestCase):
    def test_every_leaf_verifies_at_every_size_it_has_seen(self):
        store = core.MemoryNodeStore()
        digests = [_digest(f"e{i}") for i in range(25)]
        for i, d in enumerate(digests):
            core.add_leaf(store, core.leaf_hash(d))
            size = store.size()
            root = core.root_from_peaks([store.node(p) for p in core.peaks(size)])
            for j in range(i + 1):
                proof = core.inclusion_proof(store, j, size)
                self.assertTrue(core.verify_inclusion(root, size, j, digests[j], proof))

    def test_tampered_body_digest_fails(self):
        store = _grow(10)
        size = store.size()
        root = core.root_from_peaks([store.node(p) for p in core.peaks(size)])
        proof = core.inclusion_proof(store, 3, size)
        self.assertFalse(core.verify_inclusion(root, size, 3, _digest("not-entry-3"), proof))

    def test_tampered_witness_fails(self):
        store = _grow(10)
        size = store.size()
        root = core.root_from_peaks([store.node(p) for p in core.peaks(size)])
        proof = core.inclusion_proof(store, 3, size)
        bad_witness = list(proof.witness)
        if bad_witness:
            bad_witness[0] = _digest("forged-sibling").hex()
        else:
            bad_witness = [_digest("forged-sibling").hex()]
        forged = core.InclusionProof(proof.v, proof.kind, proof.size, proof.leaf_index,
                                      tuple(bad_witness), proof.peaks_left, proof.peaks_right)
        self.assertFalse(core.verify_inclusion(root, size, 3, _digest("entry-3"), forged))

    def test_verify_inclusion_never_raises_on_garbage(self):
        garbage = core.InclusionProof(1, "inclusion", 999999, 0, ("zz",), (), ())
        self.assertFalse(core.verify_inclusion(bytes(32), 999999, 0, bytes(32), garbage))
        self.assertFalse(core.verify_inclusion(b"short", 1, 0, bytes(32), None))


class TestConsistencyRoundTrip(unittest.TestCase):
    def test_consistency_holds_across_growth(self):
        store = _grow(5)
        size_a = store.size()
        root_a = core.root_from_peaks([store.node(p) for p in core.peaks(size_a)])
        _grow(7, store=store, start=5)
        size_b = store.size()
        root_b = core.root_from_peaks([store.node(p) for p in core.peaks(size_b)])

        proof = core.consistency_proof(store, size_a, size_b)
        self.assertTrue(core.verify_consistency(root_a, size_a, root_b, size_b, proof))

    def test_consistency_same_size_is_trivially_true(self):
        store = _grow(6)
        size = store.size()
        root = core.root_from_peaks([store.node(p) for p in core.peaks(size)])
        proof = core.consistency_proof(store, size, size)
        self.assertTrue(core.verify_consistency(root, size, root, size, proof))

    def test_verify_consistency_never_raises_on_garbage(self):
        garbage = core.ConsistencyProof(1, "consistency", 5, 5, (), (), ())
        self.assertFalse(core.verify_consistency(bytes(32), 5, bytes(32), 999999, garbage))
        self.assertFalse(core.verify_consistency(b"bad", 0, b"bad", 0, None))

    def test_exact_int_and_from_dict_validation_across_mmr(self):
        from enum import IntEnum

        class FakeSize(IntEnum):
            ONE = 1

        store = _grow(4)
        size = store.size()
        root = core.root_from_peaks([store.node(p) for p in core.peaks(size)])
        inc = core.inclusion_proof(store, 0, size)
        con = core.consistency_proof(store, 1, size)

        # Positive round-trip controls
        self.assertEqual(core.InclusionProof.from_dict(inc.to_dict()), inc)
        self.assertEqual(core.ConsistencyProof.from_dict(con.to_dict()), con)

        # Booleans and IntEnum rejected where exact int is required
        for idx, bad_int in enumerate((True, False, FakeSize.ONE)):
            with self.subTest(bad_int=idx):
                with self.assertRaises(core.InvalidArgumentError):
                    core.peaks(bad_int)
                with self.assertRaises(core.InvalidArgumentError):
                    core.inclusion_proof(store, bad_int, size)
                with self.assertRaises(core.InvalidArgumentError):
                    core.inclusion_proof(store, 0, bad_int)
                with self.assertRaises(core.InvalidArgumentError):
                    core.consistency_proof(store, bad_int, size)
                with self.assertRaises(core.InvalidArgumentError):
                    core.consistency_proof(store, 1, bad_int)
                self.assertFalse(core.verify_inclusion(root, bad_int, 0, _digest("entry-0"), inc))
                self.assertFalse(core.verify_inclusion(root, size, bad_int, _digest("entry-0"), inc))
                self.assertFalse(core.verify_consistency(root, bad_int, root, size, con))
                self.assertFalse(core.verify_consistency(root, 1, root, bad_int, con))

        inc_d = inc.to_dict()
        for idx, bad_inc in enumerate(
            (
                {**inc_d, "extra": 1},
                {**inc_d, "v": True},
                {**inc_d, "v": 2},
                {**inc_d, "kind": "other"},
                {**inc_d, "size": "7"},
                {**inc_d, "leaf_index": False},
                {**inc_d, "witness": "a" * 64},
                {**inc_d, "witness": ["AA" * 32]},
            )
        ):
            with self.subTest(bad_inc=idx):
                with self.assertRaises(core.InvalidArgumentError):
                    core.InclusionProof.from_dict(bad_inc)

        con_d = con.to_dict()
        for idx, bad_con in enumerate(
            (
                {**con_d, "extra": 1},
                {**con_d, "v": True},
                {**con_d, "v": 2},
                {**con_d, "kind": "other"},
                {**con_d, "size_a": "1"},
                {**con_d, "size_b": True},
                {**con_d, "old_peaks": "a" * 64},
                {**con_d, "old_peaks": ["AA" * 32]},
                {**con_d, "witness": ["a" * 64]},
            )
        ):
            with self.subTest(bad_con=idx):
                with self.assertRaises(core.InvalidArgumentError):
                    core.ConsistencyProof.from_dict(bad_con)


if __name__ == "__main__":
    unittest.main()
