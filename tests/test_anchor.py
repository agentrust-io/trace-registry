"""Tests for tools/anchor.py and tools/verify_inclusion.py.

Standard library only. Run from the repository root:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import anchor  # noqa: E402
import verify_inclusion  # noqa: E402


def _claims(n: int) -> list[dict]:
    return [{"id": i, "payload": f"claim-{i}", "signature": f"sig-{i}"} for i in range(n)]


def _decode_path(path: list[str]) -> list[bytes]:
    return [bytes.fromhex(h.split(":", 1)[1]) for h in path]


def _verify(claim: dict, index: int, path: list[str], count: int, root: bytes) -> bool:
    return verify_inclusion.verify_inclusion(claim, index, _decode_path(path), count, root)


class TestCanonicalization(unittest.TestCase):
    def test_key_order_does_not_matter(self):
        a = {"b": 1, "a": {"y": 2, "x": 3}}
        b = {"a": {"x": 3, "y": 2}, "b": 1}
        self.assertEqual(anchor.canonical_claim_bytes(a), anchor.canonical_claim_bytes(b))

    def test_compact_sorted_ascii(self):
        self.assertEqual(
            anchor.canonical_claim_bytes({"b": "é", "a": 1}),
            b'{"a":1,"b":"\\u00e9"}',
        )

    def test_non_object_claim_rejected(self):
        with self.assertRaises(ValueError):
            anchor.canonical_claim_bytes(["not", "an", "object"])

    def test_implementations_agree(self):
        claim = _claims(1)[0]
        self.assertEqual(
            anchor.canonical_claim_bytes(claim),
            verify_inclusion.canonical_claim_bytes(claim),
        )


class TestTreeConstruction(unittest.TestCase):
    def test_empty_batch_rejected(self):
        with self.assertRaises(ValueError):
            anchor.build_tree([])

    def test_single_leaf_root_is_leaf_hash(self):
        claim = _claims(1)[0]
        leaf = anchor.leaf_hash(claim)
        expected = hashlib.sha256(b"\x00" + anchor.canonical_claim_bytes(claim)).digest()
        self.assertEqual(leaf, expected)
        root, paths = anchor.build_tree([leaf])
        self.assertEqual(root, leaf)
        self.assertEqual(paths, [[]])

    def test_two_leaves_rfc6962_interior_node(self):
        claims = _claims(2)
        leaves = [anchor.leaf_hash(c) for c in claims]
        root, paths = anchor.build_tree(leaves)
        self.assertEqual(root, hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest())
        self.assertEqual(paths[0], ["sha256:" + leaves[1].hex()])
        self.assertEqual(paths[1], ["sha256:" + leaves[0].hex()])

    def test_odd_count_promotes_last_node(self):
        # RFC 6962 recursion for n=3: H(H(a,b), c), with c promoted, not duplicated.
        leaves = [anchor.leaf_hash(c) for c in _claims(3)]
        ab = hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest()
        expected_root = hashlib.sha256(b"\x01" + ab + leaves[2]).digest()
        root, paths = anchor.build_tree(leaves)
        self.assertEqual(root, expected_root)
        # The promoted leaf's path skips the level where it had no sibling.
        self.assertEqual(paths[2], ["sha256:" + ab.hex()])


class TestInclusionProofs(unittest.TestCase):
    def test_all_leaves_verify_for_sizes_1_through_9(self):
        for n in range(1, 10):
            claims = _claims(n)
            root, paths = anchor.build_tree([anchor.leaf_hash(c) for c in claims])
            for i, claim in enumerate(claims):
                with self.subTest(leaf_count=n, leaf_index=i):
                    self.assertTrue(_verify(claim, i, paths[i], n, root))

    def test_tampered_claim_fails(self):
        claims = _claims(4)
        root, paths = anchor.build_tree([anchor.leaf_hash(c) for c in claims])
        tampered = dict(claims[2], payload="claim-2-tampered")
        self.assertFalse(_verify(tampered, 2, paths[2], 4, root))
        # Tampering the signature alone also breaks the anchor.
        resigned = dict(claims[2], signature="forged")
        self.assertFalse(_verify(resigned, 2, paths[2], 4, root))

    def test_tampered_audit_path_fails(self):
        claims = _claims(5)
        root, paths = anchor.build_tree([anchor.leaf_hash(c) for c in claims])
        bad = list(paths[1])
        bad[0] = "sha256:" + "ab" * 32
        self.assertFalse(_verify(claims[1], 1, bad, 5, root))

    def test_wrong_leaf_index_fails(self):
        claims = _claims(4)
        root, paths = anchor.build_tree([anchor.leaf_hash(c) for c in claims])
        self.assertFalse(_verify(claims[0], 1, paths[0], 4, root))
        self.assertFalse(_verify(claims[0], -1, paths[0], 4, root))
        self.assertFalse(_verify(claims[0], 4, paths[0], 4, root))

    def test_truncated_and_extended_paths_fail(self):
        claims = _claims(4)
        root, paths = anchor.build_tree([anchor.leaf_hash(c) for c in claims])
        self.assertFalse(_verify(claims[0], 0, paths[0][:-1], 4, root))
        self.assertFalse(_verify(claims[0], 0, paths[0] + paths[0][:1], 4, root))

    def test_wrong_leaf_count_fails(self):
        claims = _claims(3)
        root, paths = anchor.build_tree([anchor.leaf_hash(c) for c in claims])
        self.assertFalse(_verify(claims[2], 2, paths[2], 4, root))
        self.assertFalse(_verify(claims[2], 2, paths[2], 0, root))


class TestEntryFormat(unittest.TestCase):
    def test_make_entry_fields(self):
        root, _ = anchor.build_tree([anchor.leaf_hash(c) for c in _claims(2)])
        entry = anchor.make_entry(root, 2, "cmcp-gateway/0.1.0", "b-1", "2026-06-12T00:00:00Z")
        self.assertEqual(
            sorted(entry), ["batch_id", "leaf_count", "merkle_root", "producer", "ts"]
        )
        self.assertEqual(entry["merkle_root"], "sha256:" + root.hex())
        self.assertEqual(entry["leaf_count"], 2)

    def test_malformed_hash_rejected_by_verifier(self):
        for bad in ("sha256:short", "md5:" + "0" * 64, "sha256:" + "G" * 64, 42, None):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    verify_inclusion._decode_hash(bad)


if __name__ == "__main__":
    unittest.main()
