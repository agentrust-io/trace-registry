"""Tests for tools/anchor.py and tools/verify_inclusion.py.

Standard library only. Run from the repository root:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import anchor  # noqa: E402
import verify_inclusion  # noqa: E402


def _claims(n: int) -> list[dict]:
    return [{"id": i, "payload": f"claim-{i}", "signature": f"sig-{i}"} for i in range(n)]


def _sorted_key_bytes(claim: dict) -> bytes:
    return json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _leaf(claim: dict, canonicalization_id: str = anchor.DEFAULT_CANONICALIZATION,
          raw: bytes | None = None) -> bytes:
    return anchor.leaf_hash(raw if raw is not None else _sorted_key_bytes(claim),
                             claim, canonicalization_id)


def _decode_path(path: list[str]) -> list[bytes]:
    return [bytes.fromhex(h.split(":", 1)[1]) for h in path]


def _verify(claim: dict, index: int, path: list[str], count: int, root: bytes,
            canonicalization_id: str = anchor.DEFAULT_CANONICALIZATION,
            raw: bytes | None = None) -> bool:
    return verify_inclusion.verify_inclusion(
        raw if raw is not None else _sorted_key_bytes(claim), claim,
        canonicalization_id, index, _decode_path(path), count, root,
    )


class TestCanonicalization(unittest.TestCase):
    """Both anchor-leaf constructions are first-class and permanent
    (docs/anchor-format.md): sorted-key stays the default, as-transmitted is
    an offered option -- see the "allow BOTH" framing in the PR-1 issue."""

    def test_sorted_key_key_order_does_not_matter(self):
        a = {"b": 1, "a": {"y": 2, "x": 3}}
        b = {"a": {"x": 3, "y": 2}, "b": 1}
        self.assertEqual(
            anchor.canonical_claim_bytes(b"", a, "sorted-key"),
            anchor.canonical_claim_bytes(b"", b, "sorted-key"),
        )

    def test_sorted_key_compact_sorted_ascii(self):
        self.assertEqual(
            anchor.canonical_claim_bytes(b"", {"b": "é", "a": 1}, "sorted-key"),
            b'{"a":1,"b":"\\u00e9"}',
        )

    def test_sorted_key_non_object_claim_rejected(self):
        with self.assertRaises(ValueError):
            anchor.canonical_claim_bytes(b"", ["not", "an", "object"], "sorted-key")

    def test_as_transmitted_returns_raw_bytes_verbatim(self):
        # Deliberately NOT what sort_keys=True would produce (whitespace, key
        # order) -- as-transmitted must ignore the parsed claim entirely and
        # commit to exactly what was received.
        raw = b'{ "b": "\xc3\xa9", "a" : 1 }'
        claim = json.loads(raw)
        self.assertEqual(anchor.canonical_claim_bytes(raw, claim, "as-transmitted"), raw)
        self.assertNotEqual(raw, _sorted_key_bytes(claim))

    def test_default_is_sorted_key(self):
        self.assertEqual(anchor.DEFAULT_CANONICALIZATION, "sorted-key")
        claim = _claims(1)[0]
        raw = _sorted_key_bytes(claim)
        self.assertEqual(
            anchor.canonical_claim_bytes(raw, claim),
            anchor.canonical_claim_bytes(raw, claim, "sorted-key"),
        )

    def test_unknown_canonicalization_id_raises_named_error(self):
        with self.assertRaises(anchor.UnknownCanonicalizationError):
            anchor.canonical_claim_bytes(b"{}", {}, "base64url-cbor")

    def test_content_digest_id_at_anchor_layer_is_a_named_mismatch(self):
        # "jcs" is a real CPB construction, just not one valid at this layer
        # -- the #111 trap this PR closes by declaration.
        with self.assertRaises(anchor.MismatchedCanonicalizationLayerError):
            anchor.canonical_claim_bytes(b"{}", {}, "jcs")

    def test_implementations_agree_sorted_key(self):
        claim = _claims(1)[0]
        raw = _sorted_key_bytes(claim)
        self.assertEqual(
            anchor.canonical_claim_bytes(raw, claim, "sorted-key"),
            verify_inclusion.canonical_claim_bytes(raw, claim, "sorted-key"),
        )

    def test_implementations_agree_as_transmitted(self):
        raw = b'{"weird": true,   "spacing": 1}'
        claim = json.loads(raw)
        self.assertEqual(
            anchor.canonical_claim_bytes(raw, claim, "as-transmitted"),
            verify_inclusion.canonical_claim_bytes(raw, claim, "as-transmitted"),
        )

    def test_verifier_also_names_unknown_and_mismatched(self):
        with self.assertRaises(verify_inclusion.UnknownCanonicalizationError):
            verify_inclusion.canonical_claim_bytes(b"{}", {}, "base64url-cbor")
        with self.assertRaises(verify_inclusion.MismatchedCanonicalizationLayerError):
            verify_inclusion.canonical_claim_bytes(b"{}", {}, "jcs")


class TestTreeConstruction(unittest.TestCase):
    def test_empty_batch_rejected(self):
        with self.assertRaises(ValueError):
            anchor.build_tree([])

    def test_single_leaf_root_is_leaf_hash(self):
        claim = _claims(1)[0]
        leaf = _leaf(claim)
        expected = hashlib.sha256(b"\x00" + _sorted_key_bytes(claim)).digest()
        self.assertEqual(leaf, expected)
        root, paths = anchor.build_tree([leaf])
        self.assertEqual(root, leaf)
        self.assertEqual(paths, [[]])

    def test_two_leaves_rfc6962_interior_node(self):
        claims = _claims(2)
        leaves = [_leaf(c) for c in claims]
        root, paths = anchor.build_tree(leaves)
        self.assertEqual(root, hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest())
        self.assertEqual(paths[0], ["sha256:" + leaves[1].hex()])
        self.assertEqual(paths[1], ["sha256:" + leaves[0].hex()])

    def test_odd_count_promotes_last_node(self):
        # RFC 6962 recursion for n=3: H(H(a,b), c), with c promoted, not duplicated.
        leaves = [_leaf(c) for c in _claims(3)]
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
            root, paths = anchor.build_tree([_leaf(c) for c in claims])
            for i, claim in enumerate(claims):
                with self.subTest(leaf_count=n, leaf_index=i):
                    self.assertTrue(_verify(claim, i, paths[i], n, root))

    def test_all_leaves_verify_as_transmitted(self):
        raws = [json.dumps({"n": i}).encode("ascii") for i in range(5)]
        claims = [json.loads(r) for r in raws]
        leaves = [_leaf(c, "as-transmitted", raw=r) for c, r in zip(claims, raws)]
        root, paths = anchor.build_tree(leaves)
        for i, (claim, raw) in enumerate(zip(claims, raws)):
            with self.subTest(leaf_index=i):
                self.assertTrue(
                    _verify(claim, i, paths[i], 5, root, "as-transmitted", raw=raw)
                )

    def test_tampered_claim_fails(self):
        claims = _claims(4)
        root, paths = anchor.build_tree([_leaf(c) for c in claims])
        tampered = dict(claims[2], payload="claim-2-tampered")
        self.assertFalse(_verify(tampered, 2, paths[2], 4, root))
        # Tampering the signature alone also breaks the anchor.
        resigned = dict(claims[2], signature="forged")
        self.assertFalse(_verify(resigned, 2, paths[2], 4, root))

    def test_tampered_audit_path_fails(self):
        claims = _claims(5)
        root, paths = anchor.build_tree([_leaf(c) for c in claims])
        bad = list(paths[1])
        bad[0] = "sha256:" + "ab" * 32
        self.assertFalse(_verify(claims[1], 1, bad, 5, root))

    def test_wrong_leaf_index_fails(self):
        claims = _claims(4)
        root, paths = anchor.build_tree([_leaf(c) for c in claims])
        self.assertFalse(_verify(claims[0], 1, paths[0], 4, root))
        self.assertFalse(_verify(claims[0], -1, paths[0], 4, root))
        self.assertFalse(_verify(claims[0], 4, paths[0], 4, root))

    def test_truncated_and_extended_paths_fail(self):
        claims = _claims(4)
        root, paths = anchor.build_tree([_leaf(c) for c in claims])
        self.assertFalse(_verify(claims[0], 0, paths[0][:-1], 4, root))
        self.assertFalse(_verify(claims[0], 0, paths[0] + paths[0][:1], 4, root))

    def test_wrong_leaf_count_fails(self):
        claims = _claims(3)
        root, paths = anchor.build_tree([_leaf(c) for c in claims])
        self.assertFalse(_verify(claims[2], 2, paths[2], 4, root))
        self.assertFalse(_verify(claims[2], 2, paths[2], 0, root))

    def test_wrong_construction_assumed_fails_not_silently_accepts(self):
        # A claim anchored under as-transmitted, checked as though it were
        # sorted-key: must not verify (the two preimages differ).
        raw = b'{"z": 1,  "a": 2}'  # not sorted-key-compact
        claim = json.loads(raw)
        leaf = _leaf(claim, "as-transmitted", raw=raw)
        root, paths = anchor.build_tree([leaf])
        self.assertFalse(_verify(claim, 0, paths[0], 1, root, "sorted-key"))

    def test_mismatched_layer_id_raises_named_error_not_silent_fail(self):
        raw = _sorted_key_bytes(_claims(1)[0])
        claim = json.loads(raw)
        leaf = _leaf(claim)
        root, paths = anchor.build_tree([leaf])
        with self.assertRaises(verify_inclusion.MismatchedCanonicalizationLayerError):
            _verify(claim, 0, paths[0], 1, root, "jcs", raw=raw)


class TestEntryFormat(unittest.TestCase):
    def test_make_entry_fields(self):
        root, _ = anchor.build_tree([_leaf(c) for c in _claims(2)])
        entry = anchor.make_entry(root, 2, "cmcp-gateway/0.1.0", "b-1", "2026-06-12T00:00:00Z")
        self.assertEqual(
            sorted(entry),
            ["batch_id", "canonicalization_id", "leaf_count", "merkle_root", "producer", "ts"],
        )
        self.assertEqual(entry["merkle_root"], "sha256:" + root.hex())
        self.assertEqual(entry["leaf_count"], 2)
        self.assertEqual(entry["canonicalization_id"], "sorted-key")

    def test_make_entry_declares_as_transmitted_when_asked(self):
        raw = json.dumps({"n": 1}).encode("ascii")
        claim = json.loads(raw)
        root, _ = anchor.build_tree([_leaf(claim, "as-transmitted", raw=raw)])
        entry = anchor.make_entry(root, 1, "p/1.0.0", "b-1", "2026-06-12T00:00:00Z",
                                   "as-transmitted")
        self.assertEqual(entry["canonicalization_id"], "as-transmitted")

    def test_malformed_hash_rejected_by_verifier(self):
        for bad in ("sha256:short", "md5:" + "0" * 64, "sha256:" + "G" * 64, 42, None):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    verify_inclusion._decode_hash(bad)


class TestVerifyInclusionCLI(unittest.TestCase):
    """End-to-end coverage of the vintage rule and construction declaration
    through the actual CLI entrypoint, using tempfiles like the other CLI
    tests in this repo (see tests/test_batch_anchor.py)."""

    def _anchor_and_verify(self, claim: dict, canonicalization_id: str | None,
                            drop_canonicalization_id: bool = False) -> tuple[int, Path]:
        tmp = Path(tempfile.mkdtemp())
        claim_path = tmp / "claim.json"
        claim_path.write_text(json.dumps(claim), encoding="utf-8")

        argv = ["--producer", "p/1.0.0", "--proof-dir", str(tmp), str(claim_path)]
        if canonicalization_id is not None:
            argv = ["--canonicalization", canonicalization_id] + argv
        # Capture stdout by redirecting via a pipe-free approach: anchor.main
        # prints the entry to stdout, so call the pieces directly instead.
        raw = claim_path.read_bytes()
        leaf = anchor.leaf_hash(raw, claim, canonicalization_id or anchor.DEFAULT_CANONICALIZATION)
        root, paths = anchor.build_tree([leaf])
        entry = anchor.make_entry(
            root, 1, "p/1.0.0", "b-1", "2026-06-12T00:00:00Z",
            canonicalization_id or anchor.DEFAULT_CANONICALIZATION,
        )
        if drop_canonicalization_id:
            del entry["canonicalization_id"]
        entry_path = tmp / "entry.json"
        entry_path.write_text(json.dumps(entry), encoding="utf-8")
        proof_path = tmp / "claim.proof.json"
        proof_path.write_text(
            json.dumps({"leaf_index": 0, "audit_path": paths[0]}), encoding="utf-8"
        )
        rc = verify_inclusion.main([
            "--claim", str(claim_path), "--proof", str(proof_path), "--entry", str(entry_path),
        ])
        return rc, tmp

    def test_sorted_key_round_trip(self):
        rc, _ = self._anchor_and_verify({"a": 1}, "sorted-key")
        self.assertEqual(rc, 0)

    def test_as_transmitted_round_trip(self):
        rc, _ = self._anchor_and_verify({"a": 1}, "as-transmitted")
        self.assertEqual(rc, 0)

    def test_vintage_entry_with_no_canonicalization_id_infers_sorted_key(self):
        rc, _ = self._anchor_and_verify({"a": 1}, "sorted-key", drop_canonicalization_id=True)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
