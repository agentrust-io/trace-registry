# SPDX-License-Identifier: Apache-2.0
"""Sanity tests for trace_verify._checkpoint.CheckpointRecord: signing,
digest determinism, and round-tripping through to_dict/from_dict."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trace_verify._checkpoint import CheckpointRecord, verify_checkpoint_signature_offline


def _signed_checkpoint(**overrides) -> CheckpointRecord:
    private_key = overrides.pop("_private_key", None) or Ed25519PrivateKey.generate()
    key_id = private_key.public_key().public_bytes_raw().hex()
    fields = {
        "v": 1,
        "kind": "mmr_checkpoint",
        "log_id": "test-log/v1",
        "mmr_size": 7,
        "root": "aa" * 32,
        "prev_size": 0,
        "prev_root": "",
        "key_id": key_id,
        "timestamp": "2026-08-26T00:00:00Z",
        "signature": "",
    }
    fields.update(overrides)
    cp = CheckpointRecord(**fields)
    cp.signature = private_key.sign(cp.digest().encode("ascii")).hex()
    return cp


class TestCheckpointRecord(unittest.TestCase):
    def test_signature_verifies_offline(self):
        cp = _signed_checkpoint()
        self.assertTrue(verify_checkpoint_signature_offline(cp))

    def test_tampered_root_breaks_signature(self):
        cp = _signed_checkpoint()
        cp.root = "bb" * 32
        self.assertFalse(verify_checkpoint_signature_offline(cp))

    def test_signature_from_wrong_key_fails(self):
        cp = _signed_checkpoint()
        other = Ed25519PrivateKey.generate()
        cp.signature = other.sign(cp.digest().encode("ascii")).hex()
        self.assertFalse(verify_checkpoint_signature_offline(cp))

    def test_digest_is_deterministic_and_excludes_signature(self):
        cp = _signed_checkpoint()
        d1 = cp.digest()
        cp.signature = "00" * 64
        d2 = cp.digest()
        self.assertEqual(d1, d2)

    def test_to_dict_from_dict_round_trip(self):
        cp = _signed_checkpoint()
        restored = CheckpointRecord.from_dict(cp.to_dict())
        self.assertEqual(cp.to_dict(), restored.to_dict())
        self.assertTrue(verify_checkpoint_signature_offline(restored))

    def test_first_checkpoint_has_no_consistency_proof(self):
        cp = _signed_checkpoint()
        self.assertIsNone(cp.consistency_proof)
        self.assertNotIn("consistency_proof", cp.to_dict())

    def test_non_canonical_hex_and_unknown_fields_rejected(self):
        from trace_verify._checkpoint import verify_checkpoint_chain

        cp = _signed_checkpoint()
        d = cp.to_dict()
        for bad_dict in (
            {**d, "extra_field": 1},
            {123: "non_string_key", **d},
            {**d, "v": 2},
            {**d, "kind": "wrong_kind"},
            {**d, "mmr_size": 0},
            {**d, "mmr_size": 5, "prev_size": 5},
            {**d, "prev_size": 1, "prev_root": "bb" * 32},  # missing consistency_proof
            {**d, "prev_root": "bb" * 32},  # prev_size == 0 with non-empty prev_root
            {**d, "root": "AA" * 32},
            {**d, "key_id": "AA" * 32},
            {**d, "signature": d["signature"].upper()},
        ):
            with self.subTest(bad_dict=list(bad_dict.keys())):
                with self.assertRaises(ValueError):
                    CheckpointRecord.from_dict(bad_dict)

        # Uppercase or whitespace-padded signature or bad v/kind/mmr_size must not verify
        for bad_cp in (
            _signed_checkpoint(v=2),
            _signed_checkpoint(kind="other"),
            _signed_checkpoint(mmr_size=0),
            _signed_checkpoint(mmr_size=3, prev_size=3, prev_root="bb" * 32),
            _signed_checkpoint(root="AA" * 32),
        ):
            self.assertFalse(verify_checkpoint_signature_offline(bad_cp))
            ok, errs = verify_checkpoint_chain([bad_cp])
            self.assertFalse(ok)
            self.assertTrue(errs)

        upper_sig = _signed_checkpoint()
        upper_sig.signature = upper_sig.signature.upper()
        self.assertFalse(verify_checkpoint_signature_offline(upper_sig))

        padded_sig = _signed_checkpoint()
        padded_sig.signature = "  " + padded_sig.signature + "  "
        self.assertFalse(verify_checkpoint_signature_offline(padded_sig))



if __name__ == "__main__":
    unittest.main()
