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


if __name__ == "__main__":
    unittest.main()
