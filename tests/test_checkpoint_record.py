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


def _signed_continuation_checkpoint(**overrides) -> CheckpointRecord:
    from trace_verify import _mmr

    store = _mmr.MemoryNodeStore()
    _mmr.add_leaf(store, _mmr.leaf_hash(b"\x11" * 32))
    size_a = store.size()
    prev_root = _mmr.root_from_peaks([store.node(p) for p in _mmr.peaks(size_a)]).hex()
    _mmr.add_leaf(store, _mmr.leaf_hash(b"\x22" * 32))
    size_b = store.size()
    root = _mmr.root_from_peaks([store.node(p) for p in _mmr.peaks(size_b)]).hex()
    proof = _mmr.consistency_proof(store, size_a, size_b)
    defaults = {
        "mmr_size": size_b,
        "root": root,
        "prev_size": size_a,
        "prev_root": prev_root,
        "consistency_proof": proof,
    }
    defaults.update(overrides)
    return _signed_checkpoint(**defaults)


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
        self.assertTrue(verify_checkpoint_signature_offline(cp))
        ok_ctrl, errs_ctrl = verify_checkpoint_chain([cp])
        self.assertTrue(ok_ctrl, errs_ctrl)
        d = cp.to_dict()
        for label, bad_dict in (
            ("extra_field", {**d, "extra_field": 1}),
            ("non_string_key", {123: "non_string_key", **d}),
            ("v_2", {**d, "v": 2}),
            ("wrong_kind", {**d, "kind": "wrong_kind"}),
            ("mmr_size_0", {**d, "mmr_size": 0}),
            ("prev_size_eq_mmr_size", {**d, "mmr_size": 5, "prev_size": 5}),
            ("missing_consistency_proof", {**d, "prev_size": 1, "prev_root": "bb" * 32}),
            ("non_empty_prev_root_at_zero", {**d, "prev_root": "bb" * 32}),
            ("empty_list_consistency_proof_at_zero", {**d, "consistency_proof": []}),
            ("uppercase_root", {**d, "root": "AA" * 32}),
            ("uppercase_key_id", {**d, "key_id": "AA" * 32}),
            ("uppercase_signature", {**d, "signature": d["signature"].upper()}),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    CheckpointRecord.from_dict(bad_dict)

        for label, bad_cp in (
            ("v_2", _signed_checkpoint(v=2)),
            ("wrong_kind", _signed_checkpoint(kind="other")),
            ("mmr_size_0", _signed_checkpoint(mmr_size=0)),
            ("prev_size_eq_mmr_size", _signed_checkpoint(mmr_size=3, prev_size=3, prev_root="bb" * 32)),
            ("uppercase_root", _signed_checkpoint(root="AA" * 32)),
        ):
            with self.subTest(offline_case=label):
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

    def test_direct_checkpoint_with_prev_size_without_consistency_proof_rejected(self):
        from trace_verify._checkpoint import verify_checkpoint_chain

        valid_cp = _signed_continuation_checkpoint()
        self.assertEqual(valid_cp.prev_size, 1)
        self.assertTrue(verify_checkpoint_signature_offline(valid_cp))
        ok_ctrl, errs_ctrl = verify_checkpoint_chain([valid_cp])
        self.assertTrue(ok_ctrl, errs_ctrl)

        missing_proof_cp = _signed_continuation_checkpoint(consistency_proof=None)
        self.assertEqual(missing_proof_cp.prev_size, 1)
        self.assertIsNone(missing_proof_cp.consistency_proof)
        self.assertFalse(verify_checkpoint_signature_offline(missing_proof_cp))
        ok, errs = verify_checkpoint_chain([missing_proof_cp])
        self.assertFalse(ok)
        self.assertTrue(errs)

    def test_consistency_proof_uppercase_or_whitespace_padded_hex_rejected(self):
        from trace_verify import _mmr
        from trace_verify._checkpoint import verify_checkpoint_chain

        valid_cp = _signed_continuation_checkpoint()
        self.assertTrue(verify_checkpoint_signature_offline(valid_cp))
        self.assertEqual(CheckpointRecord.from_dict(valid_cp.to_dict()).to_dict(), valid_cp.to_dict())

        base_dict = valid_cp.to_dict()
        base_proof = base_dict["consistency_proof"]
        good_peak = base_proof["old_peaks"][0]

        for label, bad_digest in (
            ("uppercase", good_peak.upper()),
            ("whitespace_padded", f"  {good_peak}  "),
        ):
            with self.subTest(case=label):
                bad_proof_dict = {
                    **base_proof,
                    "old_peaks": [bad_digest],
                }
                with self.assertRaises(_mmr.InvalidArgumentError):
                    _mmr.ConsistencyProof.from_dict(bad_proof_dict)
                with self.assertRaises(ValueError):
                    CheckpointRecord.from_dict({**base_dict, "consistency_proof": bad_proof_dict})

                direct_bad_proof = _mmr.ConsistencyProof(
                    v=valid_cp.consistency_proof.v,
                    kind=valid_cp.consistency_proof.kind,
                    size_a=valid_cp.consistency_proof.size_a,
                    size_b=valid_cp.consistency_proof.size_b,
                    old_peaks=(bad_digest,),
                    witness=valid_cp.consistency_proof.witness,
                    new_peaks=valid_cp.consistency_proof.new_peaks,
                )
                direct_bad_cp = _signed_continuation_checkpoint(consistency_proof=direct_bad_proof)
                self.assertFalse(verify_checkpoint_signature_offline(direct_bad_cp))
                ok, errs = verify_checkpoint_chain([direct_bad_cp])
                self.assertFalse(ok)
                self.assertTrue(errs)

    def test_non_string_log_id_or_timestamp_on_direct_checkpoint_rejected(self):
        from trace_verify._checkpoint import verify_checkpoint_chain

        valid_cp = _signed_checkpoint()
        self.assertTrue(verify_checkpoint_signature_offline(valid_cp))

        for field_name in ("log_id", "timestamp"):
            for bad_val in (123, None, ["bad"]):
                with self.subTest(field_name=field_name, bad_val=bad_val):
                    bad_cp = _signed_checkpoint()
                    setattr(bad_cp, field_name, bad_val)
                    self.assertFalse(verify_checkpoint_signature_offline(bad_cp))
                    ok, errs = verify_checkpoint_chain([bad_cp])
                    self.assertFalse(ok)
                    self.assertTrue(errs)



if __name__ == "__main__":
    unittest.main()
