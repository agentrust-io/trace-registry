# SPDX-License-Identifier: Apache-2.0
"""Sanity tests for trace_verify._checkpoint.CheckpointRecord: signing,
digest determinism, and round-tripping through to_dict/from_dict."""
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from trace_verify._checkpoint import (
    CheckpointRecord,
    _validate_checkpoint_fields,
    verify_checkpoint_chain,
    verify_checkpoint_link,
    verify_checkpoint_signature_offline,
)


def _signature_verifies(cp: CheckpointRecord) -> bool:
    """Check the Ed25519 signature alone, ignoring every structural rule."""
    from cryptography.exceptions import InvalidSignature

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp.key_id))
    try:
        public_key.verify(bytes.fromhex(cp.signature), cp.digest().encode("ascii"))
    except InvalidSignature:
        return False
    return True


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

    def test_consistency_proof_sizes_must_match_checkpoint_sizes(self):
        valid_cp = _signed_continuation_checkpoint()
        prev_size, mmr_size = valid_cp.prev_size, valid_cp.mmr_size
        self.assertEqual((valid_cp.consistency_proof.size_a, valid_cp.consistency_proof.size_b), (prev_size, mmr_size))
        self.assertTrue(_signature_verifies(valid_cp))
        _validate_checkpoint_fields(valid_cp)
        self.assertTrue(verify_checkpoint_signature_offline(valid_cp))
        ok_ctrl, errs_ctrl = verify_checkpoint_chain([valid_cp])
        self.assertTrue(ok_ctrl, errs_ctrl)
        self.assertEqual(CheckpointRecord.from_dict(valid_cp.to_dict()).to_dict(), valid_cp.to_dict())

        size_a_msg = r"size_a=\S+ does not match checkpoint prev_size="
        size_b_msg = r"size_b=\S+ does not match checkpoint mmr_size="
        bounds_msg = r"0 <= size_a <= size_b"
        for label, sizes, message in (
            ("size_a_ahead_of_prev_size", {"size_a": prev_size + 1}, size_a_msg),
            ("size_a_behind_prev_size", {"size_a": prev_size - 1}, size_a_msg),
            ("size_b_ahead_of_mmr_size", {"size_b": mmr_size + 1}, size_b_msg),
            ("size_b_behind_mmr_size", {"size_b": mmr_size - 1}, size_b_msg),
            ("negative_size_a", {"size_a": -1}, bounds_msg),
            ("negative_size_b", {"size_b": -mmr_size}, bounds_msg),
            ("reversed_sizes", {"size_a": mmr_size, "size_b": prev_size}, bounds_msg),
        ):
            with self.subTest(case=label):
                bad_proof = replace(valid_cp.consistency_proof, **sizes)
                bad_cp = _signed_continuation_checkpoint(consistency_proof=bad_proof)
                # The signature does not cover consistency_proof, so it stays valid.
                self.assertTrue(_signature_verifies(bad_cp))
                with self.assertRaisesRegex(ValueError, message):
                    _validate_checkpoint_fields(bad_cp)
                with self.assertRaises(ValueError):
                    CheckpointRecord.from_dict(bad_cp.to_dict())
                self.assertFalse(verify_checkpoint_signature_offline(bad_cp))
                ok, errs = verify_checkpoint_chain([bad_cp])
                self.assertFalse(ok)
                self.assertTrue(errs)

    def test_from_dict_rejects_mismatched_proof_sizes_with_named_reason(self):
        valid_cp = _signed_continuation_checkpoint()
        base = valid_cp.to_dict()
        for label, key, value, message in (
            ("size_a", "size_a", valid_cp.prev_size + 1, "does not match checkpoint prev_size"),
            ("size_b", "size_b", valid_cp.mmr_size + 1, "does not match checkpoint mmr_size"),
        ):
            with self.subTest(case=label):
                bad = {**base, "consistency_proof": {**base["consistency_proof"], key: value}}
                with self.assertRaisesRegex(ValueError, message):
                    CheckpointRecord.from_dict(bad)

    def _assert_rejected_on_every_path(self, cp, message):
        # The signature does not cover consistency_proof, so it stays valid.
        self.assertTrue(_signature_verifies(cp))
        with self.assertRaisesRegex(ValueError, message):
            _validate_checkpoint_fields(cp)
        self.assertFalse(verify_checkpoint_signature_offline(cp))
        ok, errs = verify_checkpoint_chain([cp])
        self.assertFalse(ok)
        self.assertTrue(errs)

    def test_direct_checkpoint_with_malformed_consistency_proof_rejected(self):
        valid_cp = _signed_continuation_checkpoint()
        proof = valid_cp.consistency_proof
        dict_proof_cp = _signed_continuation_checkpoint(consistency_proof=proof.to_dict())
        _validate_checkpoint_fields(dict_proof_cp)
        self.assertTrue(verify_checkpoint_signature_offline(dict_proof_cp))

        for label, bad_proof, message in (
            ("not_a_proof", "not-a-proof", "not a ConsistencyProof"),
            ("malformed_dict", {**proof.to_dict(), "size_a": "1"}, "size_a must be an integer"),
            ("mismatched_dict", {**proof.to_dict(), "size_b": proof.size_b + 1}, "does not match checkpoint mmr_size"),
            ("wrong_version", replace(proof, v=2), "v must be 1"),
            ("wrong_kind", replace(proof, kind="other"), "kind must be 'consistency'"),
            ("bool_size_a", replace(proof, size_a=True), "sizes must be integers"),
            ("float_size_b", replace(proof, size_b=float(proof.size_b)), "sizes must be integers"),
            ("peaks_not_a_sequence", replace(proof, old_peaks="abc"), "must be sequences"),
            ("witness_not_a_sequence", replace(proof, witness=("ab",)), "must be sequences"),
        ):
            with self.subTest(case=label):
                bad_cp = _signed_continuation_checkpoint(consistency_proof=bad_proof)
                self._assert_rejected_on_every_path(bad_cp, message)

    def test_first_checkpoint_with_consistency_proof_or_bad_prev_root_rejected(self):
        proof = _signed_continuation_checkpoint().consistency_proof
        self._assert_rejected_on_every_path(
            _signed_checkpoint(consistency_proof=proof), "first checkpoint must not carry consistency_proof"
        )
        for label, bad_prev_root in (("uppercase", "AA" * 32), ("empty", "")):
            with self.subTest(case=label):
                bad_cp = _signed_continuation_checkpoint(prev_root=bad_prev_root)
                self._assert_rejected_on_every_path(bad_cp, "prev_root must be 64 lowercase hex characters")

    def test_validate_checkpoint_fields_accepts_records_and_dicts(self):
        valid_cp = _signed_continuation_checkpoint()
        as_dict = valid_cp.to_dict()
        _validate_checkpoint_fields(as_dict)
        with self.assertRaisesRegex(ValueError, "non-initial checkpoint must carry consistency_proof"):
            _validate_checkpoint_fields(as_dict, consistency_proof=None)
        with self.assertRaisesRegex(ValueError, "non-initial checkpoint must carry consistency_proof"):
            _validate_checkpoint_fields(valid_cp, consistency_proof=None)
        no_proof_cp = _signed_continuation_checkpoint(consistency_proof=None)
        _validate_checkpoint_fields(no_proof_cp, consistency_proof=valid_cp.consistency_proof)
        with self.assertRaisesRegex(ValueError, "not a CheckpointRecord or dict"):
            _validate_checkpoint_fields(object())

    def test_link_rejects_non_canonical_roots_and_malformed_predecessor(self):
        key = Ed25519PrivateKey.generate()
        curr = _signed_continuation_checkpoint(_private_key=key)
        prev = _signed_checkpoint(_private_key=key, mmr_size=curr.prev_size, root=curr.prev_root)
        ok, reason = verify_checkpoint_link(prev, curr)
        self.assertTrue(ok, reason)
        ok_chain, errs = verify_checkpoint_chain([prev, curr])
        self.assertTrue(ok_chain, errs)

        upper_root = curr.prev_root.upper()
        upper_prev = _signed_checkpoint(_private_key=key, mmr_size=curr.prev_size, root=upper_root)
        upper_curr = _signed_continuation_checkpoint(_private_key=key, prev_root=upper_root)
        ok, reason = verify_checkpoint_link(upper_prev, upper_curr)
        self.assertFalse(ok)
        self.assertIn("malformed root hex", reason)

        bad_prev = _signed_checkpoint(_private_key=key, v=2, mmr_size=curr.prev_size, root=curr.prev_root)
        ok, reason = verify_checkpoint_link(bad_prev, curr)
        self.assertFalse(ok)
        self.assertIn("malformed checkpoint", reason)


if __name__ == "__main__":
    unittest.main()
