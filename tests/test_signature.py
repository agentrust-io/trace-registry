"""Tests for Ed25519 signature verification in trace_verify._signature.

These tests generate a real keypair and sign/verify claims so no mocking
of the cryptography primitives is needed.

The `cryptography` package is required for these tests. If it is not installed,
the tests are skipped.
"""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

SKIP_MSG = "cryptography package not installed"


def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    x = base64.urlsafe_b64encode(pub.public_bytes_raw()).rstrip(b"=").decode()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    return priv, jwk


def _sign_claim(priv, claim: dict) -> dict:
    from trace_verify._signature import canonical_body_bytes
    body = {k: v for k, v in claim.items() if k != "signature"}
    sig = priv.sign(canonical_body_bytes(body))
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return {**body, "signature": sig_b64}


MINIMAL_CLAIM = {
    "fmt": 1,
    "producer": "test-producer/1.0.0",
    "ts": "2026-06-22T00:00:00Z",
    "hash": "abc123",
}


@unittest.skipUnless(HAS_CRYPTOGRAPHY, SKIP_MSG)
class TestCanonicalBodyBytes(unittest.TestCase):
    def test_excludes_signature_field(self):
        from trace_verify._signature import canonical_body_bytes
        claim = {"a": 1, "signature": "should-not-appear", "b": 2}
        body_bytes = canonical_body_bytes(claim)
        parsed = json.loads(body_bytes)
        self.assertNotIn("signature", parsed)
        self.assertEqual(parsed["a"], 1)
        self.assertEqual(parsed["b"], 2)

    def test_keys_sorted(self):
        from trace_verify._signature import canonical_body_bytes
        claim = {"z": 1, "a": 2, "m": 3}
        body_bytes = canonical_body_bytes(claim)
        self.assertTrue(body_bytes.startswith(b'{"a":'))

    def test_no_whitespace(self):
        from trace_verify._signature import canonical_body_bytes
        claim = {"k": "v"}
        body_bytes = canonical_body_bytes(claim)
        self.assertNotIn(b" ", body_bytes)

    def test_ascii_encoding(self):
        from trace_verify._signature import canonical_body_bytes
        claim = {"k": "v"}
        body_bytes = canonical_body_bytes(claim)
        self.assertIsInstance(body_bytes, bytes)
        body_bytes.decode("ascii")  # must not raise


@unittest.skipUnless(HAS_CRYPTOGRAPHY, SKIP_MSG)
class TestVerifyClaimSignature(unittest.TestCase):
    def setUp(self):
        self.priv, self.jwk = _make_keypair()
        self.claim = _sign_claim(self.priv, MINIMAL_CLAIM)

    def test_valid_signature(self):
        from trace_verify._signature import verify_claim_signature
        self.assertTrue(verify_claim_signature(self.claim, self.jwk))

    def test_tampered_claim_fails(self):
        from trace_verify._signature import verify_claim_signature
        tampered = {**self.claim, "hash": "tampered"}
        self.assertFalse(verify_claim_signature(tampered, self.jwk))

    def test_wrong_key_fails(self):
        from trace_verify._signature import verify_claim_signature
        _, other_jwk = _make_keypair()
        self.assertFalse(verify_claim_signature(self.claim, other_jwk))

    def test_missing_signature_raises(self):
        from trace_verify._signature import verify_claim_signature
        claim_no_sig = {k: v for k, v in self.claim.items() if k != "signature"}
        with self.assertRaises(ValueError):
            verify_claim_signature(claim_no_sig, self.jwk)

    def test_malformed_signature_raises(self):
        from trace_verify._signature import verify_claim_signature
        claim_bad_sig = {**self.claim, "signature": "!!!not-base64url!!!"}
        with self.assertRaises(ValueError):
            verify_claim_signature(claim_bad_sig, self.jwk)

    def test_missing_x_in_jwk_raises(self):
        from trace_verify._signature import verify_claim_signature
        bad_jwk = {k: v for k, v in self.jwk.items() if k != "x"}
        with self.assertRaises(ValueError):
            verify_claim_signature(self.claim, bad_jwk)

    def test_rejects_wrong_jwk_type_or_curve(self):
        from trace_verify._signature import verify_claim_signature

        for bad_jwk in (
            {**self.jwk, "kty": "EC"},
            {**self.jwk, "crv": "X25519"},
        ):
            with self.subTest(jwk=bad_jwk):
                with self.assertRaisesRegex(ValueError, "OKP/Ed25519"):
                    verify_claim_signature(self.claim, bad_jwk)

    def test_rejects_noncanonical_or_wrong_length_base64url(self):
        from trace_verify._signature import verify_claim_signature

        for signature in (self.claim["signature"] + "=", "AA", "!!!!"):
            with self.subTest(signature=signature):
                with self.assertRaises(ValueError):
                    verify_claim_signature({**self.claim, "signature": signature}, self.jwk)

    def test_signature_field_excluded_from_signed_body(self):
        """signature field must not participate in the signed message."""
        from trace_verify._signature import verify_claim_signature
        # Re-sign the same body bytes; both should verify
        claim2 = _sign_claim(self.priv, MINIMAL_CLAIM)
        # Two independent signatures of the same body should both verify
        self.assertTrue(verify_claim_signature(self.claim, self.jwk))
        self.assertTrue(verify_claim_signature(claim2, self.jwk))


@unittest.skipUnless(HAS_CRYPTOGRAPHY, SKIP_MSG)
class TestLoadProducerKey(unittest.TestCase):
    def test_returns_none_for_missing_file(self):
        from trace_verify._signature import load_producer_key
        with tempfile.TemporaryDirectory() as tmpdir:
            result = load_producer_key("no-such/1.0.0", Path(tmpdir))
        self.assertIsNone(result)

    def test_loads_valid_key_file(self):
        from trace_verify._signature import load_producer_key
        _, jwk = _make_keypair()
        entry = {
            "producer_id": "test-producer/1.0.0",
            "key_type": "Ed25519",
            "public_key_jwk": jwk,
            "active_since": "2026-06-22T00:00:00Z",
            "contact": "test@example.com",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "test-producer-1.0.0.json"
            key_file.write_text(json.dumps(entry), encoding="utf-8")
            result = load_producer_key("test-producer/1.0.0", Path(tmpdir))
        self.assertIsNotNone(result)
        self.assertEqual(result["producer_id"], "test-producer/1.0.0")

    def test_slash_replaced_by_dash_in_filename(self):
        """producer_id with / maps to filename with -."""
        from trace_verify._signature import load_producer_key
        _, jwk = _make_keypair()
        entry = {
            "producer_id": "acme/2.0.0",
            "key_type": "Ed25519",
            "public_key_jwk": jwk,
            "active_since": "2026-06-22T00:00:00Z",
            "contact": "acme@example.com",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "acme-2.0.0.json"
            key_file.write_text(json.dumps(entry), encoding="utf-8")
            result = load_producer_key("acme/2.0.0", Path(tmpdir))
        self.assertEqual(result["producer_id"], "acme/2.0.0")

    def test_returns_none_for_invalid_json(self):
        from trace_verify._signature import load_producer_key
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = Path(tmpdir) / "broken-1.0.0.json"
            bad.write_text("{not json", encoding="utf-8")
            result = load_producer_key("broken/1.0.0", Path(tmpdir))
        self.assertIsNone(result)

    def test_rejects_path_traversal_producer_id(self):
        """Fix #4: a traversal-y producer id must not escape producers_dir."""
        from trace_verify._signature import is_valid_producer_id, load_producer_key
        for bad in (
            "../../../../etc/passwd",
            "..\\..\\windows\\system32",
            "../secret/1.0.0",
            "a/b/../../1.0.0",
            "/abs/1.0.0",
            "name/1.0.0/../../x",
        ):
            with self.subTest(producer_id=bad):
                self.assertFalse(is_valid_producer_id(bad))
                # Even if an attacker-controlled file existed, load returns None
                with tempfile.TemporaryDirectory() as tmpdir:
                    self.assertIsNone(load_producer_key(bad, Path(tmpdir)))

    def test_accepts_valid_producer_id(self):
        from trace_verify._signature import is_valid_producer_id
        self.assertTrue(is_valid_producer_id("cmcp-gateway/0.1.0"))
        self.assertTrue(is_valid_producer_id("acme.thing_2/10.20.30-rc1"))

    def test_registry_verification_rejects_mismatched_key_identity(self):
        from trace_verify._signature import verify_claim_against_registry

        priv, jwk = _make_keypair()
        claim = _sign_claim(priv, MINIMAL_CLAIM)
        entry = {
            "producer_id": "different-producer/1.0.0",
            "key_type": "Ed25519",
            "public_key_jwk": jwk,
            "active_since": "2026-06-22T00:00:00Z",
            "contact": "test@example.com",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "test-producer-1.0.0.json"
            key_file.write_text(json.dumps(entry), encoding="utf-8")
            ok, reason = verify_claim_against_registry(
                claim, "test-producer/1.0.0", Path(tmpdir)
            )
        self.assertFalse(ok)
        self.assertIn("producer_id", reason)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(HAS_CRYPTOGRAPHY, SKIP_MSG)
class TestSignaturePreimageIsJCS(unittest.TestCase):
    """The pre-image must be RFC 8785, not sorted-keys ASCII JSON (trace-spec#138).

    trace-v0.2.md section 3.2.2 names json.dumps(sort_keys=True) as insufficient.
    It agrees with JCS on ASCII and diverges on non-ASCII, so the old construction
    verified non-ASCII records against bytes the producer never signed.

    Note this is deliberately NOT the anchor-leaf canonicalization, which
    docs/anchor-format.md section 1 defines as sorted-keys ASCII over the complete
    signed claim. Two layers, two constructions, on purpose.
    """

    def test_matches_rfc8785_not_json_dumps(self):
        import rfc8785
        from trace_verify._signature import canonical_body_bytes

        claim = {"producer": "acme/1.0.0", "note": "café", "signature": "x"}
        body = {k: v for k, v in claim.items() if k != "signature"}
        self.assertEqual(canonical_body_bytes(claim), rfc8785.dumps(body))
        self.assertNotEqual(
            canonical_body_bytes(claim),
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "ascii"
            ),
        )

    def test_a_non_ascii_claim_signed_the_producer_way_verifies(self):
        """The end-to-end case that was broken: producer signs JCS, we verify it."""
        import rfc8785
        from trace_verify._signature import canonical_body_bytes

        priv, jwk = _make_keypair()
        claim = {
            "fmt": 1,
            "producer": "test-producer/1.0.0",
            "ts": "2026-06-22T00:00:00Z",
            "hash": "abc123",
            "subject": "Ünicode agent 日本語",
        }
        # Exactly what agentrust_trace.sign_record does: JCS over the body.
        sig = priv.sign(rfc8785.dumps(claim))
        signed = {**claim, "signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode()}

        from trace_verify._signature import verify_claim_signature

        self.assertTrue(verify_claim_signature(signed, jwk))
        self.assertEqual(canonical_body_bytes(signed), rfc8785.dumps(claim))
