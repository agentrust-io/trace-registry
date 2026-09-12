"""Adversarial checks against a captured receipt, not a receipt we mint."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from verify_witness_receipt import load_json, verify

PACKET = ROOT / 'docs/evidence/witness-2026-09-07'
REGISTRY_KEY = 'bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90'
WITNESS_KEY = '39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5'
# checkpoint-1.json's own timestamp, 2026-09-01T21:39:37Z, as epoch seconds.
CHECKPOINT_EPOCH = 1788298777


class WitnessReceiptTests(unittest.TestCase):
    def setUp(self):
        self.cp = load_json(PACKET / 'checkpoint-1.json')
        self.response = load_json(PACKET / 'witness-post.json')

    def check(self, cp=None, response=None, **kw):
        args = dict(registry_key=REGISTRY_KEY, witness_key=WITNESS_KEY, expected_log_id='trace-registry/v1')
        args.update(kw)
        return verify(self.cp if cp is None else cp, self.response if response is None else response, **args)

    def test_real_receipt_verifies_with_network_disabled(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            result = self.check()
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['leaf_index'], 936)
        self.assertEqual(result['tree_size'], 937)
        self.assertFalse(any(result['limits'].values()))

    def test_separately_fetched_receipt_matches(self):
        readback = load_json(PACKET / 'witness-readback.json')
        self.assertTrue(self.check(response=readback)['verified'])
        for key in ('receipt_b64', 'entry_hash', 'grade'):
            self.assertEqual(readback[key], self.response[key])
        for key in ('log_id', 'root', 'mmr_size', 'prev_root', 'prev_size', 'key_id', 'timestamp'):
            self.assertEqual(readback[key], self.cp[key])
        inclusion = load_json(PACKET / 'witness-inclusion.json')
        self.assertEqual(inclusion['receipt_b64'], self.response['receipt_b64'])
        self.assertEqual(inclusion['capsule_id'], self.check()['checkpoint_signing_digest'])

    def test_changed_checkpoint_signature_rejected(self):
        self.cp['signature'] = '00' * 64
        result = self.check()
        self.assertFalse(result['verified'])
        self.assertNotIn('checkpoint_signature', result['checks'])

    def test_changed_checkpoint_body_rejected(self):
        self.cp['root'] = '00' * 32
        self.assertFalse(self.check()['verified'])

    def test_wrong_registry_policy_rejected(self):
        self.assertFalse(self.check(registry_key='01' * 32)['verified'])
        self.assertFalse(self.check(expected_log_id='another-log')['verified'])

    def test_wrong_witness_key_rejected(self):
        result = self.check(witness_key=REGISTRY_KEY)
        self.assertFalse(result['verified'])
        self.assertTrue(result['checks']['checkpoint_receipt_binding'])
        self.assertNotIn('receipt_signature_and_inclusion', result['checks'])

    def test_tampered_receipt_signature_rejected(self):
        receipt = bytearray(base64.b64decode(self.response['receipt_b64']))
        receipt[-1] ^= 1
        self.response['receipt_b64'] = base64.b64encode(receipt).decode()
        self.assertFalse(self.check()['verified'])

    def test_valid_other_checkpoint_cannot_borrow_receipt(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from verify_witness_receipt import FIELDS
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.cp['key_id'] = public
        body = {k: self.cp[k] for k in FIELDS}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).digest()
        self.cp['signature'] = key.sign(digest.hex().encode()).hex()
        result = self.check(registry_key=public)
        self.assertFalse(result['verified'])
        self.assertTrue(result['checks']['checkpoint_signature'])
        self.assertNotIn('checkpoint_receipt_binding', result['checks'])
        # Even rewriting the response's advertised hash cannot make its
        # existing proof and signature cover our different checkpoint.
        self.response['entry_hash'] = hashlib.sha256(digest).hexdigest()
        result = self.check(registry_key=public)
        self.assertFalse(result['verified'])
        self.assertTrue(result['checks']['checkpoint_receipt_binding'])

    def test_untrusted_metadata_does_not_change_signed_scope(self):
        self.response['grade'] = 'mmr-verified'
        self.response['timestamp'] = '2099-01-01T00:00:00Z'
        result = self.check()
        self.assertTrue(result['verified'])
        self.assertFalse(result['limits']['grade_cryptographically_bound'])
        self.assertFalse(result['limits']['witness_time_established'])

    def test_response_coordinates_must_match_proof(self):
        for field in ('leaf_index', 'tree_size'):
            response = copy.deepcopy(self.response)
            response[field] += 1
            self.assertFalse(self.check(response=response)['verified'])

    def test_unknown_hash_scheme_rejected(self):
        self.response['entry_hash_scheme'] = 'sig_structure'
        self.assertFalse(self.check()['verified'])

    def test_boolean_size_rejected_before_signature(self):
        self.cp['mmr_size'] = True
        self.assertFalse(self.check()['verified'])

    def test_extra_cbor_bytes_rejected(self):
        receipt = base64.b64decode(self.response['receipt_b64']) + b'\x00'
        self.response['receipt_b64'] = base64.b64encode(receipt).decode()
        self.assertFalse(self.check()['verified'])


if __name__ == '__main__':
    unittest.main()


class SignedReceiptMetadataTests(unittest.TestCase):
    """The post-fix wire shape: a witness clock and a grade inside the signature.

    These receipts are minted here, unlike every test above, because the
    captured one predates the change. What is borrowed from the capture is
    the inclusion proof and the root it commits to; the protected header and
    the signature over it are ours, so nothing here asserts that the witness
    has deployed anything.
    """

    setUp = WitnessReceiptTests.setUp
    check = WitnessReceiptTests.check

    def mint(self, headers, *, grade=None):
        import cbor2
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        root = bytes.fromhex(self.check()['root'])
        envelope = cbor2.loads(base64.b64decode(self.response['receipt_b64'])).value
        protected = cbor2.dumps(headers)
        key = Ed25519PrivateKey.generate()
        signature = key.sign(cbor2.dumps(['Signature1', protected, b'', root]))
        receipt = cbor2.dumps(cbor2.CBORTag(18, [protected, envelope[1], None, signature]))
        response = copy.deepcopy(self.response)
        response['receipt_b64'] = base64.b64encode(receipt).decode()
        if grade is not None:
            response['grade'] = grade
        public = key.public_key().public_bytes_raw().hex()
        return self.check(response=response, witness_key=public)

    def test_captured_receipt_carries_no_signed_metadata(self):
        result = self.check()
        self.assertIsNone(result['signed_iat'])
        self.assertIsNone(result['signed_grade'])
        self.assertFalse(result['limits']['witness_time_established'])

    def test_signed_iat_is_surfaced_and_establishes_witness_time(self):
        result = self.mint({1: -8, 395: 1, 15: {6: 1788914655}})
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['signed_iat'], 1788914655)
        self.assertTrue(result['limits']['witness_time_established'])
        self.assertFalse(result['limits']['grade_cryptographically_bound'])

    def test_signed_grade_binds_only_when_it_matches_the_response(self):
        agreeing = self.mint({1: -8, 395: 1, -65537: 'countersigned-observed'},
                             grade='countersigned-observed')
        self.assertTrue(agreeing['verified'], agreeing)
        self.assertTrue(agreeing['limits']['grade_cryptographically_bound'])
        disagreeing = self.mint({1: -8, 395: 1, -65537: 'countersigned-observed'},
                                grade='mmr-verified')
        self.assertTrue(disagreeing['verified'], disagreeing)
        self.assertFalse(disagreeing['limits']['grade_cryptographically_bound'])

    def test_unreviewed_signed_header_is_refused(self):
        result = self.mint({1: -8, 395: 1, 1234: 'anything'})
        self.assertFalse(result['verified'])
        self.assertIn('unreviewed signed receipt headers', result['error'])

    def test_cwt_claims_map_carries_iat_and_nothing_else(self):
        for claims in ({6: 1788914655, 1: 'issuer'}, {}, {6: -1}, {6: 'today'}):
            with self.subTest(claims=claims):
                result = self.mint({1: -8, 395: 1, 15: claims})
                self.assertFalse(result['verified'], result)

    def test_registered_cwt_claim_beside_iat_is_refused_as_unreviewed(self):
        # iss is the claim the witness expects to add next. Refusing it is the
        # agreed profile, so the message has to say so rather than read as a
        # malformed-receipt error, which is what would send the debugging to
        # the wrong side of the wire.
        result = self.mint({1: -8, 395: 1, 15: {6: 1788914655, 1: 'witness.example'}})
        self.assertFalse(result['verified'], result)
        self.assertIn('unreviewed CWT claims', result['error'])
        self.assertIn('LIMITATIONS.md', result['error'])

    def test_iat_before_the_checkpoint_is_refused(self):
        # A witness cannot have registered a checkpoint that did not yet exist.
        result = self.mint({1: -8, 395: 1, 15: {6: CHECKPOINT_EPOCH - 1}})
        self.assertFalse(result['verified'], result)
        self.assertIn('precedes the checkpoint', result['error'])
        result = self.mint({1: -8, 395: 1, 15: {6: 1}})
        self.assertFalse(result['verified'], result)

    def test_implausibly_late_iat_is_refused(self):
        result = self.mint({1: -8, 395: 1, 15: {6: CHECKPOINT_EPOCH + 31 * 86400}})
        self.assertFalse(result['verified'], result)
        self.assertIn('implausibly long after', result['error'])

    def test_iat_on_the_checkpoint_second_is_accepted(self):
        # The bound is inclusive at both ends, so a witness registering in the
        # same second as the checkpoint is not rejected off by one.
        result = self.mint({1: -8, 395: 1, 15: {6: CHECKPOINT_EPOCH}})
        self.assertTrue(result['verified'], result)
        self.assertTrue(result['limits']['witness_time_established'])

    def test_neither_field_present_is_the_pre_fix_shape(self):
        result = self.mint({1: -8, 395: 1})
        self.assertTrue(result['verified'], result)
        self.assertIsNone(result['signed_iat'])
        self.assertIsNone(result['signed_grade'])
        self.assertFalse(any(result['limits'].values()))


class PostDeployWitnessHeaderTests(unittest.TestCase):
    """The header shape the witness operator decoded after their deploy.

    Reported on September 12, 2026 from a real submission through their live
    service: {1: -8, 395: 1, 15: {6: 1789172972}, -65537: 'mmr-verified'}.
    That submission was to asg-selftest/v1, a native log, not to this
    registry. trace-registry/v1 is enrolled as a foreign accumulator and its
    receipts will carry countersigned-observed; ForeignAccumulatorGradeTests
    below pins that shape.
    These receipts are minted here, as in the class above, so nothing asserts
    that their service produced anything. What is pinned is what our verifier
    does when a receipt of that shape arrives, before one ever does.
    """

    setUp = WitnessReceiptTests.setUp
    check = WitnessReceiptTests.check
    mint = SignedReceiptMetadataTests.mint

    REPORTED_IAT = 1789172972
    REPORTED_GRADE = 'mmr-verified'

    def _header(self, grade=None, iat=None):
        return {1: -8, 395: 1,
                15: {6: self.REPORTED_IAT if iat is None else iat},
                -65537: self.REPORTED_GRADE if grade is None else grade}

    def test_both_fields_bind_when_the_response_grade_agrees(self):
        result = self.mint(self._header(), grade=self.REPORTED_GRADE)
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['signed_iat'], self.REPORTED_IAT)
        self.assertEqual(result['signed_grade'], self.REPORTED_GRADE)
        self.assertTrue(result['limits']['witness_time_established'])
        self.assertTrue(result['limits']['grade_cryptographically_bound'])

    def test_signed_grade_alone_does_not_bind_it(self):
        """The half of the upgrade that is easy to miss.

        A witness that starts signing a grade while its response body still
        reports the previous one has moved one of the two values this field
        compares. A signed value disagreeing with the untrusted one binds
        nothing, so the field stays false and the receipt still verifies.
        """
        result = self.mint(self._header(), grade='countersigned-observed')
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['signed_grade'], self.REPORTED_GRADE)
        self.assertEqual(result['reported_grade'], 'countersigned-observed')
        self.assertTrue(result['limits']['witness_time_established'])
        self.assertFalse(result['limits']['grade_cryptographically_bound'])

    def test_the_grade_string_is_opaque_and_not_fixed_by_agreement(self):
        """countersigned-observed and mmr-verified are both just strings here.

        The bilateral agreement fixes the label (-65537), not the value. A
        verifier that hardcoded either term would have broken on this deploy.
        """
        for value in ('countersigned-observed', 'mmr-verified', 'anything-else'):
            with self.subTest(grade=value):
                result = self.mint(self._header(grade=value), grade=value)
                self.assertTrue(result['verified'], result)
                self.assertEqual(result['signed_grade'], value)
                self.assertTrue(result['limits']['grade_cryptographically_bound'])

    def test_the_reported_iat_falls_inside_the_accepted_window(self):
        """The bound is relative to the checkpoint, not to wall clock.

        Checkpoint 1 is timestamped 2026-09-01T21:39:37Z and the reported iat
        is about ten days later, so a receipt of this shape would be accepted
        for it on the clock alone. It is the deduplication described in
        LIMITATIONS.md, not this bound, that keeps checkpoint 1 from ever
        carrying one.
        """
        from trace_verify._witness import MAX_REGISTRATION_DELAY_SECONDS
        self.assertGreaterEqual(self.REPORTED_IAT, CHECKPOINT_EPOCH)
        self.assertLessEqual(self.REPORTED_IAT,
                             CHECKPOINT_EPOCH + MAX_REGISTRATION_DELAY_SECONDS)


class ForeignAccumulatorGradeTests(unittest.TestCase):
    """The grade this registry's receipts will actually carry.

    trace-registry/v1 is enrolled with the witness as a foreign accumulator:
    observed, timestamped and countersigned, with this log's own consistency
    proofs not verified by the witness. Its honest grade is
    countersigned-observed, the operator's conformance checker refuses to
    present a foreign accumulator as mmr-verified, and on the next checkpoint
    the signed header and the response body will both say
    countersigned-observed.

    The question the operator asked on September 12 was whether
    grade_cryptographically_bound tests agreement or equality to mmr-verified.
    These pin the answer: agreement, and a matching countersigned-observed binds.
    """

    setUp = WitnessReceiptTests.setUp
    check = WitnessReceiptTests.check
    mint = SignedReceiptMetadataTests.mint

    FOREIGN_GRADE = 'countersigned-observed'

    def test_agreeing_countersigned_observed_binds_both_fields(self):
        header = {1: -8, 395: 1, 15: {6: CHECKPOINT_EPOCH + 3600},
                  -65537: self.FOREIGN_GRADE}
        result = self.mint(header, grade=self.FOREIGN_GRADE)
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['signed_grade'], self.FOREIGN_GRADE)
        self.assertEqual(result['reported_grade'], self.FOREIGN_GRADE)
        self.assertTrue(result['limits']['witness_time_established'])
        self.assertTrue(result['limits']['grade_cryptographically_bound'],
                        'a matching foreign-accumulator grade must bind')

    def test_disagreement_fails_in_either_direction(self):
        header = {1: -8, 395: 1, 15: {6: CHECKPOINT_EPOCH + 3600},
                  -65537: self.FOREIGN_GRADE}
        result = self.mint(header, grade='mmr-verified')
        self.assertTrue(result['verified'], result)
        self.assertFalse(result['limits']['grade_cryptographically_bound'])

    def test_the_verifier_names_no_grade_value(self):
        """Agreement is structural, not a property of today's strings.

        If either term ever appears in the verifier, the field has started
        preferring a value, which is the conflation the operator asked about.
        """
        source = (Path(__file__).resolve().parents[1] / 'src' / 'trace_verify'
                  / '_witness.py').read_text(encoding='utf-8')
        code = '\n'.join(line for line in source.splitlines()
                         if not line.lstrip().startswith('#'))
        for term in ('mmr-verified', 'countersigned-observed'):
            self.assertNotIn(term, code)
