import concurrent.futures
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from witness_journal import Journal

POLICY = dict(witness_base='https://witness.example', expected_log_id='test',
              registry_key='registry', witness_key='witness')


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = Journal(self.root / 'state.db')
        self.identity = self.journal.enqueue(b'{}', **POLICY)

    def test_idempotent_enqueue_and_policy_identity(self):
        self.assertEqual(self.identity, self.journal.enqueue(b'{}', **POLICY))
        self.assertNotEqual(self.identity, self.journal.enqueue(b'{ }', **POLICY))
        policy = {**POLICY, 'witness_key': 'rotated'}
        self.assertNotEqual(self.identity, self.journal.enqueue(b'{}', **policy))

    def test_concurrent_claim_has_one_submission(self):
        with patch('capture_witness_receipt.capture', return_value=0) as capture:
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                results = list(pool.map(lambda _: Journal(self.journal.path).submit(
                    self.identity, self.root / 'evidence'), range(2)))
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(self.journal.status(self.identity)['state'], 'verified')

    def test_failure_is_unknown_and_never_retried(self):
        with patch('capture_witness_receipt.capture', return_value=1) as capture:
            self.journal.submit(self.identity, self.root / 'evidence')
            self.assertFalse(Journal(self.journal.path).submit(self.identity, self.root / 'evidence'))
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(self.journal.status(self.identity)['state'], 'unknown')

    def test_lost_ack_exception_retains_unknown(self):
        with patch('capture_witness_receipt.capture', side_effect=ConnectionError('lost ack')):
            with self.assertRaises(ConnectionError):
                self.journal.submit(self.identity, self.root / 'evidence')
        self.assertEqual(self.journal.status(self.identity)['state'], 'unknown')

    def test_crash_inflight_cannot_be_reclaimed(self):
        with self.journal.connect() as db:
            db.execute("UPDATE submissions SET state='inflight' WHERE id=?", (self.identity,))
        with patch('capture_witness_receipt.capture') as capture:
            self.assertFalse(Journal(self.journal.path).submit(self.identity, self.root / 'evidence'))
        capture.assert_not_called()

    def test_existing_evidence_never_overwritten(self):
        directory = self.root / 'evidence' / self.identity
        directory.mkdir(parents=True)
        (directory / 'receipt').write_text('retained')
        with self.assertRaises(FileExistsError):
            self.journal.submit(self.identity, self.root / 'evidence')
        self.assertEqual((directory / 'receipt').read_text(), 'retained')
        self.assertEqual(self.journal.status(self.identity)['state'], 'pending')

    def test_archived_receipt_real_verification_and_wrong_key(self):
        from test_capture_witness_receipt import (
            BASE, LOG_ID, REGISTRY_KEY, WITNESS_KEY, _Transport, _routes, archived,
        )
        for key, expected in ((WITNESS_KEY, 'verified'), ('00' * 32, 'unknown')):
            with self.subTest(key=key):
                identity = self.journal.enqueue(archived('checkpoint-1.json'),
                    witness_base=BASE, expected_log_id=LOG_ID,
                    registry_key=REGISTRY_KEY, witness_key=key)
                with patch('capture_witness_receipt.urllib.request.urlopen', _Transport(_routes())):
                    self.journal.submit(identity, self.root / 'evidence')
                self.assertEqual(self.journal.status(identity)['state'], expected)
