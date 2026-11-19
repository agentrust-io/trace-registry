"""Real worker termination and SQLite commit refusal at submission boundaries."""
from contextlib import contextmanager
from pathlib import Path
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from witness_journal import Journal

POLICY = dict(witness_base='https://witness.example', expected_log_id='test',
              registry_key='registry', witness_key='witness')


def _worker(database, identity, root, phase):
    root = Path(root)

    def pause():
        (root / 'ready').write_text('ready')
        while True:
            time.sleep(0.02)

    original = Journal.connect

    @contextmanager
    def connect(self):
        with original(self) as db:
            yield db
            if phase == 'before_claim_commit' and db.in_transaction:
                pause()

    def capture(**kwargs):
        if phase == 'after_claim_commit':
            pause()
        # A durable synthetic effect, not an external witness submission.
        with (root / 'effects').open('a') as output:
            output.write('committed\n')
            output.flush()
            os.fsync(output.fileno())
        (kwargs['out'] / 'receipt').write_text('retained synthetic receipt')
        if phase == 'after_remote_effect':
            pause()
        return 0

    with patch.object(Journal, 'connect', connect), patch(
        'capture_witness_receipt.capture', side_effect=capture
    ):
        Journal(database).submit(identity, root / 'evidence')
        if phase == 'after_final_commit':
            pause()


class JournalCrashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _setup(self, name):
        root = self.root / name
        root.mkdir()
        journal = Journal(root / 'state.db')
        identity = journal.enqueue(b'{}', **POLICY)
        return root, journal, identity

    def _process(self, root, journal, identity, phase):
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), '--worker',
             str(journal.path), identity, str(root), phase],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(self._stop, process)
        return process

    @staticmethod
    def _stop(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)

    def test_killed_workers_preserve_claim_and_never_repeat_effect(self):
        cases = (
            ('before_claim_commit', 'pending', 0),
            ('after_claim_commit', 'inflight', 0),
            ('after_remote_effect', 'inflight', 1),
            ('after_final_commit', 'verified', 1),
        )
        for phase, expected_state, effects in cases:
            with self.subTest(phase=phase):
                root, journal, identity = self._setup(phase)
                process = self._process(root, journal, identity, phase)
                deadline = time.monotonic() + 15
                while not (root / 'ready').exists():
                    if process.poll() is not None:
                        _, error = process.communicate(timeout=10)
                        self.fail(f'worker exited before boundary: {error}')
                    if time.monotonic() >= deadline:
                        self.fail('worker did not reach boundary')
                    time.sleep(0.02)
                process.kill()
                process.communicate(timeout=10)
                self.assertNotEqual(process.returncode, 0)
                reopened = Journal(journal.path)
                self.assertEqual(reopened.status(identity)['state'], expected_state)
                effect_file = root / 'effects'
                self.assertEqual(len(effect_file.read_text().splitlines())
                                 if effect_file.exists() else 0, effects)
                with patch('capture_witness_receipt.capture') as capture:
                    if expected_state == 'pending':
                        # The directory was created before commit. Recovery is
                        # deliberately manual; it must not be overwritten.
                        with self.assertRaises(FileExistsError):
                            reopened.submit(identity, root / 'evidence')
                    else:
                        self.assertFalse(reopened.submit(identity, root / 'evidence'))
                    capture.assert_not_called()
                if effects:
                    self.assertEqual((root / 'evidence' / identity / 'receipt').read_text(),
                                     'retained synthetic receipt')

    def test_uninterrupted_worker_is_the_positive_twin(self):
        root, journal, identity = self._setup('success')
        process = self._process(root, journal, identity, 'success')
        _, error = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, error)
        self.assertEqual(Journal(journal.path).status(identity)['state'], 'verified')
        self.assertEqual((root / 'effects').read_text().splitlines(), ['committed'])
        with patch('capture_witness_receipt.capture') as capture:
            self.assertFalse(Journal(journal.path).submit(identity, root / 'evidence'))
            capture.assert_not_called()

    def test_sqlite_commit_refusal_cannot_report_verified_or_retry(self):
        for fail_commit, expected_state, effects in ((1, 'pending', 0), (2, 'inflight', 1)):
            with self.subTest(commit=fail_commit):
                root, journal, identity = self._setup(f'commit-{fail_commit}')
                original = journal.connect
                commits = 0

                @contextmanager
                def connect():
                    with original() as db:
                        def authorize(action, operation, _arg2, _database, _trigger):
                            nonlocal commits
                            if action == sqlite3.SQLITE_TRANSACTION and operation == 'COMMIT':
                                commits += 1
                                if commits == fail_commit:
                                    return sqlite3.SQLITE_DENY
                            return sqlite3.SQLITE_OK
                        db.set_authorizer(authorize)
                        yield db

                def capture(**kwargs):
                    (kwargs['out'] / 'receipt').write_text('retained')
                    return 0

                with patch.object(journal, 'connect', connect), patch(
                    'capture_witness_receipt.capture', side_effect=capture
                ) as submit:
                    with self.assertRaises(sqlite3.DatabaseError):
                        journal.submit(identity, root / 'evidence')
                    self.assertEqual(submit.call_count, effects)
                reopened = Journal(journal.path)
                self.assertEqual(reopened.status(identity)['state'], expected_state)
                if effects:
                    self.assertEqual((root / 'evidence' / identity / 'receipt').read_text(),
                                     'retained')
                with patch('capture_witness_receipt.capture') as submit:
                    if expected_state == 'pending':
                        with self.assertRaises(FileExistsError):
                            reopened.submit(identity, root / 'evidence')
                    else:
                        self.assertFalse(reopened.submit(identity, root / 'evidence'))
                    submit.assert_not_called()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--worker':
        _worker(*sys.argv[2:])
    else:
        unittest.main()
