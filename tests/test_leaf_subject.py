"""Entry subject declarations do not change legacy leaf bytes or guess objects."""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tools'), str(ROOT / 'tests'), str(ROOT)]
import anchor
import batch_anchor
import test_batch_anchor as fixtures
import verify_inclusion as standalone
from trace_verify.__main__ import main
from trace_verify._verify import resolve_leaf_subject, claim_leaf_subject
from trace_verify._checkpoint import entry_leaf_digest


class TestLeafSubject(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.TestScheduledFinalR()
        fixture.setUp()
        self.record = fixture.record
        self.envelope = fixture._envelope(self.record)
        self.raw = fixture._raw

    def _verify(self, subject, marker, mode, *, legacy=False):
        raw = self.raw(subject)
        root = anchor.leaf_hash(subject, canonicalization_id=mode, raw_bytes=raw)
        entry = anchor.make_entry(root, 1, 'test/1.0.0', 'batch', '2026-10-15T00:00:00Z',
                                  mode, marker)
        if legacy:
            entry.pop('leaf_subject')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/'claim').write_bytes(raw)
            (p/'entry').write_text(json.dumps(entry))
            (p/'proof').write_text('{"leaf_index":0,"audit_path":[]}')
            args = ['--claim', str(p/'claim'), '--entry', str(p/'entry'),
                    '--proof', str(p/'proof')]
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                rc = main(args + ['--no-verify-signature', '--json'])
                legacy_rc = standalone.main(args)
            return rc, legacy_rc, json.loads(out.getvalue().splitlines()[0])

    def test_marked_subject_twins_under_both_canonicalizations(self):
        for mode in ('sorted-key', 'as-transmitted'):
            for name, obj in [('envelope', self.envelope), ('record', self.record)]:
                with self.subTest(mode=mode, subject=name):
                    rc, standalone_rc, result = self._verify(obj, name, mode)
                    self.assertEqual((rc, standalone_rc), (0, 0))
                    self.assertEqual(result['leaf_subject'], name)
                    wrong = 'record' if name == 'envelope' else 'envelope'
                    rc, standalone_rc, result = self._verify(obj, wrong, mode)
                    self.assertEqual((rc, standalone_rc), (1, 1))
                    self.assertIn('leaf_subject', result['error'])

    def test_unmarked_retained_e_and_r_keep_their_actual_proofs(self):
        for mode in ('sorted-key', 'as-transmitted'):
            for name, obj in [('envelope', self.envelope), ('record', self.record)]:
                rc, standalone_rc, result = self._verify(obj, name, mode, legacy=True)
                self.assertEqual((rc, standalone_rc), (0, 0))
                self.assertEqual(result['leaf_subject'], name)
        self.assertEqual(resolve_leaf_subject({'ts': '2099-01-01T00:00:00Z'}), 'unknown')
        self.assertEqual(standalone.resolve_leaf_subject({}), 'unknown')

    def test_unknown_or_non_batch_marker_refuses(self):
        for value in (None, [], {}, 'unknown', 'Envelope', 1):
            with self.assertRaises(ValueError):
                resolve_leaf_subject({'leaf_subject': value}, self.record)
        with self.assertRaises(ValueError):
            resolve_leaf_subject({'entry_type': 'checkpoint', 'leaf_subject': 'record'})

    def test_scheduled_writer_declares_final_record_before_checkpoint(self):
        class Log:
            seen = None
            def append_entry(inner, entry, timestamp):
                inner.seen = dict(entry)
                class Checkpoint:
                    mmr_size = 1
                    key_id = 'test'
                    def to_dict(self):
                        return {'test': True}
                return Checkpoint()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            log = Log()
            result = batch_anchor.anchor_group('test/1.0.0',
                [(p/'envelope.json', self.envelope, self.raw(self.envelope))],
                '2026-10-15T00:00:00Z', 'batch', p/'registry', p/'proofs', False,
                checkpoint_log=log)
            entry = json.loads(Path(result['day_file']).read_text())
            self.assertEqual(log.seen['leaf_subject'], 'record')
            self.assertEqual(entry['leaf_subject'], 'record')
            changed = {**entry, 'leaf_subject': 'envelope'}
            self.assertNotEqual(entry_leaf_digest(entry), entry_leaf_digest(changed))
            from aggregator._mmr_log import CheckpointLog
            from trace_verify._checkpoint import verify_chain_against_entries
            signed_entry = dict(log.seen)
            signed_entry['mmr_checkpoint'] = CheckpointLog(p/'checkpoints').append_entry(
                signed_entry, timestamp='2026-10-15T00:00:00Z').to_dict()
            self.assertEqual(verify_chain_against_entries([signed_entry]), [])
            altered = {**signed_entry, 'leaf_subject': 'envelope'}
            self.assertTrue(verify_chain_against_entries([altered]))


    def test_http_writer_separates_envelope_and_record(self):
        from aggregator._core import TRACEAggregator
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            agg = TRACEAggregator(p/'registry', p/'proofs', verify_signatures=False,
                             enable_mmr_checkpoints=False)
            record = {**self.record, 'producer': self.envelope['producer']}
            completed, _ = agg._anchor_batch([
                ('e', self.envelope, 'sorted-key', None),
                ('r', record, 'sorted-key', None)])
            self.assertEqual(set(completed), {'e', 'r'})
            entries = [json.loads(line) for f in (p/'registry').rglob('*.ndjson')
                       for line in f.read_text().splitlines()]
            self.assertEqual({e['leaf_subject'] for e in entries}, {'envelope', 'record'})

    def test_manual_writer_marks_subject_and_refuses_mixed_batch(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            paths = []
            for name, obj in [('envelope', self.envelope), ('record', self.record)]:
                path = p/(name+'.json'); path.write_bytes(self.raw(obj)); paths.append(str(path))
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(anchor.main([str(path), '--producer', 'test/1.0.0',
                                                   '--proof-dir', str(p/name)]), 0)
                self.assertEqual(json.loads(out.getvalue())['leaf_subject'], name)
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                anchor.main(paths + ['--producer', 'test/1.0.0'])
            self.assertEqual(claim_leaf_subject(self.record), 'record')
