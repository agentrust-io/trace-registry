"""The second witness's receipts for checkpoints 1 and 2, checked offline as captured."""
import copy
import json
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from verify_witness_receipt import load_json, signing_body, signing_body_digest, verify

PACKET = ROOT / 'docs/evidence/witness-2026-10-20-nenrin'
REGISTRY_KEY = 'bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90'
WITNESS_KEY = 'c7c47d073a2c8b348d12c7207aaf7a403f5a3c2695227bf8ed2963ff52f98baf'
OTHER_WITNESS_KEY = '39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5'


def check(i, cp=None, response=None, **kw):
    args = dict(registry_key=REGISTRY_KEY, witness_key=WITNESS_KEY, expected_log_id='trace-registry/v1')
    args.update(kw)
    cp = load_json(PACKET / f'checkpoint-{i}.json') if cp is None else cp
    response = load_json(PACKET / f'witness-response-{i}.json') if response is None else response
    return verify(cp, response, **args)


class NenrinWitnessReceiptTests(unittest.TestCase):
    def test_both_receipts_verify_with_network_disabled(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            first, second = check(1), check(2)
        self.assertTrue(first['verified'], first)
        self.assertTrue(second['verified'], second)
        self.assertEqual((first['leaf_index'], first['tree_size']), (0, 1))
        self.assertEqual((second['leaf_index'], second['tree_size']), (1, 2))

    def test_limits_are_what_the_packet_states(self):
        first, second = check(1), check(2)
        self.assertTrue(first['limits']['grade_cryptographically_bound'])
        self.assertFalse(first['limits']['witness_time_established'])
        self.assertTrue(second['limits']['grade_cryptographically_bound'])
        self.assertTrue(second['limits']['witness_time_established'])
        self.assertEqual(second['signed_iat'], 1792467378)
        self.assertEqual(second['signed_grade'], 'mmr-verified')
        for r in (first, second):
            self.assertFalse(r['limits']['registry_continuity_established'])
            self.assertFalse(r['limits']['full_checkpoint_envelope_witnessed'])

    def test_checkpoint_1_is_the_one_the_first_witness_saw(self):
        first = check(1)
        self.assertEqual(first['checkpoint_signing_digest'],
                         '41138372adb1921186ca6a0dbc3433a0ea2f6475cb863205603ab1231968f99a')
        self.assertEqual(first['entry_hash'], load_json(ROOT / 'docs/evidence/witness-2026-09-07/witness-post.json')['entry_hash'])

    def test_checkpoint_2_is_the_registry_entry(self):
        line = (ROOT / 'registry/2026/09/25.ndjson').read_text(encoding='utf-8').splitlines()[0]
        cp = json.loads(line)['mmr_checkpoint']
        self.assertEqual(signing_body_digest(signing_body(cp)).hex(), check(2)['checkpoint_signing_digest'])

    def test_swapped_receipts_rejected(self):
        self.assertFalse(check(1, response=load_json(PACKET / 'witness-response-2.json'))['verified'])
        self.assertFalse(check(2, response=load_json(PACKET / 'witness-response-1.json'))['verified'])

    def test_wrong_witness_key_rejected(self):
        self.assertFalse(check(2, witness_key=OTHER_WITNESS_KEY)['verified'])

    def test_altered_checkpoint_rejected(self):
        cp = copy.deepcopy(load_json(PACKET / 'checkpoint-2.json'))
        cp['root'] = '00' * 32
        self.assertFalse(check(2, cp=cp)['verified'])

    def test_reported_grade_must_match_the_signed_one(self):
        response = copy.deepcopy(load_json(PACKET / 'witness-response-2.json'))
        response['grade'] = 'countersigned-observed'
        result = check(2, response=response)
        self.assertTrue(result['verified'])
        self.assertFalse(result['limits']['grade_cryptographically_bound'])


    def test_bitcoin_anchor_chain_offline(self):
        import hashlib
        head = (PACKET / 'witness-tree-heads.ndjson').read_bytes().split(b'\n')[0]
        head_sha = hashlib.sha256(head).hexdigest()
        self.assertEqual(head_sha, 'aaf55bf7163e08c30fa22b4cf0dfe13bbbc37f6876c6c66fff5b0f776b90ef8d')
        record = (PACKET / 'jidec-127.txt').read_bytes()
        self.assertIn(head_sha.encode(), record)
        self.assertIn(WITNESS_KEY.encode(), record)
        claim = hashlib.sha256(record).digest()
        self.assertEqual(claim.hex(), '6d8ff0fbc1e2d3d0e3ef2e03b22be891c0cd380dba80d16153861894ec4ced67')
        proof = (PACKET / 'jidec-127.txt.ots').read_bytes()
        magic = b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
        self.assertTrue(proof.startswith(magic))
        # version 1, file hash op sha256 (0x08), then the 32-byte digest the proof commits to
        self.assertEqual(proof[len(magic):len(magic) + 2], b'\x01\x08')
        self.assertEqual(proof[len(magic) + 2:len(magic) + 34], claim)
        # the Bitcoin attestation: its tag, a 3-byte payload, height 972264 as a varint
        self.assertIn(bytes.fromhex('0588960d73d71901' '03' 'e8ab3b'), proof)


if __name__ == '__main__':
    unittest.main()
