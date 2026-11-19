"""The second witness's receipts for checkpoints 1 and 2, checked offline as captured."""
import copy
import hashlib
import json
import re
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

# Each anchored ledger entry in the packet: its record, the SHA-256 its proof commits to, and the
# Bitcoin height of its own proof. Entry 127 fixes the witness key and the first tree head; entry 143
# corrects how entry 127 describes the witness. The two heights must never stand in for each other.
ENTRY_127 = ('jidec-127.txt', '6d8ff0fbc1e2d3d0e3ef2e03b22be891c0cd380dba80d16153861894ec4ced67', 972264)
ENTRY_143 = ('jidec-143.txt', '79837a3a2e557c34ec194f940ca2fd1f1934eb0874fed8b48d84738dde5b4eed', 972850)
OTS_MAGIC = b'\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94'
BTC_TAG = bytes.fromhex('0588960d73d71901')


def read_entry(entry):
    return (PACKET / entry[0]).read_bytes(), (PACKET / (entry[0] + '.ots')).read_bytes()


def _varuint(data, i):
    value, shift = 0, 0
    while True:
        byte = data[i]
        i += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def bitcoin_heights(proof):
    """Heights of the Bitcoin attestations in a proof, read structurally: tag, payload length, height varint.

    A structural read of the bytes, not an evaluation of the operation chain. None if an attestation is cut short.
    """
    heights, i = [], proof.find(BTC_TAG)
    while i != -1:
        try:
            size, start = _varuint(proof, i + len(BTC_TAG))
            height, end = _varuint(proof, start)
        except IndexError:
            return None
        if end != start + size or end > len(proof):
            return None
        heights.append(height)
        i = proof.find(BTC_TAG, end)
    return heights


def anchor_problems(record, proof, digest_hex, height):
    """What is wrong with this record and proof as one anchored entry; [] if nothing."""
    problems = []
    claim = hashlib.sha256(record).digest()
    if claim.hex() != digest_hex:
        problems.append('record SHA-256 is not the expected digest')
    head = len(OTS_MAGIC)
    if not proof.startswith(OTS_MAGIC):
        problems.append('no OpenTimestamps magic')
    elif proof[head:head + 2] != b'\x01\x08':
        problems.append('not version 1 with file hash op sha256')
    elif proof[head + 2:head + 34] != claim:
        problems.append('proof commits to another digest')
    heights = bitcoin_heights(proof)
    if heights != [height]:
        problems.append(f'Bitcoin attestation heights {heights}, expected exactly [{height}]')
    return problems


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
        head = (PACKET / 'witness-tree-heads.ndjson').read_bytes().split(b'\n')[0]
        head_sha = hashlib.sha256(head).hexdigest()
        self.assertEqual(head_sha, 'aaf55bf7163e08c30fa22b4cf0dfe13bbbc37f6876c6c66fff5b0f776b90ef8d')
        record = (PACKET / 'jidec-127.txt').read_bytes()
        self.assertIn(head_sha.encode(), record)
        self.assertIn(WITNESS_KEY.encode(), record)
        claim = hashlib.sha256(record).digest()
        self.assertEqual(claim.hex(), ENTRY_127[1])
        proof = (PACKET / 'jidec-127.txt.ots').read_bytes()
        self.assertTrue(proof.startswith(OTS_MAGIC))
        # version 1, file hash op sha256 (0x08), then the 32-byte digest the proof commits to
        self.assertEqual(proof[len(OTS_MAGIC):len(OTS_MAGIC) + 2], b'\x01\x08')
        self.assertEqual(proof[len(OTS_MAGIC) + 2:len(OTS_MAGIC) + 34], claim)
        # the Bitcoin attestation: its tag, a 3-byte payload, height 972264 as a varint
        self.assertIn(BTC_TAG + bytes.fromhex('03' 'e8ab3b'), proof)
        self.assertEqual(anchor_problems(*read_entry(ENTRY_127), *ENTRY_127[1:]), [])

    def test_correction_anchor_offline(self):
        record, proof = read_entry(ENTRY_143)
        claim = hashlib.sha256(record).digest()
        self.assertEqual(claim.hex(), '79837a3a2e557c34ec194f940ca2fd1f1934eb0874fed8b48d84738dde5b4eed')
        self.assertTrue(proof.startswith(OTS_MAGIC))
        self.assertEqual(proof[len(OTS_MAGIC):len(OTS_MAGIC) + 2], b'\x01\x08')
        self.assertEqual(proof[len(OTS_MAGIC) + 2:len(OTS_MAGIC) + 34], claim)
        # height 972850 as a varint
        self.assertIn(BTC_TAG + bytes.fromhex('03' 'b2b03b'), proof)
        self.assertEqual(anchor_problems(record, proof, *ENTRY_143[1:]), [])
        # the correction cites the entry it corrects by that entry's SHA-256
        self.assertIn(ENTRY_127[1].encode(), record)

    def test_the_two_heights_are_separate(self):
        own_127 = bitcoin_heights(read_entry(ENTRY_127)[1])
        own_143 = bitcoin_heights(read_entry(ENTRY_143)[1])
        self.assertEqual(own_127, [972264])
        self.assertEqual(own_143, [972850])
        # jidec-143.txt names a height only in its "What it corrects" block: that is entry 127's height
        record = read_entry(ENTRY_143)[0].decode('utf-8')
        corrects = record.split('## What it corrects', 1)[1].split('\n## ', 1)[0]
        self.assertEqual(re.findall(r'claim sha256\s+([0-9a-f]{64})', corrects), [ENTRY_127[1]])
        named = [int(h) for h in re.findall(r'Bitcoin block (\d+)', record)]
        self.assertEqual(named, [int(h) for h in re.findall(r'stamped to\s+Bitcoin block (\d+)', corrects)])
        self.assertEqual(named, own_127)
        self.assertNotIn(own_143[0], named)
        # the README's table gives each entry its own height, and it matches the proofs
        rows = re.findall(r'^\| `(jidec-\d+\.txt)` \|[^|]*\| `([0-9a-f]{64})` \| `(jidec-\d+\.txt\.ots)` \| (\d+) \|$',
                          (PACKET / 'README.md').read_text(encoding='utf-8'), re.M)
        self.assertEqual(rows, [(e[0], e[1], e[0] + '.ots', str(e[2])) for e in (ENTRY_127, ENTRY_143)])

    def test_swapped_or_altered_correction_proof_rejected(self):
        record_127, proof_127 = read_entry(ENTRY_127)
        record_143, proof_143 = read_entry(ENTRY_143)
        expect_143 = ENTRY_143[1:]
        # entry 127's proof in place of the correction's, and the reverse
        self.assertNotEqual(anchor_problems(record_143, proof_127, *expect_143), [])
        self.assertNotEqual(anchor_problems(record_127, proof_143, *ENTRY_127[1:]), [])
        # the correction checked against entry 127's height, the misreading this test exists for
        self.assertNotEqual(anchor_problems(record_143, proof_143, ENTRY_143[1], ENTRY_127[2]), [])
        # the correction's proof with its height bytes swapped for entry 127's: the digest still matches
        swapped = proof_143.replace(BTC_TAG + bytes.fromhex('03b2b03b'), BTC_TAG + bytes.fromhex('03e8ab3b'))
        self.assertNotEqual(swapped, proof_143)
        self.assertEqual(swapped[len(OTS_MAGIC) + 2:len(OTS_MAGIC) + 34], hashlib.sha256(record_143).digest())
        self.assertNotEqual(anchor_problems(record_143, swapped, *expect_143), [])
        # truncated: before the Bitcoin attestation, inside it, and inside the digest
        cut = proof_143.find(BTC_TAG)
        for n in (cut, cut + 10, len(OTS_MAGIC) + 20):
            self.assertNotEqual(anchor_problems(record_143, proof_143[:n], *expect_143), [], n)
        # a second Bitcoin attestation appended
        self.assertNotEqual(anchor_problems(record_143, proof_143 + BTC_TAG + bytes.fromhex('03e8ab3b'), *expect_143), [])
        # the record altered by one byte
        self.assertNotEqual(anchor_problems(record_143.replace(b'972264', b'972850'), proof_143, *expect_143), [])

    def test_sha256sums_match_the_packet(self):
        lines = (PACKET / 'SHA256SUMS').read_text(encoding='utf-8').splitlines()
        listed = dict(reversed(line.split('  ', 1)) for line in lines)
        self.assertEqual(set(listed), {p.name for p in PACKET.iterdir()} - {'SHA256SUMS'})
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
