"""Persisted proof histories checked against a recursive forest oracle.

The oracle uses the documented position-committed hash preimages directly;
it does not call the implementation's hashing, size, peak or proof helpers.
These are synthetic algorithm checks, not external wire interoperability.
"""
from __future__ import annotations

import hashlib
import json
import unittest

from trace_verify import _mmr as core


def forest_oracle(bodies):
    def perfect(start, width, first_node):
        if width == 1:
            return hashlib.sha256(b"\x00" + bodies[start]).digest()
        half = width // 2
        left = perfect(start, half, first_node)
        right = perfect(start + half, half, first_node + width - 1)
        parent_position_plus_one = first_node + 2 * width - 1
        return hashlib.sha256(
            parent_position_plus_one.to_bytes(8, "big") + left + right
        ).digest()

    remaining, start, next_node = len(bodies), 0, 0
    peaks = []
    while remaining:
        width = 1 << (remaining.bit_length() - 1)
        peaks.append(perfect(start, width, next_node))
        remaining -= width
        start += width
        next_node += 2 * width - 1
    if not peaks:
        return bytes(32), 0
    root = peaks[-1]
    for peak in reversed(peaks[:-1]):
        root = hashlib.sha256(root + peak).digest()
    return root, next_node


class TestSerializedProofHistories(unittest.TestCase):
    def test_saved_prefix_proofs_survive_growth_and_refuse_forked_context(self):
        store = core.MemoryNodeStore()
        bodies = []
        snapshots = []
        checked = 0
        for count in range(1, 34):
            body = hashlib.sha256(b"independent-history/" + count.to_bytes(2, "big")).digest()
            bodies.append(body)
            core.add_leaf(store, core.leaf_hash(body))
            root, size = forest_oracle(bodies)
            self.assertEqual(store.size(), size)
            self.assertEqual(
                core.root_from_peaks([store.node(p) for p in core.peaks(size)]), root
            )
            inclusion = json.dumps(core.inclusion_proof(store, count - 1, size).to_dict())
            snapshots.append((root, size, body, inclusion, count - 1))
            for old_root, old_size, old_body, saved, index in snapshots:
                with self.subTest(count=count, prefix=index + 1):
                    proof = core.InclusionProof.from_dict(json.loads(saved))
                    self.assertTrue(
                        core.verify_inclusion(old_root, old_size, index, old_body, proof)
                    )
                    wrong_body = bytes([old_body[0] ^ 1]) + old_body[1:]
                    self.assertFalse(
                        core.verify_inclusion(old_root, old_size, index, wrong_body, proof)
                    )
                    if old_size != size:
                        self.assertFalse(
                            core.verify_inclusion(root, size, index, old_body, proof)
                        )
                    consistency = core.ConsistencyProof.from_dict(json.loads(json.dumps(
                        core.consistency_proof(store, old_size, size).to_dict()
                    )))
                    self.assertTrue(
                        core.verify_consistency(old_root, old_size, root, size, consistency)
                    )
                    wrong_root = bytes([root[0] ^ 1]) + root[1:]
                    self.assertFalse(
                        core.verify_consistency(
                            old_root, old_size, wrong_root, size, consistency
                        )
                    )
                    checked += 1
        self.assertEqual(checked, 561)

    def test_oracle_distinguishes_parent_position_and_peak_bag_order(self):
        bodies = [hashlib.sha256(bytes([i])).digest() for i in range(7)]
        root, size = forest_oracle(bodies)
        self.assertEqual(size, 11)
        self.assertEqual(
            root.hex(),
            "ca3dd1bd3b845ddb419dc97c65e8ee5a1d34d2fcb91bb46a8626d6b3c3645e14",
        )
        changed = list(bodies)
        changed[2], changed[3] = changed[3], changed[2]
        self.assertNotEqual(forest_oracle(changed)[0], root)


if __name__ == "__main__":
    unittest.main()
