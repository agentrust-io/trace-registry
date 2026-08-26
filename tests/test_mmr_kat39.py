# SPDX-License-Identifier: Apache-2.0
"""KAT39: the 39-node MMRIVER-draft known-answer-test vector.

Ported from ``capsule_emit``'s ``tests/checkpoint/test_mmr_kat39.py`` (itself
ported from ``capsule_ledger``), which pins the same production hash
construction this module reuses (``trace_verify._mmr``). Keeping the exact
same KAT here, unmodified, is what proves this repository's MMR is bit-for-
bit compatible with the CLL implementation those packages already ship --
not merely "structurally similar."

The leaf/node/peak constants below are copied verbatim (attributed) from
``mmr/draft_kat39_test.go`` in
https://github.com/datatrails/go-datatrails-merklelog/blob/main/mmr/draft_kat39_test.go
Copyright (c) datatrails/forestrie -- MIT licensed
(https://github.com/datatrails/go-datatrails-merklelog/blob/main/LICENSE).

Key convention: the upstream ``KAT39PeakIndices``/``KAT39PeakHashes`` maps
are keyed by "mmrIndex" -- the 0-based position of the *last* node currently
in the store, i.e. ``size - 1`` in this module's ``size`` (node-count)
convention: for a map key ``mmr_index``, the corresponding call is
``core.peaks(mmr_index + 1)``.

Leaves are fed into ``add_leaf`` pre-hashed (``KAT39_LEAVES[i]`` used
directly as the ``leaf`` argument, skipping this module's own ``leaf_hash``)
-- mirroring the reference's own ``AddHashedLeaf(db, hasher, leafHash)`` API.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from trace_verify import _mmr as core

# fmt: off
KAT39_LEAVES = [
    "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
    "cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50",
    "d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975",
    "8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc",
    "a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2",
    "4c0e071832d527694adea57b50dd7b2164c2a47c02940dcf26fa07c44d6d222a",
    "8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7",
    "0b5000b73a53f0916c93c68f4b9b6ba8af5a10978634ae4f2237e1f3fbe324fa",
    "e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504",
    "998e907bfbb34f71c66b6dc6c40fe98ca6d2d5a29755bc5a04824c36082a61d1",
    "5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d",
    "1b8d0103e3a8d9ce8bda3bff71225be4b5bb18830466ae94f517321b7ecc6f94",
    "7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c",
    "aed2b8245fdc8acc45eda51abc7d07e612c25f05cadd1579f3474f0bf1f6bdc6",
    "561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213",
    "1209fe3bc3497e47376dfbd9df0600a17c63384c85f859671956d8289e5a0be8",
    "1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b",
    "707d56f1f282aee234577e650bea2e7b18bb6131a499582be18876aba99d4b60",
    "4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786",
    "0764c726a72f8e1d245f332a1d022fffdada0c4cb2a016886e4b33b66cb9a53f",
    "e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785",
]

KAT39_NODES = [
    "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
    "cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50",
    "ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8",
    "d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975",
    "8005f02d43fa06e7d0585fb64c961d57e318b27a145c857bcd3a6bdb413ff7fc",
    "9a18d3bc0a7d505ef45f985992270914cc02b44c91ccabba448c546a4b70f0f0",
    "827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
    "a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2",
    "4c0e071832d527694adea57b50dd7b2164c2a47c02940dcf26fa07c44d6d222a",
    "b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d",
    "8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7",
    "0b5000b73a53f0916c93c68f4b9b6ba8af5a10978634ae4f2237e1f3fbe324fa",
    "6f3360ad3e99ab4ba39f2cbaf13da56ead8c9e697b03b901532ced50f7030fea",
    "508326f17c5f2769338cb00105faba3bf7862ca1e5c9f63ba2287e1f3cf2807a",
    "78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
    "e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504",
    "998e907bfbb34f71c66b6dc6c40fe98ca6d2d5a29755bc5a04824c36082a61d1",
    "f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21",
    "5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d",
    "1b8d0103e3a8d9ce8bda3bff71225be4b5bb18830466ae94f517321b7ecc6f94",
    "0a4d7e66c92de549b765d9e2191027ff2a4ea8a7bd3eb04b0ed8ee063bad1f70",
    "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710",
    "7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c",
    "aed2b8245fdc8acc45eda51abc7d07e612c25f05cadd1579f3474f0bf1f6bdc6",
    "dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae",
    "561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213",
    "1209fe3bc3497e47376dfbd9df0600a17c63384c85f859671956d8289e5a0be8",
    "6b4a3bd095c63d1dffae1ac03eb8264fdce7d51d2ac26ad0ebf9847f5b9be230",
    "4459f4d6c764dbaa6ebad24b0a3df644d84c3527c961c64aab2e39c58e027eb1",
    "77651b3eec6774e62545ae04900c39a32841e2b4bac80e2ba93755115252aae1",
    "d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
    "1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b",
    "707d56f1f282aee234577e650bea2e7b18bb6131a499582be18876aba99d4b60",
    "0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f",
    "4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786",
    "0764c726a72f8e1d245f332a1d022fffdada0c4cb2a016886e4b33b66cb9a53f",
    "c861552e9e17c41447d375c37928f9fa5d387d1e8470678107781c20a97ebc8f",
    "6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa",
    "e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785",
]

KAT39_PEAK_INDICES = {
    0: [0],
    2: [2],
    3: [2, 3],
    6: [6],
    7: [6, 7],
    9: [6, 9],
    10: [6, 9, 10],
    14: [14],
    15: [14, 15],
    17: [14, 17],
    18: [14, 17, 18],
    21: [14, 21],
    22: [14, 21, 22],
    24: [14, 21, 24],
    25: [14, 21, 24, 25],
    30: [30],
    31: [30, 31],
    33: [30, 33],
    34: [30, 33, 34],
    37: [30, 37],
    38: [30, 37, 38],
}

KAT39_PEAK_HASHES = {
    0: ["af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"],
    2: ["ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8"],
    3: ["ad104051c516812ea5874ca3ff06d0258303623d04307c41ec80a7a18b332ef8",
        "d5688a52d55a02ec4aea5ec1eadfffe1c9e0ee6a4ddbe2377f98326d42dfc975"],
    6: ["827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88"],
    7: ["827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
        "a3eb8db89fc5123ccfd49585059f292bc40a1c0d550b860f24f84efb4760fbf2"],
    9: ["827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
        "b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d"],
    10: ["827f3213c1de0d4c6277caccc1eeca325e45dfe2c65adce1943774218db61f88",
         "b8faf5f748f149b04018491a51334499fd8b6060c42a835f361fa9665562d12d",
         "8d85f8467240628a94819b26bee26e3a9b2804334c63482deacec8d64ab4e1e7"],
    14: ["78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112"],
    15: ["78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
         "e66c57014a6156061ae669809ec5d735e484e8fcfd540e110c9b04f84c0b4504"],
    17: ["78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
         "f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21"],
    18: ["78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
         "f4a0db79de0fee128fbe95ecf3509646203909dc447ae911aa29416bf6fcba21",
         "5bc67471c189d78c76461dcab6141a733bdab3799d1d69e0c419119c92e82b3d"],
    21: ["78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
         "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710"],
    22: ["78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
         "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710",
         "7a42e3892368f826928202014a6ca95a3d8d846df25088da80018663edf96b1c"],
    24: ["78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
         "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710",
         "dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae"],
    25: ["78b2b4162eb2c58b229288bbcb5b7d97c7a1154eed3161905fb0f180eba6f112",
         "61b3ff808934301578c9ed7402e3dd7dfe98b630acdf26d1fd2698a3c4a22710",
         "dd7efba5f1824103f1fa820a5c9e6cd90a82cf123d88bd035c7e5da0aba8a9ae",
         "561f627b4213258dc8863498bb9b07c904c3c65a78c1a36bca329154d1ded213"],
    30: ["d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7"],
    31: ["d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
         "1664a6e0ea12d234b4911d011800bb0f8c1101a0f9a49a91ee6e2493e34d8e7b"],
    33: ["d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
         "0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f"],
    34: ["d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
         "0c9f36783b5929d43c97fe4b170d12137e6950ef1b3a8bd254b15bbacbfdee7f",
         "4d75f61869104baa4ccff5be73311be9bdd6cc31779301dfc699479403c8a786"],
    37: ["d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
         "6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa"],
    38: ["d4fb5649422ff2eaf7b1c0b851585a8cfd14fb08ce11addb30075a96309582a7",
         "6a169105dcc487dbbae5747a0fd9b1d33a40320cf91cf9a323579139e7ff72aa",
         "e9a5f5201eb3c3c856e0a224527af5ac7eb1767fb1aff9bd53ba41a60cde9785"],
}
# fmt: on


def _build_kat39_store() -> core.MemoryNodeStore:
    store = core.MemoryNodeStore()
    for leaf_hex in KAT39_LEAVES:
        core.add_leaf(store, bytes.fromhex(leaf_hex))
    return store


class TestKat39(unittest.TestCase):
    def test_node_positions_match_reference(self):
        store = _build_kat39_store()
        self.assertEqual(store.size(), len(KAT39_NODES))
        for pos, expected_hex in enumerate(KAT39_NODES):
            self.assertEqual(store.node(pos).hex(), expected_hex, f"node position {pos}")

    def test_leaf_zero_is_untransformed(self):
        self.assertEqual(KAT39_NODES[0], KAT39_LEAVES[0])

    def test_peak_positions_and_hashes_match_reference_for_every_size(self):
        store = _build_kat39_store()
        for mmr_index, expected_peak_positions in KAT39_PEAK_INDICES.items():
            size = mmr_index + 1
            pks = core.peaks(size)
            self.assertEqual(pks, expected_peak_positions, f"mmr_index={mmr_index} (size={size})")

            expected_hashes = KAT39_PEAK_HASHES[mmr_index]
            actual_hashes = [store.node(p).hex() for p in pks]
            self.assertEqual(actual_hashes, expected_hashes, f"mmr_index={mmr_index} (size={size})")

    def test_inclusion_proofs_verify_for_every_leaf(self):
        store = _build_kat39_store()
        size = store.size()
        pks = core.peaks(size)
        root = core.root_from_peaks([store.node(p) for p in pks])

        for leaf_index, leaf_hex in enumerate(KAT39_LEAVES):
            # body_digest here is the raw pre-hashed leaf value itself, since
            # this test's tree skipped this module's own leaf_hash step on
            # the way in -- verify_inclusion always re-applies leaf_hash
            # internally, so fold the witness by hand with production
            # interior_hash instead of calling verify_inclusion directly.
            proof = core.inclusion_proof(store, leaf_index, size)
            acc = bytes.fromhex(leaf_hex)
            peak_pos, peak_height = self._peak_and_height_for(store, size, leaf_index)
            path = core._locate_path(peak_pos, peak_height, core.leaf_index_to_pos(leaf_index))
            self.assertEqual(len(path), len(proof.witness))
            for step, sib_hex in zip(path, proof.witness):
                sib = bytes.fromhex(sib_hex)
                acc = (
                    core.interior_hash(sib, acc, step.parent_pos)
                    if step.target_is_right
                    else core.interior_hash(acc, sib, step.parent_pos)
                )
            all_peaks = (
                [bytes.fromhex(h) for h in proof.peaks_left]
                + [acc]
                + [bytes.fromhex(h) for h in proof.peaks_right]
            )
            self.assertEqual(core.root_from_peaks(all_peaks), root)

    @staticmethod
    def _peak_and_height_for(store: core.MemoryNodeStore, size: int, leaf_index: int) -> tuple[int, int]:
        leaf_pos = core.leaf_index_to_pos(leaf_index)
        pks = core.peaks(size)
        idx = core._find_containing_peak(leaf_pos, pks)
        peak_pos = pks[idx]
        return peak_pos, core.height_at(peak_pos)

    def test_two_different_positions_same_content_produce_different_hashes(self):
        """Direct demonstration that position-commitment is doing real work:
        the same (left, right) pair hashed at two different positions must
        produce different interior hashes."""
        left = bytes.fromhex(KAT39_NODES[0])
        right = bytes.fromhex(KAT39_NODES[1])
        h_at_2 = core.interior_hash(left, right, 2)
        h_at_100 = core.interior_hash(left, right, 100)
        self.assertNotEqual(h_at_2, h_at_100)
        self.assertEqual(h_at_2.hex(), KAT39_NODES[2])


if __name__ == "__main__":
    unittest.main()
