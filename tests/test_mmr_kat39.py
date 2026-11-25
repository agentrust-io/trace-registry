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

The second half of the file runs the draft-mih-scitt-checkpointed-local-log-02
known-answer vectors (``tests/fixtures/cll-02/``, generated from the draft
text and not from any implementation; see issue #178): the 21-entry log at
every prefix, and the four-checkpoint chain with its negative cases. The
vectors' checkpoints are COSE; the registry's are JSON. ``_registry_checkpoint``
maps one onto the other as ``docs/mmr-checkpoint.md`` describes, so the chain
runs through ``trace_verify``'s own JSON checkpoint verifiers.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trace_verify import _checkpoint as checkpoint
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


# -- draft-mih-scitt-checkpointed-local-log-02 known-answer vectors -------------

ROOT = Path(__file__).resolve().parents[1]
CLL02_DIR = Path(__file__).resolve().parent / "fixtures" / "cll-02"
CLL02_BYTES = (CLL02_DIR / "vectors.json").read_bytes()
CLL02 = json.loads(CLL02_BYTES)
CLL02_LOG_ID = CLL02["conventions"]["log_identity"]["sub"]
# The vectors sign with the Ed25519 key whose seed is 0x07 repeated (see the
# fixture README). The registry signs JSON, not COSE, so mapped checkpoints are
# re-signed with the same key.
CLL02_KEY = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)


def _cbor_decode(data: bytes):
    """Decode the CBOR the -02 claims use: unsigned ints, byte and text strings,
    arrays and maps, definite lengths only."""
    value, end = _cbor_item(data, 0)
    if end != len(data):
        raise ValueError("trailing bytes after the CBOR item")
    return value


def _cbor_item(data: bytes, i: int):
    major, info = data[i] >> 5, data[i] & 0x1F
    i += 1
    if info < 24:
        n = info
    elif info < 28:
        width = 1 << (info - 24)
        n = int.from_bytes(data[i : i + width], "big")
        i += width
    else:
        raise ValueError("indefinite or reserved CBOR length")
    if major == 0:
        return n, i
    if major in (2, 3):
        raw = data[i : i + n]
        if len(raw) != n:
            raise ValueError("truncated CBOR string")
        return (raw if major == 2 else raw.decode("utf-8")), i + n
    if major == 4:
        items = []
        for _ in range(n):
            item, i = _cbor_item(data, i)
            items.append(item)
        return items, i
    if major == 5:
        entries = {}
        for _ in range(n):
            key, i = _cbor_item(data, i)
            entries[key], i = _cbor_item(data, i)
        return entries, i
    raise ValueError(f"CBOR major type {major} is not used by -02 claims")


def _cll02_store() -> core.MemoryNodeStore:
    store = core.MemoryNodeStore()
    for entry in CLL02["entries"]:
        core.add_leaf(store, core.leaf_hash(bytes.fromhex(entry)))
    return store


def _claims(vector: dict) -> dict:
    return _cbor_decode(bytes.fromhex(vector["claims_hex"]))


def _split_peaks(commitment: bytes) -> list:
    return [commitment[i : i + core.DIGEST_LEN] for i in range(0, len(commitment), core.DIGEST_LEN)]


def _bag(commitment: bytes) -> str:
    return core.root_from_peaks(_split_peaks(commitment)).hex()


def _reached_peaks(size_a: int, size_b: int) -> int:
    """How many peaks of MMR(size_b) hold an old peak of MMR(size_a): the ones the
    consistency-paths reach. The rest are the profile's right-peaks."""
    new = core.peaks(size_b)
    reached = set()
    for old in core.peaks(size_a):
        for index, peak in enumerate(new):
            if peak - (2 ** (core.height_at(peak) + 1) - 1) < old <= peak:
                reached.add(index)
    return len(reached)


def _registry_checkpoint(claims: dict, *, log_id: str = CLL02_LOG_ID) -> dict:
    """Map decoded -02 claims onto the registry's JSON checkpoint, as the field
    mapping in docs/mmr-checkpoint.md describes, and sign it."""
    commitment, prev_size = claims["commitment"], claims["prev_size"]
    body = {
        "v": 1,
        "kind": checkpoint.CHECKPOINT_KIND,
        "log_id": log_id,
        "mmr_size": claims["log_size"],
        "root": _bag(commitment),
        "prev_size": prev_size,
        "prev_root": _bag(claims["prev_commitment"]) if prev_size else "",
        "key_id": CLL02["kid"],
        "timestamp": claims["issued_at"],
    }
    unsigned = checkpoint.CheckpointRecord(**body, signature="")
    body["signature"] = CLL02_KEY.sign(unsigned.digest().encode("ascii")).hex()
    if "consistency_proof" in claims:
        size_a, size_b, paths, right_peaks = _cbor_decode(claims["consistency_proof"])
        reached = _reached_peaks(size_a, size_b)
        body["consistency_proof"] = {
            "v": 1,
            "kind": "consistency",
            "size_a": size_a,
            "size_b": size_b,
            "old_peaks": [p.hex() for p in _split_peaks(claims["prev_commitment"])],
            "witness": [[node.hex() for node in path] for path in paths],
            "new_peaks": [p.hex() for p in _split_peaks(commitment)[:reached]]
            + [p.hex() for p in right_peaks],
        }
    return body


def _record(body: dict) -> checkpoint.CheckpointRecord:
    # Through JSON and from_dict, the way a registry entry reaches the verifier.
    return checkpoint.CheckpointRecord.from_dict(json.loads(json.dumps(body)))


def _negative(vector: dict) -> checkpoint.CheckpointRecord:
    return _record(_registry_checkpoint(_claims(vector), log_id=vector["sub"]))


class Cll02Chain(unittest.TestCase):
    """Shared fixtures: the log, and the four vector checkpoints mapped to JSON."""

    @classmethod
    def setUpClass(cls):
        cls.store = _cll02_store()
        cls.claims = {cp["id"]: _claims(cp) for cp in CLL02["checkpoints"]}
        cls.cp = {name: _record(_registry_checkpoint(c)) for name, c in cls.claims.items()}
        cls.negatives = {n["id"]: n for n in CLL02["negative"]}


class TestCll02Fixture(unittest.TestCase):
    def test_file_matches_its_published_digest(self):
        digest, name = (CLL02_DIR / "SHA256SUMS").read_text().split()
        self.assertEqual(name, "vectors.json")
        self.assertEqual(hashlib.sha256(CLL02_BYTES).hexdigest(), digest)

    def test_docs_name_the_revisions_the_vectors_were_generated_for(self):
        self.assertEqual(CLL02["draft"], "draft-mih-scitt-checkpointed-local-log-02")
        self.assertEqual(CLL02["profile"]["draft"], "draft-bryce-cose-receipts-mmr-profile-03")
        docs = (ROOT / "docs" / "mmr-checkpoint.md").read_text(encoding="utf-8")
        for name in (CLL02["draft"], CLL02["profile"]["draft"], "draft-ietf-scitt-receipts-mmr-profile"):
            self.assertTrue(name in docs, f"docs/mmr-checkpoint.md does not name {name}")

    def test_entries_follow_the_published_convention(self):
        self.assertEqual(len(CLL02["entries"]), 21)
        for k, entry in enumerate(CLL02["entries"]):
            self.assertEqual(entry, hashlib.sha256(f"cll-02 vector entry {k}".encode()).hexdigest())

    def test_cbor_helper_decodes_the_vectors_own_rendering_and_refuses_the_rest(self):
        for cp in CLL02["checkpoints"]:
            claims = _claims(cp)
            self.assertEqual(claims["commitment"].hex(), cp["claims"]["commitment"])
            self.assertEqual(claims["log_size"], cp["claims"]["log_size"])
        for raw in (b"\x5f", b"\x42\x01", b"\x20", b"\x00\x00"):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                _cbor_decode(raw)


class TestCll02Log(unittest.TestCase):
    def test_nodes_match_the_vectors(self):
        store = _cll02_store()
        self.assertEqual([store.node(i).hex() for i in range(store.size())], CLL02["nodes"])

    def test_every_prefix_matches_node_count_peaks_and_commitment(self):
        store = core.MemoryNodeStore()
        self.assertEqual(len(CLL02["sizes"]), len(CLL02["entries"]) + 1)
        for leaves, row in enumerate(CLL02["sizes"]):
            if leaves:
                core.add_leaf(store, core.leaf_hash(bytes.fromhex(CLL02["entries"][leaves - 1])))
            with self.subTest(leaf_count=leaves, log_size=row["log_size"]):
                size = row["log_size"]
                self.assertEqual(row["leaf_count"], leaves)
                self.assertEqual(store.size(), size)  # log_size is the node count
                self.assertEqual(core.node_count(leaves), size)
                self.assertEqual(core.leaf_count(size), leaves)
                peaks = [store.node(p) for p in core.peaks(size)]
                self.assertEqual([p.hex() for p in peaks], row["peaks"])
                commitment = b"".join(peaks)  # tallest first
                self.assertEqual(commitment.hex(), row["commitment"])
                self.assertEqual(hashlib.sha256(commitment).hexdigest(), row["commitment_sha256"])


class TestCll02ChainVerification(Cll02Chain):
    def test_checkpoints_commit_to_the_log_at_their_size(self):
        for cp in CLL02["checkpoints"]:
            record = self.cp[cp["id"]]
            with self.subTest(checkpoint=cp["id"]):
                self.assertEqual(core.leaf_count(record.mmr_size), cp["leaves"])
                for size, root in ((record.mmr_size, record.root), (record.prev_size, record.prev_root)):
                    if size:
                        peaks = [self.store.node(p) for p in core.peaks(size)]
                        self.assertEqual(core.root_from_peaks(peaks).hex(), root)
                    else:
                        self.assertEqual(root, "")

    def test_registry_root_is_the_right_to_left_bag_of_the_vectors_peaks(self):
        # docs/mmr-checkpoint.md: the registry commits this where -02 commits the
        # concatenated peaks. Folded here without core.root_from_peaks.
        for name, claims in self.claims.items():
            peaks = _split_peaks(claims["commitment"])
            bag = peaks[-1]
            for peak in reversed(peaks[:-1]):
                bag = hashlib.sha256(bag + peak).digest()
            with self.subTest(checkpoint=name):
                self.assertEqual(self.cp[name].root, bag.hex())

    def test_mapped_proofs_are_the_proofs_trace_verify_generates(self):
        for name in ("cp2", "cp4"):
            record = self.cp[name]
            want = next(cp for cp in CLL02["checkpoints"] if cp["id"] == name)["consistency_proof"]
            with self.subTest(checkpoint=name):
                proof = record.consistency_proof
                self.assertEqual((proof.size_a, proof.size_b), (want["tree_size_1"], want["tree_size_2"]))
                self.assertEqual([list(w) for w in proof.witness], want["consistency_paths"])
                right = want["right_peaks"]
                self.assertEqual(list(proof.new_peaks[len(proof.new_peaks) - len(right) :]), right)
                generated = core.consistency_proof(self.store, record.prev_size, record.mmr_size)
                self.assertEqual(proof.to_dict(), generated.to_dict())

    def test_signatures_verify_offline_under_the_vectors_key(self):
        public = CLL02_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.assertEqual(public.hex(), CLL02["kid"])
        for name, record in self.cp.items():
            with self.subTest(checkpoint=name):
                self.assertTrue(checkpoint.verify_checkpoint_signature_offline(record))

    def test_growth_links_verify_through_the_mmr_and_checkpoint_verifiers(self):
        for old, new in (("cp1", "cp2"), ("cp3", "cp4"), ("cp2", "cp4")):
            prev, curr = self.cp[old], self.cp[new]
            with self.subTest(link=f"{old}->{new}"):
                self.assertEqual(checkpoint.verify_checkpoint_link(prev, curr), (True, ""))
                self.assertTrue(
                    core.verify_consistency(
                        bytes.fromhex(prev.root), prev.mmr_size,
                        bytes.fromhex(curr.root), curr.mmr_size, curr.consistency_proof,
                    )
                )

    def test_chain_without_the_repeated_checkpoint_verifies(self):
        chain = [self.cp[name] for name in ("cp1", "cp2", "cp4")]
        self.assertEqual(checkpoint.verify_checkpoint_chain(chain), (True, []))

    def test_chain_with_the_repeated_checkpoint_fails_only_at_the_repeat(self):
        ok, errors = checkpoint.verify_checkpoint_chain([self.cp[n] for n in ("cp1", "cp2", "cp3", "cp4")])
        self.assertFalse(ok)
        self.assertEqual(len(errors), 1)
        self.assertIn("non-monotonic mmr_size", errors[0])
        self.assertIn("mmr_size=11", errors[0])


class TestCll02Negative(Cll02Chain):
    PROOF_FAILS = "MMR consistency proof does not verify"
    # vector id -> (honest checkpoints already registered, how the chain verifier refuses it)
    REFUSED = {
        "fail-log-size-is-leaf-count": (("cp1",), PROOF_FAILS),
        "fail-log-size-incomplete": (("cp1",), PROOF_FAILS),
        "fail-proof-missing": (("cp1",), "no consistency_proof on curr"),
        "fail-proof-tampered-path": (("cp1",), PROOF_FAILS),
        "fail-proof-paths-disagree": (("cp1", "cp2"), PROOF_FAILS),
        "fail-proof-right-peaks-count": (("cp1",), PROOF_FAILS),
        "fail-proof-sizes": (("cp1",), PROOF_FAILS),
        "fail-no-growth-commitment-changed": (("cp1", "cp2"), "non-monotonic mmr_size"),
        "fail-commitment-not-extension": (("cp1",), PROOF_FAILS),
        "fail-registration-not-continuous": (("cp1", "cp2"), "curr.prev_size=4 does not match prev.mmr_size=11"),
        "sub-per-checkpoint-is-first-seen": (("cp1",), "log_id mismatch"),
    }
    # Break the -01 wire encodings (commitment as a CBOR array, proof as a CBOR map).
    # The registry has no COSE wire form to break; see docs/mmr-checkpoint.md.
    WIRE_ONLY = {"fail-commitment-cbor-array", "fail-proof-legacy-map"}
    # Neither maps onto a refusal; TestCll02KnownDifferences and the leaf-count test cover them.
    OTHER = {"fail-leaf-count-mismatch", "fail-proof-on-first"}

    def test_every_negative_vector_is_accounted_for(self):
        self.assertEqual(
            set(self.negatives), set(self.REFUSED) | self.WIRE_ONLY | self.OTHER
        )

    def test_chain_verifier_refuses_each_applicable_negative_vector(self):
        for vector_id, (before, reason) in self.REFUSED.items():
            with self.subTest(vector=vector_id):
                vector = self.negatives[vector_id]
                registered = [self.cp[name] for name in before]
                self.assertEqual(checkpoint.verify_checkpoint_chain(registered), (True, []))
                if vector["registered"]:
                    state = vector["registered"]
                    self.assertEqual(state["log_size"], registered[-1].mmr_size)
                    self.assertEqual(_bag(bytes.fromhex(state["commitment"])), registered[-1].root)
                ok, errors = checkpoint.verify_checkpoint_chain(registered + [_negative(vector)])
                self.assertFalse(ok)
                self.assertEqual(len(errors), 1)
                self.assertIn(reason, errors[0])

    def test_size_rules_are_the_mmr_layers(self):
        incomplete = _claims(self.negatives["fail-log-size-incomplete"])
        with self.assertRaises(core.InvalidArgumentError):
            core.peaks(incomplete["log_size"])
        # An entry count written as log_size is a valid size, but its accumulator is
        # not the commitment the checkpoint carries.
        as_leaves = _claims(self.negatives["fail-log-size-is-leaf-count"])
        self.assertEqual(as_leaves["log_size"], 7)
        self.assertNotEqual(
            len(core.peaks(as_leaves["log_size"])), len(_split_peaks(as_leaves["commitment"]))
        )

    def test_leaf_count_is_the_mmr_layers(self):
        # The registry's checkpoint has no leaf_count member, so this vector cannot
        # reach its verifier. The arithmetic it is held to does: an honest claim
        # equals core.leaf_count(log_size) and the vector's does not.
        for name in ("cp2", "cp4"):
            claims = self.claims[name]
            self.assertEqual(claims["leaf_count"], core.leaf_count(claims["log_size"]))
        bad = _claims(self.negatives["fail-leaf-count-mismatch"])
        self.assertNotEqual(bad["leaf_count"], core.leaf_count(bad["log_size"]))

    def test_no_growth_with_a_changed_commitment_fails_at_the_mmr_layer(self):
        vector = self.negatives["fail-no-growth-commitment-changed"]
        bad = _negative(vector)
        unchanged = core.consistency_proof(self.store, 11, 11)
        changed = dataclasses.replace(
            unchanged, new_peaks=tuple(p.hex() for p in _split_peaks(_claims(vector)["commitment"]))
        )
        root = bytes.fromhex(self.cp["cp2"].root)
        self.assertTrue(core.verify_consistency(root, 11, root, 11, unchanged))
        self.assertFalse(core.verify_consistency(root, 11, bytes.fromhex(bad.root), 11, changed))


class TestCll02KnownDifferences(Cll02Chain):
    """Where trace_verify is stricter or looser than -02. Each test pins today's
    behaviour, so a change is a decision: update the test and the differences
    table in docs/mmr-checkpoint.md together."""

    def test_no_growth_checkpoint_is_valid_at_the_mmr_layer_but_refused_in_the_chain(self):
        prev, repeat = self.cp["cp2"], self.cp["cp3"]
        self.assertEqual((repeat.mmr_size, repeat.root), (prev.mmr_size, prev.root))
        self.assertEqual((repeat.prev_size, repeat.prev_root), (prev.mmr_size, prev.root))
        self.assertIsNone(repeat.consistency_proof)  # -02: no proof when nothing grew
        root = bytes.fromhex(prev.root)
        trivial = core.consistency_proof(self.store, prev.mmr_size, prev.mmr_size)
        self.assertTrue(core.verify_consistency(root, 11, root, 11, trivial))
        ok, reason = checkpoint.verify_checkpoint_link(prev, repeat)
        self.assertFalse(ok)
        self.assertIn("non-monotonic mmr_size", reason)

    def test_first_checkpoint_carrying_a_proof_is_not_refused(self):
        # -02 refuses it (proof-unexpected). The registry's proof sits outside the
        # signed body and a first checkpoint is never checked against one.
        first = _negative(self.negatives["fail-proof-on-first"])
        self.assertEqual(first.prev_size, 0)
        self.assertIsNotNone(first.consistency_proof)
        self.assertEqual(checkpoint.verify_checkpoint_chain([first]), (True, []))


if __name__ == "__main__":
    unittest.main()
