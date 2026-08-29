# SPDX-License-Identifier: Apache-2.0
"""Adversarial CLL review: the checkpoint chain is this PR's headline claim,
so every test here is written mutate-first -- construct the attack, show it
would slip past a NAIVE field-equality check, then show the REAL
implementation (`trace_verify._checkpoint.verify_checkpoint_link`) rejects
it and names why.

Three attacks, per the review brief:
  (a) a rewritten/forged tree with matching prev_size/prev_root FIELDS but
      no genuine consistency proof tying it to the real prior tree;
  (b) a quiet post-hoc edit to an already-checkpointed entry (omission /
      substitution) that leaves the checkpoint chain's own internal math
      untouched but no longer matches what is actually stored;
  (c) a forked chain: two checkpoints both claiming the same prev_size but
      disagreeing about prev_root.

`_naive_link_ok` below is NOT production code -- it is the insecure
baseline this review exists to rule out, kept alive only to prove, on the
record, that it is insecure.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "tools"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trace_verify import _mmr as core
from trace_verify._checkpoint import CheckpointRecord, verify_checkpoint_chain, verify_checkpoint_link
from aggregator._mmr_log import CheckpointLog
from aggregator._core import TRACEAggregator
import verify_checkpoint_chain as verifier_tool


def _naive_link_ok(prev: CheckpointRecord, curr: CheckpointRecord) -> bool:
    """THE INSECURE BASELINE. Checks only that the two records' own recorded
    fields agree -- exactly what an implementer would write who thought
    "the previous checkpoint's root and this one's prev_root match" was
    itself the security property. It never looks at consistency_proof, so it
    is satisfied by ANY pair of records whose four values were copied
    across, genuine extension or not. This function must never be used
    outside this test file.
    """
    return curr.log_id == prev.log_id and curr.prev_size == prev.mmr_size and curr.prev_root == prev.root


def _sign(private_key: Ed25519PrivateKey, cp: CheckpointRecord) -> None:
    cp.signature = private_key.sign(cp.digest().encode("ascii")).hex()


def _key_id(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes_raw().hex()


def _build_checkpoint(
    private_key: Ed25519PrivateKey,
    store: core.NodeAppender,
    *,
    log_id: str,
    prev: CheckpointRecord | None,
    timestamp: str,
) -> CheckpointRecord:
    """Build+sign a REAL checkpoint from `store`'s current state -- test
    helper mirroring aggregator._mmr_log.CheckpointLog.append_entry's own
    construction, used here to build fixtures directly against a
    MemoryNodeStore instead of the full aggregator."""
    size = store.size()
    root = core.root_from_peaks([store.node(p) for p in core.peaks(size)]).hex()
    prev_size = prev.mmr_size if prev else 0
    prev_root = prev.root if prev else ""
    proof = core.consistency_proof(store, prev_size, size) if prev else None
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=log_id, mmr_size=size, root=root,
        prev_size=prev_size, prev_root=prev_root, key_id=_key_id(private_key),
        timestamp=timestamp, signature="", consistency_proof=proof,
    )
    _sign(private_key, cp)
    return cp


def _append(store: core.NodeAppender, tag: str) -> None:
    core.add_leaf(store, core.leaf_hash(hashlib.sha256(tag.encode()).digest()))


class TestAdversarialA_RewrittenTreeSameFields(unittest.TestCase):
    """(a) A rewritten tree with equal prev_root/prev_size FIELDS but an
    inconsistent (or absent) history must be REJECTED. Field equality alone
    is not evidence of a genuine extension."""

    def test_naive_check_wrongly_accepts_a_forged_continuation(self):
        key = Ed25519PrivateKey.generate()

        # The REAL, honest log: 5 leaves, one genuine checkpoint.
        honest_store = core.MemoryNodeStore()
        for i in range(5):
            _append(honest_store, f"honest-{i}")
        cp_a = _build_checkpoint(key, honest_store, log_id="log/v1", prev=None,
                                  timestamp="2026-08-26T00:00:00Z")

        # The ATTACKER's own, entirely different tree -- same leaf count (5)
        # at the "prev" boundary, but different content, so its own root at
        # that size is NOT cp_a.root. The attacker continues it with 4 more
        # leaves of their choosing and gets a REAL, honestly-derived
        # consistency proof -- but relative to THEIR root, not the real one.
        attacker_store = core.MemoryNodeStore()
        for i in range(5):
            _append(attacker_store, f"attacker-rewrite-{i}")
        attacker_size_a = attacker_store.size()
        for i in range(4):
            _append(attacker_store, f"attacker-new-{i}")
        attacker_size_b = attacker_store.size()
        attacker_root_b = core.root_from_peaks(
            [attacker_store.node(p) for p in core.peaks(attacker_size_b)]
        ).hex()
        forged_proof = core.consistency_proof(attacker_store, attacker_size_a, attacker_size_b)

        # Forge curr: copy prev_size/prev_root from the REAL cp_a (field
        # equality bait), but everything else -- root, consistency_proof --
        # comes from the attacker's unrelated tree.
        forged = CheckpointRecord(
            v=1, kind="mmr_checkpoint", log_id="log/v1",
            mmr_size=attacker_size_b, root=attacker_root_b,
            prev_size=cp_a.mmr_size, prev_root=cp_a.root,
            key_id=_key_id(key), timestamp="2026-08-26T01:00:00Z",
            signature="", consistency_proof=forged_proof,
        )
        _sign(key, forged)

        # RED: the naive field-equality check is fooled.
        self.assertTrue(
            _naive_link_ok(cp_a, forged),
            "sanity check on the naive baseline itself: it MUST be fooled here, "
            "or this test is not exercising the attack it claims to",
        )

        # GREEN: the real implementation is not.
        ok, reason = verify_checkpoint_link(cp_a, forged)
        self.assertFalse(ok)
        self.assertIn("consistency", reason.lower())

    def test_missing_consistency_proof_is_rejected_even_with_matching_fields(self):
        key = Ed25519PrivateKey.generate()
        store = core.MemoryNodeStore()
        for i in range(3):
            _append(store, f"e{i}")
        cp_a = _build_checkpoint(key, store, log_id="log/v1", prev=None,
                                  timestamp="2026-08-26T00:00:00Z")
        for i in range(3, 6):
            _append(store, f"e{i}")
        cp_b_no_proof = _build_checkpoint(key, store, log_id="log/v1", prev=cp_a,
                                           timestamp="2026-08-26T01:00:00Z")
        cp_b_no_proof.consistency_proof = None  # strip the real proof back out
        _sign(key, cp_b_no_proof)

        self.assertTrue(_naive_link_ok(cp_a, cp_b_no_proof))
        ok, reason = verify_checkpoint_link(cp_a, cp_b_no_proof)
        self.assertFalse(ok)
        self.assertIn("no consistency_proof", reason)


class TestAdversarialB_OmissionBetweenCheckpoints(unittest.TestCase):
    """(b) A mid-stream entry silently edited after being checkpointed --
    the checkpoint chain's own internal math is untouched (nobody re-signed
    anything), but it no longer matches what is actually stored. Caught by
    cross-checking the chain against the raw entries, not by the chain
    alone."""

    def _build_real_chain(self, tmp: Path) -> tuple[Path, list[dict]]:
        agg = TRACEAggregator(
            registry_dir=tmp / "registry", proofs_dir=tmp / "proofs",
            checkpoints_dir=tmp / "checkpoints", verify_signatures=False,
            flush_interval=0.05,
            # Fixed clock so the registry day-file matches the pinned fixture
            # date (2026-08-26); otherwise the aggregator writes today's file
            # and this suite fails once a day. See #51 review.
            now_ts=lambda: "2026-08-26T00:00:00Z",
        )
        for i in range(6):
            h = hashlib.sha256(f"claim-{i}".encode()).hexdigest()
            agg.submit([{
                "fmt": 1, "producer": f"producer-{i}/1.0.0",
                "ts": "2026-08-26T00:00:00Z", "hash": f"sha256:{h}",
                "signature": "dummy",
            }], timeout=5.0)
        day_file = tmp / "registry" / "2026" / "08" / "26.ndjson"
        entries = [json.loads(ln) for ln in day_file.read_text().splitlines() if ln.strip()]
        return day_file, entries

    def test_honest_chain_verifies_clean(self):
        with tempfile.TemporaryDirectory() as tmp_s:
            tmp = Path(tmp_s)
            day_file, entries = self._build_real_chain(tmp)
            self.assertEqual(len(entries), 6)
            self.assertTrue(all("mmr_checkpoint" in e for e in entries))

            chain_ok, chain_errors = verify_checkpoint_chain(
                [CheckpointRecord.from_dict(e["mmr_checkpoint"]) for e in entries]
            )
            self.assertTrue(chain_ok, chain_errors)
            raw_errors = verifier_tool.verify_against_raw_entries(entries)
            self.assertEqual(raw_errors, [])

    def test_tampering_a_mid_stream_entry_is_caught_and_named(self):
        with tempfile.TemporaryDirectory() as tmp_s:
            tmp = Path(tmp_s)
            day_file, entries = self._build_real_chain(tmp)

            # Quietly edit entry index 2's producer field (post-hoc storage
            # tamper) WITHOUT touching any checkpoint's own recorded
            # root/proof -- exactly what an attacker with write access to
            # the NDJSON file, but not the signing key, could attempt.
            tampered_batch_id = entries[2]["batch_id"]
            entries[2] = dict(entries[2])
            entries[2]["producer"] = "attacker-controlled/9.9.9"

            # The checkpoint chain's OWN internal math is still self
            # consistent -- nobody forged a proof, so the chain-only check
            # alone would miss this. Confirm that first, so the from-scratch
            # check below is shown to be doing real, additional work.
            chain_ok, chain_errors = verify_checkpoint_chain(
                [CheckpointRecord.from_dict(e["mmr_checkpoint"]) for e in entries]
            )
            self.assertTrue(chain_ok, chain_errors)

            # RED->GREEN: the from-scratch recompute against raw entries
            # catches it and names the exact batch that broke.
            raw_errors = verifier_tool.verify_against_raw_entries(entries)
            self.assertTrue(raw_errors)
            self.assertTrue(any(tampered_batch_id in err for err in raw_errors), raw_errors)
            self.assertTrue(any("altered after it was checkpointed" in err for err in raw_errors), raw_errors)

            # And every checkpoint from the tampered entry ONWARD also now
            # mismatches (the tamper propagates forward through the MMR),
            # not just the tampered entry itself -- confirm the break is
            # reported at (at least) the first point it becomes provable.
            self.assertGreaterEqual(len(raw_errors), 1)

    def test_cli_tool_exits_nonzero_and_prints_named_failure(self):
        with tempfile.TemporaryDirectory() as tmp_s:
            tmp = Path(tmp_s)
            day_file, entries = self._build_real_chain(tmp)
            entries[4] = dict(entries[4])
            entries[4]["leaf_count"] = 999999  # tamper a batch-level field

            tampered_file = tmp / "tampered.ndjson"
            tampered_file.write_text("\n".join(json.dumps(e) for e in entries) + "\n")

            exit_code = verifier_tool.main([str(tampered_file)])
            self.assertEqual(exit_code, 1)


class TestAdversarialC_ForkedChain(unittest.TestCase):
    """(c) Two checkpoints claiming the same prev_size but disagreeing about
    prev_root: two different histories both claim descent from "the state at
    size N", which cannot both be true. Must fail loudly, naming the fork."""

    def test_forked_prev_root_is_rejected(self):
        key = Ed25519PrivateKey.generate()
        store = core.MemoryNodeStore()
        for i in range(4):
            _append(store, f"e{i}")
        cp_a = _build_checkpoint(key, store, log_id="log/v1", prev=None,
                                  timestamp="2026-08-26T00:00:00Z")

        # A branch that honestly continues cp_a.
        branch1 = core.MemoryNodeStore()
        for h in [store.node(i) for i in range(store.size())]:
            branch1.append_nodes([h])
        for i in range(3):
            _append(branch1, f"branch1-{i}")
        cp_branch1 = _build_checkpoint(key, branch1, log_id="log/v1", prev=cp_a,
                                        timestamp="2026-08-26T01:00:00Z")
        ok, _ = verify_checkpoint_link(cp_a, cp_branch1)
        self.assertTrue(ok)

        # A forged sibling claiming the SAME prev_size as cp_branch1 but a
        # DIFFERENT prev_root (as if some other, incompatible state also
        # existed "at size 4").
        forked = CheckpointRecord(
            v=1, kind="mmr_checkpoint", log_id="log/v1",
            mmr_size=cp_branch1.mmr_size, root=cp_branch1.root,
            prev_size=cp_a.mmr_size, prev_root="ff" * 32,  # wrong prev_root, same prev_size
            key_id=_key_id(key), timestamp="2026-08-26T01:00:00Z",
            signature="", consistency_proof=cp_branch1.consistency_proof,
        )
        _sign(key, forked)

        ok, reason = verify_checkpoint_link(cp_a, forked)
        self.assertFalse(ok)
        self.assertIn("forked chain", reason)

    def test_forked_prev_size_referencing_nonexistent_state_is_rejected(self):
        key = Ed25519PrivateKey.generate()
        store = core.MemoryNodeStore()
        for i in range(4):
            _append(store, f"e{i}")
        cp_a = _build_checkpoint(key, store, log_id="log/v1", prev=None,
                                  timestamp="2026-08-26T00:00:00Z")
        for i in range(3):
            _append(store, f"more-{i}")
        cp_b = _build_checkpoint(key, store, log_id="log/v1", prev=cp_a,
                                  timestamp="2026-08-26T01:00:00Z")

        forged = CheckpointRecord(
            v=1, kind="mmr_checkpoint", log_id="log/v1",
            mmr_size=cp_b.mmr_size, root=cp_b.root,
            prev_size=cp_a.mmr_size + 1, prev_root=cp_a.root,  # claims a prev_size cp_a never had
            key_id=_key_id(key), timestamp="2026-08-26T01:00:00Z",
            signature="", consistency_proof=cp_b.consistency_proof,
        )
        _sign(key, forged)

        ok, reason = verify_checkpoint_link(cp_a, forged)
        self.assertFalse(ok)
        self.assertIn("forked chain", reason)


class TestPositiveEndToEnd(unittest.TestCase):
    """Green-path confirmation: a real multi-batch aggregator run produces a
    verifying checkpoint chain, and existing RFC 6962 per-claim inclusion
    proofs are completely unaffected by any of the above."""

    def test_full_chain_verifies_and_batch_inclusion_proofs_still_work(self):
        with tempfile.TemporaryDirectory() as tmp_s:
            tmp = Path(tmp_s)
            agg = TRACEAggregator(
                registry_dir=tmp / "registry", proofs_dir=tmp / "proofs",
                checkpoints_dir=tmp / "checkpoints", verify_signatures=False,
                flush_interval=0.05,
                # Fixed clock so the registry day-file matches the pinned
                # fixture date (2026-08-26); otherwise the aggregator writes
                # today's file and this suite fails once a day. See #51 review.
                now_ts=lambda: "2026-08-26T00:00:00Z",
            )
            all_results = []
            for i in range(8):
                h = hashlib.sha256(f"claim-{i}".encode()).hexdigest()
                claim = {"fmt": 1, "producer": f"producer-{i}/1.0.0",
                         "ts": "2026-08-26T00:00:00Z", "hash": f"sha256:{h}",
                         "signature": "dummy"}
                results = agg.submit([claim], timeout=5.0)
                all_results.append((claim, results[0]))

            day_file = tmp / "registry" / "2026" / "08" / "26.ndjson"
            entries = [json.loads(ln) for ln in day_file.read_text().splitlines() if ln.strip()]
            self.assertEqual(len(entries), 8)

            checkpoints = [CheckpointRecord.from_dict(e["mmr_checkpoint"]) for e in entries]
            for cp in checkpoints:
                from trace_verify._checkpoint import verify_checkpoint_signature_offline
                self.assertTrue(verify_checkpoint_signature_offline(cp))
            chain_ok, chain_errors = verify_checkpoint_chain(checkpoints)
            self.assertTrue(chain_ok, chain_errors)
            self.assertEqual(verifier_tool.verify_against_raw_entries(entries), [])

            # Unrelated RFC 6962 batch inclusion proofs (the pre-existing
            # feature) are untouched by any of the above.
            from trace_verify._verify import verify_inclusion as rfc_verify_inclusion, decode_hash

            for claim, result in all_results:
                entry = next(e for e in entries if e["batch_id"] == result["batch_id"])
                ok = rfc_verify_inclusion(
                    claim, result["leaf_index"],
                    [decode_hash(h) for h in result["audit_path"]],
                    entry["leaf_count"], decode_hash(entry["merkle_root"]),
                    canonicalization_id=entry.get("canonicalization_id", "sorted-key"),
                )
                self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
