# SPDX-License-Identifier: Apache-2.0
"""The scheduled pipeline must emit a checkpoint chain that survives a fresh
checkout.

`tools/batch_anchor.py` is what `anchor-pipeline.yml` actually runs. Before
this suite existed the checkpoint machinery lived only in `TRACEAggregator`,
which the scheduled job never touches, so every published entry carried batch
inclusion proofs and nothing tying one anchoring run to the next.

The property under test is not "a checkpoint field appears". It is that a
second run, starting from an empty working directory the way a GitHub Actions
checkout does, rebuilds the same tree from the published entries and extends
the same chain under the same key_id.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from trace_verify._checkpoint import verify_checkpoint_chain
from trace_verify._mmr import IntegrityError

import tools.batch_anchor as ba


def _make_key() -> tuple[str, str]:
    """Returns (pem, expected key_id hex)."""
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    key_id = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return pem.decode("ascii"), key_id


class PipelineCheckpointTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.registry = self.root / "registry"
        self.registry.mkdir(parents=True)
        self.pem, self.key_id = _make_key()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _entries(self) -> list[dict]:
        return ba.load_published_entries(self.registry)

    def _anchor(self, producer: str, n: int, ts: str) -> dict:
        """Anchor one batch through the same call path main() uses."""
        os.environ[ba.CHECKPOINT_KEY_ENV] = self.pem
        try:
            log = ba.open_checkpoint_log(self.registry, log_id="trace-registry/v1")
        finally:
            os.environ.pop(ba.CHECKPOINT_KEY_ENV, None)
        self.assertIsNotNone(log, "a PEM in the environment must yield a log")

        records = []
        for i in range(n):
            claim = {"producer": producer, "seq": i, "ts": ts}
            raw = json.dumps(claim, sort_keys=True).encode()
            # No colons in the stem: it becomes a proof filename, and
            # Windows rejects those.
            stem = f"{producer}-{ts.replace(':', '')}-{i}.json"
            records.append((Path(stem), claim, raw))

        return ba.anchor_group(
            producer,
            records,
            ts,
            ba.batch_id_for([c for _, c, _ in records]),
            self.registry,
            self.root / "proofs",
            dry_run=False,
            checkpoint_log=log,
        )

    def test_first_run_emits_a_signed_checkpoint(self) -> None:
        self._anchor("acme", 2, "2026-09-01T00:00:00Z")
        entries = self._entries()
        self.assertEqual(len(entries), 1)
        cp = entries[0].get("mmr_checkpoint")
        self.assertIsInstance(cp, dict, "pipeline entry carries no checkpoint")
        self.assertEqual(cp["key_id"], self.key_id)
        self.assertEqual(cp["log_id"], "trace-registry/v1")
        self.assertEqual(cp["mmr_size"], 1)
        self.assertEqual(cp["prev_size"], 0)

    def test_chain_extends_across_a_fresh_checkout(self) -> None:
        # Three runs, each opening a brand-new log with no on-disk MMR state,
        # exactly as three scheduled jobs on three ephemeral runners would.
        self._anchor("acme", 2, "2026-09-01T00:00:00Z")
        self._anchor("acme", 1, "2026-09-01T00:15:00Z")
        self._anchor("beta", 3, "2026-09-01T00:30:00Z")

        entries = self._entries()
        self.assertEqual(len(entries), 3)
        cps = [e["mmr_checkpoint"] for e in entries]

        # mmr_size counts MMR NODES, not leaves: appending leaves 1, 2, 3
        # gives node counts 1, 3, 4, because the second leaf also creates the
        # interior node joining it to the first. Asserting 1, 2, 3 here would
        # be asserting a leaf count the field does not carry.
        self.assertEqual([c["mmr_size"] for c in cps], [1, 3, 4])
        self.assertEqual([c["prev_size"] for c in cps], [0, 1, 3])
        for a, b in zip(cps, cps[1:]):
            self.assertEqual(b["prev_root"], a["root"], "chain link broken")
        self.assertEqual({c["key_id"] for c in cps}, {self.key_id},
                         "identity rotated between runs")

        # And the independent verifier accepts the whole chain.
        from trace_verify._checkpoint import CheckpointRecord

        ok, errors = verify_checkpoint_chain(
            [CheckpointRecord.from_dict(e["mmr_checkpoint"]) for e in entries]
        )
        self.assertTrue(ok, f"chain rejected: {errors}")
        self.assertEqual(errors, [])

    def test_replay_refuses_when_entries_and_checkpoints_disagree(self) -> None:
        self._anchor("acme", 2, "2026-09-01T00:00:00Z")
        self._anchor("acme", 1, "2026-09-01T00:15:00Z")

        # Quietly edit an already-anchored entry. Its checkpoint is untouched
        # and still internally consistent, but the leaf it covers changed.
        day = next(self.registry.rglob("*.ndjson"))
        lines = day.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["leaf_count"] = first["leaf_count"] + 1
        lines[0] = json.dumps(first)
        day.write_text("\n".join(lines) + "\n", encoding="utf-8")

        os.environ[ba.CHECKPOINT_KEY_ENV] = self.pem
        try:
            with self.assertRaises(IntegrityError) as ctx:
                ba.open_checkpoint_log(self.registry, log_id="trace-registry/v1")
        finally:
            os.environ.pop(ba.CHECKPOINT_KEY_ENV, None)
        self.assertIn("does not reproduce", str(ctx.exception))

    def test_no_key_means_no_checkpoint_not_a_wrong_one(self) -> None:
        os.environ.pop(ba.CHECKPOINT_KEY_ENV, None)
        self.assertIsNone(
            ba.open_checkpoint_log(self.registry, log_id="trace-registry/v1"),
            "a missing key must not silently mint a new identity",
        )

    def test_require_checkpoints_fails_the_run_when_the_key_is_absent(self) -> None:
        staging = self.root / "staging" / "incoming"
        staging.mkdir(parents=True)
        claim = {"producer": "acme", "seq": 0}
        (staging / "c0.json").write_text(json.dumps(claim), encoding="utf-8")

        env = {k: v for k, v in os.environ.items() if k != ba.CHECKPOINT_KEY_ENV}
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "batch_anchor.py"),
             "--json", "--require-checkpoints", "--no-verify-signatures",
             "--staging-dir", str(self.root / "staging"),
             "--registry-dir", str(self.registry),
             "--proofs-dir", str(self.root / "proofs")],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("no_checkpoint_key", proc.stdout)
        self.assertEqual(self._entries(), [], "nothing may be anchored unchecked")


class KeyHandlingTest(unittest.TestCase):
    def test_pem_signer_writes_nothing_to_disk(self) -> None:
        import tempfile

        from aggregator._mmr_log import Ed25519CheckpointSigner

        pem, key_id = _make_key()
        with tempfile.TemporaryDirectory() as tmp:
            before = list(Path(tmp).rglob("*"))
            signer = Ed25519CheckpointSigner(None, pem=pem.encode())
            self.assertEqual(signer.key_id, key_id)
            self.assertEqual(list(Path(tmp).rglob("*")), before)


if __name__ == "__main__":
    unittest.main()
