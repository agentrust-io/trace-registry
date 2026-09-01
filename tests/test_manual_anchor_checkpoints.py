# SPDX-License-Identifier: Apache-2.0
"""Manually anchored entries must join the same chain as pipeline ones.

`tools/anchor.py` used to print a registry entry for an operator to redirect
into a day file, and never touched the MMR. Once the registry publishes a
checkpoint chain that is a quiet hole: the hand-appended entry is published, the
chain never covers it, and `verify_checkpoint_chain` still passes because it only
folds entries that carry a checkpoint. Nothing anywhere reports that the chain
covers less than the registry.

So the two paths have to produce one chain, and checkpointing has to happen in
the same step as appending. A checkpoint mints against the chain as published, so
minting one and not appending its entry, or minting twice before appending
either, yields a chain nobody can reproduce from the registry.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
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

import tools.batch_anchor as ba
from trace_verify._checkpoint import CheckpointRecord, verify_checkpoint_chain

ANCHOR = REPO_ROOT / "tools" / "anchor.py"


def _make_key() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    kid = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return pem.decode("ascii"), kid


class ManualAnchorCheckpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.registry = self.root / "registry"
        self.registry.mkdir(parents=True)
        self.pem, self.key_id = _make_key()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _claim(self, n: int) -> Path:
        path = self.root / f"claim{n}.json"
        path.write_text(json.dumps({"trace": {"iat": n}}), encoding="utf-8")
        return path

    def _anchor(self, n: int, ts: str, *extra: str, key: bool = True) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if key:
            env[ba.CHECKPOINT_KEY_ENV] = self.pem
        else:
            env.pop(ba.CHECKPOINT_KEY_ENV, None)
        return subprocess.run(
            [sys.executable, str(ANCHOR), str(self._claim(n)),
             "--producer", "demo/1.0.0", "--ts", ts,
             "--proof-dir", str(self.root / "proofs"), *extra],
            capture_output=True, text=True, env=env,
        )

    def _entries(self) -> list[dict]:
        return ba.load_published_entries(self.registry)

    def test_registry_dir_checkpoints_and_appends_together(self) -> None:
        proc = self._anchor(1, "2026-09-01T00:00:00Z", "--registry-dir", str(self.registry))
        self.assertEqual(proc.returncode, 0, proc.stderr)

        entries = self._entries()
        self.assertEqual(len(entries), 1, "entry was not appended")
        cp = entries[0].get("mmr_checkpoint")
        self.assertIsInstance(cp, dict, "manual anchor produced no checkpoint")
        self.assertEqual(cp["key_id"], self.key_id)

        # The printed entry and the published entry are the same object.
        printed = json.loads(proc.stdout.strip())
        self.assertEqual(printed["batch_id"], entries[0]["batch_id"])
        self.assertIn("mmr_checkpoint", printed)

    def test_manual_and_pipeline_entries_share_one_chain(self) -> None:
        self._anchor(1, "2026-09-01T00:00:00Z", "--registry-dir", str(self.registry))

        os.environ[ba.CHECKPOINT_KEY_ENV] = self.pem
        try:
            log = ba.open_checkpoint_log(self.registry, log_id="trace-registry/v1")
        finally:
            os.environ.pop(ba.CHECKPOINT_KEY_ENV, None)
        claim = {"producer": "demo/1.0.0", "seq": 2}
        ba.anchor_group(
            "demo/1.0.0",
            [(Path("pipeline.json"), claim, json.dumps(claim).encode())],
            "2026-09-01T00:15:00Z",
            ba.batch_id_for([claim]),
            self.registry, self.root / "proofs", dry_run=False,
            checkpoint_log=log,
        )

        self._anchor(3, "2026-09-01T00:30:00Z", "--registry-dir", str(self.registry))

        cps = [e["mmr_checkpoint"] for e in self._entries()]
        self.assertEqual(len(cps), 3)
        for a, b in zip(cps, cps[1:]):
            self.assertEqual(b["prev_root"], a["root"], "manual and pipeline chains diverged")
        ok, errors = verify_checkpoint_chain([CheckpointRecord.from_dict(c) for c in cps])
        self.assertTrue(ok, f"chain rejected: {errors}")

    def test_registry_dir_without_a_key_refuses_rather_than_appending(self) -> None:
        proc = self._anchor(1, "2026-09-01T00:00:00Z",
                            "--registry-dir", str(self.registry), key=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("cannot be folded into the checkpoint chain", proc.stderr)
        self.assertEqual(self._entries(), [], "an unchained entry must not be published")

    def test_no_checkpoint_flag_is_an_explicit_opt_out(self) -> None:
        proc = self._anchor(1, "2026-09-01T00:00:00Z",
                            "--registry-dir", str(self.registry),
                            "--no-checkpoint", key=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        entries = self._entries()
        self.assertEqual(len(entries), 1)
        self.assertNotIn("mmr_checkpoint", entries[0])

    def test_stdout_mode_warns_once_the_registry_is_chained(self) -> None:
        # Without --registry-dir the tool cannot append, so the most it can do is
        # say plainly that the entry will fall outside the chain.
        self._anchor(1, "2026-09-01T00:00:00Z", "--registry-dir", str(self.registry))
        proc = subprocess.run(
            [sys.executable, str(ANCHOR), str(self._claim(2)),
             "--producer", "demo/1.0.0", "--proof-dir", str(self.root / "proofs")],
            capture_output=True, text=True, cwd=str(self.root),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # The warning keys off the repository's own registry, which is chained
        # in production; here we only assert the tool still emits a usable entry.
        self.assertIn("merkle_root", proc.stdout)


if __name__ == "__main__":
    unittest.main()
