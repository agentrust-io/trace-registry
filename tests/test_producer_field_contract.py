# SPDX-License-Identifier: Apache-2.0
"""A claim with no top-level `producer` must be refused by name, not by sentinel.

`tools/anchor.py` takes the producer id as a `--producer` argument.
`tools/batch_anchor.py`, which is what the scheduled pipeline runs, reads it from
inside the signed claim body instead, because a producer id supplied out of band
is an unsigned assertion about who signed.

The two contracts are fine. What was not fine is that a claim submitted to the
pipeline without the field was rejected as `invalid producer id '__unknown__'`,
which names an internal sentinel and tells a submitter nothing. The repository's
own `samples/example-trust-record.json` hits this, so the first thing a new
producer copies is the thing that does not work.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import tools.batch_anchor as ba


class ProducerFieldContractTest(unittest.TestCase):
    def _run(self, claim: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            incoming = root / "staging" / "incoming"
            incoming.mkdir(parents=True)
            (incoming / "claim.json").write_text(json.dumps(claim), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "tools" / "batch_anchor.py"),
                 "--json",
                 "--staging-dir", str(root / "staging"),
                 "--registry-dir", str(root / "registry"),
                 "--proofs-dir", str(root / "proofs")],
                capture_output=True, text=True,
            )
            self.assertTrue(proc.stdout.strip(), proc.stderr)
            return json.loads(proc.stdout)

    def test_missing_producer_is_named_not_sentinelled(self) -> None:
        report = self._run({"trace": {"iat": 1}, "signature": "not-checked"})
        batch = report["batches"][0]
        self.assertEqual(batch["status"], "rejected")
        detail = batch["detail"]
        self.assertIn("no top-level 'producer' field", detail)
        self.assertIn("claim.json", detail, "the offending file must be named")
        self.assertNotIn("invalid producer id", detail,
                         "the sentinel must not leak into a submitter-facing message")
        self.assertFalse(report["ok"])

    def test_shipped_sample_still_reproduces_the_case(self) -> None:
        # If a future corpus regeneration gives the sample a producer field this
        # will fail, which is the point: the samples/README note explaining why
        # it is not anchorable would then be stale and must be removed.
        sample = json.loads(
            (REPO_ROOT / "samples" / "example-trust-record.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("producer", sample)
        batch = self._run(sample)["batches"][0]
        self.assertEqual(batch["status"], "rejected")
        self.assertIn("no top-level 'producer' field", batch["detail"])

    def test_unknown_sentinel_is_not_a_valid_producer_id(self) -> None:
        from trace_verify._signature import is_valid_producer_id

        self.assertFalse(is_valid_producer_id(ba.UNKNOWN_PRODUCER))


if __name__ == "__main__":
    unittest.main()
