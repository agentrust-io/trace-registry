"""The trace-verify CLI must refuse a claim with a duplicated JSON member.

It parsed with last-wins ``json.loads``, so a claim carrying ``cmcp_version``
twice verified over the genuine value while a first-wins reader of the same
accepted file saw the other one. ``loads_unique`` already existed and only the
intake path used it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "samples" / "example-trust-record.json"


def _verify(claim: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "trace_verify", "--claim", str(claim),
         "--proof", "samples/inclusion-proof.json", "--entry", "registry/2026/06/12.ndjson"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )


def _with_duplicate(directory: Path) -> Path:
    raw = SAMPLE.read_text(encoding="utf-8")
    brace = raw.index("{") + 1
    path = directory / "duplicate.json"
    path.write_text(raw[:brace] + '\n  "cmcp_version": "EVIL-9.9",' + raw[brace:], encoding="utf-8")
    return path


class DuplicateMemberTests(unittest.TestCase):
    def test_genuine_sample_still_verifies(self):
        result = _verify(SAMPLE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_duplicated_member_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            result = _verify(_with_duplicate(Path(d)))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("duplicate JSON member name", result.stdout + result.stderr)

    def test_the_duplicate_would_mislead_a_first_wins_reader(self):
        """Why it matters: two parsers disagree about the accepted file."""
        self.assertIn('"cmcp_version"', SAMPLE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as d:
            raw = _with_duplicate(Path(d)).read_text(encoding="utf-8")
        first_wins = json.loads(raw, object_pairs_hook=lambda pairs: dict(reversed(pairs)))
        self.assertEqual(first_wins["cmcp_version"], "EVIL-9.9")
        self.assertNotEqual(json.loads(raw)["cmcp_version"], "EVIL-9.9")


if __name__ == "__main__":
    unittest.main()
