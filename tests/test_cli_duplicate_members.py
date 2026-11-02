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

    def test_standalone_tools_reject_duplicated_members(self):
        """tools/verify_inclusion.py, tools/verify_checkpoint_chain.py,
        tools/validate_registry.py, and tools/validate_producers.py must all
        refuse duplicate JSON member names (#146)."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dup_claim = _with_duplicate(tmp)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "verify_inclusion.py"),
                    "--claim", str(dup_claim),
                    "--proof", "samples/inclusion-proof.json",
                    "--entry", "registry/2026/06/12.ndjson",
                ],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("duplicate JSON member name", proc.stderr)

            # Duplicate member in registry day file for verify_checkpoint_chain & validate_registry
            entry_line = (REPO_ROOT / "registry" / "2026" / "09" / "01.ndjson").read_text(
                encoding="utf-8"
            ).splitlines()[0]
            dup_entry_line = '{"batch_id": "dup", ' + entry_line[1:]
            reg_dir = tmp / "registry" / "2026" / "09"
            reg_dir.mkdir(parents=True)
            dup_ndjson = reg_dir / "01.ndjson"
            dup_ndjson.write_text(dup_entry_line + "\n", encoding="utf-8")

            chain_proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "verify_checkpoint_chain.py"),
                    str(dup_ndjson),
                ],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(chain_proc.returncode, 0)
            self.assertIn("duplicate JSON member name", chain_proc.stderr)

            val_reg_proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "validate_registry.py"),
                    str(tmp / "registry"),
                ],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(val_reg_proc.returncode, 0)
            self.assertIn("duplicate JSON member name", val_reg_proc.stdout + val_reg_proc.stderr)

            # Duplicate member in producer key file for validate_producers.py
            prod_raw = (REPO_ROOT / "producers" / "cmcp-gateway-0.1.0.json").read_text(
                encoding="utf-8"
            )
            prod_brace = prod_raw.index("{") + 1
            prod_dir = tmp / "producers"
            prod_dir.mkdir(parents=True)
            dup_prod = prod_dir / "cmcp-gateway-0.1.0.json"
            dup_prod.write_text(
                prod_raw[:prod_brace]
                + '\n  "producer_id": "evil/9.9.9",'
                + prod_raw[prod_brace:],
                encoding="utf-8",
            )
            val_prod_proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "validate_producers.py"),
                    str(prod_dir),
                ],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertNotEqual(val_prod_proc.returncode, 0)
            self.assertIn(
                "duplicate JSON member name",
                val_prod_proc.stdout + val_prod_proc.stderr,
            )

            # Published NDJSON helpers in anchor.py and batch_anchor.py reject duplicate members
            if str(REPO_ROOT / "tools") not in sys.path:
                sys.path.insert(0, str(REPO_ROOT / "tools"))
            if str(REPO_ROOT / "src") not in sys.path:
                sys.path.insert(0, str(REPO_ROOT / "src"))
            import anchor
            import batch_anchor

            self.assertFalse(batch_anchor.is_already_anchored("dup", tmp / "registry"))
            self.assertFalse(anchor._registry_is_chained(tmp / "registry"))
            with self.assertRaises(ValueError) as ctx:
                batch_anchor.load_published_entries(tmp / "registry")
            self.assertIn("duplicate JSON member name", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
