"""Missing evidence must fail the scheduled verifier unless explicitly allowed."""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_checkpoint_chain as verifier  # noqa: E402


class EmptyCheckpointToolTests(unittest.TestCase):
    def run_tool(self, contents, *flags):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "entries.ndjson"
            path.write_text(contents, encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = verifier.main([*flags, str(path)])
            return code, stdout.getvalue(), stderr.getvalue()

    def test_empty_and_uncheckpointed_files_fail_by_default(self):
        for contents in ("", "\n", '{"batch_id":"legacy"}\n'):
            with self.subTest(contents=contents):
                code, stdout, _ = self.run_tool(contents)
                self.assertEqual(code, 1)
                self.assertIn("NOT VERIFIED: no entries with mmr_checkpoint", stdout)

    def test_allow_empty_explicitly_permits_bootstrap(self):
        for contents in ("", '{"batch_id":"legacy"}\n'):
            with self.subTest(contents=contents):
                code, stdout, _ = self.run_tool(contents, "--allow-empty")
                self.assertEqual(code, 0)
                self.assertIn("NOT VERIFIED", stdout)
                self.assertNotIn("OK:", stdout)

    def test_allow_empty_does_not_accept_malformed_checkpoint(self):
        code, _, stderr = self.run_tool(
            json.dumps({"mmr_checkpoint": {}}) + "\n", "--allow-empty"
        )
        self.assertEqual(code, 1)
        self.assertIn("malformed mmr_checkpoint", stderr)

    def test_committed_checkpoint_still_verifies(self):
        for flags in ([], ["--allow-empty"]):
            with self.subTest(flags=flags), redirect_stdout(io.StringIO()):
                self.assertEqual(verifier.main([
                    *flags, str(ROOT / "registry/2026/09/01.ndjson")
                ]), 0)

    def test_pipeline_does_not_opt_into_allow_empty(self):
        workflow = (ROOT / ".github/workflows/anchor-pipeline.yml").read_text()
        self.assertIn("python tools/verify_checkpoint_chain.py", workflow)
        self.assertNotIn("--allow-empty", workflow)
