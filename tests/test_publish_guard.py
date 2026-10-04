"""Exercise the publisher's actual shell guard without dispatching a workflow."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


@unittest.skipUnless(shutil.which("bash"), "publisher guard requires bash")
class TestPublishGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.block = workflow.split(
            "      - name: Check the tag matches the packaged version\n", 1
        )[1].split("      - name:", 1)[0]
        cls.script = textwrap.dedent(cls.block.split("        run: |\n", 1)[1])

    def run_guard(self, event, ref, dry_run="", tag="", runtime="0.4.3"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text('version = "0.4.3"\n')
            package = root / "src" / "trace_verify"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text(
                f'__version__ = "{runtime}"\n'
            )
            env = dict(os.environ, EVENT_NAME=event, GITHUB_REF=ref,
                       DRY_RUN=dry_run, TAG=tag)
            return subprocess.run(
                ["bash", "-c", self.script], cwd=root, env=env,
                capture_output=True, text=True, timeout=10,
            )

    def test_guard_is_not_skipped_for_manual_runs(self):
        self.assertIsNone(re.search(r"^\s+if:", self.block, re.MULTILINE))

    def test_valid_publication_and_build_only_paths(self):
        cases = [
            ("release", "refs/tags/v0.4.3", "", "v0.4.3", "0.4.3"),
            ("workflow_dispatch", "refs/tags/v0.4.3", "false", "", "0.4.3"),
            ("workflow_dispatch", "refs/heads/main", "true", "", "9.9.9"),
            ("workflow_dispatch", "refs/tags/v9.9.9", "true", "", "9.9.9"),
        ]
        for case in cases:
            with self.subTest(case=case):
                result = self.run_guard(*case)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_invalid_publication_paths_fail_before_build(self):
        cases = [
            ("release", "refs/heads/main", "", "v0.4.3", "0.4.3"),
            ("release", "refs/tags/v0.4.3", "", "v9.9.9", "0.4.3"),
            ("release", "refs/tags/v9.9.9", "", "v9.9.9", "0.4.3"),
            ("release", "refs/tags/v0.4.3", "", "v0.4.3", "9.9.9"),
            ("workflow_dispatch", "refs/heads/main", "false", "", "0.4.3"),
            ("workflow_dispatch", "refs/tags/v9.9.9", "false", "", "0.4.3"),
            ("workflow_dispatch", "refs/tags/other-v0.4.3", "false", "", "0.4.3"),
            ("workflow_dispatch", "refs/tags/v0.4.3", "false", "", "9.9.9"),
            ("workflow_dispatch", "refs/heads/main", "", "", "0.4.3"),
            ("workflow_dispatch", "refs/tags/v0.4.3", "invalid", "", "0.4.3"),
            ("push", "refs/tags/v0.4.3", "false", "", "0.4.3"),
        ]
        for case in cases:
            with self.subTest(case=case):
                result = self.run_guard(*case)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("::error::", result.stdout)

    def test_guard_precedes_artifact_build_and_publication(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        names = [
            "Check the tag matches the packaged version",
            "Build wheel and sdist",
            "Publish to PyPI",
        ]
        positions = [workflow.index("      - name: " + name) for name in names]
        self.assertEqual(positions, sorted(positions))
        self.assertNotRegex(
            self.block, re.compile(r"^\s+continue-on-error:", re.MULTILINE)
        )


if __name__ == "__main__":
    unittest.main()
