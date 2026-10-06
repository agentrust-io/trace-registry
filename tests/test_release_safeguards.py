"""Release graph and installed-artifact failure cases, without publishing anything."""

import ast
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github/workflows/publish.yml"
CI = ROOT / ".github/workflows/ci.yml"
spec = importlib.util.spec_from_file_location(
    "artifact_check", ROOT / "tools/check_installed_artifact.py"
)
artifact_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact_check)


def job(workflow, name):
    return re.split(r"\n  \S", workflow.split(f"\n  {name}:\n", 1)[1], maxsplit=1)[0]


def condition(block):
    lines = block.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("    if: "):
            value = line.removeprefix("    if: ")
            if value == ">-":
                continued = []
                for following in lines[i + 1:]:
                    if not following.startswith("      "):
                        break
                    continued.append(following.strip())
                value = " ".join(continued)
            return value
    raise AssertionError("missing job condition")


def evaluate(expression, **values):
    # The checked-in Actions condition supports only boolean/comparison syntax.
    # Reject anything else before evaluating it with no builtins.
    for token, value in values.items():
        expression = expression.replace(token, repr(value))
    expression = expression.replace("&&", " and ").replace("||", " or ")
    tree = ast.parse(expression.strip(), mode="eval")
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare,
               ast.Eq, ast.NotEq, ast.Constant, ast.Load)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise AssertionError(f"unexpected expression: {expression}")
    return eval(compile(tree, "<release condition>", "eval"), {"__builtins__": {}})


class TestReleaseGraph(unittest.TestCase):
    def setUp(self):
        self.workflow = PUBLISH.read_text()
        self.build = job(self.workflow, "build")
        self.publish = job(self.workflow, "publish")

    def test_validation_is_the_existing_ci_job_on_the_same_revision(self):
        self.assertIn("  workflow_call:\n", CI.read_text())
        self.assertIn("uses: ./.github/workflows/ci.yml", job(self.workflow, "validate"))
        self.assertNotRegex(self.workflow, r"(?m)^\s+ref:")
        self.assertIn("    needs: validate\n", self.build)
        self.assertIn("    needs: [validate, build]\n", self.publish)
        self.assertNotIn("continue-on-error:", self.workflow)
        self.assertNotIn("always()", condition(self.build))
        self.assertNotIn("always()", condition(self.publish))

    def test_failed_cancelled_or_skipped_validation_blocks_build_and_publication(self):
        for status in ("success", "failure", "cancelled", "skipped"):
            with self.subTest(status=status):
                values = {"success()": True, "needs.validate.result": status,
                          "needs.build.result": "success", "github.event_name": "release",
                          "github.event.inputs.dry_run": ""}
                self.assertEqual(evaluate(condition(self.build), **values), status == "success")
                self.assertEqual(evaluate(condition(self.publish), **values), status == "success")

    def test_failed_cancelled_or_skipped_artifacts_block_publication(self):
        for status in ("failure", "cancelled", "skipped"):
            self.assertFalse(evaluate(condition(self.publish), **{
                "success()": True, "needs.validate.result": "success",
                "needs.build.result": status, "github.event_name": "release",
                "github.event.inputs.dry_run": ""}))
        self.assertFalse(evaluate(condition(self.publish), **{
            "success()": False, "needs.validate.result": "success",
            "needs.build.result": "success", "github.event_name": "release",
            "github.event.inputs.dry_run": ""}))

    def test_only_release_or_explicit_manual_publication_is_eligible(self):
        for event, dry_run, eligible in (("release", "", True),
                                        ("workflow_dispatch", "false", True),
                                        ("workflow_dispatch", "true", False),
                                        ("workflow_dispatch", "", False),
                                        ("workflow_dispatch", "invalid", False),
                                        ("push", "false", False)):
            with self.subTest(event=event, dry_run=dry_run):
                self.assertEqual(evaluate(condition(self.publish), **{
                    "success()": True, "needs.validate.result": "success",
                    "needs.build.result": "success", "github.event_name": event,
                    "github.event.inputs.dry_run": dry_run}), eligible)
        self.assertRegex(self.workflow, r"(?s)dry_run:.*?default: true")

    def test_build_only_has_no_publishing_authority(self):
        self.assertNotIn("environment:", self.build)
        self.assertNotIn("id-token:", self.build)
        self.assertIn("    environment: pypi\n", self.publish)
        self.assertIn("      id-token: write\n", self.publish)
        self.assertEqual(self.workflow.count("id-token: write"), 1)
        self.assertEqual(self.workflow.count("pypa/gh-action-pypi-publish@"), 1)
        self.assertNotIn("test.pypi", self.workflow)

    def test_verified_artifacts_are_transferred_without_a_rebuild(self):
        self.assertLess(self.build.index("Verify installed wheel and sdist"),
                        self.build.index("Upload verified distributions"))
        self.assertIn("if-no-files-found: error", self.build)
        self.assertLess(self.publish.index("Download verified distributions"),
                        self.publish.index("Publish to PyPI"))
        self.assertIn("name: trace-verify-dist", self.build)
        self.assertIn("name: trace-verify-dist", self.publish)
        self.assertNotIn("checkout@", self.publish)
        self.assertNotIn("python -m build", self.publish)
        self.assertIn('for artifact in "${wheels[@]}" "${sdists[@]}"', self.build)
        self.assertIn('cd "$check_dir"', self.build)
        self.assertIn(' -I "$source_root/tools/check_installed_artifact.py"', self.build)
        for action in re.findall(r"uses: ([^\s]+)", self.workflow):
            if not action.startswith("./"):
                self.assertRegex(action, r"@[0-9a-f]{40}$")

    def test_append_only_steps_are_explicitly_skipped_without_a_push_or_pr_base(self):
        workflow = CI.read_text()
        for name in ("Determine base SHA for append-only check", "Check registry is append-only"):
            block = workflow.split(f"      - name: {name}\n", 1)[1].split("      - name:", 1)[0]
            expression = re.search(r"^        if: (.+)$", block, re.MULTILINE).group(1)
            for event, enabled in (("push", True), ("pull_request", True),
                                   ("release", False), ("workflow_dispatch", False)):
                self.assertEqual(evaluate(expression, **{
                    "github.event_name": event, "steps.base.outputs.sha": "a" * 40}), enabled)


class TestInstalledArtifactChecks(unittest.TestCase):
    def test_always_accepting_cli_is_caught_by_the_invalid_anchor(self):
        def response(command, **kwargs):
            if "--version" in command:
                stdout = "trace-verify 0.4.3\n"
            else:
                stdout = json.dumps({"verified": True, "signature_valid": True})
            return subprocess.CompletedProcess(command, 0, stdout, "")
        with patch.object(artifact_check.subprocess, "run", side_effect=response):
            with self.assertRaisesRegex(RuntimeError, "invalid anchor was not rejected"):
                artifact_check.check_cli(["fake-cli"], ROOT, "0.4.3")

    def test_always_rejecting_cli_is_caught_by_the_control(self):
        def response(command, **kwargs):
            if "--version" in command:
                return subprocess.CompletedProcess(command, 0, "trace-verify 0.4.3\n", "")
            return subprocess.CompletedProcess(command, 1, '{"verified": false}', "")
        with patch.object(artifact_check.subprocess, "run", side_effect=response):
            with self.assertRaisesRegex(RuntimeError, "valid installed-artifact verification failed"):
                artifact_check.check_cli(["fake-cli"], ROOT, "0.4.3")

    def test_cli_version_mismatch_is_caught(self):
        result = subprocess.CompletedProcess([], 0, "trace-verify 9.9.9\n", "")
        with patch.object(artifact_check.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "installed CLI version failed"):
                artifact_check.check_cli(["fake-cli"], ROOT, "0.4.3")

    def test_actual_cli_accepts_control_and_rejects_wrong_anchor(self):
        with patch.object(artifact_check.subprocess, "run", wraps=subprocess.run) as run:
            expected = re.search(r'^version = "([^"]+)"',
                                 (ROOT / "pyproject.toml").read_text(), re.MULTILINE).group(1)
            artifact_check.check_cli([sys.executable, "-m", "trace_verify"], ROOT, expected)
            self.assertEqual(run.call_count, 3)


if __name__ == "__main__":
    unittest.main()
