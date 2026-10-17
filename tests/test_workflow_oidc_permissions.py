"""Keep OIDC authority at the existing publisher, anchor signer and Scorecard."""

from pathlib import Path
import shutil
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
OIDC_JOBS = {
    ("publish.yml", "publish"),
    ("anchor-pipeline.yml", "anchor"),  # Sigstore gitsign, not a package publisher
    ("scorecard.yml", "scorecard"),
}


def oidc_write(permissions):
    if isinstance(permissions, str):
        if permissions not in {"read-all", "write-all"}:
            raise ValueError("unsupported permission shorthand")
        return permissions == "write-all"
    if not isinstance(permissions, dict):
        raise ValueError("permissions must be a mapping or shorthand")
    return permissions.get("id-token") == "write"


def validate_oidc_jobs(directory):
    grants = set()
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not paths:
        raise ValueError("no workflow files found")
    for path in paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        defaults = workflow.get("permissions", {})
        if oidc_write(defaults):
            raise ValueError(f"{path.name}: workflow-wide OIDC grant")
        for name, job in workflow["jobs"].items():
            permissions = job.get("permissions", defaults)
            if permissions == "write-all":
                raise ValueError(f"{path.name}/{name}: write-all grant")
            if oidc_write(permissions):
                grants.add((path.name, name))
    if grants != OIDC_JOBS:
        raise ValueError(f"OIDC job drift: {grants ^ OIDC_JOBS}")
    return grants


class WorkflowOidcPermissionTests(unittest.TestCase):
    def test_real_workflow_grants(self):
        self.assertEqual(validate_oidc_jobs(ROOT / ".github/workflows"), OIDC_JOBS)

    def test_permission_drift_is_rejected(self):
        cases = (
            "validation-job", "workflow-inheritance", "workflow-write-all",
            "shadowed-workflow-grant", "future-job-inheritance",
            "allowed-job-write-all", "other-job-write-all", "new-yml", "new-yaml",
            "removed-publisher", "removed-anchor", "removed-scorecard",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp) / "workflows"
                shutil.copytree(ROOT / ".github/workflows", directory)
                self.assertEqual(validate_oidc_jobs(directory), OIDC_JOBS)
                if case in {"new-yml", "new-yaml"}:
                    extension = case.removeprefix("new-")
                    (directory / f"unexpected.{extension}").write_text(
                        "name: Unexpected\non: push\npermissions: {contents: read}\njobs:\n"
                        "  validation:\n    runs-on: ubuntu-latest\n"
                        "    permissions: {id-token: write}\n"
                        "    steps:\n      - run: echo validation\n",
                        encoding="utf-8",
                    )
                else:
                    filename, job_name = "ci.yml", "validate"
                    if case in {"allowed-job-write-all", "removed-publisher"}:
                        filename, job_name = "publish.yml", "publish"
                    elif case == "removed-anchor":
                        filename, job_name = "anchor-pipeline.yml", "anchor"
                    elif case == "removed-scorecard":
                        filename, job_name = "scorecard.yml", "scorecard"
                    path = directory / filename
                    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
                    job = workflow["jobs"][job_name]
                    if case == "workflow-inheritance":
                        workflow["permissions"]["id-token"] = "write"
                        job.pop("permissions", None)
                    elif case in {"shadowed-workflow-grant", "future-job-inheritance"}:
                        # Even if every existing job narrows its permissions,
                        # a new job could inherit this broad default later.
                        workflow["permissions"]["id-token"] = "write"
                        for candidate in workflow["jobs"].values():
                            candidate["permissions"] = {"contents": "read"}
                        if case == "future-job-inheritance":
                            workflow["jobs"]["future-validation"] = {
                                "runs-on": "ubuntu-latest",
                                "steps": [{"run": "echo validation"}],
                            }
                    elif case == "workflow-write-all":
                        workflow["permissions"] = "write-all"
                    elif case in {"allowed-job-write-all", "other-job-write-all"}:
                        job["permissions"] = "write-all"
                    elif case.startswith("removed-"):
                        job["permissions"].pop("id-token")
                    else:
                        job.setdefault("permissions", {})["id-token"] = "write"
                    path.write_text(yaml.safe_dump(workflow), encoding="utf-8")
                with self.assertRaises(ValueError):
                    validate_oidc_jobs(directory)

    def test_read_only_inheritance_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "workflows"
            shutil.copytree(ROOT / ".github/workflows", directory)
            (directory / "read-only.yaml").write_text(
                "name: Read only\non: push\npermissions: read-all\njobs:\n"
                "  validation:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: echo validation\n",
                encoding="utf-8",
            )
            self.assertEqual(validate_oidc_jobs(directory), OIDC_JOBS)

    def test_empty_workflow_inventory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "no workflow files"):
                validate_oidc_jobs(Path(tmp))

    def test_invalid_permission_shapes_are_rejected(self):
        for permissions in (None, [], 1, "unsupported"):
            with self.subTest(permissions=permissions), self.assertRaises(ValueError):
                oidc_write(permissions)


if __name__ == "__main__":
    unittest.main()
