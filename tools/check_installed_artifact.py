"""Check an installed release artifact outside the checkout, using isolated Python.

Usage: <artifact-venv>/bin/python -I <checkout>/tools/check_installed_artifact.py
       <checkout> <packaged-version>
The checkout supplies offline evidence only; imports and CLI come from the venv.
"""

from importlib.metadata import version
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_cli(command, source_root, expected_version):
    result = subprocess.run(command + ["--version"], capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and result.stdout.strip() == f"trace-verify {expected_version}",
            f"installed CLI version failed: {result}")
    common = [
        "--claim", str(source_root / "samples/example-trust-record.json"),
        "--proof", str(source_root / "samples/inclusion-proof.json"),
        "--producers-dir", str(source_root / "producers"),
        "--json",
    ]
    entry = source_root / "registry/2026/06/12.ndjson"
    result = subprocess.run(command + common + ["--entry", str(entry)],
                            capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, f"valid installed-artifact verification failed: {result}")
    appraisal = json.loads(result.stdout)
    require(appraisal.get("verified") is True and appraisal.get("signature_valid") is True,
            f"valid evidence was not fully verified: {appraisal}")
    # Change only the anchored Merkle root, preserving the signed claim and key.
    # The expected result is an inclusion failure with a still-valid signature,
    # not a parser error or a missing-key rejection.
    invalid_entry = json.loads(entry.read_text())
    invalid_entry["merkle_root"] = "sha256:" + "0" * 64
    require(invalid_entry["merkle_root"] != json.loads(entry.read_text())["merkle_root"],
            "negative case did not change the anchor")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "wrong-root.ndjson"
        path.write_text(json.dumps(invalid_entry) + "\n")
        result = subprocess.run(command + common + ["--entry", str(path)],
                                capture_output=True, text=True, timeout=30)
    require(result.returncode == 1, f"invalid anchor was not rejected: {result}")
    appraisal = json.loads(result.stdout)
    require(appraisal.get("verified") is False and appraisal.get("signature_valid") is True,
            f"wrong rejection for invalid anchor: {appraisal}")


def main():
    import trace_verify

    source_root = Path(sys.argv[1]).resolve()
    expected_version = sys.argv[2]
    installed = Path(trace_verify.__file__).resolve()
    prefix = Path(sys.prefix).resolve()
    require(not Path.cwd().resolve().is_relative_to(source_root), "check ran in the checkout")
    require(installed.is_relative_to(prefix) and not installed.is_relative_to(source_root),
            f"import did not come from the artifact environment: {installed}")
    require(version("trace-verify") == expected_version == trace_verify.__version__,
            "installed metadata/runtime version differs from packaged version")
    cli = prefix / "bin/trace-verify"
    require(cli.is_file(), "installed console script is missing")
    check_cli([str(cli)], source_root, expected_version)
    print(f"installed artifact verified: {installed}; version={expected_version}")


if __name__ == "__main__":
    main()
