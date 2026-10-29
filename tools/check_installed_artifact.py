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


REGISTRY_KEY = "bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90"
WITNESS_KEY = "39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5"


def check_chain(command, source_root):
    entry = source_root / "registry/2026/09/01.ndjson"
    common = command + ["chain", "--registry-key", REGISTRY_KEY, "--json"]
    result = subprocess.run(common + [str(entry)], capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, f"valid installed chain failed: {result}")
    appraisal = json.loads(result.stdout)
    require(appraisal.get("verified") is True and appraisal.get("checkpoints") == 1,
            f"valid chain was not verified: {appraisal}")
    # Preserve the signed checkpoint; alter only the entry it commits to.
    altered = json.loads(entry.read_text())
    altered["producer"] += "-tampered"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "altered.ndjson"
        path.write_text(json.dumps(altered) + "\n")
        result = subprocess.run(common + [str(path)], capture_output=True, text=True, timeout=30)
    require(result.returncode == 1, f"altered chain was not rejected: {result}")
    appraisal = json.loads(result.stdout)
    require(appraisal.get("verified") is False and appraisal.get("checkpoints") == 1
            and any("root" in error for error in appraisal.get("errors", [])),
            f"wrong rejection for altered chain: {appraisal}")


def check_receipt(command, source_root, witness):
    evidence = source_root / "docs/evidence/witness-2026-09-07"
    common = command + ["receipt", "--checkpoint", str(evidence / "checkpoint-1.json"),
                        "--response", str(evidence / "witness-post.json"),
                        "--expected-log-id", "trace-registry/v1",
                        "--registry-key", REGISTRY_KEY, "--witness-key"]
    result = subprocess.run(common + [WITNESS_KEY], capture_output=True, text=True, timeout=30)
    if not witness:
        require(result.returncode == 2 and "the witness extra is not installed" in result.stderr
                and 'pip install "trace-verify[witness]"' in result.stderr
                and "Traceback" not in result.stderr,
                f"base install did not explain missing witness extra: {result}")
        return
    require(result.returncode == 0, f"valid installed receipt failed: {result}")
    appraisal = json.loads(result.stdout)
    require(appraisal.get("verified") is True and appraisal.get("leaf_index") == 936
            and appraisal.get("checks", {}).get("receipt_signature_and_inclusion") is True,
            f"valid receipt was not verified: {appraisal}")
    # Another valid Ed25519 public key, not malformed key material.
    result = subprocess.run(common + [REGISTRY_KEY], capture_output=True, text=True, timeout=30)
    require(result.returncode == 1, f"wrong witness key was not rejected: {result}")
    appraisal = json.loads(result.stdout)
    require(appraisal.get("verified") is False
            and appraisal.get("checks", {}).get("checkpoint_signature") is True
            and "receipt signature/inclusion failed" in appraisal.get("error", ""),
            f"wrong rejection for witness key: {appraisal}")


def main():
    import argparse
    import trace_verify

    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=Path)
    parser.add_argument("expected_version")
    parser.add_argument("--witness", action="store_true")
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    expected_version = args.expected_version
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
    check_chain([str(cli)], source_root)
    check_receipt([str(cli)], source_root, args.witness)
    print(f"installed artifact verified: {installed}; version={expected_version}")


if __name__ == "__main__":
    main()
