"""A self-consistent chain is not proof of the independently trusted signer."""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from trace_verify.__main__ import main  # noqa: E402
from trace_verify._checkpoint import CheckpointRecord  # noqa: E402


class RegistryKeyPinTests(unittest.TestCase):
    def setUp(self):
        self.sample = ROOT / "registry/2026/09/01.ndjson"
        self.entry = json.loads(self.sample.read_text())
        self.key = self.entry["mmr_checkpoint"]["key_id"]

    def run_chain(self, path, *flags):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["chain", str(path), *flags])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_matching_pin_verifies_and_reports_signer(self):
        code, stdout, _ = self.run_chain(self.sample, "--registry-key", self.key)
        self.assertEqual(code, 0)
        self.assertIn(f"key_id {self.key}", stdout)

    def test_json_reports_signer_with_or_without_pin(self):
        for flags in ([], ["--registry-key", self.key.upper()]):
            with self.subTest(flags=flags):
                code, stdout, _ = self.run_chain(self.sample, "--json", *flags)
                self.assertEqual(code, 0)
                result = json.loads(stdout)
                self.assertTrue(result["verified"])
                self.assertEqual(result["key_id"], self.key)

    def test_valid_chain_resigned_by_another_key_requires_new_trust(self):
        other = Ed25519PrivateKey.generate()
        checkpoint = CheckpointRecord.from_dict(self.entry["mmr_checkpoint"])
        checkpoint.key_id = other.public_key().public_bytes_raw().hex()
        checkpoint.signature = other.sign(checkpoint.digest().encode("ascii")).hex()
        self.entry["mmr_checkpoint"] = checkpoint.to_dict()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "replacement.ndjson"
            path.write_text(json.dumps(self.entry) + "\n")
            code, _, _ = self.run_chain(path)
            self.assertEqual(code, 0, "the replacement is internally valid")
            for flags in ([], ["--json"]):
                with self.subTest(flags=flags):
                    code, stdout, stderr = self.run_chain(
                        path, "--registry-key", self.key, *flags
                    )
                    self.assertEqual(code, 1)
                    self.assertIn("does not match pinned registry key", stdout + stderr)
                    if flags:
                        self.assertFalse(json.loads(stdout)["verified"])

    def test_malformed_pin_is_argument_error(self):
        for key in ("", "gg" * 32, "aa" * 31, "aa" * 33, "aa " * 32):
            with self.subTest(key=key), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main(["chain", str(self.sample), "--registry-key", key])
                self.assertEqual(caught.exception.code, 2)

    def test_pin_does_not_bypass_integrity_check(self):
        self.entry["producer"] = "altered/1.0.0"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "altered.ndjson"
            path.write_text(json.dumps(self.entry) + "\n")
            code, stdout, _ = self.run_chain(path, "--registry-key", self.key, "--json")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(stdout)["verified"])
        self.assertIn("altered after it was checkpointed", stdout)

    def test_pin_does_not_turn_absence_into_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.ndjson"
            path.write_text("")
            code, stdout, _ = self.run_chain(path, "--registry-key", self.key, "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stdout)["reason"], "no_checkpoints")
