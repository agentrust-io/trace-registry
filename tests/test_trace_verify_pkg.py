"""Tests for the trace_verify package (src/trace_verify/).

Standard library only. Run from the repository root:

    python -m unittest discover -s tests -v

These tests exercise the package API and CLI, including the --json flag
and --entry-url stub. They do not require the package to be pip-installed;
src/ is added to sys.path by setUp.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import anchor  # noqa: E402
from trace_verify import __version__, __anchor_format_version__  # noqa: E402
from trace_verify._verify import (  # noqa: E402
    canonical_claim_bytes,
    decode_hash,
    verify_inclusion,
    ANCHOR_FORMAT_VERSION,
)
from trace_verify.__main__ import main, build_parser  # noqa: E402


def _make_claim(i: int = 0) -> dict:
    return {"id": i, "payload": f"claim-{i}", "signature": f"sig-{i}"}


def _sorted_key_bytes(claim: dict) -> bytes:
    return json.dumps(
        claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _anchor_one(claim: dict) -> tuple[str, dict, dict]:
    """Return (merkle_root_hex, entry_dict, proof_dict) for a single claim,
    anchored under the default (sorted-key) construction."""
    leaf = anchor.leaf_hash(claim)
    root, paths = anchor.build_tree([leaf])
    entry = anchor.make_entry(root, 1, "test-gateway/0.1.0", "batch-test",
                              "2026-06-12T18:00:00Z")
    proof = {"leaf_index": 0, "audit_path": paths[0]}
    return root.hex(), entry, proof


class TestPackagePublicAPI(unittest.TestCase):
    def test_version_strings_exist(self):
        self.assertIsInstance(__version__, str)
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+")

    def test_runtime_version_matches_package_metadata(self):
        import re

        match = re.search(
            r'^version = "([^"]+)"$',
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        self.assertIsNotNone(match)
        declared = match.group(1)
        self.assertEqual(__version__, declared)

    def test_anchor_format_version(self):
        self.assertEqual(__anchor_format_version__, 1)
        self.assertEqual(ANCHOR_FORMAT_VERSION, 1)

    def test_canonical_claim_bytes_matches_tools(self):
        import verify_inclusion as vi
        claim = _make_claim(42)
        raw = _sorted_key_bytes(claim)
        self.assertEqual(
            canonical_claim_bytes(claim, canonicalization_id="sorted-key"),
            vi.canonical_claim_bytes(claim, canonicalization_id="sorted-key"),
        )
        self.assertEqual(
            canonical_claim_bytes(claim, canonicalization_id="as-transmitted", raw_bytes=raw),
            vi.canonical_claim_bytes(claim, canonicalization_id="as-transmitted", raw_bytes=raw),
        )

    def test_canonical_claim_bytes_bare_call_matches_tools_unchanged(self):
        # Additive-not-breaking (Steven, 2026-08-24): the bare call with only
        # the original positional argument must be unaffected.
        import verify_inclusion as vi
        claim = _make_claim(43)
        self.assertEqual(canonical_claim_bytes(claim), vi.canonical_claim_bytes(claim))

    def test_verify_inclusion_matches_tools(self):
        import verify_inclusion as vi
        claim = _make_claim(5)
        root_hex, entry, proof = _anchor_one(claim)
        root_bytes = bytes.fromhex(root_hex)
        path_bytes = [decode_hash(h) for h in proof["audit_path"]]

        pkg_result = verify_inclusion(claim, 0, path_bytes, 1, root_bytes)
        tool_result = vi.verify_inclusion(claim, 0, path_bytes, 1, root_bytes)
        self.assertTrue(pkg_result)
        self.assertEqual(pkg_result, tool_result)

    def test_decode_hash_valid(self):
        h = "sha256:" + "ab" * 32
        self.assertEqual(decode_hash(h), bytes.fromhex("ab" * 32))

    def test_decode_hash_rejects_bad_input(self):
        for bad in ("md5:" + "0" * 32, "sha256:short", 42, None, ""):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    decode_hash(bad)


class TestCLIWithFiles(unittest.TestCase):
    def _write(self, tmp: Path, name: str, obj: object) -> Path:
        p = tmp / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def _run(self, *args: str) -> int:
        # These tests cover inclusion-proof mechanics with synthetic claims
        # that are not signed by a registered producer, so signature
        # verification is disabled. The default-on signature gate is covered by
        # TestSignatureDefault and by test_committed_sample_verifies.
        return main(list(args) + ["--no-verify-signature"])

    def test_valid_claim_exits_0(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            rc = self._run(
                "--claim", str(self._write(tmp, "claim.json", claim)),
                "--proof", str(self._write(tmp, "proof.json", proof)),
                "--entry", str(ndjson),
            )
            self.assertEqual(rc, 0)

    def test_tampered_claim_exits_1(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            tampered = {**claim, "payload": "tampered"}
            rc = self._run(
                "--claim", str(self._write(tmp, "claim.json", tampered)),
                "--proof", str(self._write(tmp, "proof.json", proof)),
                "--entry", str(ndjson),
            )
            self.assertEqual(rc, 1)

    def test_json_output_on_success(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = self._run(
                    "--claim", str(self._write(tmp, "claim.json", claim)),
                    "--proof", str(self._write(tmp, "proof.json", proof)),
                    "--entry", str(ndjson),
                    "--json",
                )
            self.assertEqual(rc, 0)
            result = json.loads(buf.getvalue())
            self.assertTrue(result["verified"])
            self.assertEqual(result["batch_id"], "batch-test")
            self.assertIn("merkle_root", result)
            self.assertIn("ts", result)

    def test_json_output_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            tampered = {**claim, "payload": "bad"}
            _, entry, proof = _anchor_one(claim)
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = self._run(
                    "--claim", str(self._write(tmp, "claim.json", tampered)),
                    "--proof", str(self._write(tmp, "proof.json", proof)),
                    "--entry", str(ndjson),
                    "--json",
                )
            self.assertEqual(rc, 1)
            result = json.loads(buf.getvalue())
            self.assertFalse(result["verified"])

    def test_batch_id_selection(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)
            other = {**entry, "batch_id": "other-batch"}
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(
                json.dumps(other) + "\n" + json.dumps(entry) + "\n",
                encoding="utf-8",
            )
            rc = self._run(
                "--claim", str(self._write(tmp, "claim.json", claim)),
                "--proof", str(self._write(tmp, "proof.json", proof)),
                "--entry", str(ndjson),
                "--batch-id", "batch-test",
            )
            self.assertEqual(rc, 0)

    def test_entry_url_fetches_content(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)
            fake_content = (json.dumps(entry) + "\n").encode("utf-8")

            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.read.return_value = fake_content

            with patch("urllib.request.urlopen", return_value=mock_resp):
                rc = self._run(
                    "--claim", str(self._write(tmp, "claim.json", claim)),
                    "--proof", str(self._write(tmp, "proof.json", proof)),
                    # allowlisted host; arbitrary hosts are rejected by the SSRF guard
                    "--entry-url",
                    "https://raw.githubusercontent.com/agentrust-io/trace-registry/main/registry/12.ndjson",
                )
            self.assertEqual(rc, 0)

    def test_committed_sample_verifies(self):
        samples = REPO_ROOT / "samples"
        registry = REPO_ROOT / "registry" / "2026" / "06" / "12.ndjson"
        if not samples.exists() or not registry.exists():
            self.skipTest("sample files not present")
        rc = self._run(
            "--claim", str(samples / "example-trust-record.json"),
            "--proof", str(samples / "inclusion-proof.json"),
            "--entry", str(registry),
        )
        self.assertEqual(rc, 0)


class TestCanonicalizationCLI(unittest.TestCase):
    """docs/anchor-format.md section 0: both anchor-leaf constructions are
    first-class, selected by the entry's declared canonicalization_id."""

    def _write(self, tmp: Path, name: str, obj: object) -> Path:
        p = tmp / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def test_as_transmitted_entry_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            raw = _sorted_key_bytes(claim)  # any raw form works for as-transmitted
            leaf = anchor.leaf_hash(claim, canonicalization_id="as-transmitted", raw_bytes=raw)
            root, paths = anchor.build_tree([leaf])
            entry = anchor.make_entry(root, 1, "test-gateway/0.1.0", "batch-test",
                                       "2026-06-12T18:00:00Z", "as-transmitted")
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            claim_path = tmp / "claim.json"
            claim_path.write_bytes(raw)
            proof = {"leaf_index": 0, "audit_path": paths[0]}
            rc = main([
                "--claim", str(claim_path),
                "--proof", str(self._write(tmp, "proof.json", proof)),
                "--entry", str(ndjson),
                "--no-verify-signature",
            ])
        self.assertEqual(rc, 0)

    def test_vintage_entry_without_canonicalization_id_infers_sorted_key(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)
            del entry["canonicalization_id"]  # simulate a pre-PR-1 entry
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            rc = main([
                "--claim", str(self._write(tmp, "claim.json", claim)),
                "--proof", str(self._write(tmp, "proof.json", proof)),
                "--entry", str(ndjson),
                "--no-verify-signature",
            ])
        self.assertEqual(rc, 0)

    def test_mismatched_layer_id_fails_loudly_not_silently(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)
            entry["canonicalization_id"] = "jcs"  # signing-layer id, wrong layer
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            import io
            from contextlib import redirect_stderr
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main([
                    "--claim", str(self._write(tmp, "claim.json", claim)),
                    "--proof", str(self._write(tmp, "proof.json", proof)),
                    "--entry", str(ndjson),
                    "--no-verify-signature",
                ])
        self.assertEqual(rc, 1)
        self.assertIn("MismatchedCanonicalizationLayerError", err.getvalue())


class TestSignatureDefault(unittest.TestCase):
    """Fix #2: signature verification is on by default and fails closed."""

    def _write(self, tmp: Path, name: str, obj: object) -> Path:
        p = tmp / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def test_missing_producer_key_fails_closed_by_default(self):
        # No --no-verify-signature: a claim whose producer has no registered
        # key must NOT report OK; it must exit non-zero.
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)  # producer test-gateway/0.1.0
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            argv = [
                "--claim", str(self._write(tmp, "claim.json", claim)),
                "--proof", str(self._write(tmp, "proof.json", proof)),
                "--entry", str(ndjson),
                "--producers-dir", str(tmp / "no-such-producers"),
            ]
            # main() fails closed via _die() (sys.exit non-zero) when the
            # producer key is absent; it must never return 0 / print OK.
            with self.assertRaises(SystemExit) as ctx:
                main(argv)
        self.assertNotEqual(ctx.exception.code, 0)

    def test_no_verify_signature_opt_out_warns_and_passes(self):
        import io
        from contextlib import redirect_stderr
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = _make_claim(0)
            _, entry, proof = _anchor_one(claim)
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main([
                    "--claim", str(self._write(tmp, "claim.json", claim)),
                    "--proof", str(self._write(tmp, "proof.json", proof)),
                    "--entry", str(ndjson),
                    "--no-verify-signature",
                ])
        self.assertEqual(rc, 0)
        self.assertIn("WARNING", err.getvalue())

    def test_claim_and_registry_entry_producers_must_match(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            claim = {
                "producer": "claim-producer/1.0.0",
                "payload": "anchored",
                "signature": "synthetic",
            }
            _, entry, proof = _anchor_one(claim)
            self.assertNotEqual(claim["producer"], entry["producer"])
            ndjson = tmp / "12.ndjson"
            ndjson.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            argv = [
                "--claim", str(self._write(tmp, "claim.json", claim)),
                "--proof", str(self._write(tmp, "proof.json", proof)),
                "--entry", str(ndjson),
                "--producers-dir", str(tmp / "producers"),
            ]
            with self.assertRaises(SystemExit) as ctx:
                main(argv)
        self.assertEqual(ctx.exception.code, 1)


class TestSSRFGuard(unittest.TestCase):
    """Fix #3: --entry-url only fetches https from the host allowlist."""

    def test_rejects_non_https_scheme(self):
        from trace_verify.__main__ import _check_url_allowed
        self.assertIsNotNone(_check_url_allowed("http://api.github.com/x"))
        self.assertIsNotNone(_check_url_allowed("file:///etc/passwd"))

    def test_rejects_non_allowlisted_host(self):
        from trace_verify.__main__ import _check_url_allowed
        self.assertIsNotNone(_check_url_allowed("https://evil.example.com/x"))
        self.assertIsNotNone(_check_url_allowed("https://169.254.169.254/latest/meta-data"))

    def test_allows_allowlisted_https_host(self):
        from trace_verify.__main__ import _check_url_allowed
        self.assertIsNone(_check_url_allowed("https://raw.githubusercontent.com/a/b/c"))
        self.assertIsNone(_check_url_allowed("https://api.github.com/repos/x/commits/HEAD"))


class TestCLIParser(unittest.TestCase):
    def test_entry_and_entry_url_mutually_exclusive(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([
                "--claim", "c.json", "--proof", "p.json",
                "--entry", "e.ndjson", "--entry-url", "https://x.com/e.ndjson",
            ])

    def test_version_flag(self):
        parser = build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
