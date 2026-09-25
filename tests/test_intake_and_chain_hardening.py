"""Regression tests for intake robustness, checkpoint key continuity and the
append-only gate.

Each test here failed against origin/main e3910b8 before the fix it covers.
"""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
)

import batch_anchor  # noqa: E402
import check_append_only  # noqa: E402
from aggregator._core import TRACEAggregator  # noqa: E402
from aggregator._mmr_log import CheckpointLog, Ed25519CheckpointSigner  # noqa: E402
from trace_verify.__main__ import main as trace_verify_main  # noqa: E402
from trace_verify._checkpoint import (  # noqa: E402
    CheckpointRecord,
    verify_checkpoint_chain,
)
from trace_verify._signature import canonical_body_bytes  # noqa: E402


def _pem(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _signed_claim(priv, producer, tag="a"):
    body = {"fmt": 1, "producer": producer, "ts": "2026-06-22T00:00:00Z",
            "hash": "sha256:" + ("0" * 63 + tag)}
    sig = priv.sign(canonical_body_bytes(body))
    return {**body, "signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode()}


def _write_producer_key(producers_dir: Path, producer, priv):
    producers_dir.mkdir(parents=True, exist_ok=True)
    x = base64.urlsafe_b64encode(priv.public_key().public_bytes_raw()).rstrip(b"=").decode()
    entry = {
        "producer_id": producer,
        "key_type": "Ed25519",
        "public_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
        "active_since": "2026-06-01T00:00:00Z",
        "contact": "test@example.com",
    }
    (producers_dir / (producer.replace("/", "-") + ".json")).write_text(
        json.dumps(entry), encoding="utf-8"
    )


class NonStringProducerIntakeTest(unittest.TestCase):
    """A staged record whose 'producer' is a JSON array or object used to raise
    TypeError (unhashable dict key) before any rejection logic ran. In the
    scheduled pipeline that aborts the whole run, for every producer, on every
    run until someone deletes the file by hand."""

    def test_batch_anchor_rejects_it_and_still_anchors_the_valid_group(self):
        priv = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            incoming = tmp / "staging" / "incoming"
            incoming.mkdir(parents=True)
            producers = tmp / "producers"
            _write_producer_key(producers, "good/1.0.0", priv)
            (incoming / "good.json").write_text(
                json.dumps(_signed_claim(priv, "good/1.0.0")), encoding="utf-8")
            (incoming / "bad.json").write_text(
                json.dumps({"producer": ["good/1.0.0"], "signature": "x"}),
                encoding="utf-8")

            out = StringIO()
            with patch("sys.stdout", out):
                rc = batch_anchor.main([
                    "--staging-dir", str(tmp / "staging"),
                    "--registry-dir", str(tmp / "registry"),
                    "--proofs-dir", str(tmp / "proofs"),
                    "--producers-dir", str(producers),
                    "--ts", "2026-06-22T00:00:00Z",
                    "--json",
                ])
            report = json.loads(out.getvalue())

        self.assertEqual(rc, 1)
        by_status = {b["status"]: b for b in report["batches"]}
        self.assertIn("anchored", by_status)
        self.assertEqual(by_status["anchored"]["producer"], "good/1.0.0")
        self.assertIn("rejected", by_status)
        self.assertIn("not a string", by_status["rejected"]["detail"])

    def test_batch_anchor_rejects_it_even_with_signatures_off(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            incoming = tmp / "staging" / "incoming"
            incoming.mkdir(parents=True)
            (incoming / "bad.json").write_text(
                json.dumps({"producer": {"id": "x/1.0.0"}}), encoding="utf-8")
            out = StringIO()
            with patch("sys.stdout", out):
                rc = batch_anchor.main([
                    "--staging-dir", str(tmp / "staging"),
                    "--registry-dir", str(tmp / "registry"),
                    "--proofs-dir", str(tmp / "proofs"),
                    "--ts", "2026-06-22T00:00:00Z",
                    "--no-verify-signatures", "--json",
                ])
            report = json.loads(out.getvalue())
            self.assertFalse((tmp / "registry").exists())
        self.assertEqual(rc, 1)
        self.assertEqual(report["batches"][0]["status"], "rejected")

    def test_aggregator_flush_thread_survives_it(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = TRACEAggregator(
                registry_dir=tmp / "registry",
                proofs_dir=tmp / "proofs",
                flush_interval=0.2,
                git_commit=False,
                verify_signatures=False,
                enable_mmr_checkpoints=False,
            )
            bad = agg.submit([{"producer": [1], "hash": "x"}], timeout=10)
            self.assertTrue(bad[0].get("rejected"), bad)
            self.assertIn("not a string", bad[0]["reason"])
            # The flush thread must still be alive to anchor the next claim.
            good = agg.submit([{"producer": "p/1.0.0", "hash": "y"}], timeout=10)
            self.assertIn("batch_id", good[0])

    def test_aggregator_reports_an_anchoring_failure_instead_of_hanging(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = TRACEAggregator(
                registry_dir=tmp / "registry",
                proofs_dir=tmp / "proofs",
                flush_interval=0.2,
                git_commit=False,
                verify_signatures=False,
                enable_mmr_checkpoints=False,
            )
            with patch.object(agg, "_write_registry_entry",
                              side_effect=OSError("disk full")):
                failed = agg.submit([{"producer": "p/1.0.0", "hash": "a"}], timeout=10)
            self.assertTrue(failed[0].get("rejected"), failed)
            self.assertIn("disk full", failed[0]["reason"])
            ok = agg.submit([{"producer": "p/1.0.0", "hash": "b"}], timeout=10)
            self.assertIn("batch_id", ok[0])


class CheckpointKeyContinuityTest(unittest.TestCase):
    """The chain's key_id is self-certifying: every checkpoint names its own
    verification key. Nothing compared one checkpoint's key with the next, so
    a chain that switched signers midway verified clean, and the pipeline
    extended a published chain under whatever key the secret held."""

    def _entry(self, n):
        return {"ts": "2026-09-01T00:00:00Z", "merkle_root": "sha256:" + "ab" * 32,
                "leaf_count": 1, "producer": "p/1.0.0", "batch_id": f"b{n}"}

    def test_chain_verifier_rejects_a_mid_chain_key_change(self):
        a = Ed25519CheckpointSigner(None, pem=_pem(Ed25519PrivateKey.generate()))
        b = Ed25519CheckpointSigner(None, pem=_pem(Ed25519PrivateKey.generate()))
        with tempfile.TemporaryDirectory() as d:
            log = CheckpointLog(Path(d), signer=a)
            cp1 = log.append_entry(self._entry(1), timestamp="2026-09-01T00:00:00Z")
            log._signer = b  # a different key picks the chain up
            cp2 = log.append_entry(self._entry(2), timestamp="2026-09-01T00:15:00Z")
        ok, errors = verify_checkpoint_chain(
            [CheckpointRecord.from_dict(cp1.to_dict()), CheckpointRecord.from_dict(cp2.to_dict())]
        )
        self.assertFalse(ok)
        self.assertTrue(any("key_id" in e for e in errors), errors)

    def test_chain_verifier_accepts_one_key_throughout(self):
        a = Ed25519CheckpointSigner(None, pem=_pem(Ed25519PrivateKey.generate()))
        with tempfile.TemporaryDirectory() as d:
            log = CheckpointLog(Path(d), signer=a)
            cps = [log.append_entry(self._entry(i), timestamp="2026-09-01T00:00:00Z")
                   for i in range(3)]
        ok, errors = verify_checkpoint_chain(
            [CheckpointRecord.from_dict(c.to_dict()) for c in cps])
        self.assertTrue(ok, errors)

    def test_pipeline_refuses_to_extend_a_chain_under_a_different_key(self):
        first, second = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            registry = Path(d) / "registry"
            registry.mkdir()
            os.environ[batch_anchor.CHECKPOINT_KEY_ENV] = _pem(first).decode("ascii")
            try:
                log = batch_anchor.open_checkpoint_log(registry, log_id="trace-registry/v1")
                claim = {"producer": "p/1.0.0", "seq": 0}
                batch_anchor.anchor_group(
                    "p/1.0.0", [(Path("c0.json"), claim, json.dumps(claim).encode())],
                    "2026-09-01T00:00:00Z", "b0", registry, Path(d) / "proofs",
                    dry_run=False, checkpoint_log=log,
                )
                os.environ[batch_anchor.CHECKPOINT_KEY_ENV] = _pem(second).decode("ascii")
                with self.assertRaises(ValueError) as ctx:
                    batch_anchor.open_checkpoint_log(registry, log_id="trace-registry/v1")
            finally:
                os.environ.pop(batch_anchor.CHECKPOINT_KEY_ENV, None)
        self.assertIn("key_id", str(ctx.exception))


class AppendOnlyGateTest(unittest.TestCase):
    """tools/check_append_only.py is the CI gate on registry history."""

    @staticmethod
    def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)

    def _repo(self, tmp: Path) -> tuple[Path, str]:
        repo = tmp / "repo"
        repo.mkdir()
        self._git(repo, "init", "-q")
        self._git(repo, "config", "user.email", "ci@example.com")
        self._git(repo, "config", "user.name", "CI Test")
        self._git(repo, "config", "core.autocrlf", "false")
        day = repo / "registry" / "2026" / "06" / "12.ndjson"
        day.parent.mkdir(parents=True)
        # Enough lines that git's rename detection pairs an edited copy with
        # the original (50% similarity) instead of reporting delete + add.
        day.write_text("".join(
            json.dumps({"batch_id": f"b{i}", "merkle_root": "sha256:" + "ab" * 32}) + "\n"
            for i in range(1, 11)), encoding="utf-8")
        self._git(repo, "add", "registry/")
        self._git(repo, "commit", "-q", "-m", "entry")
        return repo, self._git(repo, "rev-parse", "HEAD").stdout.strip()

    def _check(self, repo: Path, base: str) -> int:
        original = check_append_only.REPO_ROOT
        try:
            check_append_only.REPO_ROOT = repo
            with redirect_stdout(io.StringIO()):
                return check_append_only.main([base])
        finally:
            check_append_only.REPO_ROOT = original

    def test_renaming_a_day_file_out_of_ndjson_is_rejected(self):
        # git diff reports a rename under the NEW name only, which does not
        # end in .ndjson, so the file silently left the registry.
        with tempfile.TemporaryDirectory() as t:
            repo, base = self._repo(Path(t))
            self._git(repo, "mv", "registry/2026/06/12.ndjson", "registry/2026/06/12.txt")
            self._git(repo, "commit", "-q", "-m", "move")
            self.assertEqual(self._check(repo, base), 1)

    def test_renaming_and_editing_a_day_file_is_rejected(self):
        # A rename to another .ndjson path was read as a brand-new file, so
        # its edited content was never compared with what was published.
        with tempfile.TemporaryDirectory() as t:
            repo, base = self._repo(Path(t))
            old = repo / "registry" / "2026" / "06" / "12.ndjson"
            new = repo / "registry" / "2026" / "06" / "13.ndjson"
            text = old.read_text(encoding="utf-8").replace('"b1"', '"b99"')
            self._git(repo, "mv", str(old.relative_to(repo)), str(new.relative_to(repo)))
            new.write_text(text, encoding="utf-8")
            self._git(repo, "add", "-A")
            self._git(repo, "commit", "-q", "-m", "move and edit")
            self.assertEqual(self._check(repo, base), 1)

    def test_unresolvable_base_fails_closed(self):
        # A force-push to main leaves github.event.before unreachable from the
        # new history: exactly the rewrite this gate exists to catch.
        with tempfile.TemporaryDirectory() as t:
            repo, _ = self._repo(Path(t))
            self.assertEqual(self._check(repo, "f" * 40), 1)

    def test_pure_append_still_passes(self):
        with tempfile.TemporaryDirectory() as t:
            repo, base = self._repo(Path(t))
            day = repo / "registry" / "2026" / "06" / "12.ndjson"
            with day.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"batch_id": "b11"}) + "\n")
            self._git(repo, "commit", "-q", "-am", "append")
            self.assertEqual(self._check(repo, base), 0)


def _sign_raw(priv, body: dict) -> dict:
    sig = priv.sign(canonical_body_bytes(body))
    return {**body, "signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode()}


class AnchorProfileIntakeTest(unittest.TestCase):
    """registry-anchor-v1 section 1: claims carry no non-integer numbers and no
    integers outside -(2^53-1)..2^53-1, and a claim is one JSON object with
    unique member names. The pipeline anchored all of these, producing leaves
    the conformance suite (trace-tests TR-ANC-002) refuses."""

    def _run(self, files: dict[str, bytes], *, verify=True, priv=None):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            incoming = tmp / "staging" / "incoming"
            incoming.mkdir(parents=True)
            producers = tmp / "producers"
            producers.mkdir()
            if priv is not None:
                _write_producer_key(producers, "good/1.0.0", priv)
            for name, raw in files.items():
                (incoming / name).write_bytes(raw)
            argv = [
                "--staging-dir", str(tmp / "staging"),
                "--registry-dir", str(tmp / "registry"),
                "--proofs-dir", str(tmp / "proofs"),
                "--producers-dir", str(producers),
                "--ts", "2026-06-22T00:00:00Z", "--json",
            ] + ([] if verify else ["--no-verify-signatures"])
            out = StringIO()
            with patch("sys.stdout", out):
                rc = batch_anchor.main(argv)
            anchored = (tmp / "registry").exists()
            return rc, json.loads(out.getvalue()), anchored

    def test_signed_float_claim_is_rejected(self):
        # JCS accepts 1.5, so the signature verifies; section 1 still
        # excludes it from the anchor leaf.
        priv = Ed25519PrivateKey.generate()
        claim = _sign_raw(priv, {"producer": "good/1.0.0", "score": 1.5})
        rc, report, anchored = self._run({"c.json": json.dumps(claim).encode()}, priv=priv)
        self.assertEqual(rc, 1)
        self.assertFalse(anchored)
        self.assertEqual(report["batches"][0]["status"], "rejected")
        self.assertIn("non-integer", report["batches"][0]["detail"])

    def test_integer_outside_safe_range_is_rejected(self):
        claim = {"producer": "good/1.0.0", "n": 2**53}
        rc, report, anchored = self._run({"c.json": json.dumps(claim).encode()}, verify=False)
        self.assertEqual(rc, 1)
        self.assertFalse(anchored)
        self.assertIn("safe-integer", report["batches"][0]["detail"])

    def test_integer_at_the_safe_bound_is_accepted(self):
        claim = {"producer": "good/1.0.0", "n": 2**53 - 1, "m": -(2**53 - 1), "b": True}
        rc, report, anchored = self._run({"c.json": json.dumps(claim).encode()}, verify=False)
        self.assertEqual(rc, 0, report)
        self.assertTrue(anchored)

    def test_duplicate_member_names_are_rejected(self):
        # json.loads keeps the last value, so the signature was checked over
        # {"hash": B} while the as-transmitted bytes also carry "hash": A.
        priv = Ed25519PrivateKey.generate()
        signed = _sign_raw(priv, {"producer": "good/1.0.0", "hash": "B"})
        raw = ('{"hash": "A", ' + json.dumps(signed)[1:]).encode()
        rc, report, anchored = self._run({"c.json": raw}, priv=priv)
        self.assertEqual(rc, 1)
        self.assertFalse(anchored)
        self.assertIn("duplicate", report["batches"][0]["detail"])

    def test_nesting_too_deep_to_parse_does_not_abort_the_run(self):
        # json.loads raises RecursionError, not JSONDecodeError, which escaped
        # scan_staging and aborted the run for every producer.
        priv = Ed25519PrivateKey.generate()
        good = _sign_raw(priv, {"producer": "good/1.0.0", "hash": "g"})
        deep = b'{"producer":"good/1.0.0","x":' + b"[" * 100000 + b"]" * 100000 + b"}"
        rc, report, anchored = self._run(
            {"good.json": json.dumps(good).encode(), "deep.json": deep}, priv=priv)
        statuses = {b["status"] for b in report["batches"]}
        self.assertIn("anchored", statuses)
        self.assertIn("rejected", statuses)
        self.assertEqual(rc, 1)

    def test_nesting_too_deep_to_canonicalize_is_rejected_not_raised(self):
        # Parses, but the JCS signature pre-image recurses past the limit.
        # RecursionError is not a ValueError and escaped the signature check.
        deep = (b'{"producer":"good/1.0.0","signature":"' + b"A" * 86 + b'","x":'
                + b"[" * 2000 + b"]" * 2000 + b"}")
        priv = Ed25519PrivateKey.generate()
        rc, report, anchored = self._run({"c.json": deep}, priv=priv)
        self.assertEqual(rc, 1)
        self.assertFalse(anchored)
        self.assertEqual(report["batches"][0]["status"], "rejected")

    def test_aggregator_submit_refuses_an_out_of_profile_claim(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = TRACEAggregator(
                registry_dir=tmp / "registry", proofs_dir=tmp / "proofs",
                flush_interval=0.2, git_commit=False, verify_signatures=False,
                enable_mmr_checkpoints=False,
            )
            with self.assertRaises(ValueError) as ctx:
                agg.submit([{"producer": "p/1.0.0", "score": 0.5}], timeout=5)
            self.assertIn("non-integer", str(ctx.exception))
            self.assertFalse((tmp / "registry").exists())

    def test_manual_anchor_tool_refuses_an_out_of_profile_claim(self):
        import anchor
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text(json.dumps({"producer": "p/1.0.0", "score": 0.5}), encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                anchor._load_claim(p)
            self.assertIn("non-integer", str(ctx.exception.code))
            p.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                anchor._load_claim(p)
            self.assertIn("duplicate", str(ctx.exception.code))


class JsonOutputOnSignatureFailureTest(unittest.TestCase):
    def test_json_mode_prints_exactly_one_document(self):
        priv = Ed25519PrivateKey.generate()  # not the key that signed the sample
        with tempfile.TemporaryDirectory() as d:
            producers = Path(d)
            _write_producer_key(producers, "cmcp-gateway/0.1.0", priv)
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = trace_verify_main([
                    "--claim", str(REPO_ROOT / "samples" / "example-trust-record.json"),
                    "--proof", str(REPO_ROOT / "samples" / "inclusion-proof.json"),
                    "--entry", str(REPO_ROOT / "registry" / "2026" / "06" / "12.ndjson"),
                    "--producers-dir", str(producers),
                    "--json",
                ])
        self.assertEqual(code, 1)
        result = json.loads(buf.getvalue())  # "Extra data" if two documents
        self.assertFalse(result["verified"])
        self.assertFalse(result["signature_valid"])
        self.assertIn("error", result)


class FetchRedirectAllowlistTest(unittest.TestCase):
    """_fetch_url checked the allowlist on the URL it was given, then let
    urllib follow any redirect: to http://, to 169.254.169.254, anywhere."""

    ALLOWED = "https://raw.githubusercontent.com/agentrust-io/trace-registry/main/registry/2026/06/12.ndjson"

    def _serve_redirect(self, location: str):
        import email.message
        import urllib.request
        import urllib.response

        from trace_verify import __main__ as tv
        allowed = self.ALLOWED

        def respond(req, code, loc=None):
            headers = email.message.Message()
            if loc:
                headers["Location"] = loc
            body = b"" if loc else b"fetched from the redirect target\n"
            resp = urllib.response.addinfourl(io.BytesIO(body), headers, req.full_url, code)
            resp.msg = "Found" if loc else "OK"
            return resp

        class FakeNetwork(urllib.request.BaseHandler):
            # No socket opens: the allowlisted URL answers 302 to `location`,
            # and anything else answers 200, so following the redirect is
            # observable as a successful fetch. Ordered ahead of urllib's own
            # HTTPS handler, which would otherwise answer first.
            handler_order = 100

            def https_open(self, req):
                if req.full_url == allowed:
                    return respond(req, 302, location)
                return respond(req, 200)

            def http_open(self, req):
                return respond(req, 200)

        handler = getattr(tv, "_AllowlistRedirectHandler", urllib.request.HTTPRedirectHandler)
        opener = urllib.request.build_opener(FakeNetwork, handler)
        return opener, tv

    def test_redirect_off_the_allowlist_is_refused(self):
        for target in ("http://raw.githubusercontent.com/x",
                       "https://169.254.169.254/latest/meta-data/",
                       "https://evil.example/registry.ndjson"):
            opener, tv = self._serve_redirect(target)
            with patch.object(tv, "_OPENER", opener, create=True), \
                    patch("urllib.request.urlopen", opener.open):
                with self.assertRaises(SystemExit) as ctx:
                    tv._fetch_url(self.ALLOWED)
            self.assertEqual(ctx.exception.code, 2, target)

    def test_redirect_within_the_allowlist_is_followed(self):
        from trace_verify import __main__ as tv
        handler = tv._AllowlistRedirectHandler()
        import urllib.request
        req = urllib.request.Request(self.ALLOWED)
        new = handler.redirect_request(
            req, None, 301, "Moved", {},
            "https://raw.githubusercontent.com/agentrust-io/renamed/main/x.ndjson")
        self.assertIsNotNone(new)
        self.assertEqual(new.full_url,
                         "https://raw.githubusercontent.com/agentrust-io/renamed/main/x.ndjson")

    def test_fetch_uses_the_allowlisting_opener(self):
        from trace_verify import __main__ as tv
        self.assertTrue(any(isinstance(h, tv._AllowlistRedirectHandler)
                            for h in tv._OPENER.handlers))


class AggregatorBodyLimitTest(unittest.TestCase):
    """The server read Content-Length bytes with no cap, and a missing or
    negative length fell through to rfile.read."""

    def setUp(self):
        import threading

        from aggregator.server import AggregatorHTTPServer
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.agg = TRACEAggregator(
            registry_dir=tmp / "registry", proofs_dir=tmp / "proofs",
            flush_interval=0.2, git_commit=False, verify_signatures=False,
            enable_mmr_checkpoints=False,
        )
        self.server = AggregatorHTTPServer(("127.0.0.1", 0), self.agg)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def _post(self, headers: dict, body: bytes = b"") -> int:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/batch", skip_accept_encoding=True)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.endheaders()
        if body:
            conn.send(body)
        status = conn.getresponse().status
        conn.close()
        return status

    def test_over_limit_is_413_without_reading_the_body(self):
        from aggregator import server
        self.assertEqual(
            self._post({"Content-Length": str(server.MAX_BODY_BYTES + 1)}), 413)

    def test_missing_negative_and_malformed_lengths_are_400(self):
        self.assertEqual(self._post({}), 400)
        self.assertEqual(self._post({"Content-Length": "-1"}), 400)
        self.assertEqual(self._post({"Content-Length": "abc"}), 400)

    def test_a_body_inside_the_limit_is_still_accepted(self):
        body = json.dumps({"claims": [{"producer": "p/1.0.0", "hash": "h"}]}).encode()
        self.assertEqual(self._post({"Content-Length": str(len(body))}, body), 200)


if __name__ == "__main__":
    unittest.main()
