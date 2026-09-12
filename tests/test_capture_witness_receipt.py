"""Tests for tools/capture_witness_receipt.py.

The happy path replays the archived September 7, 2026 responses through a fake
transport and asserts the tool reproduces that packet: same request digest, same
signing digest, same response hashes, and a real offline verification over the
captured bytes. Sockets are never opened.

The remaining cases are about the thing this tool exists to prevent. The
September capture lost a POST status to a local logging error and had to label
the field as inferred. So a non-200, a transport failure and a disagreeing
receipt each have to appear in the manifest as what happened.
"""

from __future__ import annotations

import hashlib
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import capture_witness_receipt as cwr

PACKET = REPO_ROOT / "docs" / "evidence" / "witness-2026-09-07"
BASE = "https://witness.agentactioncapsule.org"
LOG_ID = "trace-registry/v1"
REGISTRY_KEY = "bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90"
WITNESS_KEY = "39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5"
SIGNING_DIGEST = "41138372adb1921186ca6a0dbc3433a0ea2f6475cb863205603ab1231968f99a"

POST_URL = BASE + "/checkpoints"
READBACK_URL = BASE + "/checkpoints/" + LOG_ID
INCLUSION_URL = BASE + "/v1/inclusion/" + SIGNING_DIGEST


def archived(name):
    return (PACKET / name).read_bytes()


class _FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _routes(**overrides):
    routes = {
        POST_URL: (200, archived("witness-post.json")),
        READBACK_URL: (200, archived("witness-readback.json")),
        INCLUSION_URL: (200, archived("witness-inclusion.json")),
    }
    routes.update(overrides)
    return routes


class _Transport:
    """Answers from a URL map and records every request it was given."""

    def __init__(self, routes):
        self.routes = routes
        self.seen = []

    def __call__(self, req, timeout=None):
        self.seen.append(req)
        outcome = self.routes[req.full_url]
        if isinstance(outcome, Exception):
            raise outcome
        status, body = outcome
        return _FakeResponse(status, body)


class CaptureTests(unittest.TestCase):
    def _run(self, routes, **kwargs):
        transport = _Transport(routes)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name) / "capture"
        with patch.object(cwr.urllib.request, "urlopen", transport):
            code = cwr.capture(
                checkpoint_path=PACKET / "checkpoint-1.json", out=out, witness_base=BASE,
                expected_log_id=LOG_ID, registry_key=REGISTRY_KEY, witness_key=WITNESS_KEY,
                **kwargs)
        manifest = json.loads((out / "capture-manifest.json").read_text())
        verification = json.loads((out / "verification.json").read_text())
        return code, out, manifest, verification, transport

    def test_replays_the_september_packet(self):
        code, out, manifest, verification, _ = self._run(
            _routes(), source_commit="6138335", source_path="registry/2026/09/01.ndjson")
        self.assertEqual(code, 0)
        self.assertTrue(verification["verified"])
        self.assertEqual(verification["leaf_index"], 936)
        self.assertEqual(verification["tree_size"], 937)
        self.assertEqual(manifest["checkpoint_signing_digest"], SIGNING_DIGEST)
        self.assertEqual(manifest["request_sha256"],
                         hashlib.sha256(archived("checkpoint-1.json")).hexdigest())
        self.assertEqual(manifest["witness_key_id"], "19a9ab3e02fad55c")
        self.assertTrue(manifest["registry_signature_verified"])
        self.assertTrue(manifest["receipt_bytes_identical_across_responses"])

        archived_manifest = json.loads((PACKET / "capture-manifest.json").read_text())
        by_file = {event["response_file"]: event for event in manifest["events"]}
        for event in archived_manifest["events"]:
            with self.subTest(response_file=event["response_file"]):
                self.assertEqual(by_file[event["response_file"]]["sha256"], event["sha256"])
                self.assertEqual(by_file[event["response_file"]]["url"], event["url"])

    def test_the_two_witness_fields_stay_false_for_that_receipt(self):
        """The archived receipt carries no CWT iat and no signed grade.

        Replaying it must not produce a packet that claims otherwise, whatever
        the witness has deployed since.
        """
        _, _, _, verification, _ = self._run(_routes())
        self.assertFalse(verification["limits"]["witness_time_established"])
        self.assertFalse(verification["limits"]["grade_cryptographically_bound"])
        self.assertIsNone(verification["signed_iat"])
        self.assertIsNone(verification["signed_grade"])
        self.assertEqual(verification["reported_grade"], "countersigned-observed")

    def test_posts_the_checkpoint_verbatim_under_the_agreed_content_type(self):
        _, _, _, _, transport = self._run(_routes())
        post = next(req for req in transport.seen if req.get_method() == "POST")
        self.assertEqual(post.full_url, POST_URL)
        self.assertEqual(post.data, archived("checkpoint-1.json"))
        self.assertEqual(post.get_header("Content-type"), cwr.CHECKPOINT_CONTENT_TYPE)
        self.assertEqual([req.get_method() for req in transport.seen],
                         ["POST", "GET", "GET"])

    def test_sums_are_lf_and_verify(self):
        _, out, _, _, _ = self._run(_routes())
        raw = (out / "SHA256SUMS").read_bytes()
        self.assertNotIn(b"\r", raw)
        for line in raw.decode().splitlines():
            digest, name = line.split("  ", 1)
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((out / name).read_bytes()).hexdigest(), digest)
        listed = {line.split("  ", 1)[1] for line in raw.decode().splitlines()}
        on_disk = {p.name for p in out.iterdir() if p.name != "SHA256SUMS"}
        self.assertEqual(listed, on_disk)

    def test_records_a_non_200_instead_of_reconstructing_it(self):
        code, out, manifest, _, _ = self._run(_routes(**{INCLUSION_URL: (503, b'{"error":"down"}')}))
        self.assertEqual(code, 1)
        event = next(e for e in manifest["events"] if e["response_file"] == "witness-inclusion.json")
        self.assertEqual(event["status"], 503)
        self.assertEqual((out / "witness-inclusion.json").read_bytes(), b'{"error":"down"}')
        self.assertNotIn("status_source", event)
        self.assertFalse(manifest["receipt_bytes_identical_across_responses"])

    def test_records_a_transport_failure_with_no_status(self):
        failure = cwr.urllib.error.URLError("connection refused")
        code, out, manifest, verification, _ = self._run(_routes(**{READBACK_URL: failure}))
        self.assertEqual(code, 1)
        event = next(e for e in manifest["events"] if e["response_file"] == "witness-readback.json")
        self.assertIsNone(event["status"])
        self.assertIn("URLError", event["error"])
        self.assertNotIn("sha256", event)
        self.assertFalse((out / "witness-readback.json").exists())
        # The POST still verified; a lost readback does not invalidate the receipt.
        self.assertTrue(verification["verified"])

    def test_flags_responses_that_disagree_on_the_receipt(self):
        forged = json.loads(archived("witness-readback.json"))
        forged["receipt_b64"] = "0oRDoQEn" + "A" * 32
        code, _, manifest, _, _ = self._run(
            _routes(**{READBACK_URL: (200, json.dumps(forged).encode())}))
        self.assertEqual(code, 1)
        self.assertFalse(manifest["receipt_bytes_identical_across_responses"])

    def test_verification_failure_is_recorded_not_raised(self):
        tampered = json.loads(archived("witness-post.json"))
        tampered["leaf_index"] = 937
        code, _, manifest, verification, _ = self._run(
            _routes(**{POST_URL: (200, json.dumps(tampered).encode())}))
        self.assertEqual(code, 1)
        self.assertFalse(verification["verified"])
        self.assertIn("error", verification)
        self.assertTrue(manifest["registry_signature_verified"])

    def test_refuses_a_plaintext_base_before_sending_anything(self):
        transport = _Transport({})
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.object(cwr.urllib.request, "urlopen", transport):
            with self.assertRaises(ValueError) as caught:
                cwr.capture(checkpoint_path=PACKET / "checkpoint-1.json",
                            out=Path(tmp.name) / "capture", witness_base="http://witness.example",
                            expected_log_id=LOG_ID, registry_key=REGISTRY_KEY,
                            witness_key=WITNESS_KEY)
        self.assertIn("https only", str(caught.exception))
        self.assertEqual(transport.seen, [])

    def test_refuses_a_did_url_on_another_host(self):
        self.assertIsNotNone(
            cwr.check_url_allowed("https://elsewhere.example/did.json",
                                  frozenset({"witness.agentactioncapsule.org"})))

    def test_cli_rejects_a_plaintext_base_with_exit_two(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        code = cwr.main([
            "--checkpoint", str(PACKET / "checkpoint-1.json"),
            "--out", str(Path(tmp.name) / "capture"),
            "--witness-base", "http://witness.example",
            "--expected-log-id", LOG_ID,
            "--registry-key", REGISTRY_KEY,
            "--witness-key", WITNESS_KEY,
        ])
        self.assertEqual(code, 2)

    def test_replay_constructs_no_socket(self):
        """The happy path runs to completion with socket construction forbidden."""
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
            code, _, _, verification, _ = self._run(_routes())
        self.assertEqual(code, 0)
        self.assertTrue(verification["verified"])


class ExtractFromRegistryEntryTests(unittest.TestCase):
    """Capturing a published checkpoint should not need hand-editing.

    A checkpoint is published nested inside a registry entry line, so
    --checkpoint used to mean extracting it into a file yourself first. That is
    where a capture goes wrong quietly: send the whole entry and the witness
    registers a digest over the wrong object, and nothing downstream objects,
    because the digest it returns is consistent with what it was handed.
    """

    ENTRY = REPO_ROOT / "registry" / "2026" / "09" / "01.ndjson"

    def test_extraction_reproduces_the_digest_that_was_witnessed(self):
        """The check that matters: same digest as the September 7 capture.

        The extracted bytes are not the archived file's bytes, because this
        re-serializes to sorted-key compact JSON. The digest is computed from
        the nine signed fields, so it lands on the value the witness actually
        signed regardless.
        """
        extracted, batch_id = cwr.checkpoint_from_registry_entry(self.ENTRY)
        archived_bytes = (PACKET / "checkpoint-1.json").read_bytes()
        self.assertNotEqual(extracted, archived_bytes.strip(),
                            "expected re-serialization, not a byte copy")

        digest = cwr.vwr.signing_body_digest(
            cwr.vwr.signing_body(json.loads(extracted))).hex()
        self.assertEqual(digest, SIGNING_DIGEST)
        self.assertEqual(batch_id, "0150942febbe")

    def test_serialization_cannot_dodge_the_witness_deduplication(self):
        """Why re-serializing is safe, stated as a test.

        The witness deduplicates on the content-addressed entry hash, and that
        hash is SHA-256 of the signing-body digest, which comes from the nine
        signed fields. So whitespace cannot produce a digest the witness has
        not seen, and a re-submission of an already-witnessed checkpoint
        collides however it is formatted. This is the loophole that would
        otherwise look like a way to obtain a second receipt for checkpoint 1.
        """
        entry = json.loads(self.ENTRY.read_text(encoding="utf-8").strip())
        checkpoint = entry["mmr_checkpoint"]
        spellings = [
            json.dumps(checkpoint, sort_keys=True, separators=(",", ":")),
            json.dumps(checkpoint, indent=2),
            json.dumps(checkpoint, indent=4, sort_keys=True),
            json.dumps(checkpoint, separators=(", ", ": ")),
        ]
        digests = {
            cwr.vwr.signing_body_digest(
                cwr.vwr.signing_body(json.loads(text))).hex()
            for text in spellings
        }
        self.assertEqual(digests, {SIGNING_DIGEST},
                         "every spelling must land on the witnessed digest")
        entry_hashes = {
            hashlib.sha256(bytes.fromhex(d)).hexdigest() for d in digests
        }
        self.assertEqual(
            entry_hashes,
            {"dee1a92dad155b56f99cf2284e166e3b6b935528e6d27dec8a4f67bbed6dfab6"})

    def test_a_capture_driven_from_the_entry_file_reproduces_the_packet(self):
        """One command, end to end, over the archived responses."""
        transport = _Transport(_routes())
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name) / "capture"
        extracted, _ = cwr.checkpoint_from_registry_entry(self.ENTRY)
        with patch.object(cwr.urllib.request, "urlopen", transport):
            code = cwr.capture(
                checkpoint_bytes=extracted, out=out, witness_base=BASE,
                expected_log_id=LOG_ID, registry_key=REGISTRY_KEY,
                witness_key=WITNESS_KEY,
                source_path="registry/2026/09/01.ndjson")
        self.assertEqual(code, 0)
        verification = json.loads((out / "verification.json").read_text())
        self.assertTrue(verification["verified"], verification)
        self.assertEqual(verification["leaf_index"], 936)
        self.assertEqual(verification["checkpoint_signing_digest"], SIGNING_DIGEST)
        # The POST body is what the witness registers, so it has to be the
        # checkpoint and not the entry that carried it.
        post = next(r for r in transport.seen if r.get_method() == "POST")
        self.assertEqual(json.loads(post.data), json.loads(extracted))
        self.assertNotIn("batch_id", json.loads(post.data))

    def test_main_accepts_the_entry_file_and_defaults_its_provenance(self):
        transport = _Transport(_routes())
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name) / "capture"
        with patch.object(cwr.urllib.request, "urlopen", transport):
            code = cwr.main([
                "--registry-entry", str(self.ENTRY),
                "--out", str(out),
                "--witness-base", BASE,
                "--expected-log-id", LOG_ID,
                "--registry-key", REGISTRY_KEY,
                "--witness-key", WITNESS_KEY,
            ])
        self.assertEqual(code, 0)
        manifest = json.loads((out / "capture-manifest.json").read_text())
        # A manifest with no provenance is one a reader cannot re-walk, so the
        # entry file it came from is recorded without being asked for.
        self.assertEqual(manifest.get("source_path"), str(self.ENTRY))

    def test_checkpoint_and_registry_entry_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            cwr.main([
                "--checkpoint", str(PACKET / "checkpoint-1.json"),
                "--registry-entry", str(self.ENTRY),
                "--out", "unused", "--witness-base", BASE,
                "--expected-log-id", LOG_ID,
                "--registry-key", REGISTRY_KEY, "--witness-key", WITNESS_KEY,
            ])

    def test_one_of_them_is_required(self):
        with self.assertRaises(SystemExit):
            cwr.main([
                "--out", "unused", "--witness-base", BASE,
                "--expected-log-id", LOG_ID,
                "--registry-key", REGISTRY_KEY, "--witness-key", WITNESS_KEY,
            ])

    def test_an_entry_with_no_checkpoint_is_refused_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "none.ndjson"
            path.write_text(json.dumps({"batch_id": "x"}) + "\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                cwr.checkpoint_from_registry_entry(path)
        self.assertIn("no entry with an mmr_checkpoint", str(ctx.exception))

    def test_several_checkpointed_entries_require_a_batch_id(self):
        entry = json.loads(self.ENTRY.read_text(encoding="utf-8").strip())
        other = json.loads(json.dumps(entry))
        other["batch_id"] = "second"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "two.ndjson"
            path.write_text(json.dumps(entry) + "\n" + json.dumps(other) + "\n",
                            encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                cwr.checkpoint_from_registry_entry(path)
            self.assertIn("--batch-id", str(ctx.exception))
            picked, batch_id = cwr.checkpoint_from_registry_entry(path, "second")
        self.assertEqual(batch_id, "second")
        self.assertEqual(
            cwr.vwr.signing_body_digest(
                cwr.vwr.signing_body(json.loads(picked))).hex(),
            SIGNING_DIGEST)

    def test_a_checkpoint_missing_a_signed_field_is_refused(self):
        entry = json.loads(self.ENTRY.read_text(encoding="utf-8").strip())
        del entry["mmr_checkpoint"]["root"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.ndjson"
            path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                cwr.checkpoint_from_registry_entry(path)
        self.assertIn("missing signed field", str(ctx.exception))
        self.assertIn("root", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
