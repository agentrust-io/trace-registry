"""Tests for aggregator._core and aggregator.server."""

from __future__ import annotations

import hashlib
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from aggregator._core import TRACEAggregator, _batch_id, _canonical, _leaf_hash
import verify_inclusion  # noqa: E402 -- standalone third-party-style verifier


def _claim(producer="test-producer/1.0.0", tag="a"):
    h = hashlib.sha256(f"{producer}:{tag}".encode()).hexdigest()
    return {"fmt": 1, "producer": producer, "ts": "2026-06-23T00:00:00Z",
            "hash": f"sha256:{h}", "signature": "dummy"}


def _batch_body_of_size(size: int) -> bytes:
    """A valid ``POST /batch`` JSON body of exactly *size* bytes."""
    doc = {"producer": "http-test/1.0.0", "claims": [_claim(producer="http-test/1.0.0")], "pad": ""}
    doc["pad"] = "x" * (size - len(json.dumps(doc).encode()))
    body = json.dumps(doc).encode()
    assert len(body) == size
    return body


def _make_agg(tmp: Path, flush_interval=0.2, max_batch_size=0,
              verify_signatures=False) -> TRACEAggregator:
    # Most tests here exercise batching/Merkle mechanics, not the signature
    # policy, so signature verification is off by default. Signature-policy
    # behaviour is covered by TestSignatureGate below.
    return TRACEAggregator(
        registry_dir=tmp / "registry",
        proofs_dir=tmp / "proofs",
        flush_interval=flush_interval,
        max_batch_size=max_batch_size,
        git_commit=False,
        verify_signatures=verify_signatures,
    )


class TestCoreHelpers(unittest.TestCase):
    def test_canonical_sorted_keys(self):
        c = {"z": 1, "a": 2}
        self.assertTrue(_canonical(c).startswith(b'{"a":'))

    def test_batch_id_deterministic(self):
        claims = [_claim(), _claim(tag="b")]
        self.assertEqual(_batch_id(claims), _batch_id(claims))

    def test_batch_id_order_independent(self):
        c1, c2 = _claim(tag="x"), _claim(tag="y")
        self.assertEqual(_batch_id([c1, c2]), _batch_id([c2, c1]))

    def test_batch_id_16_hex(self):
        b = _batch_id([_claim()])
        self.assertEqual(len(b), 16)
        int(b, 16)


class TestAggregatorSubmit(unittest.TestCase):
    def test_single_claim_gets_proof(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            proofs = agg.submit([_claim()])
        self.assertEqual(len(proofs), 1)
        self.assertIn("batch_id", proofs[0])
        self.assertEqual(proofs[0]["leaf_index"], 0)

    def test_multiple_claims_same_batch(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            claims = [_claim(tag=str(i)) for i in range(5)]
            proofs = agg.submit(claims)
        self.assertEqual(len(proofs), 5)
        # All in same batch
        batch_ids = {p["batch_id"] for p in proofs}
        self.assertEqual(len(batch_ids), 1)
        # Leaf indices are 0..4
        indices = {p["leaf_index"] for p in proofs}
        self.assertEqual(indices, {0, 1, 2, 3, 4})

    def test_empty_submit_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            result = agg.submit([])
        self.assertEqual(result, [])

    def test_writes_registry_ndjson(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = _make_agg(tmp)
            agg.submit([_claim()])
            ndjson_files = list((tmp / "registry").rglob("*.ndjson"))
            self.assertEqual(len(ndjson_files), 1)
            entry = json.loads(ndjson_files[0].read_text())
        self.assertIn("merkle_root", entry)
        self.assertIn("batch_id", entry)
        self.assertEqual(entry["leaf_count"], 1)

    def test_writes_proof_files(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = _make_agg(tmp)
            agg.submit([_claim(), _claim(tag="b")])
            proof_files = list((tmp / "proofs").rglob("*.proof.json"))
        self.assertEqual(len(proof_files), 2)

    def test_different_producers_separate_batches(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            c1 = _claim(producer="alpha/1.0.0")
            c2 = _claim(producer="beta/1.0.0")
            proofs = agg.submit([c1, c2])
        batch_ids = {p["batch_id"] for p in proofs}
        self.assertEqual(len(batch_ids), 2)

    def test_max_batch_triggers_early_flush(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d), flush_interval=60.0, max_batch_size=2)
            t0 = time.monotonic()
            agg.submit([_claim(), _claim(tag="b")])
            elapsed = time.monotonic() - t0
        # Should flush well before the 60s flush_interval
        self.assertLess(elapsed, 10.0)

    def test_get_proof_returns_correct_entry(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            proofs = agg.submit([_claim()])
        proof = agg.get_proof(proofs[0]["batch_id"], 0)
        self.assertIsNotNone(proof)
        self.assertEqual(proof["leaf_index"], 0)

    def test_get_proof_unknown_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
        result = agg.get_proof("does-not-exist", 0)
        self.assertIsNone(result)

    def test_concurrent_producers_no_data_loss(self):
        """10 concurrent producers each submitting 3 claims -- all get proofs."""
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d), flush_interval=0.1)
            results = []
            errors = []

            def worker(producer_id):
                claims = [_claim(producer=producer_id, tag=str(i)) for i in range(3)]
                try:
                    proofs = agg.submit(claims, timeout=30.0)
                    results.append(len(proofs))
                except Exception as exc:
                    errors.append(str(exc))

            threads = [
                threading.Thread(target=worker, args=(f"prod-{i}/1.0.0",))
                for i in range(10)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

        self.assertEqual(errors, [])
        self.assertEqual(sum(results), 30)  # 10 producers x 3 claims


try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def _signed_claim(priv, producer, tag="a"):
    import base64
    from trace_verify._signature import canonical_body_bytes
    body = {"fmt": 1, "producer": producer, "ts": "2026-06-23T00:00:00Z",
            "hash": f"sha256:{'0' * 63}{tag}"}
    sig = priv.sign(canonical_body_bytes(body))
    return {**body, "signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode()}


def _write_producer_key(producers_dir: Path, producer, priv):
    import base64
    producers_dir.mkdir(parents=True, exist_ok=True)
    x = base64.urlsafe_b64encode(
        priv.public_key().public_bytes_raw()
    ).rstrip(b"=").decode()
    entry = {
        "producer_id": producer,
        "key_type": "Ed25519",
        "public_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
        "active_since": "2026-06-01T00:00:00Z",
        "contact": "test@example.com",
    }
    fname = producer.replace("/", "-") + ".json"
    (producers_dir / fname).write_text(json.dumps(entry), encoding="utf-8")


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography package not installed")
class TestSignatureGate(unittest.TestCase):
    """Fail-closed: the aggregator only anchors signature-verified claims from
    registered producers when verify_signatures is on (the default)."""

    def _agg(self, tmp, producers_dir):
        return TRACEAggregator(
            registry_dir=tmp / "registry",
            proofs_dir=tmp / "proofs",
            flush_interval=0.2,
            git_commit=False,
            producers_dir=producers_dir,
            verify_signatures=True,
        )

    def test_accepts_properly_signed_claim(self):
        priv = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            producers = tmp / "producers"
            _write_producer_key(producers, "good/1.0.0", priv)
            agg = self._agg(tmp, producers)
            claim = _signed_claim(priv, "good/1.0.0")
            results = agg.submit([claim])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].get("rejected"))
        self.assertIn("batch_id", results[0])

    def test_rejects_unknown_producer(self):
        priv = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            producers = tmp / "producers"
            producers.mkdir()  # no key registered
            agg = self._agg(tmp, producers)
            claim = _signed_claim(priv, "unknown/1.0.0")
            results = agg.submit([claim])
        self.assertTrue(results[0].get("rejected"))
        # nothing anchored
        self.assertEqual(list((tmp / "registry").rglob("*.ndjson")), [])

    def test_rejects_bad_signature(self):
        priv = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            producers = tmp / "producers"
            _write_producer_key(producers, "good/1.0.0", priv)
            agg = self._agg(tmp, producers)
            claim = _signed_claim(priv, "good/1.0.0")
            claim["hash"] = "sha256:" + "f" * 64  # tamper after signing
            results = agg.submit([claim])
        self.assertTrue(results[0].get("rejected"))
        self.assertEqual(list((tmp / "registry").rglob("*.ndjson")), [])


class TestLeafHashAdditive(unittest.TestCase):
    """_leaf_hash(claim) -- the pre-PR-2 call shape -- is unchanged."""

    def test_bare_call_unchanged(self):
        claim = {"z": 1, "a": 2}
        self.assertEqual(_leaf_hash(claim), _leaf_hash(claim, canonicalization_id="sorted-key"))

    def test_as_transmitted_requires_raw_bytes(self):
        with self.assertRaises(ValueError):
            _leaf_hash({"a": 1}, canonicalization_id="as-transmitted")

    def test_unsupported_canonicalization_id_raises(self):
        with self.assertRaises(ValueError):
            _leaf_hash({"a": 1}, canonicalization_id="jcs")


class TestAsTransmittedSubmit(unittest.TestCase):
    """PR-2: a self-attested TRACE record registers by its exact signed
    bytes -- the aggregator (the live registration path, distinct from the
    tools/anchor.py CLI) never re-serializes it. docs/anchor-format.md
    section 0; acceptance per the PR-2 issue: a record registers and
    verifies without the registry re-hashing it, and the digest matches the
    producer's own."""

    def test_requires_raw_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            with self.assertRaises(ValueError):
                agg.submit([_claim()], canonicalization_id="as-transmitted")

    def test_raw_bytes_length_must_match_claims(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            with self.assertRaises(ValueError):
                agg.submit(
                    [_claim(), _claim(tag="b")],
                    canonicalization_id="as-transmitted",
                    raw_bytes=[b"{}"],
                )

    def test_unsupported_canonicalization_id_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            with self.assertRaises(ValueError):
                agg.submit([_claim()], canonicalization_id="jcs", raw_bytes=[b"{}"])

    def test_entry_declares_as_transmitted(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = _make_agg(tmp)
            claim = _claim()
            raw = _canonical(claim)
            agg.submit([claim], canonicalization_id="as-transmitted", raw_bytes=[raw])
            ndjson_files = list((tmp / "registry").rglob("*.ndjson"))
            entry = json.loads(ndjson_files[0].read_text())
        self.assertEqual(entry["canonicalization_id"], "as-transmitted")

    def test_registers_and_verifies_without_registry_rehash(self):
        """The core PR-2 conformance vector.

        The producer transmits deliberately non-canonical bytes (unsorted
        keys, extra whitespace) -- exactly the bytes they signed. After
        registration:
          1. the stored digest (the merkle leaf, unwound via the standalone
             verify_inclusion.py tool -- deliberately not aggregator code,
             so this is an independent check) is proven over those exact
             raw bytes, not a re-serialization of them;
          2. re-serializing the parsed claim under sorted-key produces
             DIFFERENT bytes than what was transmitted -- proving that if
             the registry had recomputed (as it does for sorted-key
             registration), the digest would NOT match the producer's own.
        """
        claim = {"z_field": 1, "producer": "test-producer/1.0.0", "a_field": 2,
                  "ts": "2026-06-23T00:00:00Z", "hash": f"sha256:{'0' * 64}",
                  "signature": "dummy"}
        raw = json.dumps(claim, sort_keys=False, indent=2).encode("utf-8")
        producer_digest = hashlib.sha256(raw).hexdigest()

        # If the registry recomputed via sorted-key, the digest would differ --
        # this is exactly the trap as-transmitted registration closes.
        rehashed_digest = hashlib.sha256(_canonical(claim)).hexdigest()
        self.assertNotEqual(producer_digest, rehashed_digest)

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = _make_agg(tmp)
            results = agg.submit(
                [claim], canonicalization_id="as-transmitted", raw_bytes=[raw]
            )
            proof_files = list((tmp / "proofs").rglob("*.proof.json"))
            self.assertEqual(len(proof_files), 1)
            proof = json.loads(proof_files[0].read_text())

        result = results[0]
        merkle_root = bytes.fromhex(result["merkle_root"].split(":", 1)[1])
        audit_path = [bytes.fromhex(h.split(":", 1)[1]) for h in result["audit_path"]]

        ok = verify_inclusion.verify_inclusion(
            claim,
            proof["leaf_index"],
            audit_path,
            1,
            merkle_root,
            canonicalization_id="as-transmitted",
            raw_bytes=raw,
        )
        self.assertTrue(ok)

        # The independent verifier's own preimage hash IS the producer's digest --
        # never a re-serialization of the parsed claim.
        self.assertEqual(
            hashlib.sha256(
                verify_inclusion.canonical_claim_bytes(
                    claim, canonicalization_id="as-transmitted", raw_bytes=raw
                )
            ).hexdigest(),
            producer_digest,
        )

    def test_mismatched_construction_does_not_silently_verify(self):
        """Checking an as-transmitted registration as though it were
        sorted-key must not silently accept -- the #111 trap this PR-2
        vector guards against at the aggregator's own registration path."""
        claim = {"z": 1, "a": 2, "producer": "test-producer/1.0.0"}
        raw = b'{  "z" :1,  "a":2, "producer":"test-producer/1.0.0"  }'

        with tempfile.TemporaryDirectory() as d:
            agg = _make_agg(Path(d))
            results = agg.submit(
                [claim], canonicalization_id="as-transmitted", raw_bytes=[raw]
            )

        result = results[0]
        merkle_root = bytes.fromhex(result["merkle_root"].split(":", 1)[1])
        ok = verify_inclusion.verify_inclusion(
            claim, 0, [], 1, merkle_root, canonicalization_id="sorted-key",
        )
        self.assertFalse(ok)

    def test_mixed_canonicalizations_same_producer_split_into_separate_batches(self):
        """A registry entry declares one construction for all its leaves
        (schema/registry-entry.schema.json) -- claims from the same producer
        submitted under different constructions in the same flush window
        must anchor as separate batches, never mixed into one entry."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = _make_agg(tmp, flush_interval=60.0, max_batch_size=2)
            sorted_key_claim = _claim(tag="sk")
            as_transmitted_claim = _claim(tag="at")
            raw = _canonical(as_transmitted_claim)

            results = []
            errors = []

            def submit_sorted_key():
                try:
                    results.extend(agg.submit([sorted_key_claim], timeout=30.0))
                except Exception as exc:
                    errors.append(exc)

            def submit_as_transmitted():
                try:
                    results.extend(agg.submit(
                        [as_transmitted_claim],
                        canonicalization_id="as-transmitted",
                        raw_bytes=[raw],
                        timeout=30.0,
                    ))
                except Exception as exc:
                    errors.append(exc)

            t1 = threading.Thread(target=submit_sorted_key)
            t2 = threading.Thread(target=submit_as_transmitted)
            t1.start()
            time.sleep(0.05)  # ensure both land in the same pending window
            t2.start()
            t1.join(timeout=30)
            t2.join(timeout=30)

            ndjson_files = list((tmp / "registry").rglob("*.ndjson"))
            entries = [json.loads(ln) for ln in ndjson_files[0].read_text().splitlines()]

        self.assertEqual(errors, [])
        batch_ids = {r["batch_id"] for r in results}
        self.assertEqual(len(batch_ids), 2, "expected two separate batches, not one mixed batch")
        canon_ids = {e["canonicalization_id"] for e in entries}
        self.assertEqual(canon_ids, {"sorted-key", "as-transmitted"})

    def test_distinct_raw_bytes_same_parsed_claim_get_distinct_proof_files(self):
        """Two claims that parse to the identical dict but were transmitted
        with different byte-level formatting must not collide on the same
        proof filename under as-transmitted (docs/anchor-format.md section 0:
        as-transmitted commits to bytes, not the parsed structure)."""
        claim = {"producer": "test-producer/1.0.0", "tag": "same"}
        raw_a = json.dumps(claim, sort_keys=True).encode("utf-8")
        raw_b = json.dumps(claim, sort_keys=False, indent=4).encode("utf-8")
        self.assertNotEqual(raw_a, raw_b)

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            agg = _make_agg(tmp, max_batch_size=0, flush_interval=60.0)
            results = agg.submit(
                [dict(claim), dict(claim)],
                canonicalization_id="as-transmitted",
                raw_bytes=[raw_a, raw_b],
            )
            proof_files = list((tmp / "proofs").rglob("*.proof.json"))

        self.assertEqual(len(results), 2)
        self.assertEqual(len(proof_files), 2)


class TestHTTPServer(unittest.TestCase):
    def _start_server(self, tmp: Path, flush_interval=0.2):
        from aggregator.server import AggregatorHTTPServer
        agg = _make_agg(tmp, flush_interval=flush_interval)
        server = AggregatorHTTPServer(("127.0.0.1", 0), agg)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server, port

    def _post(self, port, body: dict) -> tuple[int, dict]:
        import urllib.error
        import urllib.request
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/batch",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())
        except Exception as exc:
            return 500, {"error": str(exc)}

    def _get(self, port, path: str) -> tuple[int, dict]:
        import urllib.request
        import urllib.error
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=10
            ) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_post_batch_returns_proofs(self):
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            status, resp = self._post(port, {
                "producer": "http-test/1.0.0",
                "claims": [_claim(producer="http-test/1.0.0")],
            })
            server.shutdown()
        self.assertEqual(status, 200)
        self.assertIn("batch_id", resp)
        self.assertEqual(len(resp["proofs"]), 1)

    def test_post_empty_claims_returns_400(self):
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            status, resp = self._post(port, {"claims": []})
            server.shutdown()
        self.assertEqual(status, 400)

    def test_get_proof_after_post(self):
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            _, post_resp = self._post(port, {
                "claims": [_claim(producer="http-test/1.0.0")],
            })
            batch_id = post_resp["batch_id"]
            status, proof = self._get(port, f"/proof/{batch_id}/0")
            server.shutdown()
        self.assertEqual(status, 200)
        self.assertIn("audit_path", proof)

    def test_get_proof_unknown_returns_404(self):
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            status, _ = self._get(port, "/proof/no-such-batch/0")
            server.shutdown()
        self.assertEqual(status, 404)

    def test_health_endpoint(self):
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            status, resp = self._get(port, "/health")
            server.shutdown()
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "ok")

    def test_unknown_path_returns_404(self):
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            status, _ = self._get(port, "/nonexistent")
            server.shutdown()
        self.assertEqual(status, 404)

    def test_content_length_rejects_non_decimal_and_conflicting_duplicates_and_enforces_max_body_bytes(self):
        import email.message
        import http.client
        import io
        from aggregator.server import MAX_BODY_BYTES, AggregatorHandler, _BodyError

        dummy_handler = object.__new__(AggregatorHandler)
        for bad_cl in ("\u0662", "+2", "1_0", " 2 ", "\u00b2"):
            dummy_handler.headers = {"Content-Length": bad_cl}
            dummy_handler.rfile = io.BytesIO(b"{}")
            with self.assertRaises(_BodyError) as ctx:
                dummy_handler._read_json_body()
            self.assertEqual(ctx.exception.status, 400)

        # Valid boundary controls: "0" and leading zeros "002"
        dummy_handler.headers = {"Content-Length": "0"}
        dummy_handler.rfile = io.BytesIO(b"")
        self.assertIsNone(dummy_handler._read_json_body())

        dummy_handler.headers = {"Content-Length": "002"}
        dummy_handler.rfile = io.BytesIO(b"{}")
        self.assertEqual(dummy_handler._read_json_body(), {})

        # A run of zeros is the number it denotes, however long it is.
        dummy_handler.headers = {"Content-Length": "0" * 5000}
        dummy_handler.rfile = io.BytesIO(b"")
        self.assertIsNone(dummy_handler._read_json_body())

        dummy_handler.headers = {"Content-Length": "0" * 5000 + "2"}
        dummy_handler.rfile = io.BytesIO(b"{}")
        self.assertEqual(dummy_handler._read_json_body(), {})

        # Exactly MAX_BODY_BYTES is read in full and parsed.
        exact = _batch_body_of_size(MAX_BODY_BYTES)
        dummy_handler.headers = {"Content-Length": str(MAX_BODY_BYTES)}
        dummy_handler.rfile = io.BytesIO(exact)
        self.assertEqual(dummy_handler._read_json_body(), json.loads(exact))

        dummy_handler.headers = {"Content-Length": "0" * 5000 + str(MAX_BODY_BYTES)}
        dummy_handler.rfile = io.BytesIO(exact)
        self.assertEqual(dummy_handler._read_json_body(), json.loads(exact))

        # MAX_BODY_BYTES + 1 and huge digit strings, zero-padded or not, are 413.
        for over_cl in (
            str(MAX_BODY_BYTES + 1),
            "0" * 5000 + str(MAX_BODY_BYTES + 1),
            "9" * 5000,
            "0" * 5000 + "9" * 5000,
        ):
            dummy_handler.headers = {"Content-Length": over_cl}
            dummy_handler.rfile = io.BytesIO(b"{}")
            with self.assertRaises(_BodyError) as ctx:
                dummy_handler._read_json_body()
            self.assertEqual(ctx.exception.status, 413)

        # A body shorter than its Content-Length is refused, not parsed.
        for declared, sent in ((10, b'{"a": 1}'), (3, b"{}"), (MAX_BODY_BYTES, exact[:-1])):
            dummy_handler.headers = {"Content-Length": str(declared)}
            dummy_handler.rfile = io.BytesIO(sent)
            with self.assertRaises(_BodyError) as ctx:
                dummy_handler._read_json_body()
            self.assertEqual(ctx.exception.status, 400)
            self.assertEqual(str(ctx.exception), "incomplete request body")

        # Conflicting duplicate Content-Length headers are rejected with 400
        dup_headers = email.message.Message()
        dup_headers.add_header("Content-Length", "2")
        dup_headers.add_header("Content-Length", "10")
        dummy_handler.headers = dup_headers
        dummy_handler.rfile = io.BytesIO(b"{}")
        with self.assertRaises(_BodyError) as ctx:
            dummy_handler._read_json_body()
        self.assertEqual(ctx.exception.status, 400)

        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            try:
                for bad_cl in ("+2", "1_0", " 2 ", "\u00b2"):
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    conn.putrequest("POST", "/batch", skip_accept_encoding=True)
                    conn.putheader("Content-Length", bad_cl)
                    conn.endheaders()
                    self.assertEqual(conn.getresponse().status, 400)
                    conn.close()

                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.putrequest("POST", "/batch", skip_accept_encoding=True)
                conn.putheader("Content-Length", "9" * 5000)
                conn.endheaders()
                self.assertEqual(conn.getresponse().status, 413)
                conn.close()
            finally:
                server.shutdown()

    def test_post_batch_rejects_invalid_producer_and_duplicate_or_nonfinite_json(self):
        import urllib.error
        import urllib.request

        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            try:
                for bad_prod in (None, "", 123, ["p/1.0.0"], {"id": "p"}):
                    status, _ = self._post(
                        port,
                        {"producer": bad_prod, "claims": [{"hash": "sha256:" + "0" * 64}]},
                    )
                    self.assertEqual(status, 400)

                for bad_raw in (
                    b'{"claims": [{"hash": "sha256:' + b"0" * 64 + b'"}], "claims": []}',
                    b'{"claims": [{"hash": "sha256:' + b"0" * 64 + b'", "x": NaN}]}',
                    b'{"claims": [{"hash": "sha256:' + b"0" * 64 + b'", "x": Infinity}]}',
                    b'{"claims": [{"hash": "sha256:' + b"0" * 64 + b'", "x": -Infinity}]}',
                ):
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/batch",
                        data=bad_raw,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        urllib.request.urlopen(req, timeout=10)
                    self.assertEqual(ctx.exception.code, 400)
            finally:
                server.shutdown()

    def _raw_post(self, port, content_length: str, body: bytes, *, half_close: bool = False):
        """POST /batch over a bare socket so the declared length and the bytes
        actually sent can disagree, which http.client and urllib prevent."""
        head = f"POST /batch HTTP/1.0\r\nContent-Length: {content_length}\r\n\r\n"
        with socket.create_connection(("127.0.0.1", port), timeout=30) as sock:
            sock.sendall(head.encode("ascii") + body)
            if half_close:
                sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        head_bytes, _, payload = b"".join(chunks).partition(b"\r\n\r\n")
        return int(head_bytes.split(b" ", 2)[1]), json.loads(payload)

    def test_post_with_body_shorter_than_content_length_is_refused_over_a_socket(self):
        body = json.dumps(
            {"producer": "http-test/1.0.0", "claims": [_claim(producer="http-test/1.0.0")]}
        ).encode()
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            try:
                # The same bytes with an honest length anchor.
                status, resp = self._raw_post(port, str(len(body)), body, half_close=True)
                self.assertEqual(status, 200)
                self.assertEqual(len(resp["proofs"]), 1)
                anchored = self._get(port, "/health")[1]["proof_index_size"]

                # A valid JSON document, a larger declared length, then the
                # client shuts down its write side: refused, and nothing anchored.
                status, resp = self._raw_post(port, str(len(body) + 100), body, half_close=True)
                self.assertEqual(status, 400)
                self.assertEqual(resp, {"error": "incomplete request body"})
                self.assertEqual(self._get(port, "/health")[1]["proof_index_size"], anchored)
            finally:
                server.shutdown()

    def test_post_of_exactly_max_body_bytes_is_read_in_full_over_a_socket(self):
        from aggregator.server import MAX_BODY_BYTES

        body = _batch_body_of_size(MAX_BODY_BYTES)
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            try:
                status, resp = self._raw_post(port, str(MAX_BODY_BYTES), body)
                self.assertEqual(status, 200)
                self.assertEqual(len(resp["proofs"]), 1)

                # Zero-padded, the same length is the same request.
                status, _ = self._raw_post(port, "0" * 5000 + str(MAX_BODY_BYTES), body)
                self.assertEqual(status, 200)

                # One byte over is refused from the header alone.
                status, resp = self._raw_post(port, str(MAX_BODY_BYTES + 1), b"")
                self.assertEqual(status, 413)
                status, resp = self._raw_post(port, "0" * 5000 + str(MAX_BODY_BYTES + 1), b"")
                self.assertEqual(status, 413)
            finally:
                server.shutdown()

    def test_post_with_long_zero_padded_content_length_matches_the_plain_number(self):
        body = json.dumps(
            {"producer": "http-test/1.0.0", "claims": [_claim(producer="http-test/1.0.0")]}
        ).encode()
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            try:
                for length in (str(len(body)), "0" * 5000 + str(len(body))):
                    status, _ = self._raw_post(port, length, body)
                    self.assertEqual(status, 200)

                # "0" * 5000 is zero, so there is no body to parse.
                status, resp = self._raw_post(port, "0" * 5000, b"")
                self.assertEqual(status, 400)
                self.assertEqual(resp, {"error": "body must be a JSON object"})
            finally:
                server.shutdown()

    def test_post_batch_rejects_non_finite_numbers_that_overflow_to_infinity(self):
        claim = json.dumps(_claim(producer="http-test/1.0.0"))
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            try:
                for number in ("1e999", "-1e999", "1E400", "1.5e+9999"):
                    with self.subTest(number=number):
                        body = f'{{"claims": [{claim}], "unused": {number}}}'.encode()
                        status, resp = self._raw_post(port, str(len(body)), body)
                        self.assertEqual(status, 400)
                        self.assertIn("non-finite", resp["error"])

                # Large but finite numbers are still numbers.
                body = f'{{"claims": [{claim}], "unused": 1e300}}'.encode()
                status, _ = self._raw_post(port, str(len(body)), body)
                self.assertEqual(status, 200)
            finally:
                server.shutdown()

    def test_loads_unique_and_checkpoint_log_reject_duplicates_and_nonfinite_constants(self):
        from aggregator._mmr_log import CheckpointLog
        from trace_verify._verify import loads_unique

        self.assertEqual(loads_unique('{"a": 1}'), {"a": 1})
        self.assertEqual(loads_unique('{"a": 1e300}'), {"a": 1e300})
        for bad_text in (
            '{"v": 1, "v": 2}',
            '{"v": NaN}',
            '{"v": Infinity}',
            '{"v": -Infinity}',
            '{"v": 1e999}',
            '{"v": -1e999}',
            '[1E400]',
        ):
            with self.subTest(bad_text=bad_text):
                with self.assertRaises(ValueError):
                    loads_unique(bad_text)
                # tools/verify_inclusion.py is a kept-in-sync copy of the same rule.
                with self.assertRaises(ValueError):
                    verify_inclusion.loads_unique(bad_text)
        self.assertEqual(verify_inclusion.loads_unique('{"a": 1e300}'), {"a": 1e300})

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            for idx, bad_cp_text in enumerate(
                (
                    '{"v": 1, "v": 2}',
                    '{"v": NaN}',
                    '{"v": Infinity}',
                    '{"v": -Infinity}',
                    '{"v": 1e999}',
                    '{"v": -1e999}',
                )
            ):
                cp_dir = tmp / f"cp_bad_{idx}"
                cp_dir.mkdir(parents=True, exist_ok=True)
                (cp_dir / "latest-checkpoint.json").write_text(bad_cp_text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    CheckpointLog(cp_dir)

    def test_checkpoint_log_refuses_overflowing_number_in_an_otherwise_valid_checkpoint(self):
        from aggregator._mmr_log import CheckpointLog

        with tempfile.TemporaryDirectory() as d:
            cp_dir = Path(d)
            CheckpointLog(cp_dir).append_entry(
                {"batch_id": "abc", "merkle_root": "00" * 32, "claim_count": 1},
                timestamp="2026-11-25T00:00:00Z",
            )
            latest = cp_dir / "latest-checkpoint.json"
            valid = latest.read_text(encoding="utf-8")
            self.assertTrue(valid.rstrip().endswith("}"))
            stem = valid.rstrip()[:-1]

            # An unknown member with a finite value loads: the one thing that
            # differs below is the number.
            latest.write_text(stem + ', "unused": 1}\n', encoding="utf-8")
            self.assertEqual(CheckpointLog(cp_dir).latest.mmr_size, 1)

            for number in ("1e999", "-1e999"):
                with self.subTest(number=number):
                    latest.write_text(stem + f', "unused": {number}}}\n', encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "non-finite"):
                        CheckpointLog(cp_dir)

    def test_checkpoint_log_refuses_checkpoint_that_is_not_a_json_object(self):
        from aggregator._mmr_log import CheckpointLog

        with tempfile.TemporaryDirectory() as d:
            cp_dir = Path(d)
            latest = cp_dir / "latest-checkpoint.json"
            for text in ("[]", "[1, 2]", "1", '"checkpoint"', "null", "true"):
                with self.subTest(text=text):
                    latest.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "is not a JSON object"):
                        CheckpointLog(cp_dir)


class TestHTTPServerAsTransmitted(unittest.TestCase):
    """PR-2 over the wire: POST /batch with canonicalization_id='as-transmitted'
    carries each claim as its exact signed JSON text (a string, not a nested
    object) so the HTTP layer preserves producer bytes end to end -- the
    server-side gap this PR closes (do_POST previously only ever parsed
    claims into dicts, discarding the bytes that were actually signed)."""

    def _start_server(self, tmp: Path, flush_interval=0.2):
        from aggregator.server import AggregatorHTTPServer
        agg = _make_agg(tmp, flush_interval=flush_interval)
        server = AggregatorHTTPServer(("127.0.0.1", 0), agg)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server, port

    def _post_raw(self, port, body_bytes: bytes) -> tuple[int, dict]:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/batch",
            data=body_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_as_transmitted_claim_registers_and_verifies_over_original_bytes(self):
        claim_text = '{  "producer": "http-test/1.0.0",\n  "z": 1, "a": 2  }\n'
        request_body = json.dumps({
            "canonicalization_id": "as-transmitted",
            "claims": [claim_text],
        }).encode("utf-8")

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            server, port = self._start_server(tmp)
            status, resp = self._post_raw(port, request_body)
            server.shutdown()
            ndjson_files = list((tmp / "registry").rglob("*.ndjson"))
            entry = json.loads(ndjson_files[0].read_text())

        self.assertEqual(status, 200)
        self.assertEqual(entry["canonicalization_id"], "as-transmitted")

        proof = resp["proofs"][0]
        merkle_root = bytes.fromhex(entry["merkle_root"].split(":", 1)[1])
        audit_path = [bytes.fromhex(h.split(":", 1)[1]) for h in proof["audit_path"]]
        ok = verify_inclusion.verify_inclusion(
            json.loads(claim_text),
            proof["leaf_index"],
            audit_path,
            entry["leaf_count"],
            merkle_root,
            canonicalization_id="as-transmitted",
            raw_bytes=claim_text.encode("utf-8"),
        )
        self.assertTrue(ok, "the transmitted text must verify byte for byte, unmodified")

    def test_as_transmitted_rejects_nested_object_claims(self):
        request_body = json.dumps({
            "canonicalization_id": "as-transmitted",
            "claims": [{"producer": "http-test/1.0.0"}],
        }).encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            status, resp = self._post_raw(port, request_body)
            server.shutdown()
        self.assertEqual(status, 400)

    def test_unsupported_canonicalization_id_returns_400(self):
        request_body = json.dumps({
            "canonicalization_id": "jcs",
            "claims": [{"producer": "http-test/1.0.0"}],
        }).encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            server, port = self._start_server(Path(d))
            status, resp = self._post_raw(port, request_body)
            server.shutdown()
        self.assertEqual(status, 400)

    def test_aggregator_validates_init_submit_and_entry_leaf_digest_profile(self):
        from trace_verify._checkpoint import entry_leaf_digest, verify_chain_against_entries

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            for idx, bad_fi in enumerate((True, False, 0, -1.0, float("nan"), float("inf"))):
                with self.subTest(bad_fi=idx):
                    with self.assertRaises(ValueError):
                        TRACEAggregator(tmp / "reg", tmp / "proofs", flush_interval=bad_fi)
            for idx, bad_mbs in enumerate((True, False, -1, 1.5, "10")):
                with self.subTest(bad_mbs=idx):
                    with self.assertRaises(ValueError):
                        TRACEAggregator(
                            tmp / "reg",
                            tmp / "proofs",
                            flush_interval=10.0,
                            max_batch_size=bad_mbs,  # type: ignore[arg-type]
                        )

            agg = _make_agg(tmp)
            with self.subTest("non_list_claims"):
                with self.assertRaises(ValueError):
                    agg.submit({"not": "a-list"})  # type: ignore[arg-type]
            for idx, bad_to in enumerate((True, False, 0, -1, float("nan"), float("inf"))):
                with self.subTest(bad_to=idx):
                    with self.assertRaises(ValueError):
                        agg.submit([_claim()], timeout=bad_to)
            with self.subTest("non_bytes_raw_bytes"):
                with self.assertRaises(ValueError):
                    agg.submit(
                        [_claim()],
                        canonicalization_id="as-transmitted",
                        raw_bytes=["not-bytes"],  # type: ignore[list-item]
                    )
            with self.subTest("mismatched_raw_bytes"):
                with self.assertRaises(ValueError):
                    agg.submit(
                        [_claim()],
                        canonicalization_id="as-transmitted",
                        raw_bytes=[b'{"different": 1}'],
                    )

        for idx, bad_entry in enumerate(
            (
                {"batch_id": "b1", "x": float("nan")},
                {"batch_id": "b1", "x": 1.5},
                {"batch_id": "b1", "x": 2**53},
            )
        ):
            with self.subTest(bad_entry=idx):
                with self.assertRaises(ValueError):
                    entry_leaf_digest(bad_entry)
                errs = verify_chain_against_entries(
                    [{**bad_entry, "mmr_checkpoint": {"mmr_size": 1, "root": "aa" * 32}}]
                )
                self.assertEqual(len(errs), 1)
                self.assertIn("malformed entry body", errs[0])


if __name__ == "__main__":
    unittest.main()
