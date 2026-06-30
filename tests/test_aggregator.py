"""Tests for aggregator._core and aggregator.server."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aggregator._core import TRACEAggregator, _batch_id, _canonical


def _claim(producer="test-producer/1.0.0", tag="a"):
    h = hashlib.sha256(f"{producer}:{tag}".encode()).hexdigest()
    return {"fmt": 1, "producer": producer, "ts": "2026-06-23T00:00:00Z",
            "hash": f"sha256:{h}", "signature": "dummy"}


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


if __name__ == "__main__":
    unittest.main()
