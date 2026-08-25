"""Tests for tools/batch_anchor.py."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import batch_anchor

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _claim(producer="cmcp-gateway/0.1.0", ts="2026-06-22T00:00:00Z", tag="a"):
    return {
        "fmt": 1,
        "producer": producer,
        "ts": ts,
        "hash": "sha256:" + ("0" * 63 + tag),
        "signature": "dummysig",
    }


def _write_claim(dir_: Path, filename: str, claim: dict) -> Path:
    p = dir_ / filename
    p.write_text(json.dumps(claim), encoding="utf-8")
    return p


def _record(path: Path, claim: dict) -> tuple[Path, dict, bytes]:
    """Build a (path, claim, raw_bytes) record like scan_staging() returns,
    for tests that construct records directly rather than via scan_staging."""
    return (path, claim, json.dumps(claim).encode("utf-8"))


def _make_staging(tmp: Path) -> tuple[Path, Path, Path]:
    incoming = tmp / "staging" / "incoming"
    processed = tmp / "staging" / "processed"
    incoming.mkdir(parents=True)
    processed.mkdir(parents=True)
    return tmp / "staging", incoming, processed


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestScanStaging(unittest.TestCase):
    def test_returns_valid_claims(self):
        with tempfile.TemporaryDirectory() as d:
            dir_ = Path(d)
            _write_claim(dir_, "c1.json", _claim())
            _write_claim(dir_, "c2.json", _claim(tag="b"))
            records = batch_anchor.scan_staging(dir_)
        self.assertEqual(len(records), 2)

    def test_skips_invalid_json(self):
        with tempfile.TemporaryDirectory() as d:
            dir_ = Path(d)
            _write_claim(dir_, "good.json", _claim())
            (dir_ / "bad.json").write_text("{not json", encoding="utf-8")
            records = batch_anchor.scan_staging(dir_)
        self.assertEqual(len(records), 1)

    def test_skips_non_object(self):
        with tempfile.TemporaryDirectory() as d:
            dir_ = Path(d)
            (dir_ / "list.json").write_text("[1, 2]", encoding="utf-8")
            records = batch_anchor.scan_staging(dir_)
        self.assertEqual(len(records), 0)

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            records = batch_anchor.scan_staging(Path(d))
        self.assertEqual(records, [])


class TestGroupByProducer(unittest.TestCase):
    def test_groups_correctly(self):
        records = [
            _record(Path("a.json"), _claim(producer="p1/1.0.0")),
            _record(Path("b.json"), _claim(producer="p2/1.0.0")),
            _record(Path("c.json"), _claim(producer="p1/1.0.0", tag="b")),
        ]
        groups = batch_anchor.group_by_producer(records, 0)
        self.assertEqual(sorted(groups.keys()), ["p1/1.0.0", "p2/1.0.0"])
        self.assertEqual(len(groups["p1/1.0.0"]), 2)
        self.assertEqual(len(groups["p2/1.0.0"]), 1)

    def test_unknown_producer_grouped(self):
        records = [_record(Path("x.json"), {"fmt": 1})]  # no producer field
        groups = batch_anchor.group_by_producer(records, 0)
        self.assertIn("__unknown__", groups)

    def test_max_batch_truncates(self):
        records = [
            _record(Path(f"{i}.json"), _claim(tag=str(i))) for i in range(5)
        ]
        groups = batch_anchor.group_by_producer(records, 3)
        self.assertEqual(len(groups["cmcp-gateway/0.1.0"]), 3)


class TestBatchIdFor(unittest.TestCase):
    def test_deterministic(self):
        claims = [_claim(), _claim(tag="b")]
        self.assertEqual(
            batch_anchor.batch_id_for(claims),
            batch_anchor.batch_id_for(claims),
        )

    def test_order_independent(self):
        c1, c2 = _claim(tag="x"), _claim(tag="y")
        self.assertEqual(
            batch_anchor.batch_id_for([c1, c2]),
            batch_anchor.batch_id_for([c2, c1]),
        )

    def test_different_claims_different_id(self):
        self.assertNotEqual(
            batch_anchor.batch_id_for([_claim(tag="x")]),
            batch_anchor.batch_id_for([_claim(tag="y")]),
        )

    def test_returns_16_hex_chars(self):
        b_id = batch_anchor.batch_id_for([_claim()])
        self.assertEqual(len(b_id), 16)
        int(b_id, 16)  # must be valid hex


class TestIsAlreadyAnchored(unittest.TestCase):
    def test_not_found_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            result = batch_anchor.is_already_anchored("deadbeef", Path(d))
        self.assertFalse(result)

    def test_found_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d) / "2026" / "06"
            reg.mkdir(parents=True)
            (reg / "22.ndjson").write_text(
                json.dumps({"batch_id": "abc123", "ts": "2026-06-22T00:00:00Z"}) + "\n",
                encoding="utf-8",
            )
            result = batch_anchor.is_already_anchored("abc123", Path(d))
        self.assertTrue(result)

    def test_different_id_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d) / "2026" / "06"
            reg.mkdir(parents=True)
            (reg / "22.ndjson").write_text(
                json.dumps({"batch_id": "abc123"}) + "\n", encoding="utf-8"
            )
            result = batch_anchor.is_already_anchored("other", Path(d))
        self.assertFalse(result)


class TestAnchorGroup(unittest.TestCase):
    def _run(self, dry_run=False, canonicalization_id=batch_anchor.DEFAULT_CANONICALIZATION):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            registry_dir = tmp / "registry"
            proofs_dir = tmp / "proofs"
            claims = [_claim(), _claim(tag="b")]
            records = [_record(Path(f"c{i}.json"), c) for i, c in enumerate(claims)]
            b_id = batch_anchor.batch_id_for(claims)
            result = batch_anchor.anchor_group(
                "cmcp-gateway/0.1.0",
                records,
                "2026-06-22T00:00:00Z",
                b_id,
                registry_dir,
                proofs_dir,
                dry_run=dry_run,
                canonicalization_id=canonicalization_id,
            )
            if not dry_run:
                ndjson = registry_dir / "2026" / "06" / "22.ndjson"
                self.assertTrue(ndjson.exists())
                entry = json.loads(ndjson.read_text())
                self.assertEqual(entry["batch_id"], b_id)
                self.assertEqual(entry["leaf_count"], 2)
                self.assertEqual(entry["canonicalization_id"], canonicalization_id)

                proof_dir = proofs_dir / "2026" / "06" / "22" / b_id
                self.assertTrue(proof_dir.exists())
                proofs = list(proof_dir.glob("*.proof.json"))
                self.assertEqual(len(proofs), 2)
            return result

    def test_dry_run_writes_nothing(self):
        result = self._run(dry_run=True)
        self.assertEqual(result["status"], "dry_run")

    def test_real_run_writes_files(self):
        result = self._run(dry_run=False)
        self.assertEqual(result["status"], "anchored")
        self.assertEqual(result["leaf_count"], 2)

    def test_real_run_declares_as_transmitted_when_asked(self):
        result = self._run(dry_run=False, canonicalization_id="as-transmitted")
        self.assertEqual(result["status"], "anchored")


class TestMoveToProcessed(unittest.TestCase):
    def test_moves_files(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            incoming = tmp / "incoming"
            incoming.mkdir()
            processed = tmp / "processed"
            processed.mkdir()
            p = _write_claim(incoming, "c.json", _claim())
            records = [_record(p, _claim())]
            batch_anchor.move_to_processed(records, "batch001", processed, dry_run=False)
            self.assertFalse(p.exists())
            self.assertTrue((processed / "batch001" / "c.json").exists())

    def test_dry_run_leaves_files(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            incoming = tmp / "incoming"
            incoming.mkdir()
            p = _write_claim(incoming, "c.json", _claim())
            records = [_record(p, _claim())]
            batch_anchor.move_to_processed(records, "batch001", tmp / "processed", dry_run=True)
            self.assertTrue(p.exists())


class TestMainCLI(unittest.TestCase):
    def _run_main(self, staging_dir, registry_dir, proofs_dir, extra_args=None):
        # These tests exercise the pipeline mechanics, not the signature
        # policy (covered by TestSignatureGate), so signatures are not verified.
        argv = [
            "--staging-dir", str(staging_dir),
            "--registry-dir", str(registry_dir),
            "--proofs-dir", str(proofs_dir),
            "--ts", "2026-06-22T00:00:00Z",
            "--no-verify-signatures",
        ] + (extra_args or [])
        captured = StringIO()
        with patch("sys.stdout", captured):
            rc = batch_anchor.main(argv)
        return rc, captured.getvalue()

    def test_no_staging_dir_exits_0(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rc, _ = self._run_main(tmp / "nosuchstaging", tmp / "registry", tmp / "proofs")
        self.assertEqual(rc, 0)

    def test_empty_incoming_exits_0(self):
        with tempfile.TemporaryDirectory() as d:
            staging, incoming, _ = _make_staging(Path(d))
            rc, _ = self._run_main(staging, Path(d) / "registry", Path(d) / "proofs")
        self.assertEqual(rc, 0)

    def test_anchors_records_exits_0(self):
        with tempfile.TemporaryDirectory() as d:
            staging, incoming, _ = _make_staging(Path(d))
            _write_claim(incoming, "c1.json", _claim())
            rc, _ = self._run_main(staging, Path(d) / "registry", Path(d) / "proofs")
        self.assertEqual(rc, 0)

    def test_json_output_anchored(self):
        with tempfile.TemporaryDirectory() as d:
            staging, incoming, _ = _make_staging(Path(d))
            _write_claim(incoming, "c1.json", _claim())
            rc, out = self._run_main(
                staging, Path(d) / "registry", Path(d) / "proofs", ["--json"]
            )
        self.assertEqual(rc, 0)
        report = json.loads(out)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["batches"]), 1)
        self.assertEqual(report["batches"][0]["status"], "anchored")

    def test_idempotent_skip(self):
        with tempfile.TemporaryDirectory() as d:
            staging, incoming, _ = _make_staging(Path(d))
            _write_claim(incoming, "c1.json", _claim())
            registry_dir = Path(d) / "registry"
            proofs_dir = Path(d) / "proofs"
            # First run -- anchors
            rc1, _ = self._run_main(staging, registry_dir, proofs_dir)
            # Second run -- incoming now empty (files moved to processed)
            rc2, out2 = self._run_main(staging, registry_dir, proofs_dir)
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as d:
            staging, incoming, _ = _make_staging(Path(d))
            _write_claim(incoming, "c1.json", _claim())
            registry_dir = Path(d) / "registry"
            rc, out = self._run_main(
                staging, registry_dir, Path(d) / "proofs", ["--dry-run", "--json"]
            )
        self.assertEqual(rc, 0)
        # registry should not have been written
        self.assertFalse(registry_dir.exists())
        report = json.loads(out)
        self.assertTrue(report["dry_run"])
        self.assertEqual(report["batches"][0]["status"], "dry_run")

    def test_canonicalization_flag_declared_on_entry(self):
        with tempfile.TemporaryDirectory() as d:
            staging, incoming, _ = _make_staging(Path(d))
            _write_claim(incoming, "c1.json", _claim())
            registry_dir = Path(d) / "registry"
            rc, out = self._run_main(
                staging, registry_dir, Path(d) / "proofs",
                ["--json", "--canonicalization", "as-transmitted"],
            )
            self.assertEqual(rc, 0)
            ndjson = registry_dir / "2026" / "06" / "22.ndjson"
            entry = json.loads(ndjson.read_text().splitlines()[0])
        self.assertEqual(entry["canonicalization_id"], "as-transmitted")

    def test_default_canonicalization_declared_as_sorted_key(self):
        with tempfile.TemporaryDirectory() as d:
            staging, incoming, _ = _make_staging(Path(d))
            _write_claim(incoming, "c1.json", _claim())
            registry_dir = Path(d) / "registry"
            rc, _ = self._run_main(staging, registry_dir, Path(d) / "proofs")
            self.assertEqual(rc, 0)
            ndjson = registry_dir / "2026" / "06" / "22.ndjson"
            entry = json.loads(ndjson.read_text().splitlines()[0])
        self.assertEqual(entry["canonicalization_id"], "sorted-key")

    def test_multiple_producers_separate_batches(self):
        with tempfile.TemporaryDirectory() as d:
            staging, incoming, _ = _make_staging(Path(d))
            _write_claim(incoming, "p1.json", _claim(producer="prod-a/1.0.0"))
            _write_claim(incoming, "p2.json", _claim(producer="prod-b/1.0.0"))
            rc, out = self._run_main(
                staging, Path(d) / "registry", Path(d) / "proofs", ["--json"]
            )
        self.assertEqual(rc, 0)
        report = json.loads(out)
        self.assertEqual(len(report["batches"]), 2)
        producers = {b["producer"] for b in report["batches"]}
        self.assertEqual(producers, {"prod-a/1.0.0", "prod-b/1.0.0"})


try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def _signed_claim(priv, producer, tag="a"):
    import base64

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from trace_verify._signature import canonical_body_bytes
    body = {"fmt": 1, "producer": producer, "ts": "2026-06-22T00:00:00Z",
            "hash": "sha256:" + ("0" * 63 + tag)}
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
    (producers_dir / (producer.replace("/", "-") + ".json")).write_text(
        json.dumps(entry), encoding="utf-8"
    )


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography package not installed")
class TestSignatureGate(unittest.TestCase):
    """Fail-closed: batch_anchor verifies producer signatures by default."""

    def _run(self, staging, registry, proofs, producers, extra=None):
        argv = [
            "--staging-dir", str(staging),
            "--registry-dir", str(registry),
            "--proofs-dir", str(proofs),
            "--producers-dir", str(producers),
            "--ts", "2026-06-22T00:00:00Z",
            "--json",
        ] + (extra or [])
        captured = StringIO()
        with patch("sys.stdout", captured):
            rc = batch_anchor.main(argv)
        return rc, json.loads(captured.getvalue())

    def test_accepts_signed_claim(self):
        priv = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            staging, incoming, _ = _make_staging(tmp)
            producers = tmp / "producers"
            _write_producer_key(producers, "good/1.0.0", priv)
            _write_claim(incoming, "c1.json", _signed_claim(priv, "good/1.0.0"))
            rc, report = self._run(staging, tmp / "registry", tmp / "proofs", producers)
        self.assertEqual(rc, 0)
        self.assertEqual(report["batches"][0]["status"], "anchored")

    def test_rejects_unknown_producer(self):
        priv = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            staging, incoming, _ = _make_staging(tmp)
            producers = tmp / "producers"
            producers.mkdir()
            _write_claim(incoming, "c1.json", _signed_claim(priv, "unknown/1.0.0"))
            registry = tmp / "registry"
            rc, report = self._run(staging, registry, tmp / "proofs", producers)
        self.assertEqual(rc, 1)
        self.assertEqual(report["batches"][0]["status"], "rejected")
        self.assertFalse(registry.exists())

    def test_rejects_bad_signature(self):
        priv = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            staging, incoming, _ = _make_staging(tmp)
            producers = tmp / "producers"
            _write_producer_key(producers, "good/1.0.0", priv)
            claim = _signed_claim(priv, "good/1.0.0")
            claim["hash"] = "sha256:" + "f" * 64  # tamper after signing
            _write_claim(incoming, "c1.json", claim)
            registry = tmp / "registry"
            rc, report = self._run(staging, registry, tmp / "proofs", producers)
        self.assertEqual(rc, 1)
        self.assertEqual(report["batches"][0]["status"], "rejected")
        self.assertFalse(registry.exists())


if __name__ == "__main__":
    unittest.main()
