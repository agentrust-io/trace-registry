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


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography package not installed")
class TestScheduledFinalR(unittest.TestCase):
    """Scheduled #102 subjects, through real registered-producer verification.

    Deterministic fixture bytes and whole-file roots below were captured by
    the unmodified pipeline before the subject-selection change. These keys
    are public, test-only material. Historical files are only ever read.
    """

    PRODUCER = "scheduled-fixture/1.0.0"
    MODES = ("sorted-key", "as-transmitted")
    # Ordered: fixture SHA256, whole-file sorted/raw roots, submission batch ID.
    BASELINE = {
        "flat": (
            "e6264145607c11d8c6be1615c7c78b08c4d7b3557b3c775deb6cfc13bb7e2831",
            "318315fa94504bb1194355c81f25da2b9ef6b7f25e136ec37f07960fa7c15d7f",
            "e79c337b31ff72dd155fe42245682e34e6386d4fe1ba2b8ddce8164037d22e6b",
            "73573ffe30683b85",
        ),
        "direct": (
            "4ce1b7bed642b6227cd3f5b24f4b98ff22d22d6c105c43d1fe9ac43783e6c9b4",
            "3faffdb039b7ae69016705aa1341cc76ce67e9ad54003fbe7729ebd883cc75fc",
            "992e63133729a1eccecb34cca5cc9c9d2a13665433c247b2a5e13e8d5480453e",
            "088b82f288c693ef",
        ),
        "object": (
            "5bae710bf0f3390a6225ffe00392a4eaf9f216e72571a0d1705d359b6b7738b5",
            "af684bd4e06693e2f4c5acc0e1a8c755a175eb21fe79074ce51b6c9161ff8598",
            "d9622955b53c5c9d03553c906f8a495c14498e3b5fa2f9fe44364e0007d2992d",
            "36e968ea84876516",
        ),
        "text": (
            "40aa2e4abd39a538992198b094badc86f2dfd78d70768ac3a2bc5a57fc4ee284",
            "b1fdc7b31722ddc76e33b134d3cfb6f8bda9ef67b931f4e0a9bd380a962d78d7",
            "a1030b24f1eb832b133d594536c465908ad07619fa5fa76d82375f6d10a355f4",
            "09b50c29812929c5",
        ),
        "extra": (
            "5be1c38e16e40d62008ab2aeb0d71f8971ee4c2b5edf9309d8ded92985c484df",
            "c48d7b12fdfda682106568e7d3f6f0d381f709b6d98bc32b393d31db214e90ac",
            "4c0f82259c8c5968bb0fcf21faa2b5fdf935b80a2036bd6008b50386b017f32c",
            "ec3477d406c53494",
        ),
        "unsigned_nested": (
            "4bf66ad9555c8518a76e8fff142e888cfa2895cfd53e15c8d22cc3c51208b673",
            "b165888d3bc033182417b250b3385b526efc5b0812bd91ed865c9b548c307dea",
            "497309f4c43fc81ffc83fc2837256d26811ecc16f5b70a58fa28fee829294bb9",
            "bb200b151100dfe2",
        ),
    }
    HISTORICAL = {
        "staging/processed/ac05cb84fd956684/bernstein-3.20.0-20260920-165918-backend-99365805.json":
            "bd39b2ecdea66b20e186663e24cd0217eab3f458256ef607ed2111a965481efb",
        "proofs/2026/09/25/ac05cb84fd956684/bernstein-3.20.0-20260920-165918-backend-99365805.proof.json":
            "036f903026790648083427f6097d7c2495f2ae9038d0fb8a639cd89c57c49f23",
        "registry/2026/09/25.ndjson":
            "e0e73b4264feb1fc51a71b466fb4a8aae308cad23cbfb18df17f9d72f59db5ac",
    }

    def setUp(self):
        self.outer_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.inner_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        self.record = self._sign({
            "cmcp_version": "0.2", "gateway": "fixture-gateway",
            "trace": {"event": "café 🌳", "count": 1},
        }, self.inner_key)
        self.text = self._raw(self.record).decode("utf-8")

    def _sign(self, claim, key=None):
        import base64
        from trace_verify._signature import canonical_body_bytes

        body = {k: v for k, v in claim.items() if k != "signature"}
        signature = (key or self.outer_key).sign(canonical_body_bytes(body))
        return {**body, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}

    @staticmethod
    def _raw(claim):
        return (json.dumps(claim, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    def _envelope(self, trace):
        return self._sign({"producer": self.PRODUCER, "trace": trace})

    def _fixtures(self):
        return {
            "flat": self._sign({
                "fmt": 1, "producer": self.PRODUCER, "ts": "2026-10-04T00:00:00Z",
                "hash": "sha256:" + "a" * 64, "note": "café 🌳",
            }),
            "direct": self._sign({
                "cmcp_version": "0.2", "producer": self.PRODUCER,
                "gateway": "fixture-gateway", "trace": {"event": "café 🌳", "count": 1},
            }),
            "object": self._envelope(self.record),
            "text": self._envelope(self.text),
            "extra": self._sign({
                "producer": self.PRODUCER, "trace": self.record,
                "extra_metadata": {"origin": "café"},
            }),
            "unsigned_nested": self._envelope({"event": "café 🌳", "count": 1}),
        }

    def _run_inputs(self, raws, mode, *, registered_key=None, registry_identity=None):
        import os

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            staging, incoming, processed = _make_staging(tmp)
            producers = tmp / "producers"
            _write_producer_key(producers, self.PRODUCER, registered_key or self.outer_key)
            if registry_identity is not None:
                key_path = producers / (self.PRODUCER.replace("/", "-") + ".json")
                key_entry = json.loads(key_path.read_text())
                key_entry["producer_id"] = registry_identity
                key_path.write_text(json.dumps(key_entry))
            names = [f"claim-{i}.json" for i in range(len(raws))]
            for name, raw in zip(names, raws):
                (incoming / name).write_bytes(raw)
            registry, proofs = tmp / "registry", tmp / "proofs"
            stdout, stderr = StringIO(), StringIO()
            argv = [
                "--staging-dir", str(staging), "--registry-dir", str(registry),
                "--proofs-dir", str(proofs), "--producers-dir", str(producers),
                "--ts", "2026-10-04T00:00:00Z", "--canonicalization", mode, "--json",
            ]
            # Never consume a developer's live checkpoint signing key.
            with patch.dict(os.environ, {batch_anchor.CHECKPOINT_KEY_ENV: ""}), \
                    patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                rc = batch_anchor.main(argv)
            snapshot = {}
            for kind, directory in (("registry", registry), ("proofs", proofs),
                                    ("processed", processed), ("incoming", incoming)):
                snapshot[kind] = {
                    str(p.relative_to(directory)): p.read_bytes()
                    for p in directory.rglob("*") if p.is_file()
                }
            return rc, json.loads(stdout.getvalue()), snapshot

    def _accepted(self, raw, mode):
        rc, report, files = self._run_inputs([raw], mode)
        self.assertEqual(rc, 0, report)
        self.assertTrue(report["ok"], report)
        result = report["batches"][0]
        self.assertEqual(result["status"], "anchored", report)
        self.assertEqual(result["leaf_count"], 1)
        self.assertEqual(len(files["registry"]), 1)
        entry = json.loads(next(iter(files["registry"].values())))
        self.assertEqual(entry["merkle_root"], result["merkle_root"])
        self.assertEqual(entry["canonicalization_id"], mode)
        self.assertEqual(len(files["proofs"]), 1)
        proof = json.loads(next(iter(files["proofs"].values())))
        self.assertEqual(proof, {"leaf_index": 0, "audit_path": []})
        self.assertEqual(list(files["processed"].values()), [raw])
        self.assertEqual(files["incoming"], {})
        return result

    def _refused(self, raws, mode, reason=None, **kwargs):
        rc, report, files = self._run_inputs(raws, mode, **kwargs)
        self.assertEqual(rc, 1, report)
        self.assertFalse(report["ok"], report)
        self.assertEqual(len(report["batches"]), 1, report)
        result = report["batches"][0]
        self.assertIn(result["status"], ("failed", "rejected"), report)
        if reason is not None:
            self.assertIn(reason, result.get("error", result.get("detail", "")))
        for kind in ("registry", "proofs", "processed"):
            self.assertEqual(files[kind], {}, (kind, report))
        self.assertEqual(files["incoming"], {
            f"claim-{i}.json": raw for i, raw in enumerate(raws)
        })
        return result

    @staticmethod
    def _direct_root(record, mode="sorted-key", raw=None):
        import anchor

        return "sha256:" + anchor.leaf_hash(
            record, canonicalization_id=mode, raw_bytes=raw,
        ).hex()

    def _assert_compatibility(self, name, mode):
        import hashlib

        claim = self._fixtures()[name]
        raw = self._raw(claim)
        digest, sorted_root, transmitted_root, batch_id = self.BASELINE[name]
        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        result = self._accepted(raw, mode)
        expected = sorted_root if mode == "sorted-key" else transmitted_root
        self.assertEqual(result["merkle_root"], "sha256:" + expected)
        self.assertEqual(result["merkle_root"], self._direct_root(claim, mode, raw))
        self.assertEqual(result["batch_id"], batch_id)

    def test_t01_flat_sorted_key(self):
        self._assert_compatibility("flat", "sorted-key")

    def test_t02_flat_as_transmitted(self):
        self._assert_compatibility("flat", "as-transmitted")

    def test_t03_object_sorted_key(self):
        envelope = self._envelope(self.record)
        raw_forms = (
            self._raw(envelope),
            json.dumps(dict(reversed(list(envelope.items()))), ensure_ascii=True).encode(),
        )
        for raw in raw_forms:
            with self.subTest(raw=raw):
                result = self._accepted(raw, "sorted-key")
                self.assertEqual(result["merkle_root"], self._direct_root(self.record))
                self.assertNotEqual(result["merkle_root"], self._direct_root(envelope))

    def test_t04_text_sorted_key(self):
        text_result = self._accepted(self._raw(self._envelope(self.text)), "sorted-key")
        object_result = self._accepted(self._raw(self._envelope(self.record)), "sorted-key")
        self.assertEqual(text_result["merkle_root"], self._direct_root(self.record))
        self.assertEqual(text_result["merkle_root"], object_result["merkle_root"])

    def test_t05_text_as_transmitted(self):
        import hashlib

        raw = self._raw(self._envelope(self.text))
        result = self._accepted(raw, "as-transmitted")
        expected = "sha256:" + hashlib.sha256(b"\x00" + self.text.encode("utf-8")).hexdigest()
        self.assertEqual(result["merkle_root"], expected)
        self.assertNotEqual(expected, self._direct_root(json.loads(raw), "as-transmitted", raw))

    def test_t06_object_as_transmitted_refused(self):
        self._refused([self._raw(self._envelope(self.record))], "as-transmitted", "exact R JSON text")
        self._accepted(self._raw(self._envelope(self.text)), "as-transmitted")

    def test_t07_no_envelope_fallback(self):
        good = self._raw(self._envelope(self.text))
        missing_text = self._raw(self._envelope(self.record))
        # A valid earlier leaf cannot cause partial publication or processing
        # when a later same-producer envelope has no exact R text.
        self._refused([good, missing_text], "as-transmitted", "exact R JSON text")
        self._accepted(good, "as-transmitted")

    def test_t08_representation_differential(self):
        alternate = json.dumps(dict(reversed(list(self.record.items()))), ensure_ascii=True)
        self.assertEqual(json.loads(self.text), json.loads(alternate))
        self.assertNotEqual(self.text.encode(), alternate.encode())
        roots = {}
        for mode in self.MODES:
            roots[mode] = [self._accepted(self._raw(self._envelope(text)), mode)["merkle_root"]
                           for text in (self.text, alternate)]
            for text, root in zip((self.text, alternate), roots[mode]):
                self.assertEqual(root, self._direct_root(self.record, mode, text.encode("utf-8")))
        self.assertEqual(*roots["sorted-key"])
        self.assertNotEqual(*roots["as-transmitted"])

    def test_t09_text_bound_by_outer_signature(self):
        good = self._envelope(self.text)
        tampered = {**good, "trace": " \n" + self.text}
        self.assertEqual(json.loads(good["trace"]), json.loads(tampered["trace"]))
        for mode in self.MODES:
            with self.subTest(mode=mode):
                self._refused([self._raw(tampered)], mode, "signature does not verify")
                self._accepted(self._raw(good), mode)
                self._accepted(self._raw(self._sign(tampered)), mode)

    def test_t10_record_mutation(self):
        changed = self._sign({**self.record, "trace": {"event": "café 🌳", "count": 2}}, self.inner_key)
        self.assertNotEqual(changed["signature"], self.record["signature"])
        for mode in self.MODES:
            with self.subTest(mode=mode):
                old = self._accepted(self._raw(self._envelope(self.text)), mode)
                new = self._accepted(self._raw(self._envelope(self._raw(changed).decode())), mode)
                self.assertNotEqual(old["merkle_root"], new["merkle_root"])
                self.assertEqual(new["merkle_root"], self._direct_root(changed, mode, self._raw(changed)))

    def test_t11_bad_text(self):
        bad_texts = (
            "{", "", "  \n", '{"a":1,"a":2}',
            '{"nested":{"a":1,"a":2}}', "[]", "null", "1", '"record"',
            '{"amount":1.5}', '{"amount":9007199254740992}',
        )
        for mode in self.MODES:
            for text in bad_texts:
                with self.subTest(mode=mode, text=text):
                    self._refused([self._raw(self._envelope(text))], mode)
            self._accepted(self._raw(self._envelope(self.text)), mode)

    def test_t12_historical_bernstein(self):
        root = Path(__file__).resolve().parents[1]
        historical = json.loads((root / next(iter(self.HISTORICAL))).read_bytes())
        entries = [json.loads(line) for line in (root / "registry/2026/09/25.ndjson").read_text().splitlines()]
        entry = next(entry for entry in entries if entry["batch_id"] == "ac05cb84fd956684")
        self.assertEqual(entry["leaf_count"], 1)
        self.assertEqual(entry["merkle_root"], self._direct_root(historical))
        self.assertNotEqual(entry["merkle_root"], self._direct_root(historical["trace"]))
        # A newly signed synthetic E uses the fixture's unchanged R. This is
        # future input in temporary directories, never a historical replay.
        future = self._envelope(historical["trace"])
        result = self._accepted(self._raw(future), "sorted-key")
        self.assertEqual(result["merkle_root"], self._direct_root(historical["trace"]))
        self.assertNotEqual(result["batch_id"], entry["batch_id"])

    def test_t13_manual_parity(self):
        result = self._accepted(self._raw(self._envelope(self.record)), "sorted-key")
        self.assertEqual(result["merkle_root"], self._direct_root(self.record))

    def test_t14_http_parity(self):
        from aggregator._core import _leaf_hash

        result = self._accepted(self._raw(self._envelope(self.text)), "as-transmitted")
        http_leaf = _leaf_hash(self.record, canonicalization_id="as-transmitted",
                               raw_bytes=self.text.encode("utf-8"))
        self.assertEqual(result["merkle_root"], "sha256:" + http_leaf.hex())

    def test_t15_bad_outer_signature(self):
        import base64

        good = self._envelope(self.text)
        invalid = {**good, "signature": base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()}
        for mode in self.MODES:
            with self.subTest(mode=mode):
                self._refused([self._raw(invalid)], mode, "signature does not verify")
                self._accepted(self._raw(good), mode)

    def test_t16_producer_mismatch(self):
        good = self._raw(self._envelope(self.text))
        for mode in self.MODES:
            with self.subTest(mode=mode):
                self._refused([good], mode, "signature does not verify", registered_key=self.inner_key)
                self._refused([good], mode, "producer_id does not match", registry_identity="other/1.0.0")
                self._accepted(good, mode)

    def test_t17_batch_id_unchanged(self):
        import hashlib

        fixtures = self._fixtures()
        for name, claim in fixtures.items():
            raw = self._raw(claim)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), self.BASELINE[name][0])
            for mode in self.MODES:
                with self.subTest(name=name, mode=mode):
                    # The object form is refused in raw mode, but its
                    # E-derived identity is still reported unchanged.
                    rc, report, _ = self._run_inputs([raw], mode)
                    self.assertEqual(report["batches"][0]["batch_id"], self.BASELINE[name][3])
                    self.assertEqual(rc, 1 if name == "object" and mode == "as-transmitted" else 0)
        claims = [fixtures["object"], fixtures["text"]]
        canonical = [json.dumps(c, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                     for c in claims]
        expected = hashlib.sha256(b"".join(sorted(canonical))).hexdigest()[:16]
        self.assertEqual(batch_anchor.batch_id_for(claims), expected)
        self.assertEqual(batch_anchor.batch_id_for(list(reversed(claims))), expected)
        for ordered in (claims, list(reversed(claims))):
            rc, report, _ = self._run_inputs([self._raw(c) for c in ordered], "sorted-key")
            self.assertEqual(rc, 0, report)
            self.assertEqual(report["batches"][0]["batch_id"], expected)

    def test_t18_historical_unchanged(self):
        import hashlib

        root = Path(__file__).resolve().parents[1]
        before = {path: (root / path).read_bytes() for path in self.HISTORICAL}
        for path, raw in before.items():
            self.assertEqual(hashlib.sha256(raw).hexdigest(), self.HISTORICAL[path])
        for mode in self.MODES:
            self._accepted(self._raw(self._envelope(self.text)), mode)
        for path, raw in before.items():
            self.assertEqual((root / path).read_bytes(), raw)

    def test_t19_direct_trace_record(self):
        direct = self._fixtures()["direct"]
        self.assertIn("producer", direct)
        self.assertIn("gateway", direct)
        self.assertIn("trace", direct)
        self.assertNotIn("signature", direct["trace"])
        for mode in self.MODES:
            with self.subTest(mode=mode):
                self._assert_compatibility("direct", mode)

    def test_t20_exact_envelope_shape(self):
        envelope = self._envelope(self.record)
        self.assertEqual(set(envelope), {"producer", "trace", "signature"})
        self.assertIn("signature", envelope["trace"])
        result = self._accepted(self._raw(envelope), "sorted-key")
        self.assertEqual(result["merkle_root"], self._direct_root(self.record))
        # Classification checks presence only: this patch adds no inner-R
        # signature/key policy, while the normal outer signature still verifies.
        for signature in ("", None):
            with self.subTest(inner_signature=signature):
                shaped = {**self.record, "signature": signature}
                result = self._accepted(self._raw(self._envelope(shaped)), "sorted-key")
                self.assertEqual(result["merkle_root"], self._direct_root(shaped))

    def test_t21_extra_member_is_direct(self):
        extra = self._fixtures()["extra"]
        self.assertEqual(set(extra), {"producer", "trace", "signature", "extra_metadata"})
        self.assertIn("signature", extra["trace"])
        for mode in self.MODES:
            with self.subTest(mode=mode):
                self._assert_compatibility("extra", mode)

    def test_t22_unsigned_nested_object_is_direct(self):
        direct = self._fixtures()["unsigned_nested"]
        self.assertEqual(set(direct), {"producer", "trace", "signature"})
        self.assertNotIn("signature", direct["trace"])
        for mode in self.MODES:
            with self.subTest(mode=mode):
                self._assert_compatibility("unsigned_nested", mode)


if __name__ == "__main__":
    unittest.main()
