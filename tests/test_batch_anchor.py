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
            (Path("a.json"), _claim(producer="p1/1.0.0")),
            (Path("b.json"), _claim(producer="p2/1.0.0")),
            (Path("c.json"), _claim(producer="p1/1.0.0", tag="b")),
        ]
        groups = batch_anchor.group_by_producer(records, 0)
        self.assertEqual(sorted(groups.keys()), ["p1/1.0.0", "p2/1.0.0"])
        self.assertEqual(len(groups["p1/1.0.0"]), 2)
        self.assertEqual(len(groups["p2/1.0.0"]), 1)

    def test_unknown_producer_grouped(self):
        records = [(Path("x.json"), {"fmt": 1})]  # no producer field
        groups = batch_anchor.group_by_producer(records, 0)
        self.assertIn("__unknown__", groups)

    def test_max_batch_truncates(self):
        records = [
            (Path(f"{i}.json"), _claim(tag=str(i))) for i in range(5)
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
    def _run(self, dry_run=False):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            registry_dir = tmp / "registry"
            proofs_dir = tmp / "proofs"
            claims = [_claim(), _claim(tag="b")]
            records = [(Path(f"c{i}.json") , c) for i, c in enumerate(claims)]
            b_id = batch_anchor.batch_id_for(claims)
            result = batch_anchor.anchor_group(
                "cmcp-gateway/0.1.0",
                records,
                "2026-06-22T00:00:00Z",
                b_id,
                registry_dir,
                proofs_dir,
                dry_run=dry_run,
            )
            if not dry_run:
                ndjson = registry_dir / "2026" / "06" / "22.ndjson"
                self.assertTrue(ndjson.exists())
                entry = json.loads(ndjson.read_text())
                self.assertEqual(entry["batch_id"], b_id)
                self.assertEqual(entry["leaf_count"], 2)

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


class TestMoveToProcessed(unittest.TestCase):
    def test_moves_files(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            incoming = tmp / "incoming"
            incoming.mkdir()
            processed = tmp / "processed"
            processed.mkdir()
            p = _write_claim(incoming, "c.json", _claim())
            records = [(p, _claim())]
            batch_anchor.move_to_processed(records, "batch001", processed, dry_run=False)
            self.assertFalse(p.exists())
            self.assertTrue((processed / "batch001" / "c.json").exists())

    def test_dry_run_leaves_files(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            incoming = tmp / "incoming"
            incoming.mkdir()
            p = _write_claim(incoming, "c.json", _claim())
            records = [(p, _claim())]
            batch_anchor.move_to_processed(records, "batch001", tmp / "processed", dry_run=True)
            self.assertTrue(p.exists())


class TestMainCLI(unittest.TestCase):
    def _run_main(self, staging_dir, registry_dir, proofs_dir, extra_args=None):
        argv = [
            "--staging-dir", str(staging_dir),
            "--registry-dir", str(registry_dir),
            "--proofs-dir", str(proofs_dir),
            "--ts", "2026-06-22T00:00:00Z",
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


if __name__ == "__main__":
    unittest.main()
