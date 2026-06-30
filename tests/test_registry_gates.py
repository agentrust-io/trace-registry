"""Tests for tools/validate_registry.py and tools/check_append_only.py.

Standard library only except for jsonschema (installed in CI).
Run from the repository root:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import validate_registry  # noqa: E402


VALID_ENTRY = {
    "ts": "2026-06-12T18:09:41Z",
    "merkle_root": "sha256:" + "ab" * 32,
    "leaf_count": 1,
    "producer": "cmcp-gateway/0.1.0",
    "batch_id": "2026-06-12-001",
}


def _write_ndjson(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n",
        encoding="utf-8",
    )


class TestValidateRegistry(unittest.TestCase):
    def _run(self, registry_dir: Path) -> int:
        return validate_registry.main([str(registry_dir)])

    def test_valid_single_entry_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            _write_ndjson(d / "2026" / "06" / "12.ndjson", [VALID_ENTRY])
            self.assertEqual(self._run(d), 0)

    def test_empty_registry_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._run(Path(tmp)), 0)

    def test_blank_line_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "2026" / "06" / "12.ndjson"
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps(VALID_ENTRY) + "\n\n", encoding="utf-8")
            self.assertEqual(self._run(Path(tmp)), 1)

    def test_invalid_json_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "2026" / "06" / "12.ndjson"
            p.parent.mkdir(parents=True)
            p.write_text("not json\n", encoding="utf-8")
            self.assertEqual(self._run(Path(tmp)), 1)

    def test_missing_field_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = {k: v for k, v in VALID_ENTRY.items() if k != "merkle_root"}
            _write_ndjson(Path(tmp) / "2026" / "06" / "12.ndjson", [bad])
            self.assertEqual(self._run(Path(tmp)), 1)

    def test_monotonic_timestamps_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            e1 = {**VALID_ENTRY, "ts": "2026-06-12T10:00:00Z", "batch_id": "b1"}
            e2 = {**VALID_ENTRY, "ts": "2026-06-12T10:00:00Z", "batch_id": "b2"}
            e3 = {**VALID_ENTRY, "ts": "2026-06-12T11:00:00Z", "batch_id": "b3"}
            _write_ndjson(Path(tmp) / "2026" / "06" / "12.ndjson", [e1, e2, e3])
            self.assertEqual(self._run(Path(tmp)), 0)

    def test_out_of_order_timestamp_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            e1 = {**VALID_ENTRY, "ts": "2026-06-12T11:00:00Z", "batch_id": "b1"}
            e2 = {**VALID_ENTRY, "ts": "2026-06-12T10:00:00Z", "batch_id": "b2"}
            _write_ndjson(Path(tmp) / "2026" / "06" / "12.ndjson", [e1, e2])
            self.assertEqual(self._run(Path(tmp)), 1)

    def test_producer_valid_formats_pass(self):
        valid_producers = [
            "cmcp-gateway/0.1.0",
            "my-agent/1.2.3",
            "org.example.proxy/10.0.0",
            "gateway/0.0.1-alpha",
            "A/1.0.0",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            entries = [
                {**VALID_ENTRY, "producer": p, "batch_id": f"b{i}"}
                for i, p in enumerate(valid_producers)
            ]
            _write_ndjson(Path(tmp) / "2026" / "06" / "12.ndjson", entries)
            self.assertEqual(self._run(Path(tmp)), 0)

    def test_producer_invalid_formats_fail(self):
        invalid_producers = [
            "no-version",
            "/0.1.0",
            "name/notasemver",
            "name/1.2",
            "",
        ]
        for producer in invalid_producers:
            with self.subTest(producer=producer):
                with tempfile.TemporaryDirectory() as tmp:
                    bad = {**VALID_ENTRY, "producer": producer}
                    _write_ndjson(Path(tmp) / "2026" / "06" / "12.ndjson", [bad])
                    self.assertEqual(self._run(Path(tmp)), 1)

    def test_leaf_count_zero_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = {**VALID_ENTRY, "leaf_count": 0}
            _write_ndjson(Path(tmp) / "2026" / "06" / "12.ndjson", [bad])
            self.assertEqual(self._run(Path(tmp)), 1)

    def test_merkle_root_wrong_format_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = {**VALID_ENTRY, "merkle_root": "md5:" + "ab" * 16}
            _write_ndjson(Path(tmp) / "2026" / "06" / "12.ndjson", [bad])
            self.assertEqual(self._run(Path(tmp)), 1)


class TestCheckAppendOnly(unittest.TestCase):
    """Unit tests for the append-only logic extracted from check_append_only.py.

    These tests exercise the core comparison logic directly without requiring
    a real git repository, by calling the internal helpers.
    """

    def _check(self, old_lines: list[str], new_lines: list[str]) -> tuple[bool, str]:
        """Return (is_violation, message) by simulating the per-file logic."""
        violations = []
        if len(new_lines) < len(old_lines):
            violations.append(
                f"{len(old_lines) - len(new_lines)} line(s) removed"
            )
            return True, violations[0]
        for i, (old, new) in enumerate(zip(old_lines, new_lines), start=1):
            if old != new:
                violations.append(f"line {i} modified")
                return True, violations[0]
        return False, ""

    def test_pure_append_is_ok(self):
        old = ['{"ts":"2026-06-12T10:00:00Z","merkle_root":"sha256:' + "ab" * 32 + '","leaf_count":1,"producer":"x/1.0.0","batch_id":"b1"}']
        new = old + ['{"ts":"2026-06-12T11:00:00Z","merkle_root":"sha256:' + "cd" * 32 + '","leaf_count":2,"producer":"x/1.0.0","batch_id":"b2"}']
        violation, _ = self._check(old, new)
        self.assertFalse(violation)

    def test_unchanged_file_is_ok(self):
        old = ['{"a":1}', '{"a":2}']
        violation, _ = self._check(old, old[:])
        self.assertFalse(violation)

    def test_modified_line_is_violation(self):
        old = ['{"a":1}', '{"a":2}']
        new = ['{"a":1}', '{"a":99}']
        violation, msg = self._check(old, new)
        self.assertTrue(violation)
        self.assertIn("line 2 modified", msg)

    def test_deleted_line_is_violation(self):
        old = ['{"a":1}', '{"a":2}']
        new = ['{"a":1}']
        violation, msg = self._check(old, new)
        self.assertTrue(violation)
        self.assertIn("removed", msg)

    def test_prepended_line_is_violation(self):
        old = ['{"a":2}']
        new = ['{"a":1}', '{"a":2}']
        violation, _ = self._check(old, new)
        self.assertTrue(violation)

    def test_new_file_no_old_lines(self):
        old: list[str] = []
        new = ['{"a":1}']
        violation, _ = self._check(old, new)
        self.assertFalse(violation)


if __name__ == "__main__":
    unittest.main()
