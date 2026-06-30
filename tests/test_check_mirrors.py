"""Tests for tools/check_mirrors.py."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import check_mirrors


CANONICAL_SHA = "abc123def456abc123def456abc123def456abc123"
MIRROR_SHA_SYNC = CANONICAL_SHA
MIRROR_SHA_BEHIND = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


def _fake_mirrors_json(mirrors=None) -> dict:
    return {
        "canonical": {
            "name": "canonical",
            "github": "agentrust-io/trace-registry",
            "head_api": "https://api.github.com/repos/agentrust-io/trace-registry/commits/HEAD",
            "contact": "security@opaque.co",
        },
        "mirrors": mirrors or [],
    }


def _mirror_entry(name="TestMirror", github="test-org/trace-registry-mirror", sha=None):
    sha = sha or MIRROR_SHA_SYNC
    return {
        "name": name,
        "github": github,
        "clone_url": f"https://github.com/{github}.git",
        "head_api": f"https://api.github.com/repos/{github}/commits/HEAD",
        "contact": "test@example.com",
        "_test_sha": sha,
    }


def _make_fetch_side_effect(canonical_sha, mirror_shas: dict):
    """Return a side_effect fn for _fetch_json that resolves by URL."""
    def side_effect(url, timeout, allowed_hosts=None):
        if "agentrust-io/trace-registry" in url:
            return {"sha": canonical_sha}
        for github, sha in mirror_shas.items():
            if github.replace("/", "%2F") in url or github in url:
                return {"sha": sha}
        raise urllib.error.URLError("no mock for " + url)
    return side_effect


class TestNoMirrors(unittest.TestCase):
    def _run(self, config, extra_argv=None):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(config, f)
            tmp = Path(f.name)
        orig = check_mirrors.MIRRORS_JSON
        check_mirrors.MIRRORS_JSON = tmp
        try:
            rc = check_mirrors.main(extra_argv or [])
        finally:
            check_mirrors.MIRRORS_JSON = orig
            tmp.unlink(missing_ok=True)
        return rc

    def test_no_mirrors_exits_0(self):
        rc = self._run(_fake_mirrors_json([]))
        self.assertEqual(rc, 0)

    def test_no_mirrors_json_output(self):
        rc = self._run(_fake_mirrors_json([]), ["--json"])
        self.assertEqual(rc, 0)


class TestMirrorCheck(unittest.TestCase):
    def _run_with_mirrors(self, mirrors_list, canonical_sha=CANONICAL_SHA, argv=None):
        config = _fake_mirrors_json(mirrors_list)
        mirror_shas = {
            m["github"]: m.get("_test_sha", canonical_sha)
            for m in mirrors_list
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(config, f)
            tmp = Path(f.name)

        orig = check_mirrors.MIRRORS_JSON
        check_mirrors.MIRRORS_JSON = tmp
        try:
            with patch.object(
                check_mirrors,
                "_fetch_json",
                side_effect=_make_fetch_side_effect(canonical_sha, mirror_shas),
            ):
                rc = check_mirrors.main(argv or [])
        finally:
            check_mirrors.MIRRORS_JSON = orig
            tmp.unlink(missing_ok=True)
        return rc

    def test_in_sync_mirror_exits_0(self):
        m = _mirror_entry(sha=CANONICAL_SHA)
        rc = self._run_with_mirrors([m])
        self.assertEqual(rc, 0)

    def test_diverged_mirror_exits_1(self):
        m = _mirror_entry(sha=MIRROR_SHA_BEHIND)
        rc = self._run_with_mirrors([m])
        self.assertEqual(rc, 1)

    def test_two_mirrors_both_in_sync(self):
        m1 = _mirror_entry("Mirror A", "org-a/trace-mirror", CANONICAL_SHA)
        m2 = _mirror_entry("Mirror B", "org-b/trace-mirror", CANONICAL_SHA)
        rc = self._run_with_mirrors([m1, m2])
        self.assertEqual(rc, 0)

    def test_one_of_two_diverged_exits_1(self):
        m1 = _mirror_entry("Mirror A", "org-a/trace-mirror", CANONICAL_SHA)
        m2 = _mirror_entry("Mirror B", "org-b/trace-mirror", MIRROR_SHA_BEHIND)
        rc = self._run_with_mirrors([m1, m2])
        self.assertEqual(rc, 1)

    def test_unreachable_mirror_exits_1(self):
        m = _mirror_entry()
        config = _fake_mirrors_json([m])
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(config, f)
            tmp = Path(f.name)

        orig = check_mirrors.MIRRORS_JSON
        check_mirrors.MIRRORS_JSON = tmp

        def fetch_side(url, timeout, allowed_hosts=None):
            if "agentrust-io" in url:
                return {"sha": CANONICAL_SHA}
            raise urllib.error.URLError("connection refused")

        try:
            with patch.object(check_mirrors, "_fetch_json", side_effect=fetch_side):
                rc = check_mirrors.main([])
        finally:
            check_mirrors.MIRRORS_JSON = orig
            tmp.unlink(missing_ok=True)

        self.assertEqual(rc, 1)

    def test_json_output_in_sync(self):
        m = _mirror_entry(sha=CANONICAL_SHA)
        config = _fake_mirrors_json([m])
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(config, f)
            tmp = Path(f.name)

        orig = check_mirrors.MIRRORS_JSON
        check_mirrors.MIRRORS_JSON = tmp
        captured = StringIO()

        def fetch_side(url, timeout, allowed_hosts=None):
            return {"sha": CANONICAL_SHA}

        try:
            with patch.object(check_mirrors, "_fetch_json", side_effect=fetch_side):
                with patch("sys.stdout", captured):
                    rc = check_mirrors.main(["--json"])
        finally:
            check_mirrors.MIRRORS_JSON = orig
            tmp.unlink(missing_ok=True)

        self.assertEqual(rc, 0)
        report = json.loads(captured.getvalue())
        self.assertTrue(report["ok"])
        self.assertEqual(report["mirrors"][0]["status"], "in_sync")

    def test_json_output_diverged(self):
        m = _mirror_entry(sha=MIRROR_SHA_BEHIND)
        config = _fake_mirrors_json([m])
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(config, f)
            tmp = Path(f.name)

        orig = check_mirrors.MIRRORS_JSON
        check_mirrors.MIRRORS_JSON = tmp
        captured = StringIO()

        def fetch_side(url, timeout, allowed_hosts=None):
            if "agentrust-io" in url:
                return {"sha": CANONICAL_SHA}
            return {"sha": MIRROR_SHA_BEHIND}

        try:
            with patch.object(check_mirrors, "_fetch_json", side_effect=fetch_side):
                with patch("sys.stdout", captured):
                    rc = check_mirrors.main(["--json"])
        finally:
            check_mirrors.MIRRORS_JSON = orig
            tmp.unlink(missing_ok=True)

        self.assertEqual(rc, 1)
        report = json.loads(captured.getvalue())
        self.assertFalse(report["ok"])
        self.assertEqual(report["mirrors"][0]["status"], "diverged")

    def test_mirror_filter_by_name(self):
        m1 = _mirror_entry("Alpha Mirror", "org-alpha/trace", CANONICAL_SHA)
        m2 = _mirror_entry("Beta Mirror", "org-beta/trace", MIRROR_SHA_BEHIND)
        # filter to Alpha only -- should pass
        rc = self._run_with_mirrors([m1, m2], argv=["--mirror", "alpha"])
        self.assertEqual(rc, 0)

    def test_mirror_filter_no_match_exits_2(self):
        m = _mirror_entry()
        rc = self._run_with_mirrors([m], argv=["--mirror", "nonexistent"])
        self.assertEqual(rc, 2)


class TestSSRFGuard(unittest.TestCase):
    """Fix #3: head_api fetches are restricted to https + a host allowlist."""

    def test_check_url_allowed_rejects_scheme_and_host(self):
        allowed = frozenset({"api.github.com"})
        self.assertIsNotNone(check_mirrors._check_url_allowed("http://api.github.com/x", allowed))
        self.assertIsNotNone(check_mirrors._check_url_allowed("file:///etc/passwd", allowed))
        self.assertIsNotNone(check_mirrors._check_url_allowed("https://169.254.169.254/x", allowed))
        self.assertIsNotNone(check_mirrors._check_url_allowed("https://evil.example.com/x", allowed))
        self.assertIsNone(check_mirrors._check_url_allowed("https://api.github.com/x", allowed))

    def test_allowlist_extended_from_config(self):
        config = _fake_mirrors_json([
            _mirror_entry("M", "org/m"),  # head_api on api.github.com
            {"name": "Custom", "head_api": "https://mirror.example.org/commits/HEAD"},
        ])
        hosts = check_mirrors._allowed_hosts_from_config(config)
        self.assertIn("api.github.com", hosts)
        self.assertIn("mirror.example.org", hosts)
        self.assertNotIn("evil.example.com", hosts)

    def test_fetch_json_refuses_disallowed_url(self):
        with self.assertRaises(ValueError):
            check_mirrors._fetch_json(
                "http://api.github.com/x", 5, frozenset({"api.github.com"})
            )
        with self.assertRaises(ValueError):
            check_mirrors._fetch_json(
                "https://evil.example.com/x", 5, frozenset({"api.github.com"})
            )


class TestGetHeadSha(unittest.TestCase):
    def test_full_sha(self):
        with patch.object(check_mirrors, "_fetch_json", return_value={"sha": "a" * 40}):
            sha = check_mirrors._get_head_sha("https://example.com", 5, frozenset({"example.com"}))
        self.assertEqual(sha, "a" * 40)

    def test_missing_sha_raises(self):
        with patch.object(check_mirrors, "_fetch_json", return_value={"commit": {}}):
            with self.assertRaises(ValueError):
                check_mirrors._get_head_sha("https://example.com", 5, frozenset({"example.com"}))

    def test_too_short_sha_raises(self):
        with patch.object(check_mirrors, "_fetch_json", return_value={"sha": "abc"}):
            with self.assertRaises(ValueError):
                check_mirrors._get_head_sha("https://example.com", 5, frozenset({"example.com"}))


if __name__ == "__main__":
    unittest.main()
