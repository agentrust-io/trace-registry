#!/usr/bin/env python3
"""Check that all registered mirrors are in sync with the canonical repo.

Reads mirrors.json, fetches the HEAD commit SHA from each mirror's API
endpoint, and compares it to the canonical repo's HEAD. Reports divergence
and exits non-zero if any mirror is behind or has diverged.

Usage:
    python tools/check_mirrors.py [--mirror NAME] [--json] [--timeout N]

Options:
    --mirror NAME   Check only the mirror whose 'name' or 'github' field
                    contains NAME (case-insensitive substring match).
    --json          Emit a machine-readable JSON report instead of plain text.
    --timeout N     HTTP timeout in seconds (default: 15).

Exit codes:
    0  All mirrors are in sync with canonical (or no mirrors registered).
    1  One or more mirrors are behind, diverged, or unreachable.
    2  Bad arguments or unreadable mirrors.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MIRRORS_JSON = REPO_ROOT / "mirrors.json"

UA = "trace-registry/check-mirrors (github.com/agentrust-io/trace-registry)"

# SSRF guard: even though mirrors.json is repo-controlled, enforce https and a
# host allowlist before fetching. The allowlist always includes the GitHub API
# hosts and is extended at runtime with the hosts already configured in
# mirrors.json. file://, http://, and internal/metadata targets are rejected.
_BASE_ALLOWED_HOSTS = frozenset({"api.github.com", "raw.githubusercontent.com"})


def _host_of(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "").lower()


def _allowed_hosts_from_config(config: dict) -> frozenset:
    hosts = set(_BASE_ALLOWED_HOSTS)
    entries = [config.get("canonical", {})] + list(config.get("mirrors", []))
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        api = entry.get("head_api")
        if isinstance(api, str) and urllib.parse.urlparse(api).scheme == "https":
            host = _host_of(api)
            if host:
                hosts.add(host)
    return frozenset(hosts)


def _check_url_allowed(url: str, allowed_hosts: frozenset) -> str | None:
    """Return None if url is safe to fetch, else a rejection reason."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        return f"cannot parse URL: {exc}"
    if parsed.scheme != "https":
        return f"scheme {parsed.scheme!r} not allowed (https only)"
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts:
        return f"host {host!r} not in allowlist {sorted(allowed_hosts)}"
    return None


def _fetch_json(url: str, timeout: int, allowed_hosts: frozenset) -> dict:
    reason = _check_url_allowed(url, allowed_hosts)
    if reason is not None:
        raise ValueError(f"refusing to fetch {url}: {reason}")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _get_head_sha(api_url: str, timeout: int, allowed_hosts: frozenset) -> str:
    """Fetch the HEAD commit SHA from a mirror's API endpoint."""
    data = _fetch_json(api_url, timeout, allowed_hosts)
    sha = data.get("sha")
    if not isinstance(sha, str) or len(sha) < 7:
        raise ValueError(f"unexpected response shape: {list(data.keys())}")
    return sha


def _load_mirrors() -> dict:
    try:
        return json.loads(MIRRORS_JSON.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: cannot read {MIRRORS_JSON}: {exc}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {MIRRORS_JSON}: {exc}", file=sys.stderr)
        sys.exit(2)


def _check_one(entry: dict, canonical_sha: str, timeout: int, allowed_hosts: frozenset) -> dict:
    name = entry.get("name", entry.get("github", "unknown"))
    api_url = entry.get("head_api", "")
    result: dict = {"name": name, "api_url": api_url}

    if not api_url:
        result.update({"status": "error", "detail": "no head_api configured"})
        return result

    try:
        mirror_sha = _get_head_sha(api_url, timeout, allowed_hosts)
    except urllib.error.URLError as exc:
        result.update({"status": "unreachable", "detail": str(exc)})
        return result
    except (ValueError, KeyError) as exc:
        result.update({"status": "error", "detail": str(exc)})
        return result

    result["mirror_sha"] = mirror_sha
    result["canonical_sha"] = canonical_sha

    if mirror_sha == canonical_sha:
        result["status"] = "in_sync"
    elif canonical_sha.startswith(mirror_sha) or mirror_sha.startswith(canonical_sha):
        # abbreviated SHA match
        result["status"] = "in_sync"
    else:
        result["status"] = "diverged"
        result["detail"] = f"mirror={mirror_sha[:12]} canonical={canonical_sha[:12]}"

    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check TRACE Registry mirrors are in sync with the canonical repo."
    )
    parser.add_argument("--mirror", default=None, metavar="NAME",
                        help="check only mirrors matching this substring (case-insensitive)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit machine-readable JSON report")
    parser.add_argument("--timeout", type=int, default=15, metavar="N",
                        help="HTTP timeout in seconds (default: 15)")
    args = parser.parse_args(argv)

    config = _load_mirrors()
    canonical = config.get("canonical", {})
    mirrors = config.get("mirrors", [])
    allowed_hosts = _allowed_hosts_from_config(config)

    if not mirrors:
        msg = "no mirrors registered in mirrors.json; nothing to check"
        if args.as_json:
            print(json.dumps({"status": "no_mirrors", "detail": msg}))
        else:
            print(msg)
        return 0

    if args.mirror:
        needle = args.mirror.lower()
        mirrors = [
            m for m in mirrors
            if needle in m.get("name", "").lower()
            or needle in m.get("github", "").lower()
        ]
        if not mirrors:
            print(f"error: no mirror matching {args.mirror!r}", file=sys.stderr)
            return 2

    # Fetch canonical HEAD first
    canonical_api = canonical.get("head_api", "")
    if not canonical_api:
        print("error: canonical.head_api not set in mirrors.json", file=sys.stderr)
        return 2

    try:
        canonical_sha = _get_head_sha(canonical_api, args.timeout, allowed_hosts)
    except (urllib.error.URLError, ValueError) as exc:
        msg = f"cannot reach canonical repo API: {exc}"
        if args.as_json:
            print(json.dumps({"status": "error", "detail": msg}))
        else:
            print(f"error: {msg}", file=sys.stderr)
        return 1

    results = [_check_one(m, canonical_sha, args.timeout, allowed_hosts) for m in mirrors]

    failures = [r for r in results if r["status"] != "in_sync"]

    if args.as_json:
        print(json.dumps({
            "canonical_sha": canonical_sha,
            "mirrors": results,
            "ok": len(failures) == 0,
        }, indent=2))
    else:
        for r in results:
            status = r["status"]
            name = r["name"]
            detail = r.get("detail", "")
            if status == "in_sync":
                print(f"OK    {name} (sha {r.get('mirror_sha', '')[:12]})")
            elif status == "unreachable":
                print(f"FAIL  {name} -- unreachable: {detail}", file=sys.stderr)
            elif status == "diverged":
                print(f"FAIL  {name} -- diverged: {detail}", file=sys.stderr)
            else:
                print(f"FAIL  {name} -- error: {detail}", file=sys.stderr)

        if failures:
            print(
                f"\n{len(failures)}/{len(results)} mirror(s) failed. "
                "A diverged mirror may indicate a history-rewrite attempt on the canonical repo "
                "or a stale/broken mirror.",
                file=sys.stderr,
            )
            return 1
        print(f"all {len(results)} mirror(s) in sync (canonical sha {canonical_sha[:12]})")

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
