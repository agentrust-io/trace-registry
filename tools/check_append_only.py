#!/usr/bin/env python3
"""Check that registry/*.ndjson files are append-only relative to a base commit.

Existing lines must not be modified or deleted. New lines may only be added
to the end of the file. New files are always permitted.

Usage:
    python tools/check_append_only.py BASE_SHA

Exit status: 0 if all changes are append-only, 1 otherwise.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: check_append_only.py BASE_SHA", file=sys.stderr)
        return 2

    base_sha = argv[0]

    # Verify the base SHA resolves (guard against empty string or bad ref).
    check = git("rev-parse", "--verify", base_sha)
    if check.returncode != 0:
        print(f"cannot resolve base SHA {base_sha!r} -- skipping append-only check")
        return 0

    # List .ndjson files that differ between base and HEAD.
    diff = git("diff", "--name-only", base_sha, "HEAD", "--", "registry/")
    changed = [f for f in diff.stdout.splitlines() if f.endswith(".ndjson")]

    if not changed:
        print("no registry/*.ndjson files changed -- append-only OK")
        return 0

    failures = 0
    for rel_path in changed:
        old_result = git("show", f"{base_sha}:{rel_path}")
        if old_result.returncode != 0:
            # File did not exist at base: every line is an addition.
            print(f"{rel_path}: new file, OK")
            continue

        old_lines = old_result.stdout.splitlines()
        new_path = REPO_ROOT / rel_path

        if not new_path.exists():
            print(f"ERROR: {rel_path}: file deleted -- registry is append-only")
            failures += 1
            continue

        new_lines = new_path.read_text(encoding="utf-8").splitlines()

        if len(new_lines) < len(old_lines):
            print(
                f"ERROR: {rel_path}: {len(old_lines) - len(new_lines)} line(s) removed"
                f" ({len(old_lines)} -> {len(new_lines)})"
            )
            failures += 1
            continue

        # Every old line must appear unchanged at the same position.
        for i, (old_line, new_line) in enumerate(zip(old_lines, new_lines), start=1):
            if old_line != new_line:
                print(f"ERROR: {rel_path}:{i}: existing line was modified")
                print(f"  was: {old_line!r}")
                print(f"  now: {new_line!r}")
                failures += 1
                break
        else:
            added = len(new_lines) - len(old_lines)
            print(f"{rel_path}: OK (+{added} line(s))")

    if failures:
        print(f"\nFAIL: {failures} file(s) violated the append-only constraint")
        return 1

    print("OK: all registry changes are append-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
