#!/usr/bin/env python3
"""Validate every line of every registry/**/*.ndjson file against the entry schema.

Used by CI. Requires the `jsonschema` package (the reference anchor/verify
tools themselves are stdlib-only; this validator is a CI convenience).

Usage:
    python tools/validate_registry.py [REGISTRY_DIR]

Exit status: 0 if all lines validate (or no day files exist yet), 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schema" / "registry-entry.schema.json"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    registry_dir = Path(argv[0]) if argv else REPO_ROOT / "registry"

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    day_files = sorted(registry_dir.glob("**/*.ndjson"))
    if not day_files:
        print(f"no .ndjson files under {registry_dir}; nothing to validate")
        return 0

    failures = 0
    for day_file in day_files:
        rel = day_file.relative_to(REPO_ROOT) if day_file.is_relative_to(REPO_ROOT) else day_file
        for lineno, line in enumerate(
            day_file.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                print(f"{rel}:{lineno}: blank line not allowed in ndjson")
                failures += 1
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"{rel}:{lineno}: invalid JSON: {exc}")
                failures += 1
                continue
            errors = sorted(validator.iter_errors(entry), key=str)
            for error in errors:
                print(f"{rel}:{lineno}: schema violation: {error.message}")
            failures += len(errors)
        print(f"validated {rel}")

    if failures:
        print(f"FAIL: {failures} problem(s) found")
        return 1
    print(f"OK: {len(day_files)} day file(s) valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
