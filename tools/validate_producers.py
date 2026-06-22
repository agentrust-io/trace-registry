#!/usr/bin/env python3
"""Validate all producer key files in producers/ against the schema.

Used by CI. Requires the `jsonschema` package.

Usage:
    python tools/validate_producers.py [PRODUCERS_DIR]

Exit status: 0 if all files are valid (or no files exist), 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schema" / "producer-key.schema.json"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    producers_dir = Path(argv[0]) if argv else REPO_ROOT / "producers"

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    key_files = sorted(producers_dir.glob("*.json"))
    if not key_files:
        print(f"no .json files under {producers_dir}; nothing to validate")
        return 0

    failures = 0
    for key_file in key_files:
        rel = key_file.relative_to(REPO_ROOT) if key_file.is_relative_to(REPO_ROOT) else key_file
        try:
            entry = json.loads(key_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"{rel}: invalid JSON: {exc}")
            failures += 1
            continue

        errors = sorted(validator.iter_errors(entry), key=str)
        for error in errors:
            print(f"{rel}: schema violation: {error.message}")
        failures += len(errors)

        # Filename must match producer_id with / replaced by -
        producer_id = entry.get("producer_id", "")
        expected_name = producer_id.replace("/", "-") + ".json"
        if key_file.name != expected_name:
            print(
                f"{rel}: filename mismatch: expected {expected_name!r} "
                f"for producer_id {producer_id!r}"
            )
            failures += 1

        if not failures:
            print(f"validated {rel}")

    if failures:
        print(f"FAIL: {failures} problem(s) found")
        return 1
    print(f"OK: {len(key_files)} producer key file(s) valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
