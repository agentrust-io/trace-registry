"""CLI entry point for trace-verify.

Usage:
    trace-verify --claim CLAIM.json --proof PROOF.json --entry ENTRY.ndjson
    trace-verify --claim CLAIM.json --proof PROOF.json --entry-url URL
    python -m trace_verify ...

Exit code 0: claim is proven included.
Exit code 1: proof does not verify.
Exit code 2: bad arguments or unreadable files.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from trace_verify import __version__
from trace_verify._verify import decode_hash, verify_inclusion


def _load_json_file(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        _die(f"cannot read {path}: {exc}")
    except json.JSONDecodeError as exc:
        _die(f"invalid JSON in {path}: {exc}")


def _fetch_url(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310
            return resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        _die(f"cannot fetch {url}: {exc}")


def _load_entry(source: str, batch_id: str | None) -> dict:
    """Load a registry entry from a local file path or a URL."""
    if source.startswith("https://") or source.startswith("http://"):
        raw = _fetch_url(source)
    else:
        path = Path(source)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            _die(f"cannot read {source}: {exc}")

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    entries = []
    for ln in lines:
        try:
            entries.append(json.loads(ln))
        except json.JSONDecodeError as exc:
            _die(f"invalid JSON line in entry source: {exc}")

    if batch_id is not None:
        entries = [e for e in entries if isinstance(e, dict) and e.get("batch_id") == batch_id]
        if not entries:
            _die(f"no entry with batch_id {batch_id!r} in {source}")

    if len(entries) != 1:
        _die(
            f"{source} contains {len(entries)} entries; "
            "use --batch-id to select one"
        )
    if not isinstance(entries[0], dict):
        _die(f"entry in {source} is not a JSON object")
    return entries[0]


def _die(msg: str, code: int = 2) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _output(ok: bool, entry: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps({
            "verified": ok,
            "batch_id": entry.get("batch_id"),
            "merkle_root": entry.get("merkle_root"),
            "ts": entry.get("ts"),
        }))
    elif ok:
        print(
            f"OK: claim is included in batch {entry.get('batch_id')!r} "
            f"(root {entry.get('merkle_root')}, ts {entry.get('ts')})"
        )
    else:
        print(
            "FAIL: inclusion proof does not verify against the registry entry",
            file=sys.stderr,
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trace-verify",
        description=(
            "Verify a TRACE claim inclusion proof against a registry entry. "
            "Exit code 0 means the signed claim was provably anchored in the "
            "registry at the entry timestamp."
        ),
    )
    p.add_argument("--version", action="version", version=f"trace-verify {__version__}")
    p.add_argument("--claim", required=True, metavar="FILE",
                   help="signed claim JSON file")
    p.add_argument("--proof", required=True, metavar="FILE",
                   help='inclusion proof file: {"leaf_index": int, "audit_path": [...]}')

    entry_group = p.add_mutually_exclusive_group(required=True)
    entry_group.add_argument("--entry", metavar="FILE",
                             help="registry entry file (single JSON object or .ndjson day file)")
    entry_group.add_argument("--entry-url", metavar="URL",
                             help="fetch the registry entry from this URL (e.g. a raw GitHub URL)")

    p.add_argument("--batch-id", default=None, metavar="ID",
                   help="select the entry with this batch_id from a multi-line day file")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="emit a machine-readable JSON result instead of plain text")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    claim = _load_json_file(Path(args.claim))
    proof = _load_json_file(Path(args.proof))

    entry_source = args.entry_url if args.entry_url else args.entry
    entry = _load_entry(entry_source, args.batch_id)

    try:
        if not isinstance(claim, dict):
            raise ValueError("claim is not a JSON object")
        if not isinstance(proof, dict):
            raise ValueError("proof is not a JSON object")
        raw_path = proof.get("audit_path")
        if not isinstance(raw_path, list):
            raise ValueError("proof.audit_path must be a list")
        audit_path = [decode_hash(h) for h in raw_path]
        merkle_root = decode_hash(entry.get("merkle_root"))
        ok = verify_inclusion(
            claim,
            proof.get("leaf_index"),
            audit_path,
            entry.get("leaf_count"),
            merkle_root,
        )
    except ValueError as exc:
        if args.as_json:
            print(json.dumps({"verified": False, "error": str(exc)}))
        else:
            print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    _output(ok, entry, args.as_json)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
