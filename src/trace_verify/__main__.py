"""CLI entry point for trace-verify.

Usage:
    trace-verify --claim CLAIM.json --proof PROOF.json --entry ENTRY.ndjson
    trace-verify --claim CLAIM.json --proof PROOF.json --entry-url URL
    trace-verify --claim CLAIM.json --proof PROOF.json --entry ENTRY.ndjson --verify-signature --producers-dir ./producers
    python -m trace_verify ...

Exit code 0: claim is proven included (and signature valid, if --verify-signature).
Exit code 1: proof does not verify or signature is invalid.
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


def _output(ok: bool, entry: dict, sig_result: bool | None, as_json: bool) -> None:
    if as_json:
        result: dict = {
            "verified": ok,
            "batch_id": entry.get("batch_id"),
            "merkle_root": entry.get("merkle_root"),
            "ts": entry.get("ts"),
        }
        if sig_result is not None:
            result["signature_valid"] = sig_result
        print(json.dumps(result))
    elif ok:
        sig_note = ""
        if sig_result is True:
            sig_note = ", signature valid"
        elif sig_result is False:
            sig_note = ", signature INVALID"
        print(
            f"OK: claim is included in batch {entry.get('batch_id')!r} "
            f"(root {entry.get('merkle_root')}, ts {entry.get('ts')}){sig_note}"
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

    p.add_argument("--verify-signature", action="store_true",
                   help=(
                       "also verify the claim's Ed25519 signature against the producer key "
                       "registry (requires 'cryptography' package; see --producers-dir)"
                   ))
    p.add_argument("--producers-dir", default=None, metavar="DIR",
                   help=(
                       "directory containing producer key .json files "
                       "(default: producers/ relative to the current directory)"
                   ))
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    claim = _load_json_file(Path(args.claim))
    proof = _load_json_file(Path(args.proof))

    entry_source = args.entry_url if args.entry_url else args.entry
    entry = _load_entry(entry_source, args.batch_id)

    sig_result: bool | None = None

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

    if args.verify_signature:
        from trace_verify._signature import load_producer_key, verify_claim_signature

        producers_dir = Path(args.producers_dir) if args.producers_dir else Path("producers")
        producer_id = claim.get("producer") if isinstance(claim, dict) else None
        if not producer_id:
            _die("claim has no 'producer' field; cannot look up signing key")

        key_entry = load_producer_key(producer_id, producers_dir)
        if key_entry is None:
            _die(
                f"no key file found for producer {producer_id!r} in {producers_dir}; "
                "register the producer first"
            )

        try:
            sig_result = verify_claim_signature(claim, key_entry["public_key_jwk"])
        except (ImportError, ValueError) as exc:
            if args.as_json:
                print(json.dumps({"verified": False, "signature_valid": False, "error": str(exc)}))
            else:
                print(f"error: {exc}", file=sys.stderr)
            return 2

        if not sig_result:
            ok = False

    _output(ok, entry, sig_result, args.as_json)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
