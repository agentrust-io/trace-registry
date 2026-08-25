"""CLI entry point for trace-verify.

Usage:
    trace-verify --claim CLAIM.json --proof PROOF.json --entry ENTRY.ndjson
    trace-verify --claim CLAIM.json --proof PROOF.json --entry-url URL
    trace-verify --claim CLAIM.json --proof PROOF.json --entry ENTRY.ndjson --producers-dir ./producers
    python -m trace_verify ...

By default the claim's Ed25519 signature is verified against the producer key
registry: exit code 0 means BOTH Merkle inclusion and the producer signature
verified. Pass --no-verify-signature to skip signature verification and check
inclusion only (prints a warning; inclusion alone does not prove the named
producer signed the claim).

Exit code 0: claim is proven included AND (unless --no-verify-signature) signed.
Exit code 1: inclusion proof or signature does not verify, or the producer key
             is missing / unloadable so the signature cannot be verified.
Exit code 2: bad arguments or unreadable files.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from trace_verify import __version__
from trace_verify._verify import VINTAGE_CANONICALIZATION, decode_hash, verify_inclusion

# SSRF guard: only fetch registry entries over https from known registry hosts.
# This blocks file://, http://, and internal/metadata targets such as
# 169.254.169.254.
_ALLOWED_HOSTS = frozenset({"api.github.com", "raw.githubusercontent.com"})


def _check_url_allowed(url: str) -> str | None:
    """Return None if url is safe to fetch, else a rejection reason."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        return f"cannot parse URL: {exc}"
    if parsed.scheme != "https":
        return f"scheme {parsed.scheme!r} not allowed (https only)"
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        return f"host {host!r} not in allowlist {sorted(_ALLOWED_HOSTS)}"
    return None


def _load_json_file(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        _die(f"cannot read {path}: {exc}")
    except json.JSONDecodeError as exc:
        _die(f"invalid JSON in {path}: {exc}")


def _fetch_url(url: str) -> str:
    reason = _check_url_allowed(url)
    if reason is not None:
        _die(f"refusing to fetch {url}: {reason}")
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


def _output(
    ok: bool, entry: dict, sig_result: bool | None, as_json: bool,
    canonicalization_id: str,
) -> None:
    if as_json:
        result: dict = {
            "verified": ok,
            "batch_id": entry.get("batch_id"),
            "merkle_root": entry.get("merkle_root"),
            "ts": entry.get("ts"),
            "canonicalization_id": canonicalization_id,
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
            f"(root {entry.get('merkle_root')}, ts {entry.get('ts')}, "
            f"canonicalization_id {canonicalization_id!r}){sig_note}"
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

    p.add_argument("--no-verify-signature", action="store_true",
                   help=(
                       "DANGEROUS: skip verifying the claim's Ed25519 signature and "
                       "report success on Merkle inclusion alone. Inclusion proves the "
                       "claim was anchored, NOT that the named producer signed it."
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

    claim_path = Path(args.claim)
    try:
        claim_raw = claim_path.read_bytes()
        claim = json.loads(claim_raw)
    except OSError as exc:
        _die(f"cannot read {claim_path}: {exc}")
    except json.JSONDecodeError as exc:
        _die(f"invalid JSON in {claim_path}: {exc}")
    proof = _load_json_file(Path(args.proof))

    entry_source = args.entry_url if args.entry_url else args.entry
    entry = _load_entry(entry_source, args.batch_id)

    sig_result: bool | None = None
    canonicalization_id = entry.get("canonicalization_id", VINTAGE_CANONICALIZATION)

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
            claim_raw,
            claim,
            canonicalization_id,
            proof.get("leaf_index"),
            audit_path,
            entry.get("leaf_count"),
            merkle_root,
        )
    except ValueError as exc:
        if args.as_json:
            print(json.dumps({"verified": False, "error": f"{type(exc).__name__}: {exc}"}))
        else:
            print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.no_verify_signature:
        # Loud warning: inclusion alone does not prove producer authenticity.
        print(
            "WARNING: --no-verify-signature is set. This checks Merkle inclusion "
            "ONLY and does NOT verify that the named producer signed this claim. "
            "Anyone who can get a claim anchored can forge the producer identity.",
            file=sys.stderr,
        )
    else:
        from trace_verify._signature import (
            is_valid_producer_id,
            verify_claim_against_registry,
        )

        producers_dir = Path(args.producers_dir) if args.producers_dir else Path("producers")
        # Resolve the producer identity: prefer the claim's own 'producer'
        # field, falling back to the producer named in the anchored registry
        # entry (claim bodies are not required to carry a top-level producer).
        producer_id = None
        if isinstance(claim, dict):
            producer_id = claim.get("producer")
        if not producer_id:
            producer_id = entry.get("producer")
        if not producer_id:
            _die(
                "cannot determine producer for signature verification; "
                "no 'producer' field in claim or registry entry "
                "(pass --no-verify-signature to skip, at your own risk)",
                code=1,
            )
        if not is_valid_producer_id(producer_id):
            _die(f"invalid producer id {producer_id!r}", code=1)

        claim_producer = claim.get("producer")
        entry_producer = entry.get("producer")
        if claim_producer and entry_producer and claim_producer != entry_producer:
            _die(
                "claim producer does not match the producer named by the registry entry",
                code=1,
            )

        sig_result, reason = verify_claim_against_registry(
            claim, producer_id, producers_dir
        )
        if not sig_result:
            if args.as_json:
                print(
                    json.dumps(
                        {
                            "verified": False,
                            "signature_valid": False,
                            "error": reason,
                        }
                    )
                )
            else:
                _die(reason, code=1)
            ok = False

    _output(ok, entry, sig_result, args.as_json, canonicalization_id)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
