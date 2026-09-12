"""CLI entry point for trace-verify.

Three questions, one command each:

    trace-verify --claim CLAIM.json --proof PROOF.json --entry ENTRY.ndjson
        Is this claim anchored in the registry, and did its producer sign it?

    trace-verify chain ENTRY.ndjson [MORE...]
        Does the registry checkpoint chain hold, and does it still match the
        entries stored under it?

    trace-verify receipt --checkpoint CP.json --response POST.json
        Does an external witness's COSE receipt verify offline against keys
        you pin? Needs the witness extra: pip install "trace-verify[witness]".

Other forms of the inclusion check:

    trace-verify --claim CLAIM.json --proof PROOF.json --entry-url URL
    trace-verify --claim CLAIM.json --proof PROOF.json --entry ENTRY.ndjson --producers-dir ./producers
    python -m trace_verify ...

The inclusion check takes no subcommand name, so every invocation written
against 0.3.x keeps working unchanged.

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


def _main_inclusion(argv: list[str] | None) -> int:
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
            claim,
            proof.get("leaf_index"),
            audit_path,
            entry.get("leaf_count"),
            merkle_root,
            canonicalization_id=canonicalization_id,
            raw_bytes=claim_raw,
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


def _read_entries(names: list[str]) -> list[dict]:
    """Load registry entries from one or more .ndjson files, in order."""
    entries: list[dict] = []
    for name in names:
        path = Path(name)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            _die(f"cannot read {path}: {exc}")
        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                _die(f"{path}:{lineno}: invalid JSON: {exc}")
            if not isinstance(entry, dict):
                _die(f"{path}:{lineno}: entry is not a JSON object")
            entries.append(entry)
    return entries


def _main_chain(argv: list[str]) -> int:
    """Verify the checkpoint chain, and the entries stored under it."""
    p = argparse.ArgumentParser(
        prog="trace-verify chain",
        description=(
            "Verify a TRACE registry checkpoint chain. Two independent checks "
            "run: that each checkpoint carries a genuine MMR consistency proof "
            "back to the one before it, and that rebuilding the MMR from the "
            "raw entries reproduces what each checkpoint claims. The second is "
            "the one that catches a quiet edit to an already-anchored entry."
        ),
    )
    p.add_argument("entries", nargs="+", metavar="ENTRY",
                   help="registry .ndjson file(s), in registry order")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="emit a machine-readable JSON result instead of plain text")
    args = p.parse_args(argv)

    from trace_verify._checkpoint import (
        CheckpointRecord,
        verify_chain_against_entries,
        verify_checkpoint_chain,
    )

    entries = _read_entries(args.entries)
    checkpointed = [e for e in entries if isinstance(e.get("mmr_checkpoint"), dict)]
    if not checkpointed:
        if args.as_json:
            print(json.dumps({"verified": True, "checkpoints": 0, "errors": []}))
        else:
            print("no entries with mmr_checkpoint found; nothing to verify")
        return 0

    checkpoints = [CheckpointRecord.from_dict(e["mmr_checkpoint"]) for e in checkpointed]
    _, chain_errors = verify_checkpoint_chain(checkpoints)
    errors = chain_errors + verify_chain_against_entries(entries)

    if args.as_json:
        result: dict = {
            "verified": not errors,
            "checkpoints": len(checkpointed),
            "errors": errors,
        }
        if not errors:
            result["mmr_size"] = checkpoints[-1].mmr_size
            result["root"] = checkpoints[-1].root
        print(json.dumps(result))
        return 0 if not errors else 1

    if errors:
        for err in errors:
            print(f"FAIL: {err}", file=sys.stderr)
        print(
            f"FAIL: {len(errors)} problem(s) found across "
            f"{len(checkpointed)} checkpoint(s)"
        )
        return 1
    print(
        f"OK: {len(checkpointed)} checkpoint(s) verified, chain-consistent and "
        f"matching the raw entries (mmr_size {checkpoints[-1].mmr_size}, "
        f"root {checkpoints[-1].root})"
    )
    return 0


def _main_receipt(argv: list[str]) -> int:
    """Verify an external witness's COSE receipt offline against pinned keys."""
    p = argparse.ArgumentParser(
        prog="trace-verify receipt",
        description=(
            "Verify a TRACE checkpoint receipt from an external witness, "
            "offline, against keys you supply. Both keys are required "
            "arguments and neither is ever fetched: a receipt verified under a "
            "key the receipt itself named would prove nothing about who signed "
            "it."
        ),
    )
    p.add_argument("--checkpoint", required=True, metavar="FILE",
                   help="the signed checkpoint JSON that was submitted")
    p.add_argument("--response", required=True, metavar="FILE",
                   help="the witness response JSON carrying receipt_b64")
    p.add_argument("--registry-key", required=True, metavar="HEX",
                   help="independently accepted raw Ed25519 registry key, hex")
    p.add_argument("--witness-key", required=True, metavar="HEX",
                   help="independently accepted raw Ed25519 witness key, hex")
    p.add_argument("--expected-log-id", required=True, metavar="ID",
                   help="the log id the checkpoint must name, e.g. trace-registry/v1")
    args = p.parse_args(argv)

    try:
        import cbor2  # noqa: F401
        import scitt_cose  # noqa: F401
    except ImportError as exc:
        _die(
            f"the witness extra is not installed ({exc}). "
            'Install it with: pip install "trace-verify[witness]"'
        )

    from trace_verify import _witness

    try:
        result = _witness.verify(
            _witness.load_json(args.checkpoint),
            _witness.load_json(args.response),
            registry_key=args.registry_key,
            witness_key=args.witness_key,
            expected_log_id=args.expected_log_id,
        )
    except Exception as exc:  # noqa: BLE001 - reported to the caller, not swallowed
        result = {"verified": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result, indent=2))
    return 0 if result["verified"] else 1


_SUBCOMMANDS = {"chain": _main_chain, "receipt": _main_receipt}


def main(argv: list[str] | None = None) -> int:
    """Dispatch to a subcommand, or run the inclusion check.

    An unrecognised first token is not an error here. It falls through to the
    inclusion parser, which is what keeps every 0.3.x invocation working and
    what reports the argument error in the vocabulary the caller used.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in _SUBCOMMANDS:
        return _SUBCOMMANDS[argv[0]](argv[1:])
    return _main_inclusion(argv)


if __name__ == "__main__":
    sys.exit(main())
