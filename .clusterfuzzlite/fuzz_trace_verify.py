#!/usr/bin/python3
"""Fuzz what the trace-verify command reads: receipts, claims, proofs, entries.

A third party runs `trace-verify` on files it was sent. The command's
contract is its exit status: 0 verified, 1 not verified, 2 bad input, with an
error message rather than a traceback. An exception escaping main() breaks
that contract, and a 0 for anything but the genuine evidence is worse.

Three modes, chosen by the first byte. The rest is a JSON object:
  0. {"checkpoint": {...}, "response": {...}} verified by
     _witness.verify against the pinned registry and witness keys
     (seeded from docs/evidence/witness-2026-09-07). Optional
     "registry_key" / "witness_key" strings replace the pinned ones.
  1. {"claim": text, "proof": text, "entry": text, "batch_id": ...} run
     through `trace-verify --claim --proof --entry` (seeded from samples/
     and registry/2026/06/12.ndjson).
  2. {"entries": text} run through `trace-verify chain --json`.

Properties:
  * _witness.verify never raises, and verifies only the genuine checkpoint
    signing body under the genuine keys;
  * main() returns or exits with 0, 1 or 2, never a traceback;
  * an inclusion check exits 0 only for the genuine sample claim body, the
    one the pinned producer key signed.
"""
import contextlib
import hashlib
import io
import json
import sys
import tempfile
from pathlib import Path

import atheris

_ROOT = Path(__file__).resolve().parents[1]
if (_ROOT / "src" / "trace_verify").is_dir():
    sys.path.insert(0, str(_ROOT / "src"))

with atheris.instrument_imports():
    from trace_verify import _witness
    from trace_verify.__main__ import main as trace_verify_main
    from trace_verify._signature import canonical_body_bytes

# Public keys, pinned exactly as the CI smoke test pins them.
_REGISTRY_KEY = "bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90"
_WITNESS_KEY = "39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5"
_LOG_ID = "trace-registry/v1"
# sha256 signing-body digest of docs/evidence/witness-2026-09-07/checkpoint-1.json.
_GENUINE_CHECKPOINT_DIGEST = "41138372adb1921186ca6a0dbc3433a0ea2f6475cb863205603ab1231968f99a"
# sha256 of the RFC 8785 body of samples/example-trust-record.json, and the
# producers/cmcp-gateway-0.1.0.json key that signed it.
_GENUINE_CLAIM_BODY_SHA = "55fb96ef02a71245271dc125997bde5ece95b4ea0f2e685c43d3b6ef20a0d72c"
_PRODUCER = "cmcp-gateway/0.1.0"
_PRODUCER_X = "ToB3lvrNHGjbh8ZPnK0Ogh0zTxLNURCt1rjk5L_M18Q"

_WORK = Path(tempfile.mkdtemp(prefix="fuzz-trace-verify-"))
_PRODUCERS = _WORK / "producers"
_PRODUCERS.mkdir()
(_PRODUCERS / "cmcp-gateway-0.1.0.json").write_text(json.dumps({
    "producer_id": _PRODUCER,
    "key_type": "Ed25519",
    "public_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": _PRODUCER_X},
}), encoding="utf-8")


def _receipt(doc: dict) -> None:
    registry_key = doc.get("registry_key", _REGISTRY_KEY)
    witness_key = doc.get("witness_key", _WITNESS_KEY)
    result = _witness.verify(
        doc.get("checkpoint"), doc.get("response"),
        registry_key=registry_key, witness_key=witness_key, expected_log_id=_LOG_ID,
    )
    assert isinstance(result, dict) and isinstance(result.get("verified"), bool)
    if result["verified"]:
        assert registry_key == _REGISTRY_KEY and witness_key == _WITNESS_KEY, "verified under another key"
        digest = result["checkpoint_signing_digest"]
        assert digest == _GENUINE_CHECKPOINT_DIGEST, ("verified a checkpoint nobody signed", digest)
        assert result["entry_hash"] == hashlib.sha256(bytes.fromhex(digest)).hexdigest()


def _run(argv: list) -> int:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = trace_verify_main(argv)
        except SystemExit as exc:
            code = exc.code
    assert code in (0, 1, 2), (code, argv, err.getvalue()[-400:])
    return code


def _write(name: str, value) -> str:
    path = _WORK / name
    if isinstance(value, str):
        path.write_bytes(value.encode("utf-8", "surrogatepass"))
    else:
        path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


def _inclusion(doc: dict) -> None:
    argv = [
        "--claim", _write("claim.json", doc.get("claim", "")),
        "--proof", _write("proof.json", doc.get("proof", "")),
        "--entry", _write("entry.ndjson", doc.get("entry", "")),
        "--producers-dir", str(_PRODUCERS),
    ]
    batch_id = doc.get("batch_id")
    if isinstance(batch_id, str) and batch_id and not batch_id.startswith("-"):
        argv += ["--batch-id", batch_id]
    if doc.get("json") is True:
        argv.append("--json")
    if _run(argv) == 0:
        claim = json.loads((_WORK / "claim.json").read_bytes())
        body_sha = hashlib.sha256(canonical_body_bytes(claim)).hexdigest()
        assert body_sha == _GENUINE_CLAIM_BODY_SHA, "inclusion check passed for a claim nobody signed"


def _chain(doc: dict) -> None:
    _run(["chain", _write("chain.ndjson", doc.get("entries", "")), "--json"])


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, payload = data[0] % 3, data[1:]
    try:
        doc = json.loads(payload)
    except (ValueError, RecursionError):
        return
    if not isinstance(doc, dict):
        return
    if mode == 0:
        _receipt(doc)
    elif mode == 1:
        _inclusion(doc)
    else:
        _chain(doc)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
