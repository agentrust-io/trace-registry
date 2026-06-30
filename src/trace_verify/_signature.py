"""Ed25519 signature verification for TRACE Trust Records.

Signing scheme (docs/anchor-format.md): the producer signs the canonical
JSON bytes of the claim body -- all fields except 'signature' -- using
Ed25519. The result is base64url-encoded without padding and stored in the
top-level 'signature' field of the Trust Record.

Requires the 'cryptography' package:
    pip install "trace-verify[signature]"
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

# Producer ids look like name/semver (see schema/producer-key.schema.json and
# schema/registry-entry.schema.json). This is the same pattern both schemas
# enforce; we re-validate here so a hostile producer id can never escape the
# producers/ directory when it is turned into a key filename.
_PRODUCER_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*/[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._+\-]*$"
)


def is_valid_producer_id(producer_id: object) -> bool:
    """Return True iff producer_id matches the name/semver producer-id schema.

    Rejects anything containing path separators (other than the single
    name/version separator the pattern allows) or '..' traversal sequences.
    """
    if not isinstance(producer_id, str):
        return False
    if ".." in producer_id or "\\" in producer_id:
        return False
    return bool(_PRODUCER_ID_RE.match(producer_id))


def _require_cryptography():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey, InvalidSignature
    except ImportError:
        raise ImportError(
            "Signature verification requires the 'cryptography' package. "
            "Install it with: pip install \"trace-verify[signature]\""
        )


def canonical_body_bytes(claim: dict) -> bytes:
    """Canonical JSON bytes of the claim body (all fields except 'signature')."""
    body = {k: v for k, v in claim.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def verify_claim_signature(claim: dict, public_key_jwk: dict) -> bool:
    """Return True iff the claim's Ed25519 signature is valid.

    public_key_jwk must be an OKP/Ed25519 JWK with an 'x' field containing
    the base64url-encoded 32-byte public key.

    Raises ValueError on malformed inputs. Raises ImportError if the
    'cryptography' package is not installed.
    """
    Ed25519PublicKey, InvalidSignature = _require_cryptography()

    sig_b64 = claim.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        raise ValueError("claim has no 'signature' field")

    try:
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception as exc:
        raise ValueError(f"cannot decode signature: {exc}")

    x_b64 = public_key_jwk.get("x")
    if not isinstance(x_b64, str) or not x_b64:
        raise ValueError("public_key_jwk has no 'x' coordinate")

    try:
        pub_bytes = base64.urlsafe_b64decode(x_b64 + "==")
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as exc:
        raise ValueError(f"cannot load public key: {exc}")

    try:
        pub.verify(sig, canonical_body_bytes(claim))
        return True
    except InvalidSignature:
        return False


def load_producer_key(producer_id: str, producers_dir: Path) -> dict | None:
    """Load the producer key file for producer_id from producers_dir.

    Returns the parsed JSON object, or None if the file does not exist or the
    producer_id is not a valid name/semver id (which prevents path traversal
    out of producers_dir).
    The expected filename is producer_id with '/' replaced by '-' plus '.json'.
    """
    if not is_valid_producer_id(producer_id):
        return None
    filename = producer_id.replace("/", "-") + ".json"
    key_file = producers_dir / filename
    if not key_file.exists():
        return None
    try:
        return json.loads(key_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def verify_claim_against_registry(
    claim: dict, producer_id: str, producers_dir: Path
) -> tuple[bool, str]:
    """Fail-closed check used by the anchoring paths.

    Looks up the active registered key for producer_id and verifies the claim's
    signature against it. Returns (ok, reason). ok is True only when an active
    key exists AND the signature verifies. reason describes the rejection when
    ok is False.

    A claim is rejected if:
      - producer_id is malformed or has no registered key file;
      - the key file is malformed or missing a public_key_jwk;
      - the claim carries no signature, or the signature does not verify.
    """
    if not is_valid_producer_id(producer_id):
        return False, f"invalid producer id {producer_id!r}"

    key_entry = load_producer_key(producer_id, producers_dir)
    if key_entry is None:
        return False, f"no registered key for producer {producer_id!r}"

    jwk = key_entry.get("public_key_jwk")
    if not isinstance(jwk, dict):
        return False, f"key file for {producer_id!r} has no public_key_jwk"

    try:
        ok = verify_claim_signature(claim, jwk)
    except (ImportError, ValueError) as exc:
        return False, f"signature check failed for {producer_id!r}: {exc}"

    if not ok:
        return False, f"signature does not verify for producer {producer_id!r}"
    return True, "ok"
