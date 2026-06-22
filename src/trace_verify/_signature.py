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
from pathlib import Path


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

    Returns the parsed JSON object, or None if the file does not exist.
    The expected filename is producer_id with '/' replaced by '-' plus '.json'.
    """
    filename = producer_id.replace("/", "-") + ".json"
    key_file = producers_dir / filename
    if not key_file.exists():
        return None
    try:
        return json.loads(key_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
