"""Offline verifier for TRACE JSON checkpoints and stage-1 COSE receipts.

This deliberately does not import the witness service. The receipt math and
COSE verification come from the separately published scitt-cose package.
No network I/O, key discovery, timestamp certification, or continuity claim.

cbor2 and scitt-cose are imported inside verify() rather than at module scope,
so `import trace_verify` keeps working for a reader who only wants inclusion or
chain verification and has not installed the witness extra. Nothing above that
call needs either library.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

__all__ = ['FIELDS', 'load_json', 'read_protected', 'signing_body',
           'signing_body_digest', 'verify']

FIELDS = ('v', 'kind', 'log_id', 'mmr_size', 'root', 'prev_size',
          'prev_root', 'key_id', 'timestamp')


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)



# COSE protected-header labels this adapter accepts. alg and vds are the
# stage-1 profile. 15 is the CWT Claims map (RFC 9597 s2), carrying 6, iat
# (RFC 8392 s3.1.6), the witness clock at registration. -65537 is private
# use: a witness may put its grade there, and a private-use label has no
# registered meaning, so it is read as an opaque string and only counts
# once it agrees with the grade the response reports. Anything else is
# refused rather than ignored: unreviewed signed metadata is not neutral.
# Duplicate labels collapse in the CBOR decoder rather than raising; that is
# tolerable here only because these bytes are inside the witness signature.
CWT_CLAIMS = 15
CWT_IAT = 6
PRIVATE_GRADE = -65537
ALLOWED_PROTECTED = {1, 395, CWT_CLAIMS, PRIVATE_GRADE}
# -65537 is provisional and sits in the private-use range by bilateral
# agreement with the witness operator, not by registration. A third
# implementer must not read it as standard: if a registered label is ever
# assigned for a grade, this value moves and the change is coordinated.
#
# RFC 9597's CWT claims map is general, so the claims this adapter accepts
# are a profile rather than a property of the format. Refusing an unreviewed
# claim is the rule the protected header already follows one layer out, and
# it means a witness adding iss, sub or any other registered claim is a
# coordinated change rather than an outage. LIMITATIONS.md states the set so
# both sides can cite it.
ACCEPTED_CWT_CLAIMS = {CWT_IAT}
# A witness cannot register a checkpoint before that checkpoint existed, so
# the checkpoint's own timestamp is a real lower bound on a signed iat rather
# than a heuristic. The upper bound is only a sanity check against a clock
# that is implausible on its face; the lower bound is the load-bearing one.
MAX_REGISTRATION_DELAY_SECONDS = 30 * 86400


def read_protected(protected, decode, *, checkpoint_epoch):
    """Return (iat, grade) from the protected header, refusing anything else."""
    if not isinstance(protected, (bytes, bytearray)) or not protected:
        raise ValueError('receipt protected header must be a non-empty bstr')
    headers = decode(protected)
    if not isinstance(headers, dict):
        raise ValueError('receipt protected header must decode to a map')
    if headers.get(1) != -8 or headers.get(395) != 1:
        raise ValueError('unsupported receipt algorithm or verifiable data structure')
    unknown = set(headers) - ALLOWED_PROTECTED
    if unknown:
        raise ValueError('unreviewed signed receipt headers: ' + ', '.join(map(str, sorted(unknown, key=str))))
    iat = None
    if CWT_CLAIMS in headers:
        claims = headers[CWT_CLAIMS]
        if not isinstance(claims, dict):
            raise ValueError('CWT claims header must decode to a map')
        if CWT_IAT not in claims:
            raise ValueError('CWT claims map must carry iat')
        unreviewed = set(claims) - ACCEPTED_CWT_CLAIMS
        if unreviewed:
            raise ValueError('unreviewed CWT claims: ' + ', '.join(map(str, sorted(unreviewed, key=str)))
                             + '; the accepted set is exactly {iat} by agreement, see LIMITATIONS.md')
        iat = claims[CWT_IAT]
        if type(iat) is not int or iat <= 0:
            raise ValueError('CWT iat must be a positive integer')
        if iat < checkpoint_epoch:
            raise ValueError('CWT iat precedes the checkpoint it registers')
        if iat > checkpoint_epoch + MAX_REGISTRATION_DELAY_SECONDS:
            raise ValueError('CWT iat is implausibly long after the checkpoint it registers')
    grade = None
    if PRIVATE_GRADE in headers:
        grade = headers[PRIVATE_GRADE]
        if not isinstance(grade, str) or not grade:
            raise ValueError('private-use grade label must be a non-empty text string')
    return iat, grade

def signing_body(checkpoint):
    """Return the nine-field signing body the registry signature covers."""
    return {key: checkpoint[key] for key in FIELDS}


def signing_body_digest(body):
    """SHA-256 over sorted-key compact JSON of the signing body."""
    encoded = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(encoded.encode()).digest()


def verify(checkpoint, response, *, registry_key, witness_key, expected_log_id):
    import cbor2
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from scitt_cose.receipt import verify_receipt
    from scitt_cose.cose_sign1 import strict_decode

    result = {'verified': False, 'checks': {}, 'limits': {
        'witness_time_established': False,
        'grade_cryptographically_bound': False,
        'registry_continuity_established': False,
        'full_checkpoint_envelope_witnessed': False,
    }}
    checks = result['checks']
    try:
        if not isinstance(checkpoint, dict) or not isinstance(response, dict):
            raise ValueError('checkpoint and response must be objects')
        body = signing_body(checkpoint)
        if body['v'] != 1 or type(body['v']) is not int or body['kind'] != 'mmr_checkpoint':
            raise ValueError('unsupported checkpoint version/kind')
        for key in ('mmr_size', 'prev_size'):
            if type(body[key]) is not int:
                raise ValueError(key + ' must be an integer')
        if not 0 <= body['prev_size'] < body['mmr_size']:
            raise ValueError('invalid checkpoint sizes')
        for key in ('root', 'prev_root'):
            value = body[key]
            if key == 'prev_root' and body['prev_size'] == 0 and value == '':
                continue
            if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError('invalid lowercase hex ' + key)
        if not isinstance(body['timestamp'], str):
            raise ValueError('checkpoint timestamp must have a timezone')
        checkpoint_time = datetime.fromisoformat(body['timestamp'].replace('Z', '+00:00'))
        if checkpoint_time.tzinfo is None:
            raise ValueError('checkpoint timestamp must have a timezone')
        checkpoint_epoch = int(checkpoint_time.timestamp())
        checks['checkpoint_structure'] = True
        if body['log_id'] != expected_log_id or body['key_id'] != registry_key:
            raise ValueError('checkpoint does not match supplied registry identity policy')
        checks['registry_identity'] = True
        digest = signing_body_digest(body)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(registry_key)).verify(
            bytes.fromhex(checkpoint['signature']), digest.hex().encode('ascii'))
        checks['checkpoint_signature'] = True
        # The JSON route registers the 32-byte signing-body digest as an
        # opaque statement. Its legacy entry_hash is SHA256(those 32 bytes).
        entry_hash = hashlib.sha256(digest).hexdigest()
        if response['entry_hash_scheme'] != 'legacy' or response['entry_hash'] != entry_hash:
            raise ValueError('receipt response is not bound to this checkpoint signing body')
        checks['checkpoint_receipt_binding'] = True
        receipt = base64.b64decode(response['receipt_b64'], validate=True)
        # Restrict this adapter to the observed, reviewed stage-1 profile.
        # New algorithms, signed metadata or proof structures need review.
        decoded = strict_decode(receipt)
        envelope = decoded.value if hasattr(decoded, 'tag') and decoded.tag == 18 else None
        if envelope is None or len(envelope) != 4:
            raise ValueError('receipt must be tagged COSE_Sign1')
        protected, unprotected, payload, signature = envelope
        if payload is not None:
            raise ValueError('unsupported receipt protected headers or attached payload')
        signed_iat, signed_grade = read_protected(protected, cbor2.loads, checkpoint_epoch=checkpoint_epoch)
        if set(unprotected) != {396} or set(unprotected[396]) != {-1} or len(unprotected[396][-1]) != 1:
            raise ValueError('expected exactly one inclusion proof')
        checks['receipt_profile'] = True
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(witness_key))
        verified = verify_receipt(receipt, leaf_entry_hex=entry_hash,
                                  log_public_key_pem=pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        if not verified.ok:
            raise ValueError('receipt signature/inclusion failed: ' + '; '.join(map(str, verified.errors)))
        checks['receipt_signature_and_inclusion'] = True
        for key in ('leaf_index', 'tree_size'):
            if type(response[key]) is not int or response[key] != getattr(verified, key):
                raise ValueError('response ' + key + ' disagrees with verified proof')
        checks['response_coordinates'] = True
        result.update(verified=True, checkpoint_signing_digest=digest.hex(), entry_hash=entry_hash,
                      root=verified.root, leaf_index=verified.leaf_index, tree_size=verified.tree_size,
                      reported_grade=response.get('grade'), signed_iat=signed_iat,
                      signed_grade=signed_grade, witness_key=witness_key)
        # A signed iat is a witness clock inside the covered bytes. A signed
        # grade counts only when it is the grade the response reports: a
        # private-use label agreeing with untrusted metadata is what binds it.
        result['limits']['witness_time_established'] = signed_iat is not None
        result['limits']['grade_cryptographically_bound'] = (
            signed_grade is not None and signed_grade == response.get('grade'))
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    return result


