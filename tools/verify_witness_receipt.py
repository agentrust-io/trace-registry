#!/usr/bin/env python3
"""Offline verifier for TRACE JSON checkpoints and stage-1 COSE receipts.

This deliberately does not import the witness service. The receipt math and
COSE verification come from the separately published scitt-cose package.
No network I/O, key discovery, timestamp certification, or continuity claim.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

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
        body = {key: checkpoint[key] for key in FIELDS}
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
        if not isinstance(body['timestamp'], str) or datetime.fromisoformat(body['timestamp'].replace('Z', '+00:00')).tzinfo is None:
            raise ValueError('checkpoint timestamp must have a timezone')
        checks['checkpoint_structure'] = True
        if body['log_id'] != expected_log_id or body['key_id'] != registry_key:
            raise ValueError('checkpoint does not match supplied registry identity policy')
        checks['registry_identity'] = True
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).digest()
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
        if protected != cbor2.dumps({1: -8, 395: 1}) or payload is not None:
            raise ValueError('unsupported receipt protected headers or attached payload')
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
                      reported_grade=response.get('grade'), witness_key=witness_key)
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--response', required=True)
    parser.add_argument('--registry-key', required=True, help='independently accepted raw Ed25519 public key, hex')
    parser.add_argument('--witness-key', required=True, help='independently accepted raw Ed25519 public key, hex')
    parser.add_argument('--expected-log-id', required=True)
    args = parser.parse_args()
    try:
        result = verify(load_json(args.checkpoint), load_json(args.response), registry_key=args.registry_key,
                        witness_key=args.witness_key, expected_log_id=args.expected_log_id)
    except Exception as exc:
        result = {'verified': False, 'error': type(exc).__name__ + ': ' + str(exc)}
    print(json.dumps(result, indent=2))
    return 0 if result['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
