# Capsule Anchor receipt pilot — 2026-08-18

This pilot tests one narrow composition: an external SCITT transparency service
issues a verifiable receipt over a TRACE Anchor Format v1 leaf digest. Only the
digest was disclosed to the service.

## Input

- Public signed Trust Record vector:
  `agentrust-io/trace-spec/examples/canonicalization-boundary/01-non-ascii-values.json`
  (`record` member)
- Focused signature/canonicalization check:
  `python -m pytest -q tests/test_canonicalization_boundary.py`
- Result: 12 passed
- Anchor Format v1 canonical bytes: 964 bytes
- TRACE anchor leaf
  (`SHA-256(0x00 || canonical_claim_bytes)`):
  `a09f455ed68c50fed9291c3acd38c7e57800ae771815fc910658d96c9b6261a7`

The non-ASCII vector was selected deliberately. It detects accidental reuse of
RFC 8785 signing bytes at the anchor layer because Anchor Format v1 escapes its
non-ASCII values into ASCII.

## Registration

The 32-byte TRACE anchor-leaf digest was submitted as `capsule_id` to the public
`https://anchor.agentactioncapsule.org/v1/digest` endpoint. No Trust Record
contents were submitted.

The service returned:

```json
{
  "entry_hash": "7010960cf741e062f529123042e6867e4e15781772740e61fc4918f5caa7573e",
  "leaf_index": 275,
  "tree_size": 276,
  "receipt_b64": "0oRHogEnGQGLAaEZAYyhIIFYkIMZARQZAROEWCA1GYMTOzW8yFpVpy5b3Ty4IMYtljE/Qlenyh7Ww36mz1ggtn9mRWQGfWjLf+k9LK9XoGx/D8qnco6ayF5lF1FR9nRYIHojyd11jQlvZMo6DtFjK0nETEQ2avUvqBYUsjQjfm6QWCCP7CPbgg2czyziyn+NEzpFWDC8Pv0HEU25bS2ECXbuLPZYQGzl8TohAgcvmL7UgeCfujY4QFlI57wWndPuTpxT59WGVNkV5LKX827nqF3DeIE5oRKmgAbG4wVkh7djVVUQvQ4="
}
```

Per the service contract, `entry_hash` is
`SHA-256(bytes.fromhex(trace_anchor_leaf))`.

## Independent verification

The receipt was verified with the published `scitt-cose` 0.1.1 package rather
than the submission service. The verifier fetched the service's raw Ed25519
authority key, converted it to SubjectPublicKeyInfo PEM, and called
`verify_receipt(receipt, leaf_entry_hex=entry_hash, log_public_key_pem=key)`.

Observed result:

```text
authority key_id: 19a9ab3e02fad55c
ok: true
root: 368ed5a1166aa4839a0b4566f227a5ee440da26bd3e5406715a3ac8a3198309d
tree_size: 276
leaf_index: 275
errors: []
```

## What this proves

The receipt proves that the external log included the 32-byte value derived
from this exact signed Trust Record under TRACE Anchor Format v1. Recomputing
the TRACE leaf from a changed record produces a different value and no longer
matches this receipt.

It does not prove the Trust Record's claims are true, authenticate the record's
producer, or make the external service part of TRACE governance.

## Open integration point

This pilot does not write the receipt into the signed record. Doing so after
registration would change both the signature pre-image and the anchored leaf.
The production profile needs a non-circular rule for the `transparency` claim,
such as a stable predeclared receipt locator or a detached receipt supplied
alongside the signed record. That rule must be specified before claiming the
receipt is embedded end to end.
