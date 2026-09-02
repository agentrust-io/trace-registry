# Contributing

Thank you for your interest in contributing to the TRACE Registry.

## How to Contribute

1. Fork the repository
2. Create a feature branch
3. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org)
4. Open a pull request against `main`

## Becoming a TRACE Producer

A producer is any system that generates signed TRACE Trust Records and anchors them into the registry. To register your key:

1. Generate an Ed25519 keypair. Example using Python:
   ```python
   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
   import base64, json
   priv = Ed25519PrivateKey.generate()
   pub = priv.public_key()
   x = base64.urlsafe_b64encode(pub.public_bytes_raw()).rstrip(b"=").decode()
   print(json.dumps({"kty": "OKP", "crv": "Ed25519", "x": x}))
   ```
   Keep the private key secret -- never commit it.

2. Create `producers/<your-id>-<version>.json`. The filename must equal the `producer_id` field with `/` replaced by `-`, plus `.json`. Example for producer `acme-gateway/1.0.0`:
   ```json
   {
     "producer_id": "acme-gateway/1.0.0",
     "key_type": "Ed25519",
     "public_key_jwk": {
       "kty": "OKP",
       "crv": "Ed25519",
       "x": "<43-char base64url public key>",
       "kid": "acme-XXXXXXXX"
     },
     "active_since": "2026-06-22T00:00:00Z",
     "contact": "security@example.com"
   }
   ```

3. Open a pull request. CI will validate the file against `schema/producer-key.schema.json` and check the filename matches the `producer_id`.

4. Sign your Trust Records over the canonical body bytes -- all fields except `signature` -- serialized as **RFC 8785 (JCS)**, the signing-layer canonicalization (TRACE v0.2 §3.2; not the sorted-key ASCII JSON used for the anchor leaf -- see `docs/anchor-format.md`):
   ```python
   import rfc8785
   rfc8785.dumps(body)
   ```
   Store the raw 64-byte signature as base64url (no padding) in the top-level `signature` field.

5. Submit records for anchoring by opening a pull request that adds them to `staging/incoming/`, one JSON file per record. The scheduled pipeline picks them up, groups them by `producer`, verifies every signature against your registered key before anchoring anything, and writes an inclusion proof back for each anchored claim; see [`staging/README.md`](staging/README.md) for the outputs and where they land. A record must carry the top-level `producer` field, because a producer id supplied out of band is an unsigned assertion about who signed, and a group is rejected whole if any signature in it fails.

## Reporting Security Issues

Use [GitHub Security Advisories](https://github.com/agentrust-io/trace-registry/security/advisories/new) rather than opening a public issue.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
