# Contributing

Thank you for your interest in contributing to the TRACE Registry.

## How to Contribute

1. Fork the repository
2. Create a feature branch
3. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org)
4. Open a pull request against `main`

A pull request that adds or changes behaviour must add or update tests in `tests/` that fail without it. CI runs `python -m unittest discover -s tests` and `ruff check .`; both must pass before merge.

## Running tests locally

From the repository root, create a Python 3.12 virtual environment to match CI:

```bash
python -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements/ci.txt
pip install --require-hashes -r requirements/witness.txt
pip install --require-hashes -r requirements/runtime.txt
pip install --no-deps -e ".[signature]"
python -m unittest discover -s tests
ruff check .
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1` in
PowerShell instead. The three lockfiles supply the CI tools, offline witness
verification dependencies, and runtime dependencies before the editable install.

## Release checks

The PyPI workflow runs the existing CI validation job against the release or manual
run's revision before building. The append-only comparison is explicitly skipped on
those events because they have no push/PR base SHA; registry validation, checkpoint
verification, staged-record dry runs and the test suite still run.

Manual dispatch defaults to build-only. It builds and checks the wheel and sdist,
installs each in a separate clean environment, and exercises the installed CLI outside
the checkout with both valid evidence and a wrong anchor root. The resulting files are
uploaded together. Only a published release or an explicit `dry_run=false` dispatch
on the exact version tag can reach the separate PyPI job. That job downloads those
checked artifacts and holds the `pypi` environment and OIDC permission; build-only
execution has neither publishing authority.

These workflow checks do not configure environment reviewers, registry trusted
publishers or backup operators. Those settings remain separate maintainer work.

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

## Using AI to contribute

Use agents. A lot of this was built with them and saying otherwise would be dishonest.

The rule is that you have to understand what you submit. If you cannot explain what your change does and how it interacts with the rest of the system, with the agent closed, do not open the pull request. Reviewing a change nobody can explain costs more than writing it did, and it becomes someone else's problem the moment it merges.

That is a rule about understanding, not about tooling.

## Reporting Security Issues

Use [GitHub Security Advisories](https://github.com/agentrust-io/trace-registry/security/advisories/new) rather than opening a public issue.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
