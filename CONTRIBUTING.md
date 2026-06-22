# Contributing

Thank you for your interest in contributing to the TRACE Registry.

## How to Contribute

1. Fork the repository
2. Create a feature branch
3. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org)
4. Open a pull request against `main`

## Becoming a TRACE Producer

A producer is any system that generates signed TRACE Trust Records and anchors them into the registry. Work through the four steps below before anchoring production records.

### Prerequisites

- You have a component that emits TRACE Trust Records (JSON objects with at least `fmt`, `producer`, `ts`, `hash`, and `signature` fields).
- The `producer` field in your Trust Records follows the format `<component>/<semver>` -- for example `acme-gateway/1.2.0`. CI rejects entries that do not match this pattern.
- You have the `cryptography` Python package available for key generation and signing (`pip install cryptography`).

### Step 1: Generate an Ed25519 keypair

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64, hashlib, json

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()
pub_raw = pub.public_bytes_raw()

x = base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode()
kid = "your-prefix-" + hashlib.sha256(pub_raw).hexdigest()[:8]

print(json.dumps({"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}))
```

Store the private key securely (HSM, secrets manager, or an encrypted keyfile). **Never commit it.**

### Step 2: Register your key

Create `producers/<your-id>-<version>.json`. The filename must equal your `producer_id` with `/` replaced by `-`, plus `.json`.

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

Open a pull request adding this file. CI validates it against `schema/producer-key.schema.json` and checks the filename convention. A maintainer will review and merge before you proceed to step 3.

### Step 3: Do a zeroed test anchor

Before anchoring real records, send one batch with a **zeroed measurement** so the full signing and anchoring path is exercised without real data in the registry.

Create a test Trust Record with `hash` set to 64 zeros and `note` set to `"zeroed-test-anchor"`:

```python
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Load your private key (shown here from raw bytes for illustration)
priv = Ed25519PrivateKey.from_private_bytes(your_private_key_bytes)

claim_body = {
    "fmt": 1,
    "producer": "acme-gateway/1.0.0",
    "ts": "2026-06-22T00:00:00Z",
    "hash": "sha256:" + "0" * 64,
    "note": "zeroed-test-anchor",
}
body_bytes = json.dumps(
    claim_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("ascii")
sig = priv.sign(body_bytes)
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

claim = {**claim_body, "signature": sig_b64}
with open("test-anchor.json", "w") as fh:
    json.dump(claim, fh, indent=2)
```

Anchor it:

```bash
python tools/anchor.py test-anchor.json \
    --producer acme-gateway/1.0.0 \
    --batch-id $(date -u +%Y-%m-%d)-test \
    --ts $(date -u +%Y-%m-%dT%H:%M:%SZ) \
    --proof-dir ./ \
    >> registry/$(date -u +%Y/%m/%d).ndjson
```

Verify the resulting proof round-trips:

```bash
python -m trace_verify \
    --claim test-anchor.json \
    --proof test-anchor.proof.json \
    --entry registry/$(date -u +%Y/%m/%d).ndjson \
    --verify-signature \
    --producers-dir producers
```

Open a pull request adding the new `.ndjson` line. CI will run the append-only check and schema validation. Mention in the PR description that it is a zeroed test anchor so reviewers know what to expect.

### Step 4: Batch cadence and anchor commits

Once your test anchor is merged, your producer is fully onboarded. For production anchoring:

- Anchor one batch per logical processing window (hourly, per-run, or per-job -- whatever fits your workload).
- Each batch goes on the day file for the UTC anchoring date: `registry/YYYY/MM/DD.ndjson`.
- If you anchor multiple batches in the same day, append a new line for each. The file is append-only; do not modify or delete existing lines.
- Use a monotonically increasing `ts` within a day. CI will reject an anchor whose `ts` is earlier than the previous entry in the same day file.
- Open a pull request per anchor (or per day) rather than bulk-committing weeks of entries. Smaller PRs are faster to review.

### What to do if an anchor commit fails

| Symptom | Likely cause | Fix |
|---|---|---|
| CI fails "append-only violation" | An existing line was modified or deleted | Restore the original line; add new entries at the end only |
| CI fails "timestamp out of order" | Your `ts` is earlier than the previous entry | Use a timestamp after the last committed entry for that day |
| CI fails "schema violation: producer" | `producer` field does not match `<component>/<semver>` | Fix the producer_id format in your Trust Record |
| CI fails "filename mismatch" | Key file name does not match `producer_id` | Rename the file to match the convention |
| `verify_claim_signature` returns `False` | Private key does not match registered public key, or message was built incorrectly | Re-check the canonical serialization (sorted keys, no spaces, ASCII) and that you are signing the body **excluding** the `signature` field |

## Reporting Security Issues

Use [GitHub Security Advisories](https://github.com/agentrust-io/trace-registry/security/advisories/new) rather than opening a public issue.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
