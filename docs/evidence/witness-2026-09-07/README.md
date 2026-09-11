# Checkpoint 1 external witness receipt

Captured September 7, 2026 (Pacific time; the readback timestamps are September 8 UTC).
The source checkpoint is unchanged from registry main `6138335`,
`registry/2026/09/01.ndjson`. Only the exact nested JSON checkpoint object was sent,
using `Content-Type: application/cll-checkpoint+json`. No claim payload or private
key was sent, and no new registry signature or checkpoint was created.

The Action State witness returned a receipt at leaf 936 of a 937-leaf tree.
The POST response, log-id readback, and digest-addressed inclusion readback all
carry the same receipt bytes. The verifier recomputes the checkpoint signing
digest and receipt leaf instead of trusting the returned `entry_hash`.

## Verify offline

From the repository root, in an isolated Python environment:

```sh
python -m pip install --require-hashes -r requirements/witness.txt
python tools/verify_witness_receipt.py \
  --checkpoint docs/evidence/witness-2026-09-07/checkpoint-1.json \
  --response docs/evidence/witness-2026-09-07/witness-post.json \
  --expected-log-id trace-registry/v1 \
  --registry-key bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90 \
  --witness-key 39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5
```

Expected: `verified: true`, seven successful checks, leaf 936, tree size 937.
The command does not fetch keys or make network calls. Tests run it with sockets
disabled and exercise altered bodies/signatures, wrong key pins, a different
valid checkpoint borrowing this receipt, metadata changes and proof coordinates.

Trust policy is explicit. The registry key was previously published for
`trace-registry/v1`. The witness key was fetched from its HTTPS DID document and
matches the previously reported key ID `19a9ab3e02fad55c`, computed as the first
16 hex characters of SHA-256(raw public key). This is an operator key accepted
for this demonstration, not a public CA certification or independently established
organizational identity. `witness-did.json` records that discovery; changing it
does not change the verifier's required key argument.

The receipt is verified by the separately published `scitt-cose==0.2.2` library,
not by importing the witness's service or asking its endpoint for a verdict.
That implementation documents its receipt encoding as tracking a COSE Merkle
proof draft. This packet makes no final-RFC conformance claim.

## Exact binding and limits

The registry signature verifies over the ASCII lowercase SHA-256 hex digest of
sorted-key compact JSON containing `v`, `kind`, `log_id`, `mmr_size`, `root`,
`prev_size`, `prev_root`, `key_id`, and `timestamp`. The witness JSON route
registers the raw 32-byte digest. Its `legacy` entry hash is SHA-256 of those
32 bytes; the RFC 9162 leaf hash is SHA-256(0x00 || entry-hash bytes).

- Checkpoint signing digest: `41138372adb1921186ca6a0dbc3433a0ea2f6475cb863205603ab1231968f99a`.
- Receipt entry hash: `dee1a92dad155b56f99cf2284e166e3b6b935528e6d27dec8a4f67bbed6dfab6`.
- Verified witness root: `f8ee69f33629abc413a9b5530f9166230c8efd3b29f052216f22fb2412e1ef91`.
- Receipt SHA-256: `4e075e8494da20ab72a9b8077432663317c4dad58aa8f8fdcd452c166c20bdd7`, the same
  bytes in all three captured responses.

The COSE signature authenticates that root. Its protected headers contain only
algorithm and tree profile, decoding to `{1: -8, 395: 1}`. There is no signed
witness timestamp. The signature covers that header, so `witness_time_established`
and `grade_cryptographically_bound` are false for this receipt permanently rather
than pending a witness upgrade: a receipt carrying a CWT `iat` or a signed grade is
a separately signed receipt, and this packet's bytes are unchanged by one. The
checkpoint timestamp is the registry signer's assertion; collection time is the
observer's local record. Neither is an authenticated witness observation time.

`grade: countersigned-observed` is reported by the HTTPS response, outside the
signed receipt. The verifier exposes it as `reported_grade` and always reports
`grade_cryptographically_bound: false`. It must not become an authenticated
policy input merely because the receipt verifies.

The witnessed digest excludes the registry signature and optional consistency
proof. The verifier checks the registry signature separately. This single receipt
does not verify cross-checkpoint consistency, witness-log consistency across
observations, registry completeness, payload availability, or absence of forks.
The June entry predates checkpointing and remains outside checkpoint 1.

No recurring witness submission was deployed. The registry is a producer of
checkpoints, not an endpoint accepting others' checkpoints. Additional witnesses,
including a Rekor demonstration, remain future work.

## Capture provenance

`capture-manifest.json` lists URLs and response hashes. The first POST wrote its
response before a local logging error; its status field was reconstructed from
the saved receipt response and is labeled accordingly. It was not resubmitted
to hide that error. Both subsequent GETs returned 200 with recorded timestamps.

The evidence package contains public artifacts only. `SHA256SUMS` checks file
integrity, while the verifier establishes the cryptographic binding. Neither
the capture manifest nor SHA256SUMS is represented as a signed witness statement.
