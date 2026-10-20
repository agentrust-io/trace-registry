# Checkpoints 1 and 2: receipts from a second, independent witness

Captured October 20, 2026, 03:36:18 UTC, from registry main `555f27a`. The witness is operated by HORIZON SHIELD (The HORIZONs Co., Ltd.), which also holds a registered mirror of this registry (MIRRORS.md). Witness code: [`registry-witness-v0`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/workers/hs-ledger/nenrin/registry-witness-v0).

| | checkpoint 1 (`mmr_size` 1) | checkpoint 2 (`mmr_size` 3) |
|---|---|---|
| signing-body digest | `41138372…968f99a` | `8b21417c…dbc6cf22f` |
| entry hash | `dee1a92d…bed6dfab6` | `df8e89a8…d7d9372ee` |
| leaf / tree size | 0 / 1 | 1 / 2 |
| grade signed under `-65537` | `mmr-verified` | `mmr-verified` |
| CWT `iat` signed | no: the checkpoint was more than 30 days old | yes, `1792467378` (2026-10-20T03:36:18Z) |
| `grade_cryptographically_bound` | true | true |
| `witness_time_established` | false | true |

Checkpoint 1 already has the Action State receipt of September 7, so it now has two witnesses. Checkpoint 2 had none.

## Verify offline

From the repository root:

```
python -m pip install --require-hashes -r requirements/witness.txt
for i in 1 2; do
  python tools/verify_witness_receipt.py \
    --checkpoint docs/evidence/witness-2026-10-20-nenrin/checkpoint-$i.json \
    --response docs/evidence/witness-2026-10-20-nenrin/witness-response-$i.json \
    --expected-log-id trace-registry/v1 \
    --registry-key bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90 \
    --witness-key c7c47d073a2c8b348d12c7207aaf7a403f5a3c2695227bf8ed2963ff52f98baf
done
```

Expected: `verified: true` and seven checks for each. The limits are as in the table. `tests/test_witness_receipt_nenrin.py` runs both with sockets disabled, and tries altered bodies and swapped receipts.

## What the grade means here

`mmr-verified` is signed only after the witness has done three things itself:
- run both of this registry's chain checks over the files at the source commit, with `trace-verify`'s own functions;
- pinned the registry key;
- confirmed that every checkpoint it signed before is still present, byte for byte, on the same line.

It does not mean anything about the claims the registry anchors.

## What `iat` means here

The witness clock at the start of the run. It sits inside the signature, so it binds as a witness statement. On its own it is still the witness's assertion. The witness log's tree head (`witness-tree-heads.ndjson`, line SHA-256 `aaf55bf7163e08c30fa22b4cf0dfe13bbbc37f6876c6c66fff5b0f776b90ef8d`) is anchored to Bitcoin through the JIDEC ledger, which gives an upper bound from a clock neither party controls.

## Limits

These receipts do not establish:
- registry continuity in the receipt itself (`registry_continuity_established` stays false);
- absence of forks;
- payload retention;
- that every observer saw the same history.

Two independent witnesses on checkpoint 1 are a start on split-view detection, not proof of it. The June entry predates checkpointing and is outside both checkpoints.

The witness signs one receipt per checkpoint and never reissues it. Its log is append-only, and each tree head carries an RFC 9162 consistency proof from the previous one.

## Files

| file | what it is |
|---|---|
| `checkpoint-1.json`, `checkpoint-2.json` | the checkpoints as witnessed, sorted-key compact JSON (the digest is field-derived, see LIMITATIONS.md) |
| `witness-response-1.json`, `witness-response-2.json` | the witness responses, in the shape `--response` reads |
| `verification-1.json`, `verification-2.json` | `trace-verify receipt` output over those bytes |
| `witness-key.json` | the witness public key and its key id |
| `witness-tree-heads.ndjson` | the witness log's signed tree heads at capture |
| `SHA256SUMS` | file integrity; not a signed statement |
