# Checkpoints 1 and 2: receipts from a second witness

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

## How new this witness is

The witness key first appears in horizon-shield commit `65b0db6` (2026-10-20 03:48 UTC), 12 minutes before this PR was opened. The witness log holds only the two leaves in this packet. The witness is operated by a party other than the registry operator, and that party also runs one of the registered mirrors. Nothing here shows a track record, or independence beyond being a different operator with its own key.

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

The witness clock at the start of the run. It sits inside the signature, so it binds as a witness statement. On its own it is still the witness's assertion. The witness log's first tree head is anchored to Bitcoin, which gives an upper bound from a clock neither party controls. The proof is in this packet:

1. `witness-tree-heads.ndjson`: the SHA-256 of its first line, without the newline, is `aaf55bf7163e08c30fa22b4cf0dfe13bbbc37f6876c6c66fff5b0f776b90ef8d`.
2. `jidec-127.txt`: the JIDEC ledger's entry 127 as the ledger serves it (`https://ledger.horizonshield.dev/ledger/127?format=raw`). It names that line SHA-256 and the witness key. Its SHA-256 is `6d8ff0fbc1e2d3d0e3ef2e03b22be891c0cd380dba80d16153861894ec4ced67`.
3. `jidec-127.txt.ots`: the OpenTimestamps proof over that SHA-256 (also at `https://ledger.horizonshield.dev/ledger/127/ots`). It commits to the Bitcoin block header at height 972264 (merkle root `81b695d07d509468fab75fa9dc550808302bb6a7cf667a34058395b06d949653`, block time 2026-10-20 05:09:57 UTC).

```
python -m pip install opentimestamps-client
ots info docs/evidence/witness-2026-10-20-nenrin/jidec-127.txt.ots     # shows the attestation at 972264
ots verify docs/evidence/witness-2026-10-20-nenrin/jidec-127.txt.ots   # needs a Bitcoin node
ots info docs/evidence/witness-2026-10-20-nenrin/jidec-143.txt.ots     # shows the attestation at 972850
```

Entry 127 describes the witness as "independent". That wording is corrected by a later entry, which cites entry 127 and does not edit it: jidec-143.txt (the ledger's entry 143 as served at https://ledger.horizonshield.dev/ledger/143?format=raw, proof also at https://ledger.horizonshield.dev/ledger/143/ots). It uses the wording of this README.

So the first tree head, the witness key and both receipts existed before 2026-10-20 05:09:57 UTC. The anchor bounds the time from above only.

## Two anchors, two heights

The packet holds two anchored ledger entries. Each has its own proof and its own Bitcoin height:

| record | role | record SHA-256 | proof | Bitcoin height |
|---|---|---|---|---|
| `jidec-127.txt` | entry 127: fixes the witness key and the first tree head | `6d8ff0fbc1e2d3d0e3ef2e03b22be891c0cd380dba80d16153861894ec4ced67` | `jidec-127.txt.ots` | 972264 |
| `jidec-143.txt` | entry 143: corrects how entry 127 describes the witness | `79837a3a2e557c34ec194f940ca2fd1f1934eb0874fed8b48d84738dde5b4eed` | `jidec-143.txt.ots` | 972850 |

Block 972850 has merkle root `bfb0efe3c54ef54dc8a7101d028b93e93be3b6e8e58fffd7ffd6cd5d27deb31c` and block time 2026-10-24 00:13:42 UTC.

Inside `jidec-143.txt`, the line `stamped to      Bitcoin block 972264` sits in the "What it corrects" block. It names the anchor of entry 127, the entry being corrected. It is not the anchor of entry 143. Entry 143's own proof is `jidec-143.txt.ots`, at height 972850. `jidec-143.txt` is the anchored record and is not edited.

`tests/test_witness_receipt_nenrin.py` checks this offline, for each entry separately: the record's SHA-256, the proof's OpenTimestamps header (magic, version 1, file hash op `0x08`) and the 32-byte digest that follows it, and that the proof holds exactly one Bitcoin attestation, at the height in the table. For entry 127 it also checks steps 1 and 2 above. It checks that entry 143 cites entry 127's SHA-256, that the height named in the "What it corrects" block of `jidec-143.txt` is the height of entry 127's proof and not of entry 143's, that this table matches the proofs, and that `SHA256SUMS` matches the files. A correction proof that is swapped for entry 127's, truncated, or carries the other height fails. These are structural reads of the proof bytes. The tests do not evaluate the full operation chain, and checking the block header itself needs a node or a block explorer.

## Limits

These receipts do not establish:
- registry continuity in the receipt itself (`registry_continuity_established` stays false);
- absence of forks;
- payload retention;
- that every observer saw the same history.

Two witnesses from different operators on checkpoint 1 are a start on split-view detection, not proof of it. The June entry predates checkpointing and is outside both checkpoints.

The witness signs one receipt per checkpoint and never reissues it. Its log is append-only, and each tree head carries an RFC 9162 consistency proof from the previous one.

## Files

| file | what it is |
|---|---|
| `checkpoint-1.json`, `checkpoint-2.json` | the checkpoints as witnessed, sorted-key compact JSON (the digest is field-derived, see LIMITATIONS.md) |
| `witness-response-1.json`, `witness-response-2.json` | the witness responses, in the shape `--response` reads |
| `verification-1.json`, `verification-2.json` | `trace-verify receipt` output over those bytes |
| `witness-key.json` | the witness public key and its key id |
| `witness-tree-heads.ndjson` | the witness log's signed tree heads at capture |
| `jidec-127.txt`, `jidec-127.txt.ots` | the ledger entry that fixes the first tree head, and its OpenTimestamps proof |
| `jidec-143.txt`, `jidec-143.txt.ots` | the later ledger entry that corrects how entry 127 describes the witness, and its OpenTimestamps proof |
| `SHA256SUMS` | file integrity; not a signed statement |
