[![License](https://img.shields.io/badge/License-Apache_2.0_(code)_%2F_CC_BY_4.0_(data)-lightgrey.svg)](LICENSE)
[![TRACE Spec](https://img.shields.io/badge/TRACE-Spec_v0.1-0ea5e9)](https://github.com/agentrust-io/trace-spec)
[![Discord](https://dcbadge.limes.pink/api/server/9JWNpH7E?style=flat)](https://discord.gg/9JWNpH7E)

# TRACE Registry

The public accountability layer for TRACE claim anchors. Each entry records the
Merkle root of a batch of signed TRACE Trust Records, committed to this
repository as an append-only record. Git's commit history is the
tamper-evidence layer: any rewrite of a published entry diverges the commit
hashes that auditors and mirrors have already observed.

Project support is recognized in [SPONSORS.md](SPONSORS.md). Sponsorship is
separate from producer registration, registry governance, verification
semantics, and mirror operation.

## Current Registry State

The registry currently contains **two** entries, and neither is a production Trust
Record.

- `registry/2026/06/12.ndjson`, producer `cmcp-gateway`, is a software-only example
  anchor with advisory enforcement and a zeroed measurement, committed as a
  launch-day example.
- `registry/2026/09/01.ndjson`, producer `verifiable-agent-summit-demo`, is a
  demonstration anchor produced for a conference session.

No production entries have been anchored yet.

The anchoring pipeline is live and runs on a schedule, verifying producer signatures
before it anchors anything. A scheduled run with nothing to anchor is a no-op, so the
gaps between entries reflect claim volume rather than a stalled pipeline.

The anchor construction (canonical claim bytes, leaf hashing, RFC 6962 Merkle
tree, inclusion proofs) is specified in
[docs/anchor-format.md](docs/anchor-format.md). A third party can implement a
verifier from that document alone; the reference tools in [tools/](tools/) are
one implementation.

> **Status.** The format, reference tooling, schema validation, and two anchored
> entries are live. Scheduled anchoring is operational and `trace-verify` is
> published on PyPI. What is missing is volume: two entries, both produced by us,
> neither of them production, and no mirror we do not operate.
> See [ROADMAP.md](ROADMAP.md) for what that means and what would change it, and
> [LIMITATIONS.md](LIMITATIONS.md) for what an anchor does and does not prove.

## External witness receipt

Checkpoint 1 now has an offline-verifiable receipt from an independently operated witness.
The [September 7 evidence packet](docs/evidence/witness-2026-09-07/README.md) includes the
original checkpoint, returned receipt, separately fetched copies, key provenance and verifier.
It proves inclusion of that checkpoint signing-body digest under the pinned witness key.
It does not certify continuity. Whether a receipt carries a witness time or a signed grade is
a property of that receipt, so the verifier reports `witness_time_established` and
`grade_cryptographically_bound` rather than asserting either. Both are false for this capture
and stay false for it. Its protected header carries algorithm and tree profile only, and the
witness signature covers that header, so a receipt carrying either field is a new receipt rather
than this one re-read.
A further capture runs through `tools/capture_witness_receipt.py`, which submits the
checkpoint, reads the receipt back by log id and by digest, and writes the response
bodies, a capture manifest, the offline verification and `SHA256SUMS` into one
directory. Every status, timestamp and hash it records comes from an observed
response, and a failed request is recorded as it failed.
The pipeline does not yet submit future checkpoints automatically. Parallel independent
witnesses remain supported as a deployment choice; only one operator is demonstrated here.

## Why this exists

Anyone holding a TRACE trust record and its inclusion proof can verify that the
record was anchored in this registry without trusting the operator who issued
it, using only this public git history and the verifier below. Independent observations and retained checkpoints help expose divergent histories;
one receipt does not prove that every observer received the same history.

## Registry Format

Each daily file in `registry/YYYY/MM/` is newline-delimited JSON, one anchor
entry per line, validated by CI against
[schema/registry-entry.schema.json](schema/registry-entry.schema.json):

```json
{"ts": "2026-06-12T18:09:41Z", "merkle_root": "sha256:9279...bada", "leaf_count": 1, "producer": "cmcp-gateway/0.1.0", "batch_id": "2026-06-12-001"}
```

Entries are append-only. See [docs/anchor-format.md](docs/anchor-format.md)
for field semantics.

## Using the registry

There are three questions you can ask of this registry, and one command each.
Install once:

```bash
pip install trace-verify
```

**Is my claim in the registry?** You need three things: your signed claim (Trust
Record), the inclusion proof your producer gave you, and the registry entry for
the batch.

```bash
trace-verify \
  --claim samples/example-trust-record.json \
  --proof samples/inclusion-proof.json \
  --entry registry/2026/06/12.ndjson
# OK: claim is included in batch '2026-06-12-001' (root sha256:9279..., ts 2026-06-12T18:09:41Z), signature valid
```

Exit code 0 means the claim is proven included **and** its producer's signature
verified; 1 means one of those failed.

You do not need a clone. Swap `--entry` for `--entry-url` and both the entry and
the producer key that signed the claim are fetched over https, from an
allowlisted host only:

```bash
trace-verify \
  --claim your-record.json \
  --proof your-record.proof.json \
  --entry-url https://raw.githubusercontent.com/agentrust-io/trace-registry/main/registry/2026/06/12.ndjson
# OK: claim is included in batch '2026-06-12-001' (...), signature valid
#      producer key fetched from .../producers/cmcp-gateway-0.1.0.json
```

The producers base is derived from the entry URL, and the derived URL goes
through the same host allowlist. Point it elsewhere with `--producers-url`, or
at a local directory with `--producers-dir`. A key that arrived over the network
is a different trust statement from one already on disk, so the command says
which it used rather than letting the OK line imply a local check.

Inclusion proves the signed claim bytes were anchored at the entry's timestamp.
It does not prove the claim is true, and it is not a statement about anything
the claim asserts.

**Does the registry's own history hold?** Batches anchored via the aggregator
carry a signed `mmr_checkpoint` proving, by math, that each entry honestly
extends the previous one, not just that git history was not rewritten.

```bash
trace-verify chain registry/2026/06/12.ndjson registry/2026/09/01.ndjson
```

Two independent checks run. The first asks whether the checkpoints are
consistent with each other, which a forged or forked chain fails. The second
rebuilds the Merkle Mountain Range from the entries themselves and compares it
to what each checkpoint claims, which is what catches a quiet edit to an entry
that was already anchored. See
[docs/mmr-checkpoint.md](docs/mmr-checkpoint.md) for what each does and does not
catch.

**Does an outside witness agree?** Verifying a witness receipt needs COSE, so it
ships as an extra rather than in the base install:

```bash
pip install "trace-verify[witness]"
trace-verify receipt \
  --checkpoint docs/evidence/witness-2026-09-07/checkpoint-1.json \
  --response docs/evidence/witness-2026-09-07/witness-post.json \
  --expected-log-id trace-registry/v1 \
  --registry-key bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90 \
  --witness-key 39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5
```

Both keys are arguments and neither is ever fetched. A receipt verified under a
key the receipt itself named would prove nothing about who signed it, so you
pin the keys you accept and the command refuses anything else.

Nothing above requires trusting us. The verifier is a small package you can
audit, the anchor construction is specified in
[docs/anchor-format.md](docs/anchor-format.md), and a third party can
reimplement the whole thing from that document. The `samples/` files are a real
anchored example to exercise the tooling against, and the `tools/` scripts in
this repository are the same code reached by a different path.

## Anchoring claims

There are two paths, and they disagree on purpose about where the producer id
comes from. Pick the one that matches how you are submitting.

**By hand.** The producer id is an argument, so the claim itself need not carry
one:

```bash
python tools/anchor.py claim1.json claim2.json \
  --producer my-gateway/1.0 --proof-dir proofs/ \
  >> registry/2026/06/12.ndjson
```

This emits the registry entry line and writes one inclusion proof per claim to
hand back to claim holders.

Once the registry publishes a checkpoint chain, pass `--registry-dir` so the
entry is folded into the chain and appended in the same step:

```bash
python tools/anchor.py claim1.json --producer my-gateway/1.0.0 \
  --proof-dir proofs/ --registry-dir registry/
```

These are one operation, not two. A checkpoint is minted against the chain as
published, so minting one without appending its entry, or minting two before
appending either, produces a chain that cannot be reproduced from the
registry. Without `--registry-dir` the entry is printed for you to redirect and
is **not** covered by the chain, which nothing downstream will report, because
the chain only ever claims to cover the entries it checkpointed.

**Through the scheduled pipeline.** Drop claims in `staging/incoming/` and the
pipeline batches them. Here the producer id **must be a top-level `producer`
field inside the signed claim body**:

```json
{
  "producer": "my-gateway/1.0.0",
  "trace": { "...": "..." },
  "signature": "..."
}
```

It has to be inside the body rather than alongside it, because the pipeline
verifies every claim against the key registered for that producer before
anchoring anything, and a producer id supplied out of band is an unsigned
assertion about who signed. A claim with no `producer` field is rejected rather
than guessed at, and the whole group is rejected if any signature fails.

The id must match a file in `producers/` and the `name/semver` pattern in
[`schema/producer-key.schema.json`](schema/producer-key.schema.json).

## Canonical Registry

This repository exists for independence: TRACE claim anchors can be checked
without trusting any single operator's infrastructure, and the git history is
auditable by anyone.

## Community

Questions, feedback, integration help: [Discord](https://discord.gg/9JWNpH7E).

## License

Dual: **Apache-2.0** for code (`src/`, `tools/`, `aggregator/`, `tests/`, `.github/`) and
**CC BY 4.0** for registry data, proofs, schemas and documentation. See [LICENSE](LICENSE).

The code was previously under CC BY 4.0, which Creative Commons itself recommends
against for software: no patent grant, no software-tailored warranty disclaimer,
and not OSI-approved. Mirroring this registry means running that code, so it needs
a license written for software.

Using or submitting to the registry is covered by [TERMS.md](TERMS.md), which states
what anchoring does not mean, what you grant by submitting, and the removal position.
