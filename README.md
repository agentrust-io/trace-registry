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

## Why this exists

Anyone holding a TRACE trust record and its inclusion proof can verify that the
record was anchored in this registry without trusting the operator who issued
it, using only this public git history and the verifier below. No single
operator controls the audit trail.

## Registry Format

Each daily file in `registry/YYYY/MM/` is newline-delimited JSON, one anchor
entry per line, validated by CI against
[schema/registry-entry.schema.json](schema/registry-entry.schema.json):

```json
{"ts": "2026-06-12T18:09:41Z", "merkle_root": "sha256:9279...bada", "leaf_count": 1, "producer": "cmcp-gateway/0.1.0", "batch_id": "2026-06-12-001"}
```

Entries are append-only. See [docs/anchor-format.md](docs/anchor-format.md)
for field semantics.

## Verifying a claim

You need three things: your signed claim (Trust Record), the inclusion proof
your producer gave you, and the registry entry for the batch. Then:

```bash
git clone https://github.com/agentrust-io/trace-registry.git
cd trace-registry
python tools/verify_inclusion.py \
  --claim samples/example-trust-record.json \
  --proof samples/inclusion-proof.json \
  --entry registry/2026/06/12.ndjson
# OK: claim is included in batch '2026-06-12-001' (root sha256:9279..., ts 2026-06-12T18:09:41Z)
```

Exit code 0 means the claim is proven included; 1 means it is not. The
verifier is a single standard-library Python file, so you can audit it (or
reimplement it from the spec) rather than trust it. The `samples/` files above
are a real anchored example you can use to exercise the tooling.

Inclusion verification proves the signed claim bytes were anchored at the
entry's timestamp. Validating the claim's signature against the producer key
is a separate TRACE step.

Batches anchored via the aggregator (below) also carry a signed `mmr_checkpoint`
proving, by math, that each entry honestly extends the previous one -- not
just that git history was not rewritten. Verify the whole chain with:

```bash
python tools/verify_checkpoint_chain.py registry/2026/06/12.ndjson
```

See [docs/mmr-checkpoint.md](docs/mmr-checkpoint.md) for how this works and
what it does and does not catch.

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
