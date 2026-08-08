[![License](https://img.shields.io/badge/License-Apache_2.0_(code)_%2F_CC_BY_4.0_(data)-lightgrey.svg)](LICENSE)
[![TRACE Spec](https://img.shields.io/badge/TRACE-Spec_v0.1-0ea5e9)](https://github.com/agentrust-io/trace-spec)
[![Discord](https://dcbadge.limes.pink/api/server/9JWNpH7E?style=flat)](https://discord.gg/9JWNpH7E)

# TRACE Registry

The public accountability layer for TRACE claim anchors. Each entry records the
Merkle root of a batch of signed TRACE Trust Records, committed to this
repository as an append-only record. Git's commit history is the
tamper-evidence layer: any rewrite of a published entry diverges the commit
hashes that auditors and mirrors have already observed.

## Current Registry State

The registry currently contains **one** entry (`registry/2026/06/12.ndjson`). It is
a software-only example anchor with advisory enforcement and a zeroed measurement,
committed as a launch-day example. It does not represent a production Trust Record,
and no production entries have been anchored yet.

The anchoring pipeline is live and runs on a schedule, verifying producer signatures
before it anchors anything. A scheduled run with nothing to anchor is a no-op, so the
gap since June reflects claim volume rather than a stalled pipeline.

The anchor construction (canonical claim bytes, leaf hashing, RFC 6962 Merkle
tree, inclusion proofs) is specified in
[docs/anchor-format.md](docs/anchor-format.md). A third party can implement a
verifier from that document alone; the reference tools in [tools/](tools/) are
one implementation.

> **Status.** The format, reference tooling, schema validation, and a first
> real entry ([registry/2026/06/12.ndjson](registry/2026/06/12.ndjson)) are live.
> Scheduled anchoring is operational and `trace-verify` is published on PyPI. What
> is missing is volume: one entry, one producer, and no mirror we do not operate.
> See [ROADMAP.md](ROADMAP.md) for what that means and what would change it.

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

## Anchoring claims

Producers batch signed claims and anchor them with:

```bash
python tools/anchor.py claim1.json claim2.json \
  --producer my-gateway/1.0 --proof-dir proofs/ \
  >> registry/2026/06/12.ndjson
```

This emits the registry entry line and writes one inclusion proof per claim to
hand back to claim holders.

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
