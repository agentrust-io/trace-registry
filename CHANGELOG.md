# Changelog

Notable changes to the TRACE Registry and the `trace-verify` package. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/).

Two different things are versioned here and they move independently:

- **The registry** is append-only and has no version. Entries under `registry/`
  are never rewritten; see [GOVERNANCE.md](GOVERNANCE.md).
- **`trace-verify`**, the packaged verifier, uses semantic-ish versioning while
  pre-1.0 and is published to PyPI.

## Unreleased

- **`trace-verify` 0.4.0: the CLL (Checkpointed Local Log) checkpoint chain
  -- cryptographic consistency between anchoring runs, not just git commit
  history.** Every anchored registry entry now also folds as one leaf into a
  single, append-only Merkle Mountain Range (MMR) spanning the whole
  registry, and carries a signed `mmr_checkpoint` (constant-size regardless
  of log volume, `O(log n)` per append, no per-batch tree rebuild) proving
  it mathematically extends the previous entry's checkpoint -- not merely
  that the two records' `prev_root`/`root` fields happen to match (field
  equality alone is not sufficient evidence of an honest extension; a real
  MMR consistency/extension proof is required and enforced, see
  `docs/mmr-checkpoint.md`). Conforms to
  `draft-mih-scitt-checkpointed-local-log`, and reuses the exact same
  checkpoint field set and MMR construction already shipped in
  `capsule-emit`/`capsule-ledger` (pinned against the same 39-node
  MMRIVER-draft KAT vector, `tests/test_mmr_kat39.py`) rather than a
  divergent format. Existing per-batch RFC 6962/9162 inclusion proofs
  (`merkle_root`, `tools/verify_inclusion.py`) are completely unchanged and
  unaffected -- this is additive. New: `trace_verify._mmr`,
  `trace_verify._checkpoint` (`CheckpointRecord`,
  `verify_checkpoint_signature_offline`, `verify_checkpoint_link`,
  `verify_checkpoint_chain`, all exported from `trace_verify`),
  `aggregator/_mmr_log.py`, `tools/verify_checkpoint_chain.py` (reference
  verifier CLI), and an optional `mmr_checkpoint` object on
  `schema/registry-entry.schema.json`. Complements, and does not replace,
  `docs/checkpoint-architecture.md` (issue #17)'s separate, not-yet-
  implemented proposal for a second-level tree over batch roots at high
  volume -- see `docs/mmr-checkpoint.md` for how the two relate.

- **`trace-verify` 0.3.3 (additive, not breaking): the anchor-leaf
  construction is now a declared, registered `canonicalization_id`
  (docs/anchor-format.md section 0), not an assumed fact of the format.**
  Two CPB anchor-leaf constructions are first-class and permanently valid --
  neither deprecates the other: `sorted-key` (unchanged default) and
  `as-transmitted` (offered on technical merit: no re-serialization of an
  already-signed object). `trace_verify._verify.canonical_claim_bytes()` /
  `verify_inclusion()` (and their `tools/` mirrors) each gain two new
  keyword-only parameters, `canonicalization_id` and `raw_bytes`, both
  optional; every original positional parameter keeps its name, order, and
  default behavior. **Every existing call site -- `canonical_claim_bytes(claim)`,
  `verify_inclusion(claim, leaf_index, audit_path, leaf_count, merkle_root)`
  -- returns byte-for-byte what it always has.** `tools/anchor.py`,
  `tools/batch_anchor.py`, `aggregator/_core.py`, `trace_verify._verify` and
  `tools/verify_inclusion.py` all now emit `canonicalization_id` on every new
  registry entry (a data field, not a call-signature change). Entries
  anchored before this field existed carry none; the vintage rule infers
  `sorted-key` for those (the only construction that existed at the time),
  never `as-transmitted`. A `canonicalization_id` naming a real but
  wrong-layer CPB construction (e.g. `jcs`, the signing-layer algorithm) now
  fails loudly with `MismatchedCanonicalizationLayerError` instead of a
  silent non-verify -- the #111 trap this closes by declaration rather than
  by forcing a choice. `schema/registry-entry.schema.json` gained an
  optional `canonicalization_id` enum field. `CONTRIBUTING.md` step 4 also
  corrected: it demonstrated signing with sorted-key JSON, which has not
  matched `_signature.py`'s RFC 8785 (JCS) requirement since 0.3.0.

- **`trace-verify` 0.3.2 binds all three producer identities before reporting
  verified.** The signed claim producer, anchored registry-entry producer, and
  selected producer-key record must agree. Key records must also declare
  Ed25519 and carry an OKP/Ed25519 JWK; signature and key encodings are strict,
  unpadded base64url of the required lengths. This closes a consumer-boundary
  gap where inclusion and a valid signature could be reported together even
  though the registry entry named a different producer.

- RFC 8785 is now a base dependency because signature verification is the CLI's
  safe default. A plain `pip install trace-verify` no longer installs a command
  that necessarily fails until the historical `[signature]` extra is added.
  The extra remains as an empty compatibility alias.

- The runtime `trace_verify.__version__` now matches the distribution version;
  it had remained at `0.1.0` while package releases advanced.

- **`trace-verify` 0.3.1: the published package pointed its Documentation and
  Homepage at a private repository (trace-spec#138).** The `[project.urls]` fix
  landed on `main` after `v0.3.0` was tagged and without a version bump, so PyPI
  has been serving the old metadata ever since. Anyone installing `trace-verify`
  and following its Documentation link to the anchor format got a 404, which is
  the normative rule the package implements.

  The version bump is the fix. Nothing in the URLs needed changing; they were
  already correct in the tree.

- **`docs/anchor-format.md` is now a pointer rather than a second copy.** The
  normative document is `trace-spec/spec/registry-anchor-v1.md`, which is public
  and already the more complete of the two, carrying the canonicalization warning
  in §0, the `transparency` claim relationship in §6, reference implementations in
  §7 and conformance in §8. Two copies of a normative canonicalization rule, one
  of them unreachable by the readers who need it, is how implementations end up
  disagreeing about which serialization a layer uses.

- **Licensing split: Apache-2.0 for code, CC BY 4.0 for registry data, schemas and
  docs.** The repository declared CC BY 4.0 in full, including the Python under
  `src/`, `tools/` and `aggregator/`. Creative Commons recommends against CC
  licenses for software: no patent grant, no software-tailored warranty
  disclaimer, and not OSI-approved, which some corporate policies reject outright.
  Mirroring this registry means running that code, and an independent mirror is
  the mechanism that makes the operator checkable, so the code has to carry a
  licence a mirror operator's legal team will accept.

  Done before publication deliberately. Relicensing needs contributor agreement,
  and the contributor set only grows once a repository is public. It is clean
  today: `git log --format='%an' -- src/ tools/ aggregator/` returns one human
  author, plus dependabot for workflow bumps.

  `trace-verify` 0.2.0 is on PyPI declaring `CC-BY-4.0` in its metadata. The
  package metadata now says `Apache-2.0`; a republish is needed for the published
  metadata to match.

- `.gitignore` covers `dist/`, `*.egg-info/` and `.venv/`. It listed only
  `__pycache__/`, so a local build of the package sat untracked-but-not-ignored,
  one `git add -A` away from being committed.

- Public-readiness pass: governance, maintainers, roadmap, this changelog,
  `NOTICE`, `CODEOWNERS`, Dependabot config, and issue/PR templates.

## trace-verify

### 0.3.0

- **The signature pre-image is now RFC 8785 (JCS). Published 0.2.0 verified non-ASCII records against bytes the producer never signed.** `canonical_body_bytes` built the pre-image with `json.dumps(sort_keys=True, ensure_ascii=True)` while `agentrust_trace.sign_record` signs through `rfc8785.dumps`. The two agree on ASCII and diverge everywhere else, so signer and verifier were computing different bytes for any record carrying an accented character, a non-Latin script, or an emoji.

  **The failure mode is rejection, not acceptance.** A record whose bytes the verifier reconstructs differently fails its signature check, so 0.2.0 rejected valid records; it did not accept invalid ones. No advisory, because nothing was forgeable through this. It was still wrong in the one function whose whole job is reproducing what a producer signed.

  **Behaviour change, which is why this is 0.3.0 rather than 0.2.1.** Signature verification now *refuses* rather than guessing when `rfc8785` is unavailable: `pip install "trace-verify[signature]"`. Falling back to a canonicalization that only agrees on ASCII is how the defect shipped in the first place, so the fallback is gone and the error says what to install.

  Scope is one function, deliberately. Four other `json.dumps(sort_keys=True, ...)` sites in this repository are correct: the **anchor leaf** is defined as sorted-key JSON by `docs/anchor-format.md` §1 and must not move. The two canonicalizations at two layers are the trap that document's §0 exists to name, and fixing the wrong one would have created the very bug it warns about.


### 0.2.0
- Producer signatures are **verified before anchoring**, and verification is on by
  default rather than opt-in. Adds an SSRF allowlist for producer key fetching.
  Anchoring an unverified claim would have let a producer put anything into the
  record, which is the one thing the registry must not permit.
- Anchor commits are signed and verified in CI, and the checkout in the anchor
  pipeline is pinned by SHA.
- Schema fix: batch entries without `entry_type` no longer trigger the checkpoint
  required-fields branch.

### 0.1.0
- `trace-verify` packaged as an installable CLI and published to PyPI via trusted
  publishing.

## Registry

### 2026-08
- Anchor pipeline runs on a 15-minute schedule. It has produced no new entries
  since the June entry below, because there is no production claim volume yet;
  a run with nothing to anchor is a no-op by design, not a failure.

### 2026-06
- Log aggregator service and the checkpoint architecture
  ([docs/checkpoint-architecture.md](docs/checkpoint-architecture.md)) designed for
  the volumes that would make one-line-per-batch impractical. Designed, not yet
  needed: the thresholds that would trigger it are in that document.
- Automated anchoring pipeline.
- Mirror network: [MIRRORS.md](MIRRORS.md), `check-mirrors` workflow, and
  [docs/mirroring.md](docs/mirroring.md) for running an independent copy.
- Producer key registry with Ed25519 signature verification.
- CI enforces append-only, monotonic timestamps, and producer ID format. This is
  the mechanical half of the append-only rule; the governance half is in
  GOVERNANCE.md.
- Anchor format specified ([docs/anchor-format.md](docs/anchor-format.md)), verifier
  tooling shipped, and the first real entry landed
  (`registry/2026/06/12.ndjson`).
