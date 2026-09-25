# Fuzzing

Coverage-guided fuzzing via [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/),
running Atheris against the inputs this repository takes from people it has
not yet decided to trust: producers submitting claims, and readers handed a
claim, a proof, a day file or a witness receipt by somebody else.

| Target | Surface |
| --- | --- |
| `fuzz_intake.py` | A staged claim file through `tools/batch_anchor.py` (`loads_unique`, `anchor_profile_violation`, producer grouping, the signature gate), and a `POST /batch` body through `aggregator/server.py` into `TRACEAggregator.submit` and its flush. |
| `fuzz_checkpoint.py` | Registry day files through `CheckpointRecord.from_dict`, `verify_checkpoint_chain` and `verify_chain_against_entries`; fuzzed fields overlaid on a genuine signed chain; `verify_checkpoint_link` on arbitrary pairs. |
| `fuzz_proofs.py` | RFC 9162 inclusion (`trace_verify._verify.verify_inclusion`) and MMR inclusion and consistency (`trace_verify._mmr`), each against a genuine tree built by the producer-side code. |
| `fuzz_trace_verify.py` | What `trace-verify` reads: a witness receipt and checkpoint through `_witness.verify`, and claim, proof and entry files through `main()`, for the inclusion check and `chain`. |

## The properties

No target stops at "does not crash".

* Every function either returns or raises the error its contract names.
  `verify_checkpoint_link`, `verify_checkpoint_chain` and the MMR verifiers
  never raise; the parsers raise `ValueError`; `trace-verify` exits 0, 1 or 2
  and never prints a traceback; the aggregator answers 200, 400, 413 or 422.
* Nothing verifies under a key other than the genuine one. Each target holds a
  fixed test key or pins the published one, and the fuzzer cannot sign, so an
  accepted claim, checkpoint or receipt that is not byte-for-byte the genuine
  signed body is a bypass.
* A proof for leaf i never verifies for another leaf, another index or another
  root, and a proof that verifies is the genuine proof. For RFC 9162 the leaf
  count is excluded from that property on purpose: the verifier takes it from
  the signed registry entry, and one audit path can be valid for two tree
  sizes.

## Standing of the targets when added

The first local runs found four bugs, all fixed with regression tests in
`tests/test_fuzz_regressions.py`:

* `CheckpointRecord.from_dict` raised `KeyError` or `TypeError` on a missing or
  mistyped member, and `OverflowError` for an `Infinity` size in its
  consistency proof, so `trace-verify chain` printed a traceback for a
  malformed day file. It also let a non-string `root` through to
  `verify_checkpoint_link`, which documents that it never raises and raised
  `TypeError`.
* A registry entry whose `canonicalization_id` is a JSON array made
  `canonical_claim_bytes` raise `TypeError` (unhashable), which the inclusion
  check does not catch.
* `trace-verify` caught `JSONDecodeError` only, so a file that is not UTF-8 or
  is nested past the recursion limit escaped as a traceback instead of exit 2.
* `POST /batch` with a body nested past the recursion limit raised
  `RecursionError` out of `do_POST`: no response, and a dead handler thread.

## Running locally

```
git clone https://github.com/google/clusterfuzzlite --depth 1 /tmp/clusterfuzzlite
python /tmp/clusterfuzzlite/infra/helper.py build_image --external $PWD
python /tmp/clusterfuzzlite/infra/helper.py build_fuzzers --external --sanitizer address $PWD
python /tmp/clusterfuzzlite/infra/helper.py run_fuzzer --external $PWD fuzz_checkpoint
```

A crash is written to a file whose path the runner prints; pass that file back
as the last argument to reproduce it. Seed corpora are built at image build
time by `seed_corpora.py` from committed fixtures, which it only reads.

## In CI

`cflite_pr.yml` fuzzes only code the pull request touched, for five minutes.
`cflite_batch.yml` runs every target nightly, 30 minutes shared between them.
Both are read-only and report through the job log and the crash artifact
rather than as code-scanning alerts.
