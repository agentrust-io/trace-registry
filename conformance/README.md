# Portable verifier corpus, first slice

`verifier-v1.json` supplies 28 offline Boolean cases for batch inclusion under
both registered canonicalizations, registered producer signatures, MMR inclusion
and consistency, and pinned-key checkpoint signatures. Every operation includes
accepted and refused cases. Inputs, public synthetic keys and expected outcomes
travel together; no service, credentials or registry writes are needed.

Run the reference adapter from the repository root:

```
python tools/run_verifier_corpus.py -- python tools/conformance_adapter.py
```

A third-party adapter receives one JSON object on stdin with `id`, `operation`
and `input`; expectations are omitted from the request. IDs are opaque; this is not expectation
isolation from a trusted executable that can read the corpus on disk. It returns exactly
`{"id":"<same case id>","accepted":true}` or the Boolean false equivalent.
Each invocation has a five-second timeout. Crashes, extra output, a wrong ID,
integer-instead-of-Boolean verdict and malformed output fail the run; they never
count as a security refusal. Adapter commands are trusted local executables,
not sandboxed plugins. Do not run an untrusted command with this runner.

Batch inputs carry a decoded claim, zero-based leaf index, sibling hashes,
leaf count, lowercase root hex and declared canonicalization. As-transmitted
inputs additionally carry exact retained bytes as hex. These inputs test
inclusion, not signature authenticity. Producer cases supply a selected
producer ID and registered public key entries; the mismatched-producer negative
is re-signed so a bad signature cannot mask that binding check.

MMR cases use the local position-committed MMR profile already implemented in
`trace_verify._mmr`; this is separate from the per-batch tree and does not claim
external MMR wire interoperability. Checkpoint cases independently pin the key
instead of accepting the key named by a signed object as trusted configuration.

The ten multi-leaf cases use independent SHA-256 calculations for two-leaf
and three-leaf trees, every leaf position, and tampered siblings.

The original fixtures were generated deterministically with test-only keys and the existing
reference proof generator. This is a bounded regression corpus, not a new
normative format, a full independent oracle, a conformance level or complete
TRACE/certificate/registry-history verification. The runner's tests demonstrate
that accept-all, reject-all and crashed adapters cannot pass. Existing private
input-shape repairs and third-party operator evidence remain separate work.
