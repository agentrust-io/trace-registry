# Samples

`example-trust-record.json` is a **TRACE v0.1** record, carrying the profile URI
`tag:agentrust.io,2026:trace-v0.1`.

The stack now emits **v0.2** (`tag:agentrust-io.com,2026:trace-v0.2`). The v0.1 URI
named a domain this project never controlled, which RFC 4151 does not permit for a
tag URI. See [trace-spec#107](https://github.com/agentrust-io/trace-spec/pull/107).

This sample was not rewritten because it carries a real signature over a payload
that includes the profile URI. Editing the string while keeping the signature would
produce a record that fails verification, which is a poor thing for a registry
sample to be. It regenerates with the rest of the recorded corpus.

## Verify the historical sample offline

From the repository root, install the verifier from this checkout and run:

```bash
python -m pip install .
python -m trace_verify --claim samples/example-trust-record.json --proof samples/inclusion-proof.json --entry registry/2026/06/12.ndjson
```

Expected: exit code 0 and `OK: claim is included in batch '2026-06-12-001'`
with `signature valid`. The command uses the local registry entry and producer
key. It checks the historical inclusion proof and producer signature; it does
not establish present-day freshness, current authorization or TRACE conformance.
The sample and its signed bytes are unchanged.

For historical conformance testing, the package is `agentrust-trace-tests`
0.3.x and its executable is `trace-tests`. That is a separate check: the sample
exceeds its default 24-hour freshness window. Increasing `--max-age` relaxes
that policy for archival inspection; a resulting pass does not make this old
record fresh. Version 0.4.0 and later require v0.2, so they cannot be used to
claim conformance for this v0.1 sample. Use the offline recipe above to
reproduce the registry's signature and inclusion result without changing a
freshness policy.

## This sample is not anchorable through the pipeline

`example-trust-record.json` carries no top-level `producer` field, so
`tools/batch_anchor.py` rejects it: the scheduled pipeline reads the producer
id from inside the signed body (see README, Anchoring claims). It anchors fine
with `tools/anchor.py --producer ...`, which takes the id as an argument.

That is not a defect in the sample and the sample must not be edited to fix it.
It carries a real signature over a body that does not include a `producer`
field, so adding one would break verification, for the same reason the v0.1
profile URI above was left alone. It is a verification sample. When the
recorded corpus regenerates, the replacement should carry `producer` in the
signed body so it demonstrates both paths.
