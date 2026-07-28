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

Verify it with `agentrust-trace-tests` 0.3.x. Version 0.4.0 and later require v0.2.
