# Witness submission journal (review draft)

`tools/witness_journal.py` supplies a durable SQLite claim around the existing
receipt capture tool. It is an operator-invoked staging tool, not an enabled
external submission service. No registry history or published checkpoint changes.

Install the existing runtime and witness requirements, with `PYTHONPATH=src`.
`python tools/witness_journal.py --help` describes the three commands:

1. `--database state.sqlite enqueue --checkpoint FILE --witness-base URL
   --expected-log-id ID --registry-key HEX --witness-key HEX` stores exact bytes
   and an explicitly pinned trust policy, returning a deterministic identity.
2. `--database state.sqlite submit ID --evidence-root DIRECTORY` makes at most one
   capture attempt for that identity. This command performs external network I/O.
3. `--database state.sqlite status ID` returns state and retained evidence location.

The identity hashes exact checkpoint bytes plus the serialized trust policy. An
identical enqueue is idempotent. Different serialization or keys is deliberately
a different identity: operators must not use policy changes to bypass unresolved
submissions. This is not semantic checkpoint deduplication across key rotation.

`BEGIN IMMEDIATE` serializes claims. `synchronous=FULL` commits the claim before
network I/O. Evidence directories are exclusive and never overwritten. Successful
capture means the existing verifier checked the receipt cryptographically and the
three captured responses agreed. HTTP failures, verification failures and caught
exceptions become `unknown`. A killed process can leave `inflight`; neither state
is automatically claimable. Keep the database and its evidence directory together
on durable local storage with one operational owner. Do not restore stale database
backups over newer submission evidence. This is not a distributed queue.

There is intentionally no automatic retry or reset command. A lost acknowledgement
can mean the witness committed the checkpoint; retrying blindly cannot establish
exactly-once behavior. Readback reconciliation, key rotation, retention/backups,
backlog monitoring and required-versus-best-effort publication remain explicit
maintainer decisions before scheduled deployment. An inflight record requires
operator investigation; a live worker must not be presumed dead by a timeout.

Seven tests cover two concurrent workers, restart, crash/inflight refusal,
lost-acknowledgement exceptions, failed capture, immutable evidence, identity
binding, and replay of the archived real cryptographic receipt (including a wrong
witness key). The transport is mocked; no external witness was contacted.
