# Known Limitations

What the TRACE Registry does **not** do, and where its guarantees end. Honest scope boundaries
prevent misplaced trust.

## What an anchor does not prove

**An anchor says nothing about the claim's contents.**
Anchoring proves that a signed Trust Record existed in a particular form and was committed to this
log at a particular time. It does not establish that the agent behaved correctly, that the policy
it ran under was a good policy, that the measurement was meaningful, or that the producer's
description of its own runtime was accurate. A record of a bad run anchors exactly as cleanly as a
record of a good one.

**An inclusion proof proves membership, not correctness.**
`verify_inclusion` establishes that a specific claim was one of the leaves in a specific batch
under a specific Merkle root. That is the whole of what it establishes.

**Absence is not evidence.**
The anchoring job runs on a schedule and a run with nothing to anchor is a no-op that leaves no
entry. A gap in the log therefore means no claims were submitted, or that the pipeline did not
run, and the log itself does not distinguish the two.

## Where the tamper-evidence actually comes from

**Git history only protects observers who were already watching.**
The tamper-evidence argument is that rewriting a published entry diverges the commit hashes that
auditors and mirrors have already observed. That protects anyone holding an earlier view. It does
**not** protect a reader arriving for the first time today: with no prior observation of their own
and no independent copy to compare against, they cannot detect a rewrite that happened before they
arrived. They are trusting the operator.

**The operator and the log are currently the same party.**
OPAQUE Systems runs the anchoring pipeline and hosts the canonical repository, and there is no
mirror operated by anyone else. A mirror run by the operator checks almost nothing. Until an
organization with no incentive to cover for us holds a copy, the independence claim rests on
intent rather than on structure. See [MIRRORS.md](MIRRORS.md) and
[docs/mirroring.md](docs/mirroring.md).

**The log is not witnessed by anything outside itself.**
Anchoring this registry's own history into an external transparency log is on the roadmap and is
not built. Today the tamper-evidence is git plus mirrors, which is a record we host.

## What is in the log today

**Two entries, neither of them production.**
`registry/2026/06/12.ndjson` is a software-only launch-day example with advisory enforcement and a
zeroed measurement. `registry/2026/09/01.ndjson` is a demonstration anchor produced for a
conference session. Both were produced by us. No production Trust Record has been anchored.

**One independent producer count: zero.**
Both registered producers are ours. The format is more valuable the more independent producers
anchor into it, and that number has not started yet.

## Operational boundaries

**Producer key trust is an out-of-band concern.**
Anchoring verifies a submission's signature against a registered producer key. Deciding that a
given producer key legitimately represents the organization it claims to is not something this
registry does or can do for you.

**Not checkpointed.**
Checkpointing is designed ([docs/checkpoint-architecture.md](docs/checkpoint-architecture.md))
with explicit thresholds and is deliberately not built, because current volume does not warrant
it. Verification cost therefore grows with log size.

**Reference tooling is one implementation, not the definition.**
The anchor construction is specified in [docs/anchor-format.md](docs/anchor-format.md) so that a
third party can write a verifier from that document alone. Where the tools in `tools/` and the
document disagree, the document is what other implementations were written against, and the
disagreement is a bug worth reporting.
