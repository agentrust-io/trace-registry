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

**One checkpoint has an independently operated witness receipt.**
Checkpoint 1's signing-body digest is included under a root signed by Action State's witness key.
The receipt returned on September 7, 2026 (Pacific time) verifies offline against an explicit
key pin, and matches the separately fetched receipt. See
[the evidence packet](docs/evidence/witness-2026-09-07/README.md).

This is a one-checkpoint demonstration, not continuous or reciprocal witnessing. It does not
prove registry continuity, prevent split views, cover the June entry, or prove payload retention.
The JSON response reports `countersigned-observed`, but that grade is not signed inside this
receipt, and this receipt signs a Merkle root without a witness timestamp: the checkpoint
timestamp is the registry signer's assertion, and our capture time is an observer's local
record. Do not present either as a cryptographically authenticated witness time. Both are
properties of a receipt rather than of the profile. A witness may sign a registration time as
a CWT `iat` and its grade under a private-use label; where it does, `verify_witness_receipt`
reports `witness_time_established` and `grade_cryptographically_bound`, and where it does not,
both stay false. Read those two fields rather than this paragraph. They are read from the
receipt's protected header, which the witness signature covers, so a witness that later deploys
support for them changes what a subsequent receipt carries and cannot change what an issued one
carries.

A witness upgrade does not re-stamp an existing checkpoint, and there is no path by which it
could. The witness registers a checkpoint by its content-addressed entry hash and deduplicates
on it, so re-submitting an already-witnessed checkpoint returns the original receipt, header and
all, rather than issuing a second one under the new code. That is the correct behaviour: a
witness that reissued a different receipt for a checkpoint it had already witnessed would be a
witness whose receipts are not final. The consequence for this registry is that a receipt
carrying `iat` or a signed grade requires a checkpoint the witness has not seen, which means the
log has to advance first. Checkpoint 1 will read `witness_time_established: false` and
`grade_cryptographically_bound: false` for as long as it exists, and no deployment on either
side changes that. Confirmed with the witness operator on September 12, 2026, after their
deploy, and recorded here because both sides had assumed otherwise in their own runbooks.

`grade_cryptographically_bound` compares two values and a witness has to move both. The signed
grade counts only when it equals the grade the HTTPS response reports, so a witness that starts
signing a grade while its response body still reports the previous one leaves the field false,
correctly: a signed value that disagrees with the untrusted one binds nothing. The value itself
is opaque to the verifier and is not fixed by this agreement. The September 7 response reported
`countersigned-observed`; the operator's post-deploy receipts sign `mmr-verified`. Neither is a
registered term, and the verifier reads the label as a string rather than interpreting it. The September 7 receipt's protected header is algorithm and tree profile only
(`{1: -8, 395: 1}`, receipt SHA-256
`4e075e8494da20ab72a9b8077432663317c4dad58aa8f8fdcd452c166c20bdd7`), and all three captured
copies are those same bytes. The receipt binds the
checkpoint's nine-field signing body by digest; its signature and optional consistency proof
are not included in that witnessed digest. Registry signature verification is a separate check.

Two properties of that reading are agreements with the witness operator rather than properties
of COSE or of RFC 9597, and are recorded here so either side can cite them. The accepted CWT
claim set is exactly `iat`: RFC 9597's claims map is general, so a witness adding `iss`, `sub`
or any other registered claim is refused as unreviewed until this line changes, which makes it
a coordinated change rather than an outage. And the grade label `-65537` is provisional, chosen
from the private-use range by bilateral agreement rather than registered; a third implementer
must not read it as standard, and if a registered label is assigned the value moves under a
migration note sent before the change. A signed `iat` is also required to fall between the
checkpoint's own timestamp and thirty days after it, because a witness cannot have registered a
checkpoint that did not yet exist; the lower bound is the real cross-check and the upper bound
only rejects a clock that is implausible on its face.

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

**Checkpointed, but only from the first checkpoint onward.**
Signed MMR checkpoints are built and running in the scheduled pipeline
([docs/checkpoint-architecture.md](docs/checkpoint-architecture.md)). Checkpoint 1 was published
on 2026-09-01 under `log_id trace-registry/v1`. Two consequences a verifier should know. The
checkpoint chain folds **only** entries that carry an `mmr_checkpoint`, so the pre-checkpoint
entry of 2026-06-12 was never a leaf of this log and is deliberately never folded in
retroactively. And a checkpoint attests consistency of the log's own history, which is not the
same as coverage: see "What an anchor does not prove" above.

**Reference tooling is one implementation, not the definition.**
The anchor construction is specified in [docs/anchor-format.md](docs/anchor-format.md) so that a
third party can write a verifier from that document alone. Where the tools in `tools/` and the
document disagree, the document is what other implementations were written against, and the
disagreement is a bug worth reporting.
