# Terms of Use

TRACE Registry is a public, append-only log of anchor entries. These terms cover using it and
submitting to it.

They are version-controlled. The git history of this file is the record of what changed and when,
and it is the only change record: there is no separate notice mechanism to miss.

## Anchoring is not endorsement

An entry records that a signed Trust Record existed in a given form at a given time.

It is not a statement that the claim is true, that the agent behaved acceptably, that the policy
it ran under was sound, or that the producer is who they say they are. See
[LIMITATIONS.md](LIMITATIONS.md) for what an anchor does and does not establish.

Do not represent an entry in this registry as validation, certification, or approval by the
operator or by any maintainer.

## Who operates this

The operator of record is named in [MAINTAINERS.md](MAINTAINERS.md). It is OPAQUE Systems today.

The operator is expected to change. The registry is intended to be run by a neutral body, and
these terms travel with the service rather than with whoever is running it. A change of operator
is made in public, in this repository, like any other change.

None of that asks you to trust the operator, present or future. The argument for this registry is
that it is append-only, publicly mirrored, and verifiable without trusting whoever runs it, which
is the position [GOVERNANCE.md](GOVERNANCE.md) takes on the same question. If you find a case
where trusting the operator is still required, that is a bug worth filing.

## Submitting

Anyone may register as a producer and submit records. [CONTRIBUTING.md](CONTRIBUTING.md) describes
how.

When you submit, you are confirming two things. That you have the right to publish what you are
submitting. And that it contains nothing confidential, personal, or otherwise unsuited to
permanent public disclosure, because that is what publication here means.

You grant permission for what you submit to be published, copied, and redistributed under
[CC BY 4.0](LICENSE), which is the licence this registry's data carries. Mirrors depend on that
permission, and a mirror operated by someone who distrusts us is the point rather than a
side effect.

The maintainers may decline a producer registration, decline a submission, or deactivate a
registered key. The reason is recorded in the pull request, unless stating it publicly would
itself cause harm.

## Availability

The service is provided as is, with no warranty of any kind and no service level commitment.

Anchoring runs on a schedule rather than on demand, so there is no guaranteed latency between
submitting a record and seeing it anchored, and a scheduled run with nothing to anchor does
nothing at all.

There is no undertaking to operate this registry indefinitely. If operation ends, the log and its
history stay published for as long as is practical, and notice is given in this repository.

## Removal

The log is append-only, and the tamper-evidence depends on published entries staying where they
are. Entries are therefore not removable on request. Lawful removal requests are handled case by
case, as described in [PRIVACY.md](PRIVACY.md).

If a removal ever happens, it is recorded in this repository, stating what was removed and why. It
is not done silently. That commitment is the point of the log, and it is worth being plain that it
constrains the operator rather than you.

Two consequences worth understanding before you submit. A removal breaks verification for anyone
holding an earlier view of the log, which is what tamper-evidence means working correctly. And any
inclusion proof already issued for a removed entry stops reproducing the committed root, so
holders of that proof will see a failure rather than a silent change.

Do not submit anything on the assumption that it can be withdrawn.

## Changes

These terms change by pull request, in public, with history. Using the registry after a change
means the current version applies.

## Contact

Open an issue at https://github.com/agentrust-io/trace-registry/issues. For security matters use
[GitHub Security Advisories](https://github.com/agentrust-io/trace-registry/security/advisories/new)
rather than a public issue.
