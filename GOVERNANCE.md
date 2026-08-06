# Governance

This repository is an **append-only public record**. That shapes its governance
more than the usual open-source concerns do: the thing being governed is not
mainly a codebase, it is a log that third parties are asked to trust without
trusting its operator.

## The rule that outranks the others

**A published registry entry is never rewritten.** Not to fix a typo, not to
reformat, not to correct a producer name. Git's commit history is the
tamper-evidence layer: mirrors and auditors record the commit hashes they have
observed, and rewriting a published line diverges them from everyone else's copy.
A registry whose operator edits history is worth nothing, and "it was only a small
edit" is exactly the claim an operator under pressure would make.

Corrections are made by **appending** a superseding entry and documenting it, never
by editing. If an entry is wrong, say so in a new entry and in
[docs/anchor-format.md](docs/anchor-format.md).

This binds the Project Lead as much as anyone. If the rule is ever broken, the
honest response is to announce it publicly rather than quietly re-anchor, because
mirrors will detect it either way ([MIRRORS.md](MIRRORS.md)).

## Roles

### Contributor

Anyone who submits a PR, files an issue, or runs a mirror. No appointment needed.
Follow the [Code of Conduct](CODE_OF_CONDUCT.md) and sign off commits (DCO).

### Mirror operator

Runs an independent copy of this registry and reports divergence. Mirrors are the
check on the operator, so they are deliberately outside this governance: a mirror
operator needs no permission from us and can be someone who distrusts us. See
[docs/mirroring.md](docs/mirroring.md).

### Maintainer

Review and merge rights, and publish rights on the `trace-verify` package.
Responsible for keeping the anchor format and the verifier honest with each other.

**Advancement**: 3+ merged substantive PRs, nominated by a Maintainer, confirmed by
the Project Lead.

### Project Lead

Final decision authority on the anchor format, verification semantics, and
Maintainer appointments. Currently Imran Siddique (OPAQUE Systems). See
[MAINTAINERS.md](MAINTAINERS.md).

## Changes that need extra care

A change to the anchor format or to verification semantics can **invalidate
inclusion proofs third parties already hold**. Those changes require:

1. a statement in the PR of what happens to existing proofs;
2. a version marker in `docs/anchor-format.md`, so a verifier can tell which rules
   applied to which entries;
3. existing proofs continuing to verify, or an explicit, documented break.

This is why `/registry/`, `/schema/`, `/src/`, `/tools/` and
`docs/anchor-format.md` all carry code-owner review in
[CODEOWNERS](.github/CODEOWNERS).

## Decision-making

Consensus where possible, Project Lead decides where not. Disagreements about the
format belong in issues rather than in review comments, so the reasoning is
findable later by someone auditing why a rule exists.

## Conflict of interest

OPAQUE Systems operates a producer that anchors into this registry. That is a
conflict, and the answer to it is not a promise of good behaviour: it is that the
registry is append-only, publicly mirrored, and verifiable without trusting the
operator. If you find a case where trusting us is still required, that is a bug
worth filing.
