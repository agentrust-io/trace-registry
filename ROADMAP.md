# Roadmap

## Now

- **The anchor format is specified and stable enough to implement against**
  ([docs/anchor-format.md](docs/anchor-format.md)). A third party can write a
  verifier from that document alone; the tooling here is one implementation, not
  the definition.
- **`trace-verify` is on PyPI** and the reference verifier is a small,
  standard-library-only file precisely so it can be audited rather than trusted.
- **Anchoring runs on a schedule** and verifies producer signatures before
  anchoring anything.
- **Mirroring is documented and checked** ([docs/mirroring.md](docs/mirroring.md),
  `check-mirrors`), because the operator being checkable by strangers is the point.

## Honest status

The registry holds **two entries**, neither of them production: a software-only
launch-day example (`registry/2026/06/12.ndjson`) and a demonstration anchor
produced for a conference session (`registry/2026/09/01.ndjson`). The machinery is
live and the format is real; the volume is not there yet. A scheduled run with
nothing to anchor is a no-op, so a long gap between entries reflects claim volume
rather than a broken pipeline.

Nothing here should be read as "operating at scale". It is a working accountability
layer waiting for production traffic.

## Next

- **Production claim volume**, from producers other than our own. The format is more
  valuable the more independent producers anchor into it, and right now the number
  of independent producers is zero.
- **An independent mirror we do not operate.** A mirror run by OPAQUE Systems
  checks almost nothing: the value comes from an operator with no incentive to
  cover for us. See [MIRRORS.md](MIRRORS.md) and
  [docs/mirroring.md](docs/mirroring.md).
- **Maintainers from outside OPAQUE Systems** ([MAINTAINERS.md](MAINTAINERS.md)),
  for the same reason.
- **Automated submission to independent witnesses**, with receipts retained and verified
  under explicit key policies. Checkpointing itself is live since September 1;
  the first external receipt is a manual demonstration, not a deployed submission loop.
- **Receipt-bound witness time and grade**, if those properties are required by policy.
  The captured receipt authenticates a root, not the response's grade or an observation time.

## Later

- Parallel witnesses and an independent mirror. The September 7 receipt demonstrates
  one checkpoint at one external operator; see the evidence packet linked from README.
  A second operator, continuous submission and independent split-view monitoring remain open.
- A conformance suite for third-party verifier implementations, so "I implemented
  the anchor format" is checkable rather than asserted.

## What we will not do

- **Rewrite a published entry.** Not to fix a typo, not to reformat. Corrections
  are appended. See [GOVERNANCE.md](GOVERNANCE.md); this is the rule the whole
  thing rests on.
- **Claim the registry proves more than inclusion.** Verifying inclusion proves the
  signed claim bytes were anchored at that timestamp. It does not validate the
  claim's signature against a producer key, and it does not say the claim is
  *true*: it says it was recorded and cannot be quietly un-recorded.

## Influencing this

Open an issue. If you are evaluating TRACE and want to run a mirror or hold
maintainer rights, say so explicitly; both are more useful to us than a PR.
