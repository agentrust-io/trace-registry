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

The registry holds **three entries**: a software-only launch-day example
(`registry/2026/06/12.ndjson`) and a demonstration anchor produced for a conference
session (`registry/2026/09/01.ndjson`), both ours, and a Level 0 record from the
first outside producer, `bernstein/3.20.0` (`registry/2026/09/25.ndjson`). The machinery is
live and the format is real; the volume is not there yet. A scheduled run with
nothing to anchor is a no-op, so a long gap between entries reflects claim volume
rather than a broken pipeline.

Nothing here should be read as "operating at scale". It is a working accountability
layer waiting for production traffic.

## Next

- **Production claim volume**, from producers other than our own. The format is more
  valuable the more independent producers anchor into it, and right now the number
  of independent producers is one.
- **More independent mirrors.** Two organizations we do not operate hold registered
  mirrors (Sip Your Drink Ltd since 2026-09-20, HORIZON SHIELD since 2026-10-04).
  More are welcome. A mirror run by the AgenTrust project
  checks almost nothing: the value comes from an operator with no incentive to
  cover for us. See [MIRRORS.md](MIRRORS.md) and
  [docs/mirroring.md](docs/mirroring.md).
- **Maintainers who do not run a producer anchoring here** ([MAINTAINERS.md](MAINTAINERS.md)),
  for the same reason.
- **Automated submission to independent witnesses**, with receipts retained and verified
  under explicit key policies. Checkpointing itself is live since September 1;
  the external receipts so far (September 7, and October 20 from a second operator) were
  taken by hand, not by a deployed submission loop.
- **Receipt-bound witness time and grade**, if those properties are required by policy.
  The captured receipt authenticates a root, not the response's grade or an observation time.

## Later

- Parallel witnesses and split-view monitoring. The September 7 receipt covers checkpoint 1
  at one external operator. Since October 20 a second operator, HORIZON SHIELD (a party other
  than the registry operator, with its own key, which also holds a registered mirror), has
  receipts for checkpoints 1 and 2
  ([docs/evidence/witness-2026-10-20-nenrin](docs/evidence/witness-2026-10-20-nenrin/README.md)).
  Nothing there shows a track record or independence beyond a different operator and key.
  Continuous submission and independent split-view monitoring remain open.
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
