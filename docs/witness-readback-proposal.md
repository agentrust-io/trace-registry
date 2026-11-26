# Proposal: reconcile an unknown witness submission

Status: informative design draft for #144; no deployment or protocol change.
The journal deliberately leaves a lost acknowledgement in `unknown`/`inflight`.
This proposal preserves that refusal to resubmit automatically. A timeout does
not prove that the witness failed to commit.

## Proposed operator flow

1. Freeze the original attempt: source checkpoint bytes, submission digest,
   witness identity, pinned verification policy and attempt identifier.
2. Fetch readback only from a separately configured witness endpoint. Never
   follow a URL supplied by the evidence without the existing network policy.
3. Verify returned evidence with the existing cryptographic verifier, including
   exact checkpoint identity and the pinned witness key. Archive the response,
   verification inputs and result in a new immutable attempt directory.
4. In one journal transaction, compare the current attempt and policy identity
   with the frozen values. Only matching authenticated inclusion may promote it
   to `verified`. Concurrent reconciliation cannot overwrite another result.
5. Missing data, timeout, malformed data, wrong key, wrong checkpoint or a policy
   change leaves the attempt unresolved. A negative HTTP lookup is not proof of
   absence. Conflicting authenticated responses are retained for investigation.

No resubmission follows from step 5. A safe retry would require a separate,
accepted idempotency/absence contract with the witness. This draft supplies none.

## Decisions requested

| Question | Conservative default pending agreement |
| --- | --- |
| What API and signed response establish inclusion? | None selected; no automatic promotion |
| Is lookup indexed by exact bytes, receipt ID or checkpoint identity? | Keep exact bytes plus trust-policy identity from #144 |
| How are key rotation and revoked keys handled? | Require explicit operator-selected policy; no key discovery |
| Can the witness prove non-inclusion or offer idempotent retry? | Neither assumed |
| Who retains readback archives and for how long? | Deployment decision; no deletion policy introduced |

## Implementation acceptance cases after agreement

Use a local signed witness fixture with independently pinned keys. A committed
submission with a lost ACK and valid matching readback becomes verified once.
Wrong key, changed checkpoint, truncated response and unsigned absence remain
unknown. Concurrent workers and a crash before/after the journal transaction do
not lose the original evidence or cause resubmission. A changed policy cannot
reuse an earlier reconciliation verdict. Each rejection gets its own passing
control and a test that fails when its guard is disabled.

This is not witness availability, transparency completeness, exactly-once delivery
or deployment acceptance. No external witness is contacted by this document.
