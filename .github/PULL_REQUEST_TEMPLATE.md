## What and why

<!-- What changes, and what problem it solves. -->

## Registry impact

- [ ] This PR does **not** modify any existing line under `registry/`

Existing entries are append-only. If you are changing one, say why here: mirrors
and auditors may already have observed the current commit hashes, and a rewrite
diverges them.

## Checks

- [ ] `pytest` passes
- [ ] Registry and producer files still validate (`tools/validate_registry.py`,
      `tools/validate_producers.py`)
- [ ] If the anchor format or verification semantics changed, `docs/anchor-format.md`
      is updated in the same PR, and existing inclusion proofs still verify
- [ ] Commits are signed off (DCO)
