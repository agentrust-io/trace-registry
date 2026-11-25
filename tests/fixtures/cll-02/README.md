# CLL -02 known-answer vectors

Byte-exact copies of `vectors.json` and `SHA256SUMS` from
[`cll-02-vectors/`](https://github.com/action-state-group/checkpointed-local-log/tree/43300c3c91221f5ad9a601e67481cd8b55a7bd6b/cll-02-vectors)
in `action-state-group/checkpointed-local-log` at commit
`43300c3c91221f5ad9a601e67481cd8b55a7bd6b`.

| | |
|---|---|
| CLL draft | `draft-mih-scitt-checkpointed-local-log-02` |
| MMR profile | `draft-bryce-cose-receipts-mmr-profile-03`, algorithms from the editors' main at `f1320c0` (now `draft-ietf-scitt-receipts-mmr-profile`) |

The vectors are generated from the draft text, not from any implementation.
`tests/test_mmr_kat39.py` runs them against `trace_verify` and checks the file
against `SHA256SUMS`. `.gitattributes` marks this directory `-text` so a
checkout never rewrites line endings under the digest.

To refresh after a new CLL revision: copy both files from the new upstream
commit, update the commit above, and update the draft names in
`docs/mmr-checkpoint.md`.
