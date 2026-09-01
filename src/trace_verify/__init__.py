"""trace-verify: verify TRACE claim inclusion proofs against the public registry.

Standard library only. Anchor format v1 (docs/anchor-format.md).
"""

from __future__ import annotations

__version__ = "0.4.0"
__anchor_format_version__ = 1
__all__ = [
    "verify_inclusion",
    "canonical_claim_bytes",
    "ANCHOR_LEAF_CANONICALIZATIONS",
    "UnknownCanonicalizationError",
    "MismatchedCanonicalizationLayerError",
    "CheckpointRecord",
    "verify_checkpoint_signature_offline",
    "verify_checkpoint_link",
    "verify_checkpoint_chain",
]

from trace_verify._verify import (
    ANCHOR_LEAF_CANONICALIZATIONS,
    MismatchedCanonicalizationLayerError,
    UnknownCanonicalizationError,
    canonical_claim_bytes,
    verify_inclusion,
)
from trace_verify._checkpoint import (
    CheckpointRecord,
    verify_checkpoint_chain,
    verify_checkpoint_link,
    verify_checkpoint_signature_offline,
)
