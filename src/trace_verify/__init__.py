"""trace-verify: verify TRACE claim inclusion proofs against the public registry.

Standard library only. Anchor format v1 (docs/anchor-format.md).
"""

from __future__ import annotations

__version__ = "0.3.3"
__anchor_format_version__ = 1
__all__ = [
    "verify_inclusion",
    "canonical_claim_bytes",
    "ANCHOR_LEAF_CANONICALIZATIONS",
    "UnknownCanonicalizationError",
    "MismatchedCanonicalizationLayerError",
]

from trace_verify._verify import (
    ANCHOR_LEAF_CANONICALIZATIONS,
    MismatchedCanonicalizationLayerError,
    UnknownCanonicalizationError,
    canonical_claim_bytes,
    verify_inclusion,
)
