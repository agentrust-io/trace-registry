"""trace-verify: verify TRACE claim inclusion proofs against the public registry.

Standard library only. Anchor format v1 (docs/anchor-format.md).
"""

from __future__ import annotations

__version__ = "0.1.0"
__anchor_format_version__ = 1
__all__ = ["verify_inclusion", "canonical_claim_bytes"]

from trace_verify._verify import canonical_claim_bytes, verify_inclusion
