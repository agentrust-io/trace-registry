#!/usr/bin/env python3
"""Repo-local entry point for the offline witness receipt verifier.

The implementation moved into the published package as
`trace_verify._witness`, so that `pip install "trace-verify[witness]"` and
`trace-verify receipt ...` reach the same code a reader of this repository
runs. This file stays because the evidence packets and the capture tool cite
it by path, and because a second copy of the verifier is exactly what should
not exist: it re-exports, it does not reimplement.

    python tools/verify_witness_receipt.py --checkpoint CP.json --response POST.json \
        --registry-key HEX --witness-key HEX --expected-log-id trace-registry/v1

is equivalent to:

    trace-verify receipt --checkpoint CP.json --response POST.json \
        --registry-key HEX --witness-key HEX --expected-log-id trace-registry/v1
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from trace_verify._witness import (  # noqa: E402
    FIELDS,
    load_json,
    read_protected,
    signing_body,
    signing_body_digest,
    verify,
)

__all__ = ['FIELDS', 'load_json', 'read_protected', 'signing_body',
           'signing_body_digest', 'verify', 'main']


def main(argv: list[str] | None = None) -> int:
    from trace_verify.__main__ import _main_receipt

    return _main_receipt(list(sys.argv[1:] if argv is None else argv))


if __name__ == '__main__':
    raise SystemExit(main())
