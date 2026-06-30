"""Entry point: python -m aggregator [options]

Usage:
    python -m aggregator [--host HOST] [--port PORT]
                         [--registry-dir DIR] [--proofs-dir DIR]
                         [--flush-interval SECONDS] [--max-batch N]
                         [--git-commit]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aggregator",
        description="TRACE log aggregator: HTTP intake service for multi-producer anchoring.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="port (default: 8765)")
    parser.add_argument("--registry-dir", default=None, metavar="DIR",
                        help="registry root (default: registry/ in repo root)")
    parser.add_argument("--proofs-dir", default=None, metavar="DIR",
                        help="proofs root (default: proofs/ in repo root)")
    parser.add_argument("--flush-interval", type=float, default=900.0, metavar="SECONDS",
                        help="seconds between automatic flushes (default: 900 = 15 min)")
    parser.add_argument("--max-batch", type=int, default=0, metavar="N",
                        help="trigger early flush when pending claims >= N (0 = never, default: 0)")
    parser.add_argument("--git-commit", action="store_true",
                        help="run git add + git commit after each flush")
    parser.add_argument("--producers-dir", default=None, metavar="DIR",
                        help="producer key directory (default: producers/ in repo root)")
    parser.add_argument("--no-verify-signatures", action="store_true",
                        help="DANGEROUS: anchor claims without verifying producer "
                             "signatures (default: verify and reject unverified claims)")
    args = parser.parse_args(argv)

    registry_dir = Path(args.registry_dir) if args.registry_dir else REPO_ROOT / "registry"
    proofs_dir = Path(args.proofs_dir) if args.proofs_dir else REPO_ROOT / "proofs"
    producers_dir = Path(args.producers_dir) if args.producers_dir else REPO_ROOT / "producers"

    if args.no_verify_signatures:
        print(
            "WARNING: --no-verify-signatures is set; claims will be anchored "
            "WITHOUT verifying producer signatures. Do not use in production.",
            flush=True,
        )

    from aggregator._core import TRACEAggregator
    from aggregator.server import AggregatorHTTPServer

    aggregator = TRACEAggregator(
        registry_dir=registry_dir,
        proofs_dir=proofs_dir,
        flush_interval=args.flush_interval,
        max_batch_size=args.max_batch,
        git_commit=args.git_commit,
        producers_dir=producers_dir,
        verify_signatures=not args.no_verify_signatures,
    )

    server = AggregatorHTTPServer((args.host, args.port), aggregator)
    print(
        f"TRACE aggregator listening on {args.host}:{args.port} "
        f"(flush every {args.flush_interval}s, max_batch={args.max_batch})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
