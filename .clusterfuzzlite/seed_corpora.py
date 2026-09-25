#!/usr/bin/env python3
"""Build each fuzz target's seed corpus from files committed in this repository.

    python .clusterfuzzlite/seed_corpora.py OUT_DIR

writes OUT_DIR/<target>_seed_corpus.zip, the name ClusterFuzzLite looks for.
Fixtures are only read. Each seed is the target's mode byte followed by its
payload, in the format the target's docstring describes.
"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> bytes:
    return (ROOT / rel).read_bytes()


def _text(rel: str) -> str:
    return _read(rel).decode("utf-8")


def _registry_files() -> list[str]:
    return sorted(str(p.relative_to(ROOT)).replace("\\", "/") for p in (ROOT / "registry").rglob("*.ndjson"))


def seeds() -> dict[str, list[bytes]]:
    claim = _read("samples/example-trust-record.json")
    claim_obj = json.loads(claim)
    proof = _text("samples/inclusion-proof.json")
    first_entry = _text("registry/2026/06/12.ndjson")
    day_files = [_text(p) for p in _registry_files()]
    witness = "docs/evidence/witness-2026-09-07/"
    checkpoint = json.loads(_read(witness + "checkpoint-1.json"))
    response = json.loads(_read(witness + "witness-post.json"))

    def mode(m: int, payload) -> bytes:
        if not isinstance(payload, bytes):
            payload = json.dumps(payload).encode("utf-8")
        return bytes([m]) + payload

    return {
        "fuzz_intake": [
            mode(0, claim),
            mode(1, {"seq": 2}),
            mode(1, {"producer": "cmcp-gateway/0.1.0"}),
            mode(2, {"producer": claim_obj.get("producer", "cmcp-gateway/0.1.0"), "claims": [claim_obj]}),
            mode(2, {"canonicalization_id": "as-transmitted", "claims": [claim.decode("utf-8")]}),
            mode(3, {}),
            mode(3, {"as_transmitted": True}),
        ],
        "fuzz_checkpoint": (
            [mode(0, "".join(day_files).encode("utf-8"))]
            + [mode(0, f.encode("utf-8")) for f in day_files]
            + [mode(1, {"i": 2, "cp": {"root": "00" * 32}}), mode(1, {"drop": 4}), mode(1, {})]
            + [mode(2, [json.loads(ln)["mmr_checkpoint"] for f in day_files for ln in f.splitlines()
                        if ln.strip() and "mmr_checkpoint" in json.loads(ln)][:2])]
        ),
        # fuzz_proofs reads fixed-layout bytes: tree kind, sizes, index, mode,
        # then a payload. No committed fixture has that shape, so these are
        # one seed per mode, with JSON payloads where the mode parses JSON.
        "fuzz_proofs": (
            [bytes([1, 12, 5, m]) + bytes(range(40, 104)) for m in range(5)]
            + [bytes([1, 12, 5, 5]) + b'"sorted-key"', bytes([1, 12, 5, 5]) + b'["jcs"]',
               bytes([1, 12, 5, 3]) + b'"3"']
            + [bytes([0, 20, 7, 3, m]) + bytes(range(64)) for m in (0, 3, 4)]
            + [bytes([0, 20, 7, 3, 1]) + b'{"witness": []}',
               bytes([0, 20, 7, 3, 2]) + b'{"old_peaks": [], "size_a": 0}']
        ),
        "fuzz_trace_verify": [
            mode(0, {"checkpoint": checkpoint, "response": response}),
            mode(1, {"claim": claim.decode("utf-8"), "proof": proof, "entry": first_entry}),
            mode(1, {"claim": claim.decode("utf-8"), "proof": proof, "entry": first_entry, "json": True}),
            mode(2, {"entries": "".join(day_files)}),
        ],
    }


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else Path(".")
    out.mkdir(parents=True, exist_ok=True)
    for target, corpus in seeds().items():
        with zipfile.ZipFile(out / f"{target}_seed_corpus.zip", "w") as zf:
            for i, seed in enumerate(corpus):
                zf.writestr(f"seed-{i:03d}", seed)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
