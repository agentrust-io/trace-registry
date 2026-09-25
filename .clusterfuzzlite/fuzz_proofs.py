#!/usr/bin/python3
"""Fuzz the two proof verifiers a reader runs on proofs someone else supplied.

RFC 9162 inclusion (trace_verify._verify.verify_inclusion) checks one claim
against a batch Merkle root. MMR inclusion and consistency
(trace_verify._mmr.verify_inclusion / verify_consistency) check the
registry-wide log the checkpoints sign.

Every iteration builds a genuine tree with the producer-side code
(aggregator._core._build_tree for batches, _mmr.add_leaf and the proof
builders for the log) and first asserts the genuine proof verifies, so a
builder/verifier drift fails here too. Then it attacks it.

Properties:
  * a proof for leaf i never verifies for a different leaf, a different
    index or a different root;
  * a proof that verifies is the genuine one (the fuzzer cannot find a
    second path without a SHA-256 collision, so any hit is a verifier bug);
  * the MMR verifiers never raise, and the parsers raise only ValueError.
"""
import hashlib
import json
import sys
from pathlib import Path

import atheris

# Local runs import the tools from the checkout. The ClusterFuzzLite build
# bundles them through PyInstaller --paths instead (build.sh).
_ROOT = Path(__file__).resolve().parents[1]
for _p in (_ROOT, _ROOT / "src"):
    if (_p / "aggregator").is_dir() or (_p / "trace_verify").is_dir():
        sys.path.insert(0, str(_p))

with atheris.instrument_imports():
    from aggregator import _core
    from trace_verify import _mmr
    from trace_verify._verify import (
        canonical_claim_bytes,
        decode_hash,
        verify_inclusion,
    )


def _claims(n: int) -> list:
    return [{"producer": "fuzz/1.0.0", "seq": k} for k in range(n)]


class _Reader:
    """Fixed-layout reader: small integers from the front, the rest as payload.

    Used instead of atheris.FuzzedDataProvider so a seed file means the same
    thing to the fuzzer as it does to seed_corpora.py and a local replay.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def ConsumeIntInRange(self, lo: int, hi: int) -> int:
        nbytes = max(1, ((hi - lo).bit_length() + 7) // 8)
        raw = self.ConsumeBytes(nbytes).ljust(nbytes, b"\0")
        return lo + int.from_bytes(raw, "big") % (hi - lo + 1)

    def ConsumeBool(self) -> bool:
        return bool(self.ConsumeIntInRange(0, 1))

    def ConsumeBytes(self, n: int) -> bytes:
        out = self._data[self._pos:self._pos + n]
        self._pos += len(out)
        return out

    def ConsumeUnicodeNoSurrogates(self, n: int) -> str:
        return self.ConsumeBytes(n).decode("utf-8", "replace")

    def remaining_bytes(self) -> int:
        return len(self._data) - self._pos


def _as_bytes(value):
    if isinstance(value, dict):
        return {k: _as_bytes(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_as_bytes(v) for v in value]
    if isinstance(value, str) and value not in ("inclusion", "consistency"):
        return bytes.fromhex(value)
    return value


def _fuzz_digest(fdp) -> bytes:
    return fdp.ConsumeBytes(32).ljust(32, b"\0")


def _batch(fdp) -> None:
    n = fdp.ConsumeIntInRange(1, 64)
    i = fdp.ConsumeIntInRange(0, n - 1)
    claims = _claims(n)
    root, paths = _core._build_tree([_core._leaf_hash(c) for c in claims])
    path = [decode_hash(h) for h in paths[i]]
    assert verify_inclusion(claims[i], i, path, n, root), (n, i)

    mode = fdp.ConsumeIntInRange(0, 5)
    if mode == 0 and n > 1:
        j = fdp.ConsumeIntInRange(0, n - 1)
        if j != i:
            assert not verify_inclusion(claims[j], i, path, n, root), ("leaf", n, i, j)
            assert not verify_inclusion(claims[i], j, path, n, root), ("index", n, i, j)
    elif mode == 1:
        other = _fuzz_digest(fdp)
        if other != root:
            assert not verify_inclusion(claims[i], i, path, n, other), ("root", n, i)
    elif mode == 2:
        k = fdp.ConsumeIntInRange(0, 8)
        fuzzed = [_fuzz_digest(fdp) for _ in range(k)]
        if verify_inclusion(claims[i], i, fuzzed, n, root):
            assert fuzzed == path, ("second path", n, i)
    elif mode == 3:
        # The entry's leaf_index / leaf_count come from JSON, so any type.
        raw = fdp.ConsumeBytes(fdp.remaining_bytes())
        try:
            value = json.loads(raw)
        except (ValueError, RecursionError):
            return
        try:
            verify_inclusion(claims[i], value, path, n, root)
            verify_inclusion(claims[i], i, path, value, root)
        except ValueError:
            pass
    elif mode == 4:
        text = fdp.ConsumeUnicodeNoSurrogates(80)
        try:
            decode_hash(text)
        except ValueError:
            pass
    else:
        # canonicalization_id comes from the registry entry: a string in a
        # well-formed entry, anything JSON can express in a hostile one.
        raw = fdp.ConsumeBytes(fdp.remaining_bytes())
        try:
            cid = json.loads(raw)
        except (ValueError, RecursionError):
            cid = raw.decode("latin-1")
        try:
            canonical_claim_bytes(claims[i], canonicalization_id=cid, raw_bytes=b"{}")
        except ValueError:
            pass


def _log(fdp) -> None:
    m = fdp.ConsumeIntInRange(1, 40)
    store = _mmr.MemoryNodeStore()
    bodies = [hashlib.sha256(b"leaf-%d" % k).digest() for k in range(m)]
    sizes = []
    for b in bodies:
        _mmr.add_leaf(store, _mmr.leaf_hash(b))
        sizes.append(store.size())
    size = store.size()
    root = _mmr.root_from_peaks([store.node(p) for p in _mmr.peaks(size)])

    i = fdp.ConsumeIntInRange(0, m - 1)
    proof = _mmr.inclusion_proof(store, i, size)
    assert _mmr.verify_inclusion(root, size, i, bodies[i], proof), (m, i)

    a = fdp.ConsumeIntInRange(0, m - 1)
    size_a = sizes[a]
    root_a = _mmr.root_from_peaks([store.node(p) for p in _mmr.peaks(size_a)])
    cproof = _mmr.consistency_proof(store, size_a, size)
    assert _mmr.verify_consistency(root_a, size_a, root, size, cproof), (m, a)

    mode = fdp.ConsumeIntInRange(0, 4)
    if mode == 0:
        j = fdp.ConsumeIntInRange(0, m - 1)
        if j != i:
            assert not _mmr.verify_inclusion(root, size, i, bodies[j], proof), ("leaf", i, j)
            moved = _mmr.InclusionProof(**{**proof.__dict__, "leaf_index": j})
            assert not _mmr.verify_inclusion(root, size, j, bodies[i], moved), ("index", i, j)
        other = _fuzz_digest(fdp)
        if other != root:
            assert not _mmr.verify_inclusion(other, size, i, bodies[i], proof), "root"
            assert not _mmr.verify_consistency(root_a, size_a, other, size, cproof), "root_b"
    elif mode in (1, 2):
        raw = fdp.ConsumeBytes(fdp.remaining_bytes())
        try:
            doc = json.loads(raw)
        except (ValueError, RecursionError):
            return
        if not isinstance(doc, dict):
            return
        genuine = (proof if mode == 1 else cproof).to_dict()
        merged = {**genuine, **doc}
        parse = _mmr.InclusionProof.from_dict if mode == 1 else _mmr.ConsistencyProof.from_dict
        try:
            fuzzed = parse(merged)
        except ValueError:
            return
        if mode == 1:
            ok = _mmr.verify_inclusion(root, size, i, bodies[i], fuzzed)
        else:
            ok = _mmr.verify_consistency(root_a, size_a, root, size, fuzzed)
        if ok:
            # Compared as bytes: fromhex accepts upper case and spaces, which
            # is the same proof spelled differently, not a second proof.
            assert _as_bytes(fuzzed.to_dict()) == _as_bytes(genuine), ("second proof", merged)
    elif mode == 3:
        # Replace one witness element with fuzzed bytes.
        w = list(proof.witness)
        if w:
            k = fdp.ConsumeIntInRange(0, len(w) - 1)
            w[k] = _fuzz_digest(fdp).hex()
            fuzzed = _mmr.InclusionProof(**{**proof.__dict__, "witness": tuple(w)})
            if _mmr.verify_inclusion(root, size, i, bodies[i], fuzzed):
                assert tuple(w) == proof.witness, "second witness"
    else:
        # Arbitrary sizes and indices: must be a False, never an exception.
        s = fdp.ConsumeIntInRange(0, 2**51)
        li = fdp.ConsumeIntInRange(0, 2**51)
        assert _mmr.verify_inclusion(root, s, li, bodies[i], proof) in (True, False)
        assert _mmr.verify_consistency(root_a, s, root, li, cproof) in (True, False)


def TestOneInput(data: bytes) -> None:
    fdp = _Reader(data)
    if fdp.ConsumeBool():
        _batch(fdp)
    else:
        _log(fdp)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
