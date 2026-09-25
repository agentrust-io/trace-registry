#!/usr/bin/python3
"""Fuzz checkpoint parsing and checkpoint-chain verification.

`trace-verify chain` reads registry day files that anyone can hand a reader,
builds CheckpointRecord objects from the mmr_checkpoint member of each entry,
and runs verify_checkpoint_chain and verify_chain_against_entries over them.
verify_checkpoint_link and verify_checkpoint_chain document that they never
raise; CheckpointRecord.from_dict documents ValueError for malformed input.

Three modes, chosen by the first byte:
  0. The rest is an NDJSON day file (seeded from registry/*.ndjson).
  1. The rest is a JSON object overlaid on a genuine five-entry chain this
     target signs itself: {"i": n, "entry": {...}, "cp": {...}, "drop": n}.
  2. The rest is a JSON array [prev, curr] of two checkpoint objects.

Properties beyond "raises nothing undocumented":
  * a verified chain never changes signer;
  * a chain that verifies after an overlay is a prefix of the genuine chain,
    entry for entry and checkpoint for checkpoint: nothing verifies under a
    root or key other than the genuine one;
  * a link that verifies under this target's key has a genuine signing body.
"""
import copy
import json
import sys
from pathlib import Path

import atheris

_ROOT = Path(__file__).resolve().parents[1]
for _p in (_ROOT, _ROOT / "src"):
    if (_p / "aggregator").is_dir() or (_p / "trace_verify").is_dir():
        sys.path.insert(0, str(_p))

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    from aggregator._mmr_log import CheckpointLog, Ed25519CheckpointSigner
    from trace_verify._checkpoint import (
        CHECKPOINT_KIND,
        CheckpointRecord,
        entry_leaf_digest,
        verify_chain_against_entries,
        verify_checkpoint_chain,
        verify_checkpoint_link,
    )

# Fixed, published test key: this target signs its own seed chain and nothing else.
_PEM = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
)
_SIGNER = Ed25519CheckpointSigner(None, pem=_PEM)
_KEY_ID = _SIGNER.key_id


def _genuine_chain() -> list:
    log = CheckpointLog(None, log_id="trace-registry/v1", signer=_SIGNER, replay_entries=[])
    entries = []
    for k in range(5):
        ts = "2026-09-%02dT00:00:00Z" % (k + 1)
        entry = {
            "ts": ts,
            "merkle_root": "sha256:" + ("%02x" % k) * 32,
            "leaf_count": k + 1,
            "producer": "fuzz/1.0.0",
            "batch_id": "batch-%d" % k,
            "canonicalization_id": "sorted-key",
        }
        entry[CHECKPOINT_KIND] = log.append_entry(entry, timestamp=ts).to_dict()
        entries.append(entry)
    return entries


_GENUINE = _genuine_chain()
_GENUINE_LEAVES = [entry_leaf_digest(e) for e in _GENUINE]
_GENUINE_BODIES = [CheckpointRecord.from_dict(e[CHECKPOINT_KIND]).signing_body() for e in _GENUINE]


def _verify(entries: list):
    """What `trace-verify chain` does after reading the files.

    Returns (verified, checkpoints) or None when a checkpoint is malformed,
    which the CLI reports as a failure.
    """
    checkpointed = [e for e in entries if isinstance(e.get(CHECKPOINT_KIND), dict)]
    try:
        checkpoints = [CheckpointRecord.from_dict(e[CHECKPOINT_KIND]) for e in checkpointed]
    except ValueError:
        return None
    ok, errors = verify_checkpoint_chain(checkpoints)
    assert ok == (not errors), (ok, errors)
    entry_errors = verify_chain_against_entries(entries)
    assert isinstance(entry_errors, list)
    verified = bool(checkpoints) and ok and not entry_errors
    if verified:
        assert len({cp.key_id for cp in checkpoints}) == 1, "signer changed mid-chain"
    return verified, checkpointed, checkpoints


def _ndjson(payload: bytes) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            return
        if not isinstance(entry, dict):
            return
        entries.append(entry)
    _verify(entries)


def _overlay(payload: bytes) -> None:
    try:
        doc = json.loads(payload)
    except (ValueError, RecursionError):
        return
    if not isinstance(doc, dict):
        return
    entries = copy.deepcopy(_GENUINE)
    i = doc.get("i", 0)
    if type(i) is not int or not 0 <= i < len(entries):
        return
    if isinstance(doc.get("entry"), dict):
        entries[i].update(doc["entry"])
    if isinstance(doc.get("cp"), dict) and isinstance(entries[i].get(CHECKPOINT_KIND), dict):
        entries[i][CHECKPOINT_KIND].update(doc["cp"])
    drop = doc.get("drop")
    if type(drop) is int and 0 <= drop < len(entries):
        del entries[drop]
    result = _verify(entries)
    if not result or not result[0]:
        return
    _, checkpointed, checkpoints = result
    assert len(checkpointed) <= len(_GENUINE)
    for k, (entry, cp) in enumerate(zip(checkpointed, checkpoints)):
        assert entry_leaf_digest(entry) == _GENUINE_LEAVES[k], ("entry changed", k, doc)
        assert cp.signing_body() == _GENUINE_BODIES[k], ("checkpoint changed", k, doc)


def _link(payload: bytes) -> None:
    try:
        doc = json.loads(payload)
    except (ValueError, RecursionError):
        return
    if not isinstance(doc, list) or len(doc) != 2:
        return
    try:
        prev, curr = (CheckpointRecord.from_dict(d) for d in doc)
    except ValueError:
        return
    ok, reason = verify_checkpoint_link(prev, curr)
    assert isinstance(ok, bool) and isinstance(reason, str)
    if ok:
        assert curr.key_id == prev.key_id
        if curr.key_id == _KEY_ID:
            assert curr.signing_body() in _GENUINE_BODIES, "forged link under the target key"


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, payload = data[0] % 3, data[1:]
    if mode == 0:
        _ndjson(payload)
    elif mode == 1:
        _overlay(payload)
    else:
        _link(payload)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
