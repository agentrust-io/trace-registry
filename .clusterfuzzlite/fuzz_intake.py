#!/usr/bin/python3
"""Fuzz claim intake: the staging pipeline and the aggregator's POST /batch.

Both take bytes from a producer the registry has not yet trusted, and both
decide whether to anchor them. tools/batch_anchor.py reads a staged file
(loads_unique, anchor_profile_violation, the producer grouping and the
signature gate). aggregator/server.py parses a request body and hands the
claims to TRACEAggregator.submit, whose flush groups, verifies and anchors.

Four modes, chosen by the first byte:
  0. The rest is a staged claim file.
  1. The rest is a JSON object overlaid on a genuine signed claim, then
     staged.
  2. The rest is a POST /batch body.
  3. The rest is a JSON object overlaid on a genuine POST /batch body, in
     either canonicalization.

The aggregator runs for real except for its flush thread and its disk
writes: a synchronous condition runs the same _anchor_batch the thread
would, and the two write methods record instead of writing.

Properties:
  * nothing raises out of the intake path, and the server answers with a
    status it documents (a 500 means an exception escaped);
  * a claim is accepted only if it is the genuine claim, signed by this
    target's key and naming this target's producer. The fuzzer cannot sign,
    so anything else accepted is a signature-gate bypass.
"""
import base64
import copy
import io
import json
import sys
import tempfile
from pathlib import Path

import atheris

_ROOT = Path(__file__).resolve().parents[1]
for _p in (_ROOT, _ROOT / "src", _ROOT / "tools"):
    if _p.is_dir():
        sys.path.insert(0, str(_p))

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import batch_anchor
    from aggregator import _core, server
    from trace_verify._signature import canonical_body_bytes

_PRODUCER = "fuzz-producer/1.0.0"
# Fixed, published test key: this target signs its own seed claim and nothing else.
_PRIV = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


_WORK = Path(tempfile.mkdtemp(prefix="fuzz-intake-"))
_PRODUCERS = _WORK / "producers"
_PRODUCERS.mkdir()
(_PRODUCERS / "fuzz-producer-1.0.0.json").write_text(json.dumps({
    "producer_id": _PRODUCER,
    "key_type": "Ed25519",
    "public_key_jwk": {"kty": "OKP", "crv": "Ed25519",
                       "x": _b64url(_PRIV.public_key().public_bytes_raw())},
}), encoding="utf-8")
_INCOMING = _WORK / "incoming"
_INCOMING.mkdir()

_SEED = {
    "producer": _PRODUCER,
    "trace": {"iat": 1781138542, "subject": "spiffe://example.org/agent",
              "data_class": "public", "tools": ["test.echo"]},
    "note": "café",
    "seq": 1,
}
_SEED["signature"] = _b64url(_PRIV.sign(canonical_body_bytes(_SEED)))
_SEED_BODY = canonical_body_bytes(_SEED)


def _assert_genuine(claim, producer) -> None:
    assert producer == _PRODUCER, ("accepted under another producer", producer)
    assert canonical_body_bytes(claim) == _SEED_BODY, ("accepted a claim nobody signed", claim)


# -- staging pipeline -----------------------------------------------------------


def _stage(raw: bytes) -> None:
    for old in _INCOMING.iterdir():
        old.unlink()
    (_INCOMING / "claim.json").write_bytes(raw)
    records, rejections = batch_anchor.scan_staging_with_rejections(_INCOMING)
    assert len(records) + len(rejections) <= 1
    groups = batch_anchor.group_by_producer(records, 0)
    for producer, recs in groups.items():
        claims = [c for _, c, _ in recs]
        batch_anchor.batch_id_for(claims)
        for cid in batch_anchor.ANCHOR_LEAF_CANONICALIZATIONS:
            batch_anchor._build_tree([batch_anchor._leaf_hash(r, c, cid) for _, c, r in recs])
        if producer in (batch_anchor.UNKNOWN_PRODUCER, batch_anchor.INVALID_PRODUCER):
            continue
        if batch_anchor.verify_group(producer, recs, _PRODUCERS) is None:
            for claim in claims:
                _assert_genuine(claim, producer)


# -- aggregator -------------------------------------------------------------------


class _SyncCondition:
    """Stands in for the flush thread: waiting runs the flush inline."""

    def __init__(self, agg):
        self._agg = agg

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def notify_all(self):
        pass

    def wait(self, timeout=None):
        batch = list(self._agg._pending)
        self._agg._pending.clear()
        completed, proof_index = self._agg._anchor_batch(batch)
        self._agg._completed.update(completed)
        self._agg._proof_index.update(proof_index)


class _Aggregator(_core.TRACEAggregator):
    def __init__(self):  # no flush thread, no checkpoint log, no disk
        self._producers_dir = _PRODUCERS
        self._verify_signatures = True
        self._checkpoint_log = None
        self._git_commit = False
        self._max_batch_size = 0
        self._now_ts = lambda: "2026-09-25T00:00:00Z"
        self._pending = []
        self._completed = {}
        self._proof_index = {}
        self._cond = _SyncCondition(self)
        self.anchored = []

    def _write_registry_entry(self, entry, ts):
        pass

    def _write_proofs(self, batch_id, claims, paths, ts, raw_bytes=None):
        self.anchored.extend(claims)


class _Handler(server.AggregatorHandler):
    def __init__(self, body: bytes, aggregator):  # no socket
        self.headers = {"Content-Length": str(len(body))}
        self.rfile = io.BytesIO(body)
        self.path = "/batch"
        self.server = type("S", (), {"aggregator": aggregator})()
        self.sent = None

    def _send_json(self, code, body):
        self.sent = (code, body)


def _post(body: bytes) -> None:
    agg = _Aggregator()
    handler = _Handler(body, agg)
    handler.do_POST()
    assert handler.sent is not None, "no response sent"
    code, reply = handler.sent
    assert code in (200, 400, 413, 422), (code, reply)
    if code == 200:
        assert agg.anchored, reply
    for claim in agg.anchored:
        _assert_genuine(claim, claim.get("producer"))


def _overlay_json(payload: bytes):
    try:
        doc = json.loads(payload)
    except (ValueError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, payload = data[0] % 4, data[1:]
    if mode == 0:
        _stage(payload)
    elif mode == 1:
        doc = _overlay_json(payload)
        if doc is not None:
            claim = copy.deepcopy(_SEED)
            claim.update(doc)
            _stage(json.dumps(claim).encode("utf-8"))
    elif mode == 2:
        _post(payload)
    else:
        doc = _overlay_json(payload)
        if doc is None:
            return
        transmitted = doc.pop("as_transmitted", False) is True
        claim = json.dumps(_SEED) if transmitted else copy.deepcopy(_SEED)
        body = {"producer": _PRODUCER, "claims": [claim]}
        if transmitted:
            body["canonicalization_id"] = "as-transmitted"
        body.update(doc)
        _post(json.dumps(body).encode("utf-8"))


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
