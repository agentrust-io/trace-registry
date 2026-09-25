"""Regression tests for what the ClusterFuzzLite targets found on their first run.

Each case is a reproducer the local smoke run of .clusterfuzzlite/ produced
against origin/main 22dd565, reduced by hand. Every one was an exception
escaping a function whose contract says it does not raise, or raises only
ValueError, on input a reader or a producer controls.
"""

from __future__ import annotations

import copy
import http.client
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from aggregator._core import TRACEAggregator  # noqa: E402
from aggregator._mmr_log import CheckpointLog, Ed25519CheckpointSigner  # noqa: E402
from trace_verify import _mmr  # noqa: E402
from trace_verify.__main__ import main as trace_verify_main  # noqa: E402
from trace_verify._checkpoint import (  # noqa: E402
    CheckpointRecord,
    verify_chain_against_entries,
    verify_checkpoint_chain,
    verify_checkpoint_link,
)
from trace_verify._verify import (  # noqa: E402
    UnknownCanonicalizationError,
    canonical_claim_bytes,
)

SAMPLE_CLAIM = REPO_ROOT / "samples" / "example-trust-record.json"
SAMPLE_PROOF = REPO_ROOT / "samples" / "inclusion-proof.json"
SAMPLE_ENTRY = REPO_ROOT / "registry" / "2026" / "06" / "12.ndjson"


def _chain(n: int = 3) -> list[dict]:
    pem = Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    log = CheckpointLog(None, signer=Ed25519CheckpointSigner(None, pem=pem), replay_entries=[])
    entries = []
    for k in range(n):
        entry = {"ts": "2026-09-01T00:00:00Z", "merkle_root": "sha256:" + "ab" * 32,
                 "leaf_count": 1, "producer": "p/1.0.0", "batch_id": f"b{k}"}
        entry["mmr_checkpoint"] = log.append_entry(entry, timestamp=entry["ts"]).to_dict()
        entries.append(entry)
    return entries


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = trace_verify_main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class CanonicalizationIdTypeTest(unittest.TestCase):
    """canonicalization_id comes from the registry entry. A JSON array there
    raised TypeError (unhashable) from the frozenset membership test, which
    the CLI does not catch, so `trace-verify` died with a traceback."""

    def test_non_string_id_is_an_unknown_canonicalization(self):
        for cid in (["sorted-key"], {"a": 1}, 1, None):
            with self.assertRaises(UnknownCanonicalizationError, msg=repr(cid)):
                canonical_claim_bytes({}, canonicalization_id=cid, raw_bytes=b"{}")

    def test_cli_reports_it_as_not_verified(self):
        entry = json.loads(SAMPLE_ENTRY.read_text(encoding="utf-8"))
        entry["canonicalization_id"] = ["sorted-key"]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "entry.ndjson"
            path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
            code, _, err = _run_cli(["--claim", str(SAMPLE_CLAIM), "--proof", str(SAMPLE_PROOF),
                                     "--entry", str(path), "--no-verify-signature"])
        self.assertEqual(code, 1)
        self.assertIn("UnknownCanonicalizationError", err)


class CliUnreadableInputTest(unittest.TestCase):
    """Bytes that are not UTF-8, and JSON nested past the recursion limit,
    raised UnicodeDecodeError and RecursionError out of main(). Neither is a
    JSONDecodeError, which is all the loaders caught. Exit 2 is the contract."""

    def _inclusion(self, claim: bytes, proof: bytes, entry: bytes) -> int:
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for name, data in (("c.json", claim), ("p.json", proof), ("e.ndjson", entry)):
                (Path(d) / name).write_bytes(data)
                paths.append(str(Path(d) / name))
            code, _, _ = _run_cli(["--claim", paths[0], "--proof", paths[1],
                                   "--entry", paths[2], "--no-verify-signature"])
        return code

    def test_invalid_utf8_in_each_input_exits_2(self):
        claim, proof, entry = (p.read_bytes() for p in (SAMPLE_CLAIM, SAMPLE_PROOF, SAMPLE_ENTRY))
        bad = b"\xed\xa0\x80"
        self.assertEqual(self._inclusion(bad, proof, entry), 2)
        self.assertEqual(self._inclusion(claim, bad, entry), 2)
        self.assertEqual(self._inclusion(claim, proof, bad), 2)

    def test_nesting_too_deep_in_each_input_exits_2(self):
        claim, proof, entry = (p.read_bytes() for p in (SAMPLE_CLAIM, SAMPLE_PROOF, SAMPLE_ENTRY))
        deep = b"[" * 100_000 + b"]" * 100_000
        self.assertEqual(self._inclusion(deep, proof, entry), 2)
        self.assertEqual(self._inclusion(claim, deep, entry), 2)
        self.assertEqual(self._inclusion(claim, proof, deep), 2)

    def test_chain_input_that_is_not_utf8_or_too_deep_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            for data in (b"\xff\xfe", b"[" * 100_000 + b"]" * 100_000):
                path = Path(d) / "e.ndjson"
                path.write_bytes(data)
                code, _, _ = _run_cli(["chain", str(path)])
                self.assertEqual(code, 2, data[:4])


class MalformedCheckpointTest(unittest.TestCase):
    """CheckpointRecord.from_dict raised KeyError or TypeError on a missing or
    mistyped member, and verify_checkpoint_link, documented as never raising,
    raised TypeError when a root was not a string."""

    def setUp(self):
        self.entries = _chain(3)
        self.cps = [e["mmr_checkpoint"] for e in self.entries]

    def test_from_dict_raises_value_error_for_every_malformation(self):
        cases = [None, [], "x"]
        for key in ("v", "kind", "log_id", "mmr_size", "root", "prev_size",
                    "key_id", "timestamp", "signature"):
            missing = copy.deepcopy(self.cps[1])
            del missing[key]
            cases.append(missing)
        for key, value in (("root", 5), ("root", ["a"]), ("key_id", None), ("mmr_size", "3"),
                           ("mmr_size", True), ("mmr_size", 3.0), ("v", [1]),
                           ("prev_size", {}), ("signature", 1), ("consistency_proof", 5),
                           ("consistency_proof", {"v": 1}), ("consistency_proof", []),
                           ("consistency_proof", {**self.cps[1]["consistency_proof"],
                                                  "size_b": float("inf")})):
            bad = copy.deepcopy(self.cps[1])
            bad[key] = value
            cases.append(bad)
        for case in cases:
            with self.assertRaises(ValueError, msg=repr(case)[:120]):
                CheckpointRecord.from_dict(case)

    def test_well_formed_records_still_round_trip(self):
        for cp in self.cps:
            self.assertEqual(CheckpointRecord.from_dict(cp).to_dict(), cp)
        ok, errors = verify_checkpoint_chain([CheckpointRecord.from_dict(c) for c in self.cps])
        self.assertTrue(ok, errors)

    def test_link_with_a_non_string_root_fails_instead_of_raising(self):
        prev = CheckpointRecord.from_dict(self.cps[0])
        curr = CheckpointRecord.from_dict(self.cps[1])
        prev.root = 5
        curr.prev_root = 5
        ok, reason = verify_checkpoint_link(prev, curr)
        self.assertFalse(ok)
        self.assertIn("root", reason)
        ok, _ = verify_checkpoint_chain([prev, curr])
        self.assertFalse(ok)

    def test_entry_check_does_not_accept_a_boolean_size(self):
        entries = copy.deepcopy(self.entries[:1])
        entries[0]["mmr_checkpoint"]["mmr_size"] = True  # == 1 in Python
        errors = verify_chain_against_entries(entries)
        self.assertTrue(errors)

    def test_entry_check_reports_a_non_object_entry(self):
        errors = verify_chain_against_entries([self.entries[0], ["not", "an", "entry"]])
        self.assertTrue(any("not a JSON object" in e for e in errors), errors)

    def test_cli_chain_reports_a_malformed_checkpoint_as_not_verified(self):
        entries = copy.deepcopy(self.entries)
        del entries[1]["mmr_checkpoint"]["root"]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "e.ndjson"
            path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
            code, out, _ = _run_cli(["chain", str(path), "--json"])
            result = json.loads(out)
            self.assertEqual(code, 1)
            self.assertFalse(result["verified"])
            self.assertTrue(any("root" in e for e in result["errors"]), result)

            tool = subprocess.run(
                [sys.executable, str(REPO_ROOT / "tools" / "verify_checkpoint_chain.py"), str(path)],
                capture_output=True, text=True,
            )
        self.assertEqual(tool.returncode, 1, tool.stderr)
        self.assertNotIn("Traceback", tool.stderr)


class MalformedMmrProofTest(unittest.TestCase):
    """The proof parsers raised KeyError and TypeError; the verifiers below
    them are total, so ValueError is the one error a caller should need."""

    def test_from_dict_raises_invalid_argument(self):
        store = _mmr.MemoryNodeStore()
        for k in range(5):
            _mmr.add_leaf(store, _mmr.leaf_hash(bytes([k]) * 32))
        inc = _mmr.inclusion_proof(store, 1, store.size()).to_dict()
        con = _mmr.consistency_proof(store, 1, store.size()).to_dict()
        for parse, good in ((_mmr.InclusionProof.from_dict, inc),
                            (_mmr.ConsistencyProof.from_dict, con)):
            for key in good:
                bad = dict(good)
                del bad[key]
                with self.assertRaises(_mmr.InvalidArgumentError):
                    parse(bad)
            with self.assertRaises(_mmr.InvalidArgumentError):
                parse(None)
            with self.assertRaises(_mmr.InvalidArgumentError):
                parse({**good, "size" if "size" in good else "size_a": [1]})
        with self.assertRaises(_mmr.InvalidArgumentError):
            _mmr.ConsistencyProof.from_dict({**con, "witness": [1, 2]})
        # json.loads reads Infinity as a float, and int(inf) is OverflowError.
        with self.assertRaises(_mmr.InvalidArgumentError):
            _mmr.ConsistencyProof.from_dict({**con, "size_a": float("inf")})
        with self.assertRaises(_mmr.InvalidArgumentError):
            _mmr.InclusionProof.from_dict({**inc, "leaf_index": float("inf")})


class AggregatorDeepNestingTest(unittest.TestCase):
    """A POST /batch body nested past the recursion limit raised
    RecursionError out of do_POST. The handler thread died and the client got
    no response at all instead of a 400."""

    def setUp(self):
        from aggregator.server import AggregatorHTTPServer
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.agg = TRACEAggregator(
            registry_dir=tmp / "registry", proofs_dir=tmp / "proofs",
            flush_interval=0.2, git_commit=False, verify_signatures=False,
            enable_mmr_checkpoints=False,
        )
        self.server = AggregatorHTTPServer(("127.0.0.1", 0), self.agg)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def _post(self, body: bytes) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/batch", body=body,
                     headers={"Content-Length": str(len(body))})
        status = conn.getresponse().status
        conn.close()
        return status

    def test_deep_body_is_400(self):
        self.assertEqual(self._post(b"[" * 100_000 + b"]" * 100_000), 400)

    def test_deep_as_transmitted_claim_is_400(self):
        inner = "[" * 100_000 + "]" * 100_000
        body = json.dumps({"canonicalization_id": "as-transmitted", "claims": [inner]}).encode()
        self.assertEqual(self._post(body), 400)


if __name__ == "__main__":
    unittest.main()
