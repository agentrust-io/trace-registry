import importlib.util
import json
import hashlib
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_tool("run_verifier_corpus")
adapter = load_tool("conformance_adapter")
CORPUS = json.loads((ROOT / "conformance/verifier-v1.json").read_text())


class PortableCorpusTests(unittest.TestCase):
    def test_reference_adapter_and_paired_operation_domains(self):
        domains = {}
        for case in CORPUS["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIs(adapter.evaluate(case), case["expected"])
                domains.setdefault(case["operation"], set()).add(case["expected"])
        self.assertTrue(all(outcomes == {True, False} for outcomes in domains.values()))

    def test_actual_adapter_process(self):
        self.assertEqual(runner.run(CORPUS, [sys.executable, str(ROOT / "tools/conformance_adapter.py")]),
                         len(CORPUS["cases"]))

    def test_accept_all_and_reject_all_cannot_pass(self):
        for verdict in (True, False):
            command = [sys.executable, "-c",
                       "import json,sys; r=json.load(sys.stdin); print(json.dumps({'id':r['id'],'accepted':" + str(verdict) + "}))"]
            with self.subTest(verdict=verdict), self.assertRaisesRegex(ValueError, "expected"):
                runner.run(CORPUS, command)

    def test_crash_is_not_a_refusal(self):
        with self.assertRaisesRegex(ValueError, "exited"):
            runner.run(CORPUS, [sys.executable, "-c", "raise RuntimeError('adapter failed')"])

    def test_reply_binds_boolean_and_case_id(self):
        case = CORPUS["cases"][0]
        for reply in ({"id": "wrong", "accepted": True}, {"id": case["id"], "accepted": 1},
                      {"id": case["id"], "accepted": True, "ignored": 1}):
            with self.subTest(reply=reply), self.assertRaisesRegex(ValueError, "malformed"):
                runner.check_reply(case, reply)

    def test_case_id_and_expectation_integrity(self):
        for cases in ([CORPUS["cases"][0], CORPUS["cases"][0], *CORPUS["cases"][2:]],
                      [{**CORPUS["cases"][0], "expected": 1}, *CORPUS["cases"][1:]]):
            with self.assertRaises(ValueError):
                runner.run({**CORPUS, "cases": cases}, [sys.executable, str(ROOT / "tools/conformance_adapter.py")])

    def test_missing_operation_domain_is_rejected(self):
        for operation in {case["operation"] for case in CORPUS["cases"]}:
            cases = [case for case in CORPUS["cases"] if case["operation"] != operation]
            with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, "inventory"):
                runner.run({**CORPUS, "cases": cases}, [sys.executable, "-c", "raise AssertionError()"])

    def test_duplicate_reply_members_are_rejected_in_subprocess(self):
        for key in ("id", "accepted"):
            code = ("import json,sys; r=json.load(sys.stdin); "
                    "s=json.dumps({'id':r['id'],'accepted':True}); "
                    f"print(s[:-1]+','+json.dumps({key!r})+':'+json.dumps(r['id'] if {key!r}=='id' else True)+'}}')")
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "duplicate JSON"):
                runner.run(CORPUS, [sys.executable, "-c", code])

    def test_exact_inventory_and_opaque_ids(self):
        self.assertEqual(len(CORPUS["cases"]), 28)
        self.assertEqual([c["id"] for c in CORPUS["cases"]],
                         [f"case-{i:03d}" for i in range(1, 29)])

    def test_multileaf_vectors_match_independent_reference(self):
        # Bounded RFC 6962 reference; never calls the production tree generator.
        def digest(data):
            return hashlib.sha256(data).digest()
        claims = [{"record_id": f"multi-{i}"} for i in range(3)]
        leaves = [digest(b"\x00" + json.dumps(c, sort_keys=True, separators=(",", ":")).encode())
                  for c in claims]
        pair = digest(b"\x01" + leaves[0] + leaves[1])
        triple = digest(b"\x01" + pair + leaves[2])
        expected = []
        for count, paths, root in ((2, [[leaves[1]], [leaves[0]]], pair),
                                   (3, [[leaves[1], leaves[2]], [leaves[0], leaves[2]], [pair]], triple)):
            for index, path in enumerate(paths):
                data = {"claim": claims[index], "leaf_index": index, "leaf_count": count,
                        "audit_path": [p.hex() for p in path], "root": root.hex(),
                        "canonicalization_id": "sorted-key"}
                expected.append((data, True))
                bad = copy.deepcopy(data)
                bad["audit_path"][0] = "00" * 32
                expected.append((bad, False))
        self.assertEqual([(c["input"], c["expected"]) for c in CORPUS["cases"][18:]], expected)
