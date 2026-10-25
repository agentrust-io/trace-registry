import importlib.util
import json
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
        for cases in ([CORPUS["cases"][0]] * 2,
                      [{**CORPUS["cases"][0], "expected": 1}]):
            with self.assertRaises(ValueError):
                runner.run({**CORPUS, "cases": cases}, [sys.executable, str(ROOT / "tools/conformance_adapter.py")])
