"""Run each portable case through an explicitly selected, trusted local adapter."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def check_reply(case, reply):
    if (not isinstance(reply, dict) or set(reply) != {"id", "accepted"}
            or reply["id"] != case["id"] or type(reply["accepted"]) is not bool):
        raise ValueError("malformed or misbound adapter response")
    if reply["accepted"] != case["expected"]:
        raise ValueError(f"{case['id']}: expected {case['expected']}, got {reply['accepted']}")


def run(corpus, command):
    if corpus.get("format") != "agentrust-verifier-corpus-v1" or not corpus.get("cases"):
        raise ValueError("unsupported or empty corpus")
    ids = set()
    for case in corpus["cases"]:
        if case["id"] in ids or type(case["expected"]) is not bool:
            raise ValueError("duplicate case id or non-Boolean expectation")
        ids.add(case["id"])
        request = {key: case[key] for key in ("id", "operation", "input")}
        result = subprocess.run(command, input=json.dumps(request), text=True,
                                capture_output=True, timeout=5, check=False)
        if result.returncode:
            raise ValueError(f"{case['id']}: adapter exited {result.returncode}: {result.stderr[:200]}")
        check_reply(case, json.loads(result.stdout))
    return len(ids)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path(__file__).resolve().parents[1] / "conformance/verifier-v1.json")
    parser.add_argument("adapter", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.adapter
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("supply a trusted local adapter command after --")
    count = run(json.loads(args.corpus.read_text()), command)
    print(f"PASS {count} portable verifier cases")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        raise SystemExit(1) from None
