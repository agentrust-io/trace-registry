"""Reference adapter for the portable, offline verifier corpus."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from trace_verify import verify_inclusion
from trace_verify import _mmr
from trace_verify._checkpoint import CheckpointRecord, verify_checkpoint_signature_offline
from trace_verify._signature import verify_claim_against_registry


def evaluate(case):
    data = case["input"]
    operation = case["operation"]
    if operation == "batch_inclusion":
        return verify_inclusion(data["claim"], data["leaf_index"],
                                [bytes.fromhex(x) for x in data["audit_path"]],
                                data["leaf_count"], bytes.fromhex(data["root"]),
                                canonicalization_id=data["canonicalization_id"],
                                raw_bytes=bytes.fromhex(data["raw_hex"]) if "raw_hex" in data else None)
    if operation == "producer_signature":
        with tempfile.TemporaryDirectory() as directory:
            for entry in data["registered_keys"]:
                filename = entry["producer_id"].replace("/", "-") + ".json"
                if Path(filename).name != filename:
                    raise ValueError("invalid fixture producer path")
                (Path(directory) / filename).write_text(json.dumps(entry))
            return verify_claim_against_registry(data["claim"], data["producer_id"], Path(directory))[0]
    if operation == "mmr_inclusion":
        return _mmr.verify_inclusion(bytes.fromhex(data["root"]), data["size"], data["leaf_index"],
                                     bytes.fromhex(data["body_digest"]),
                                     _mmr.InclusionProof.from_dict(data["proof"]))
    if operation == "mmr_consistency":
        return _mmr.verify_consistency(bytes.fromhex(data["old_root"]), data["old_size"],
                                       bytes.fromhex(data["new_root"]), data["new_size"],
                                       _mmr.ConsistencyProof.from_dict(data["proof"]))
    if operation == "checkpoint_signature":
        checkpoint = CheckpointRecord.from_dict(data["checkpoint"])
        return (checkpoint.key_id == data["trusted_key_id"]
                and verify_checkpoint_signature_offline(checkpoint))
    raise ValueError(f"unsupported operation: {operation}")


def main():
    case = json.load(sys.stdin)
    # Fixture-domain errors are distinct from a Boolean refusal. Unexpected
    # exceptions exit nonzero and the runner never counts them as rejection.
    result = evaluate(case)
    print(json.dumps({"id": case["id"], "accepted": result}))


if __name__ == "__main__":
    main()
