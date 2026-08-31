"""HTTP server wrapping TRACEAggregator.

Endpoints
---------
POST /batch
    Body (canonicalization_id defaults to "sorted-key"):
        {"producer": "name/1.0.0", "claims": [{...}, ...]}
    Body for as-transmitted registration -- each element of "claims" is the
    exact JSON text the producer signed, verbatim, as a string (not a nested
    object): the registry commits to those bytes with no re-serialization
    (docs/anchor-format.md section 0):
        {"producer": "name/1.0.0", "canonicalization_id": "as-transmitted",
         "claims": ["{\\"a\\":1,...}", ...]}
    Returns: {"batch_id": "...", "proofs": [{leaf_index, audit_path, ...}, ...]}
    Blocks until anchored.

GET /proof/<batch_id>/<leaf_index>
    Returns: {"leaf_index": int, "audit_path": [...]}
    404 if not found.

GET /health
    Returns: {"status": "ok", "pending": N, "completed_jobs": N}
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aggregator._core import TRACEAggregator

_PROOF_PATH = re.compile(r"^/proof/([A-Za-z0-9._:-]+)/(\d+)$")


class AggregatorHandler(BaseHTTPRequestHandler):
    server: "AggregatorHTTPServer"

    def log_message(self, fmt, *args):  # suppress default access log spam
        pass

    def _send_json(self, code: int, body: object) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> object:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_POST(self):
        if self.path != "/batch":
            self._send_json(404, {"error": "not found"})
            return
        try:
            body = self._read_json_body()
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
            canonicalization_id = body.get("canonicalization_id", "sorted-key")
            raw_claims = body.get("claims")
            if not isinstance(raw_claims, list) or not raw_claims:
                raise ValueError("'claims' must be a non-empty list")
            producer = body.get("producer")

            if canonicalization_id == "as-transmitted":
                # Each element is the producer's exact signed claim text --
                # decoding it to bytes (not re-encoding the parsed result) is
                # what lets the registry commit to it with no re-serialization.
                claims: list[dict] = []
                claim_raw_bytes: list[bytes] | None = []
                for item in raw_claims:
                    if not isinstance(item, str) or not item:
                        raise ValueError(
                            "'claims' must be a list of exact signed-claim "
                            "JSON text strings when canonicalization_id="
                            "'as-transmitted'"
                        )
                    rb = item.encode("utf-8")
                    parsed = json.loads(item)
                    if not isinstance(parsed, dict):
                        raise ValueError("claim must be a JSON object")
                    if producer and "producer" not in parsed:
                        parsed["producer"] = producer
                    claims.append(parsed)
                    claim_raw_bytes.append(rb)
            elif canonicalization_id == "sorted-key":
                claims = raw_claims
                claim_raw_bytes = None
                if not all(isinstance(c, dict) for c in claims):
                    raise ValueError("'claims' must be a list of JSON objects")
                if producer:
                    for claim in claims:
                        if "producer" not in claim:
                            claim["producer"] = producer
            else:
                raise ValueError(
                    f"unsupported canonicalization_id {canonicalization_id!r}; "
                    "expected 'sorted-key' or 'as-transmitted'"
                )
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        try:
            results = self.server.aggregator.submit(
                claims,
                canonicalization_id=canonicalization_id,
                raw_bytes=claim_raw_bytes,
            )
        except TimeoutError as exc:
            self._send_json(504, {"error": str(exc)})
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})
            return

        # Fail-closed: claims whose producer is not a registered, signature-
        # verified key are rejected by the aggregator and never anchored.
        rejected = [r for r in results if r.get("rejected")]
        if rejected:
            self._send_json(422, {
                "error": "one or more claims rejected: unregistered producer "
                         "or signature verification failed",
                "rejected": rejected,
            })
            return

        batch_id = results[0]["batch_id"] if results else None
        self._send_json(200, {"batch_id": batch_id, "proofs": results})

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", **self.server.aggregator.stats()})
            return

        m = _PROOF_PATH.match(self.path)
        if m:
            batch_id = m.group(1)
            leaf_index = int(m.group(2))
            proof = self.server.aggregator.get_proof(batch_id, leaf_index)
            if proof is None:
                self._send_json(404, {"error": "proof not found"})
            else:
                self._send_json(200, proof)
            return

        self._send_json(404, {"error": "not found"})


class AggregatorHTTPServer(ThreadingHTTPServer):
    def __init__(self, addr: tuple, aggregator: TRACEAggregator) -> None:
        super().__init__(addr, AggregatorHandler)
        self.aggregator = aggregator
