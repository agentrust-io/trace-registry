"""HTTP server wrapping TRACEAggregator.

Endpoints
---------
POST /batch
    Body: {"producer": "name/1.0.0", "claims": [{...}, ...]}
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
from pathlib import Path

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
            claims = body.get("claims")
            if not isinstance(claims, list) or not claims:
                raise ValueError("'claims' must be a non-empty list")
            # Inject producer field into each claim if not already set
            producer = body.get("producer")
            if producer:
                for claim in claims:
                    if isinstance(claim, dict) and "producer" not in claim:
                        claim["producer"] = producer
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return

        try:
            results = self.server.aggregator.submit(claims)
        except TimeoutError as exc:
            self._send_json(504, {"error": str(exc)})
            return
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})
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
