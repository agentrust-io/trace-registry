"""Redirects must never trigger a second network request."""

import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

from tools import capture_witness_receipt, check_mirrors


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("target", ["localhost", "127.0.0.1"])
@pytest.mark.parametrize("client", ["capture", "mirror"])
def test_redirect_is_not_followed(status, target, client):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send_response(status)
            self.send_header("Location", f"http://{target}:{self.server.server_port}/secret")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/allowed"
    try:
        # The real guard enforces HTTPS; relax it only for this loopback transport.
        if client == "capture":
            with patch.object(capture_witness_receipt, "check_url_allowed", return_value=None):
                result = capture_witness_receipt.request(url, {"127.0.0.1"}, timeout=5)
            assert result["status"] == status
        else:
            with patch.object(check_mirrors, "_check_url_allowed", return_value=None):
                with pytest.raises(urllib.error.HTTPError) as exc:
                    check_mirrors._fetch_json(url, 5, frozenset({"127.0.0.1"}))
            assert exc.value.code == status
        assert seen == ["/allowed"]
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
