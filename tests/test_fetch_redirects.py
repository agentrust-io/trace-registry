"""CI-discovered loopback controls: redirects must not cause another request."""
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from tools import capture_witness_receipt, check_mirrors


class RedirectTests(unittest.TestCase):
    def _check(self, status, target, client):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def handle_request(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                seen.append((self.command, self.path, body))
                response_status = status if self.path == "/allowed" else 200
                self.send_response(response_status)
                if response_status != 200:
                    location = "/secret" if target == "relative" else (
                        f"http://localhost:{self.server.server_port}/secret"
                    )
                    self.send_header("Location", location)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            do_GET = handle_request
            do_POST = handle_request

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
        )
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/allowed"
        body = b'{"synthetic":"checkpoint"}' if client == "capture-post" else None
        try:
            # Relax only the initial URL guard for synthetic loopback HTTP.
            # The actual opener and redirect handler remain under test.
            if client.startswith("capture"):
                with patch.object(capture_witness_receipt, "check_url_allowed", return_value=None):
                    result = capture_witness_receipt.request(
                        url, {"127.0.0.1"}, timeout=2, body=body,
                        content_type="application/json" if body is not None else None,
                    )
                self.assertEqual(result["status"], status)
                self.assertEqual(result["body"], b'{"ok":true}')
            else:
                with patch.object(check_mirrors, "_check_url_allowed", return_value=None):
                    if status == 200:
                        self.assertEqual(check_mirrors._fetch_json(url, 2, frozenset({"127.0.0.1"})), {"ok": True})
                    else:
                        with self.assertRaises(urllib.error.HTTPError) as caught:
                            check_mirrors._fetch_json(url, 2, frozenset({"127.0.0.1"}))
                        self.assertEqual(caught.exception.code, status)
                        caught.exception.close()
            self.assertEqual(seen, [("POST" if body is not None else "GET", "/allowed", body or b"")])
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
            self.assertFalse(thread.is_alive())

    def test_redirects_are_not_followed(self):
        for client in ("capture-get", "capture-post", "mirror"):
            for target in ("relative", "cross-host"):
                for status in (301, 302, 303, 307, 308):
                    with self.subTest(client=client, target=target, status=status):
                        self._check(status, target, client)

    def test_successful_requests_still_work(self):
        for client in ("capture-get", "capture-post", "mirror"):
            with self.subTest(client=client):
                self._check(200, "relative", client)
