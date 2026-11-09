"""Regression tests for the read-only local approval API smoke probe."""
import http.server
import threading
import unittest

from smoke_approval_api import probe


class ApprovalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/v1/approvals/pending" and self.headers.get("X-Redirect-Test") == "1":
            self.send_response(302)
            self.send_header("Location", "http://example.org/")
        elif self.path == "/api/v1/approvals/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.org/")
        elif self.path != "/api/v1/approvals/pending":
            self.send_response(404)
        elif self.headers.get("Authorization") == "Bearer reviewer-test-token":
            self.send_response(200)
        else:
            self.send_response(401)
        if self.headers.get("Authorization") == "Bearer reviewer-test-token":
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.path == "/api/v1/approvals/pending" and self.headers.get("Authorization") == "Bearer reviewer-test-token":
            self.wfile.write(b"[]")

    def log_message(self, *_args):
        pass


class ApprovalSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ApprovalHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_anonymous_is_denied(self):
        self.assertIn("denied", probe(self.url, None)[0])

    def test_reviewer_can_read(self):
        self.assertIn("returned 200", probe(self.url, "reviewer-test-token")[1])

    def test_rejects_html_login_page_disguised_as_success(self):
        from unittest.mock import patch

        def html_response(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/html")
            handler.end_headers()
            handler.wfile.write(b"<html>Sign in</html>")

        with patch.object(ApprovalHandler, "do_GET", html_response):
            with self.assertRaisesRegex(RuntimeError, "did not return JSON"):
                probe(self.url, "reviewer-test-token")

    def test_rejects_invalid_json_with_correct_media_type(self):
        from unittest.mock import patch

        def invalid_json(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.end_headers()
            handler.wfile.write(b"<not-json>")

        with patch.object(ApprovalHandler, "do_GET", invalid_json):
            with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                probe(self.url, "reviewer-test-token")

    def test_rejects_oversized_json_response(self):
        from unittest.mock import patch

        def oversized(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.end_headers()
            handler.wfile.write(b" " * 65537)

        with patch.object(ApprovalHandler, "do_GET", oversized):
            with self.assertRaisesRegex(RuntimeError, "exceeds 64 KiB"):
                probe(self.url, "reviewer-test-token")

    def test_invalid_reviewer_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "expected 200"):
            probe(self.url, "not-a-reviewer")

    def test_rejects_base_url_paths(self):
        with self.assertRaisesRegex(ValueError, "path"):
            probe(self.url + "/unexpected", None)

    def test_rejects_token_line_breaks(self):
        with self.assertRaisesRegex(ValueError, "line breaks"):
            probe(self.url, "token\nInjected: value")

    def test_rejects_carriage_return_in_token(self):
        with self.assertRaisesRegex(ValueError, "line breaks"):
            probe(self.url, "token\rInjected: value")

    def test_rejects_nonpositive_timeout(self):
        with self.assertRaisesRegex(ValueError, "Timeout"):
            probe(self.url, None, timeout=0)

    def test_redirect_does_not_follow_to_external_host(self):
        from unittest.mock import patch
        original = ApprovalHandler.do_GET

        def redirect(_handler):
            _handler.send_response(302)
            _handler.send_header("Location", "http://example.org/")
            _handler.end_headers()

        with patch.object(ApprovalHandler, "do_GET", redirect):
            with self.assertRaisesRegex(RuntimeError, "redirected"):
                probe(self.url, "reviewer-test-token")

    def test_rejects_remote_plain_http(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            probe("http://example.org:8080", None)

    def test_rejects_embedded_credentials(self):
        with self.assertRaisesRegex(ValueError, "credentials"):
            probe("http://user:secret@localhost:8080", None)


if __name__ == "__main__":
    unittest.main()
