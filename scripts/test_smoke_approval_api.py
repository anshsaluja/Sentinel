"""Regression tests for the read-only local approval API smoke probe."""
import http.server
import threading
import unittest

from smoke_approval_api import probe


class ApprovalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/api/v1/approvals/pending":
            self.send_response(404)
        elif self.headers.get("Authorization") == "Bearer reviewer-test-token":
            self.send_response(200)
        else:
            self.send_response(401)
        self.end_headers()

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

    def test_invalid_reviewer_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "expected 200"):
            probe(self.url, "not-a-reviewer")

    def test_rejects_remote_plain_http(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            probe("http://example.org:8080", None)

    def test_rejects_embedded_credentials(self):
        with self.assertRaisesRegex(ValueError, "credentials"):
            probe("http://user:secret@localhost:8080", None)


if __name__ == "__main__":
    unittest.main()
