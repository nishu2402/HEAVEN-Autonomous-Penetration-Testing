"""Deliberately SSRF-vulnerable web app for HEAVEN's cloud metadata-SSRF lab.

The ``/fetch?url=`` endpoint performs a server-side GET of the operator-supplied
URL and returns the body verbatim — a textbook SSRF (no allow-list, no private-
IP / link-local blocking). In the lab this lets a request for
``http://169.254.169.254/...`` reach the sibling fake IMDS, exactly as a real
cloud SSRF would. This is a lab target: it is meant to be vulnerable.
"""
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/fetch":
            body = (b"<html><body>HEAVEN SSRF lab. Try "
                    b"/fetch?url=http://example.com/</body></html>")
            self._send(200, body)
            return
        qs = parse_qs(parsed.query)
        target = (qs.get("url") or [""])[0]
        if not target:
            self._send(400, b"missing url parameter")
            return
        try:
            # The vulnerability: fetch whatever URL was supplied, server-side.
            req = urllib.request.Request(target, headers={"Metadata": "true"})
            with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 - lab SSRF
                data = r.read()
            self._send(200, data)
        except Exception as e:  # noqa: BLE001 - surface the fetch error like a real app
            self._send(502, f"fetch error: {e}".encode())

    def _send(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), App).serve_forever()
