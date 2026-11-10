#!/usr/bin/env python3
"""HEAVEN business-logic lab: a deliberately mass-assignable sign-up app.

A tiny registration form whose backend binds EVERY submitted field that happens
to name a column on its ``User`` model, with no allow-list of which columns are
user-writable -- the textbook mass-assignment flaw (CWE-915, OWASP API6:2023 /
A04:2021). The form only ever exposes username / email / password, but the model
also carries the privileged columns ``role`` and ``is_admin``; because the
handler binds the raw request body onto the model, an attacker who adds those
fields to the POST has them accepted and reflected back as bound.

Crucially the handler drops field names that are NOT model columns, so a
scanner's garbage control field is correctly never reflected. That is the exact
differential HEAVEN's ``_audit_mass_assignment`` relies on: a privileged field
echoed as bound while the control field is not proves genuine attribute binding
rather than a page that merely re-renders every input (which would echo the
control too, and HEAVEN suppresses). Passwords are bound but never echoed, so
the lab reflects a real misconfiguration without leaking a secret of its own.

Loopback only, inert (it persists nothing and runs no user input as code).
Deliberately insecure by construction -- never publish it on ``0.0.0.0`` on a
reachable interface. Pure standard library so the lab needs no image build:
``python massassign_app.py [host] [port]`` (defaults 127.0.0.1:5002), or the
``logic-compose.yml`` stack runs it inside ``python:3.12-slim``.
"""

from __future__ import annotations

import sys
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

# The User model's columns. A framework that binds the request body straight
# onto the model (Rails/Django/Laravel/Mongoose style) will set ANY of these,
# including the privileged ones the sign-up UI never shows. Fields whose names
# are NOT columns here are silently dropped -- so the scanner's control field is
# never echoed, and neither are privileged names this model happens not to carry
# (e.g. account_type / balance), which keeps the lab's positives honest.
MODEL_COLUMNS = ("username", "email", "password", "role", "is_admin")
# Columns that exist but must never be written back into a response.
SECRET_COLUMNS = frozenset({"password"})

_FORM_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Acme sign-up</title></head>
<body>
<h1>Create your Acme account</h1>
<form method="post" action="/register">
  <label>Username <input name="username" value=""></label>
  <label>Email <input name="email" type="email" value=""></label>
  <label>Password <input name="password" type="password" value=""></label>
  <button type="submit">Register</button>
</form>
</body></html>"""


def _render_account(bound: dict[str, str]) -> str:
    rows = "".join(
        "<li>{} = {}</li>".format(escape(k), escape(v))
        for k, v in bound.items()
        if k not in SECRET_COLUMNS
    )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>Account created</title></head><body>"
        "<h1>Account created</h1><ul>{}</ul></body></html>".format(rows)
    )


class _Handler(BaseHTTPRequestHandler):
    server_version = "AcmeSignup/1.0"
    # Keep the default HTTP/1.0 behaviour (close per response); we set our own
    # Content-Length so the client reads a complete body.

    def _send(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = self.path.split("?", 1)[0]
        if path in ("/", "/register", "/signup"):
            self._send(200, _FORM_PAGE)
        else:
            self._send(404, "<!doctype html><html><body><h1>Not found</h1></body></html>")

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        raw = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
        submitted = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
        # VULNERABLE: bind every submitted field that names a model column, with
        # no allow-list of which columns a sign-up may set. Non-column fields are
        # dropped (so an unknown control field is never bound, nor reflected).
        bound = {col: submitted[col] for col in MODEL_COLUMNS if col in submitted}
        self._send(200, _render_account(bound))

    def log_message(self, *_args) -> None:  # silence per-request logging
        return


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5002
    server = ThreadingHTTPServer((host, port), _Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
