"""A tiny, native, deliberately-vulnerable REST + GraphQL API for offline tests.

Why this exists
---------------
The network/service benchmark (Metasploitable-2) needs a live VM, and the web
benchmark reproduces DVWA. Neither exercises HEAVEN's **API** scanner
(``heaven/vulnscan/api_scanner.py`` — OWASP API Security Top 10). This module is
the API analogue of ``native/vuln_app.py``: a faithful, in-process target that
reproduces exactly the behaviours the real API scanner probes for, natively and
deterministically, with **no Docker and no network egress** — so the API tier
gets an always-on, reproducible precision/recall number too.

Each route is the genuine sink the corresponding detector looks for — the scanner
observes a real HTTP response, it is never told what to find:

* ``POST /graphql``            — schema exposed via **introspection** (API3), a
  deep query accepted with **no cost limit** (API4), and **unbounded batching**
  (API4). A real GraphQL server, faithfully.
* ``GET  /api/users/<id>``     — object endpoint that serves **distinct** records
  for sequential IDs with no auth → **BOLA/IDOR** signal (API1).
* ``GET/PUT /api/users/me``    — a ``PUT`` that accepts and reflects an injected
  privileged field → **mass assignment** (API3/API6).
* ``POST /api/login``          — no rate limiting: 50 rapid attempts, no ``429``.
* ``GET  /api/config``         — a real AWS key shape leaked in the body (API3).
* ``GET  /openapi.json``       — OpenAPI spec reachable unauthenticated (API9).
* ``GET  /api/users``          — a protected-looking collection served with no
  credentials → **broken authentication** (API2).

Everything else 404s, so the scanner's own false-positive guards (a single 200 is
not BOLA; a placeholder is not a secret; a batching-disabled server is not flagged)
are exercised against a target that only reports what is genuinely there.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Iterator

from flask import Flask, jsonify, make_response, request

# The canonical AWS *documentation example* access-key id (a well-known public,
# non-secret placeholder). It matches the scanner's unambiguous ``AKIA[0-9A-Z]{16}``
# provider pattern, so a naive app leaking it in a response body is a genuine,
# structurally-confirmed secret leak — exactly what the detector is built to catch.
_AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 - public AWS doc example, not a secret

# Five per-object records so an ID-swap returns DISTINCT bodies (the BOLA signal).
_USERS = {
    "1": {"id": 1, "username": "alice", "email": "alice@example.com", "role": "user"},
    "2": {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user"},
    "3": {"id": 3, "username": "carol", "email": "carol@example.com", "role": "admin"},
    "4": {"id": 4, "username": "dave", "email": "dave@example.com", "role": "user"},
    "5": {"id": 5, "username": "erin", "email": "erin@example.com", "role": "user"},
}

_INDEX = (
    "<!doctype html><html><head><title>vuln-api</title></head><body>"
    "<h1>vuln-api</h1><ul>"
    '<li><a href="/graphql">GraphQL</a></li>'
    '<li><a href="/api/users">Users collection</a></li>'
    '<li><a href="/api/users/1">User object</a></li>'
    '<li><a href="/openapi.json">OpenAPI spec</a></li>'
    "</ul></body></html>"
)

# A minimal but real-shaped OpenAPI document — the inventory detector confirms the
# body actually looks like a spec ('"openapi"' present), not just any 200.
_OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "vuln-api", "version": "1.0.0"},
    "paths": {
        "/api/users": {"get": {"summary": "List users"}},
        "/api/users/{id}": {"get": {"summary": "Get a user"}},
        "/api/login": {"post": {"summary": "Log in"}},
    },
}


def _graphql_introspection() -> dict:
    """A schema-introspection reply: ``data.__schema`` with types + a mutation."""
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [
                    {"name": "Query", "kind": "OBJECT", "fields": [{"name": "user"}]},
                    {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "login"}]},
                    {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}]},
                ],
            }
        }
    }


def create_app() -> Flask:
    app = Flask(__name__)
    app.logger.disabled = True

    @app.route("/")
    def index() -> str:
        return _INDEX

    # ── GraphQL (API3 introspection, API4 resource consumption) ──────────────
    @app.route("/graphql", methods=["POST"])
    def graphql():
        payload = request.get_json(silent=True)
        # A batched request is a JSON array — process every entry, unbounded (the
        # unlimited-batching sink). Each processed entry carries data + no errors.
        if isinstance(payload, list):
            return jsonify([{"data": {"__typename": "Query"}} for _ in payload])
        query = ""
        if isinstance(payload, dict):
            query = str(payload.get("query", ""))
        if "__schema" in query:
            return jsonify(_graphql_introspection())
        if "__type" in query:
            # Deep/nested query processed with NO depth or cost limit (no error
            # naming a limit) → the complexity detector's positive signal.
            return jsonify({"data": {"__type": {"name": "Query",
                                                "fields": [{"name": "user"}]}}})
        return jsonify({"data": {"__typename": "Query"}})

    # ── BOLA / IDOR (API1): distinct objects per raw ID, no auth ─────────────
    @app.route("/api/users/<user_id>")
    def user_object(user_id: str):
        rec = _USERS.get(user_id)
        if rec is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(rec)

    # ── Broken authentication (API2): protected collection, no creds ─────────
    @app.route("/api/users")
    def users_collection():
        return jsonify([_USERS[k] for k in ("1", "2", "3", "4", "5")])

    # ── Mass assignment (API3/API6): PUT reflects injected privileged fields ─
    @app.route("/api/users/me", methods=["GET", "PUT"])
    def users_me():
        base = {"id": 1, "username": "me", "role": "user"}
        if request.method == "GET":
            return jsonify(base)
        injected = request.get_json(silent=True) or {}
        if isinstance(injected, dict):
            base.update(injected)  # no field whitelist → the mass-assignment sink
        return jsonify(base)

    # ── No rate limiting: /api/login always processes, never 429 ─────────────
    @app.route("/api/login", methods=["POST"])
    def login():
        return jsonify({"error": "invalid credentials"}), 401

    # ── Secret leak (API3): a real AWS-key shape in a config response ─────────
    @app.route("/api/config")
    def api_config():
        return jsonify({
            "service": "vuln-api",
            "region": "us-east-1",
            "aws_access_key_id": _AWS_EXAMPLE_KEY,
        })

    # Benign sibling endpoints the secret detector probes BEFORE /api/config —
    # they must not carry a secret, so the leak is attributed to /api/config.
    @app.route("/api")
    def api_root():
        return jsonify({"name": "vuln-api", "version": "1.0.0"})

    @app.route("/api/health")
    def api_health():
        return jsonify({"status": "ok"})

    # ── Improper inventory management (API9): OpenAPI spec, unauthenticated ───
    @app.route("/openapi.json")
    def openapi():
        resp = make_response(jsonify(_OPENAPI))
        resp.headers["Content-Type"] = "application/json"
        return resp

    return app


@contextlib.contextmanager
def serve(host: str = "127.0.0.1", port: int = 0) -> Iterator[str]:
    """Run the API app in a background thread; yield its base URL. Docker-free."""
    import logging

    from werkzeug.serving import make_server

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    server = make_server(host, port, create_app(), threaded=True)
    real_port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{real_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
