"""GraphQL introspection detection must confirm the actual schema payload, not
merely that the string ``__schema`` appears in the response.

A server with introspection DISABLED still answers the introspection query with
HTTP 200 and an ``errors`` array whose message echoes the queried field name,
for example::

    {"errors": [{"message": "GraphQL introspection has been disabled, but the
     requested query contained the field \"__schema\"."}]}

The old detector did ``"__schema" in str(data)`` and then read
``data.get("data", {}).get("__schema", {})`` -> ``{}`` -> ``types == []``, and
reported "GraphQL Introspection Enabled: Found 0 types" anyway. That is a false
positive: the server is correctly hardened. The fix requires a populated
``types`` list under ``data.__schema`` as positive evidence.

See heaven/vulnscan/api_scanner.py (GraphQLScanner.test_introspection).
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan.api_scanner import GraphQLScanner


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status
        self.headers = {"Content-Type": "application/json"}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self, content_type=None):
        return self._payload

    async def text(self):
        import json
        return json.dumps(self._payload)


class _Session:
    """Answers every POST with a fixed payload — models one GraphQL endpoint."""

    def __init__(self, payload):
        self._payload = payload

    def post(self, endpoint, json=None, timeout=None):  # noqa: A002 - mirror aiohttp
        return _Resp(self._payload)


def _run(coro):
    return asyncio.run(coro)


def test_disabled_introspection_echoing_field_name_is_not_flagged() -> None:
    # graphql-js / Apollo response when introspection is turned off.
    session = _Session({"errors": [{"message": (
        'GraphQL introspection has been disabled, but the requested query '
        'contained the field "__schema".')}]})
    findings = _run(GraphQLScanner.test_introspection(session, "http://t"))
    assert findings == [], [f.to_dict() for f in findings]


def test_null_data_with_schema_in_error_is_not_flagged() -> None:
    # Some servers send data:null alongside the errors array.
    session = _Session({"data": None, "errors": [
        {"message": 'Cannot query field "__schema" on type "Query".'}]})
    findings = _run(GraphQLScanner.test_introspection(session, "http://t"))
    assert findings == []


def test_empty_types_list_is_not_flagged() -> None:
    # Defensive: a __schema object with no types is not evidence of a usable
    # introspection surface.
    session = _Session({"data": {"__schema": {"types": [], "mutationType": None}}})
    findings = _run(GraphQLScanner.test_introspection(session, "http://t"))
    assert findings == []


def test_real_introspection_payload_is_flagged() -> None:
    session = _Session({"data": {"__schema": {
        "types": [{"name": "Query", "kind": "OBJECT"},
                  {"name": "User", "kind": "OBJECT"}],
        "mutationType": {"name": "Mutation"},
    }}})
    findings = _run(GraphQLScanner.test_introspection(session, "http://t"))
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "graphql_introspection"
    assert f.evidence["types_count"] == 2
    assert f.evidence["has_mutations"] is True
    assert "Query" in f.evidence["type_names"]


def test_real_introspection_without_mutations_reports_none() -> None:
    session = _Session({"data": {"__schema": {
        "types": [{"name": "Query", "kind": "OBJECT"}],
        "mutationType": None,
    }}})
    findings = _run(GraphQLScanner.test_introspection(session, "http://t"))
    assert len(findings) == 1
    assert findings[0].evidence["has_mutations"] is False
    assert "Mutations: none" in findings[0].description
