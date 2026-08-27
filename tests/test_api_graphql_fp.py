"""GraphQL DoS detectors must not fire on a server that ENFORCES its limits.

`test_query_complexity` used to flag "No Query Depth/Complexity Limit" on any
HTTP 200, and `test_batching` flagged "Unlimited Query Batching" on any list of
>50 entries — even when the server answered 200 with an ``errors`` array that
*rejected* the deep query / rejected the batch. A depth-limited, batching-
disabled GraphQL server was therefore reported as vulnerable to both. These
tests pin the fix: a finding requires the query to be ACCEPTED, not rejected.

See heaven/vulnscan/api_scanner.py (_gql_rejected_on_complexity,
_gql_batch_succeeded).
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan.api_scanner import (
    GraphQLScanner,
    _gql_batch_succeeded,
    _gql_rejected_on_complexity,
)


# --- pure helpers -----------------------------------------------------------

def test_rejected_on_complexity_recognises_limit_errors() -> None:
    assert _gql_rejected_on_complexity(
        {"data": None, "errors": [{"message": "Query is too deep: depth 8 exceeds maximum of 5"}]}
    ) is True
    assert _gql_rejected_on_complexity(
        {"errors": [{"message": "Query cost 900 exceeds the maximum cost limit"}]}
    ) is True


def test_rejected_on_complexity_ignores_success_and_unrelated_errors() -> None:
    # A processed query (no errors) is not a rejection.
    assert _gql_rejected_on_complexity({"data": {"__type": {"fields": []}}}) is False
    # An error unrelated to depth/complexity should not suppress a real signal.
    assert _gql_rejected_on_complexity(
        {"errors": [{"message": "Field 'foo' is deprecated"}]}
    ) is False


def test_batch_succeeded_counts_only_processed_entries() -> None:
    processed = [{"data": {"__typename": "Query"}} for _ in range(100)]
    assert _gql_batch_succeeded(processed) == 100
    rejected = [{"errors": [{"message": "batching disabled"}]} for _ in range(100)]
    assert _gql_batch_succeeded(rejected) == 0
    assert _gql_batch_succeeded({"data": {}}) == 0  # not a list


# --- driven through the real detectors via a fake session -------------------

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


def test_complexity_not_flagged_when_depth_limit_enforced() -> None:
    session = _Session({"data": None, "errors": [{"message": "depth 8 exceeds maximum of 5"}]})
    findings = _run(GraphQLScanner.test_query_complexity(session, "http://t"))
    assert findings == []


def test_complexity_flagged_when_deep_query_accepted() -> None:
    session = _Session({"data": {"__type": {"fields": []}}})
    findings = _run(GraphQLScanner.test_query_complexity(session, "http://t"))
    assert len(findings) == 1
    assert findings[0].vuln_type == "graphql_complexity"
    # Downgraded to a verify-me signal, not an over-claimed high.
    assert findings[0].severity == "medium"


def test_batching_not_flagged_when_batching_rejected() -> None:
    session = _Session([{"errors": [{"message": "batching disabled"}]} for _ in range(100)])
    findings = _run(GraphQLScanner.test_batching(session, "http://t"))
    assert findings == []


def test_batching_flagged_when_batch_processed() -> None:
    session = _Session([{"data": {"__typename": "Query"}} for _ in range(100)])
    findings = _run(GraphQLScanner.test_batching(session, "http://t"))
    assert len(findings) == 1
    assert findings[0].vuln_type == "graphql_batching"
