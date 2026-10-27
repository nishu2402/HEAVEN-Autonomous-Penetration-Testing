"""Regression: API request-body / query-param validation (P2).

Nearly every POST handler reads its body with ``body = await request.json()``
and then calls ``body.get(...)``. A well-formed body that is *not* a JSON object
(``[1,2,3]``, ``"x"``, ``5``, ``true``) — or a literal ``null`` — made ``.get``
raise ``AttributeError`` into an uncaught 500 (request-body type confusion). All
such handlers now route through :func:`heaven.api.server._json_object`, which
returns ``{}`` for an absent / empty / malformed body and answers a non-object
body with a clean 422. These tests lock that in, confirm degenerate bodies never
500, and check the one previously unbounded ``limit``-style query param.
"""
from __future__ import annotations

import pytest

import heaven.api.server as server


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    from fastapi.testclient import TestClient
    # raise_server_exceptions=False so a regressed handler surfaces as a real 500
    # (mirroring uvicorn) instead of re-raising into the test.
    try:
        yield TestClient(server.create_app(), raise_server_exceptions=False)
    finally:
        auth_mod._auth_manager = None


# Representative converted body-reading endpoints with light dependencies.
_BODY_ENDPOINTS = [
    "/api/correlate",
    "/api/analyze/decode",
    "/api/cve/lookup",
    "/api/cloud/storage",
    "/api/pivot/run",
    "/api/chat",
]

_NON_OBJECT_BODIES = [
    ("array", [1, 2, 3]),
    ("string", "hello"),
    ("number", 42),
    ("bool", True),
]


@pytest.mark.parametrize("path", _BODY_ENDPOINTS)
@pytest.mark.parametrize("label,payload", _NON_OBJECT_BODIES, ids=[b[0] for b in _NON_OBJECT_BODIES])
def test_non_object_body_is_422_not_500(client, path, label, payload):
    """A valid-but-non-object JSON body is a clean 422, never a 500."""
    r = client.post(path, json=payload)
    assert r.status_code == 422, (
        f"{path} with a JSON {label} body returned {r.status_code}, expected 422 "
        f"(body.get on a non-dict must not crash): {r.text[:200]}")


@pytest.mark.parametrize("path", _BODY_ENDPOINTS)
def test_degenerate_bodies_never_500(client, path):
    """Absent / null / malformed bodies produce the handler's own 2xx/4xx, not 500."""
    for sender in (
        lambda: client.post(path),                       # no body
        lambda: client.post(path, json=None),            # literal null
        lambda: client.post(path, content=b"{not json",  # malformed
                            headers={"content-type": "application/json"}),
    ):
        r = sender()
        assert r.status_code < 500, (
            f"{path} degenerate body returned {r.status_code}: {r.text[:200]}")


@pytest.mark.parametrize("path", _BODY_ENDPOINTS)
def test_deeply_nested_json_does_not_500(client, path):
    """A deeply nested body (parser recursion) must be absorbed, never 500."""
    deep = ("[" * 6000) + ("]" * 6000)
    r = client.post(path, content=deep.encode(),
                    headers={"content-type": "application/json"})
    assert r.status_code < 500, f"{path} nested body -> {r.status_code}"


@pytest.mark.parametrize("bad", [-1, 0, 101, 100000])
def test_knowledge_rank_top_is_bounded(client, bad):
    """`top` was an unbounded int Query (negative -> a surprising ``[:top]`` slice).
    It is now ge=1/le=100, so out-of-range values are rejected by validation."""
    r = client.get(f"/api/knowledge/rank?top={bad}")
    assert r.status_code == 422, f"top={bad} should be rejected, got {r.status_code}"


def test_knowledge_rank_valid_top_accepted(client):
    r = client.get("/api/knowledge/rank?top=5")
    assert r.status_code == 200, r.text


# ── _json_object helper (direct unit test, no HTTP) ──
class _FakeRequest:
    def __init__(self, payload, *, raise_decode=False):
        self._payload = payload
        self._raise = raise_decode

    async def json(self):
        if self._raise:
            import json
            raise json.JSONDecodeError("boom", "", 0)
        return self._payload


async def test_json_object_passes_through_a_dict():
    assert await server._json_object(_FakeRequest({"a": 1})) == {"a": 1}


async def test_json_object_empty_for_null_and_malformed():
    assert await server._json_object(_FakeRequest(None)) == {}
    assert await server._json_object(_FakeRequest(None, raise_decode=True)) == {}


@pytest.mark.parametrize("payload", [[1, 2], "x", 42, True])
async def test_json_object_rejects_non_object(payload):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        await server._json_object(_FakeRequest(payload))
    assert ei.value.status_code == 422
