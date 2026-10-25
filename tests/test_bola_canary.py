"""Phase 4 — cross-identity BOLA with a ground-truth reciprocal cross-read.

The new IDOR probe must confirm a real object-level authorization break (user A
reads user B's object and vice-versa, two distinct access-controlled objects),
while staying silent on a server that enforces ownership and on shared
authenticated content that merely happens to require a login.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiohttp")

from aiohttp import web  # noqa: E402

from heaven.vulnscan.idor_scanner import IDORScanner  # noqa: E402

_DATA = {
    "1": "<html>Account holder: Alice | SSN 111-11-1111 | balance $10</html>",
    "2": "<html>Account holder: Bob | SSN 222-22-2222 | balance $20</html>",
}
_OWNER = {"1": "Bearer AAA", "2": "Bearer BBB"}


async def _run(mode: str):
    async def item(request):
        oid = request.match_info["oid"]
        auth = request.headers.get("Authorization", "")
        if not auth:
            return web.Response(status=401, text="auth required")
        if oid not in _DATA:
            return web.Response(status=404, text="not found")
        if mode == "secure" and auth != _OWNER[oid]:
            return web.Response(status=403, text="forbidden")
        if mode == "shared":
            return web.Response(text="<html>Shared authenticated dashboard</html>")
        return web.Response(text=_DATA[oid])

    app = web.Application()
    app.router.add_get("/api/item/{oid}", item)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    sc = IDORScanner(auth_headers={"Authorization": "Bearer AAA"},
                     alt_auth_headers={"Authorization": "Bearer BBB"})
    try:
        res = await sc.scan([f"http://127.0.0.1:{port}/api/item/1"])
    finally:
        await runner.cleanup()
    return [f for f in res["findings"] if f["vuln_type"] == "bola"]


@pytest.mark.asyncio
async def test_bola_confirmed_on_broken_object_authorization():
    bola = await _run("vuln")
    assert len(bola) == 1
    f = bola[0]
    assert f["severity"] == "critical"
    assert f["evidence"]["probe_type"] == "cross_identity_bola"
    assert f["evidence"]["own_id"] == "1" and f["evidence"]["other_id"] == "2"


@pytest.mark.asyncio
async def test_bola_silent_when_ownership_enforced():
    assert await _run("secure") == []


@pytest.mark.asyncio
async def test_bola_silent_on_shared_authenticated_content():
    # Same content for every authenticated user (login-gated but not per-user):
    # the exact-equality "distinct object" gate excludes it, so no false BOLA.
    assert await _run("shared") == []


@pytest.mark.asyncio
async def test_bola_requires_two_identities():
    # With only one identity there is nothing to cross-read.
    async def item(request):
        return web.Response(text=_DATA.get(request.match_info["oid"], "x"))

    app = web.Application()
    app.router.add_get("/api/item/{oid}", item)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    sc = IDORScanner(auth_headers={"Authorization": "Bearer AAA"})  # no alt identity
    try:
        res = await sc.scan([f"http://127.0.0.1:{port}/api/item/1"])
    finally:
        await runner.cleanup()
    assert [f for f in res["findings"] if f["vuln_type"] == "bola"] == []
