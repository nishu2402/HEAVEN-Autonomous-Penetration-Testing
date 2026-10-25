"""Phase 2 — OAuth 2.0 / OIDC / SAML flow-abuse scanner.

Each weakness is asserted against a deliberately-vulnerable provider AND shown to
stay silent against a hardened one, so the scanner proves bugs from observed
redirects / reflections and metadata facts without inventing any.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiohttp")

from aiohttp import web  # noqa: E402

from heaven.vulnscan.oauth_scanner import scan_oauth_flows  # noqa: E402

_SAML_UNSIGNED = (
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp1">'
    '<SPSSODescriptor WantAssertionsSigned="false" AuthnRequestsSigned="false"/>'
    '</EntityDescriptor>'
)
_SAML_SIGNED = (
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp1">'
    '<SPSSODescriptor WantAssertionsSigned="true" AuthnRequestsSigned="true"/>'
    '</EntityDescriptor>'
)


async def _serve(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}/"


def _vuln_app() -> web.Application:
    async def wellknown(request):
        host = request.host
        return web.json_response({
            "issuer": f"http://{host}",
            "authorization_endpoint": f"http://{host}/authorize",
            "token_endpoint": f"http://{host}/token",
            "response_types_supported": ["code", "id_token token"],  # implicit
            "grant_types_supported": ["authorization_code", "password"],  # ROPC
            # code_challenge_methods_supported intentionally absent -> no PKCE
        })

    async def authorize(request):
        # Weak validator: echoes any redirect_uri straight into Location.
        return web.Response(status=302,
                            headers={"Location": request.query.get("redirect_uri", "")})

    async def reset(request):
        xf = request.headers.get("X-Forwarded-Host", request.host)
        return web.Response(text=f'<a href="https://{xf}/reset?token=abc">reset</a>')

    async def saml(request):
        return web.Response(text=_SAML_UNSIGNED, content_type="application/xml")

    app = web.Application()
    app.router.add_get("/.well-known/openid-configuration", wellknown)
    app.router.add_get("/authorize", authorize)
    app.router.add_route("*", "/forgot-password", reset)
    app.router.add_get("/saml/metadata", saml)
    return app


def _secure_app() -> web.Application:
    async def wellknown(request):
        host = request.host
        return web.json_response({
            "issuer": f"http://{host}",
            "authorization_endpoint": f"http://{host}/authorize",
            "token_endpoint": f"http://{host}/token",
            "response_types_supported": ["code"],                  # no implicit
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],          # PKCE advertised
        })

    async def authorize(request):
        ru = request.query.get("redirect_uri", "")
        allow = f"http://{request.host}/cb"
        # Strict exact-match validator: reject anything not pre-registered.
        if ru != allow:
            return web.Response(status=400, text="invalid redirect_uri")
        return web.Response(status=302, headers={"Location": ru})

    async def reset(request):
        # Builds the link from a FIXED configured base, ignoring Host / XFH.
        return web.Response(text='<a href="https://sso.secure.example/reset?token=abc">reset</a>')

    async def saml(request):
        return web.Response(text=_SAML_SIGNED, content_type="application/xml")

    app = web.Application()
    app.router.add_get("/.well-known/openid-configuration", wellknown)
    app.router.add_get("/authorize", authorize)
    app.router.add_route("*", "/forgot-password", reset)
    app.router.add_get("/saml/metadata", saml)
    return app


@pytest.mark.asyncio
async def test_vulnerable_provider_surfaces_all_flow_bugs():
    runner, base = await _serve(_vuln_app())
    try:
        res = await scan_oauth_flows([base], reset_urls=[base + "forgot-password"])
    finally:
        await runner.cleanup()

    vts = {f["vuln_type"] for f in res["findings"]}
    assert "oauth_implicit_flow_enabled" in vts
    assert "oauth_pkce_not_advertised" in vts
    assert "oauth_ropc_enabled" in vts
    assert "oauth_redirect_uri_bypass" in vts
    assert "password_reset_host_poisoning" in vts
    assert "saml_assertion_signing_not_enforced" in vts
    # The redirect bypass carries the observed off-origin Location as proof.
    rb = next(f for f in res["findings"] if f["vuln_type"] == "oauth_redirect_uri_bypass")
    assert "heaven-oauth-probe.example" in rb["evidence"]["location"]
    assert rb["severity"] == "high"


@pytest.mark.asyncio
async def test_hardened_provider_is_silent():
    runner, base = await _serve(_secure_app())
    try:
        res = await scan_oauth_flows([base], reset_urls=[base + "forgot-password"])
    finally:
        await runner.cleanup()

    # A correctly configured provider yields no flow-abuse finding.
    assert res["findings"] == [], [f["vuln_type"] for f in res["findings"]]


@pytest.mark.asyncio
async def test_standard_oidc_response_types_not_flagged_as_implicit():
    # A plain OIDC provider advertising code / id_token / code id_token returns
    # only an ID-token assertion in the fragment, never a bearer access token, so
    # it must NOT be reported as implicit-flow enabled. A substring match on
    # "token" (which "id_token" contains) would false-positive on every such
    # provider; the term-split matcher does not.
    async def wellknown(request):
        host = request.host
        return web.json_response({
            "issuer": f"http://{host}",
            "authorization_endpoint": f"http://{host}/authorize",
            "token_endpoint": f"http://{host}/token",
            "response_types_supported": ["code", "id_token", "code id_token"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
        })

    app = web.Application()
    app.router.add_get("/.well-known/openid-configuration", wellknown)
    runner, base = await _serve(app)
    try:
        res = await scan_oauth_flows([base])
    finally:
        await runner.cleanup()
    vts = {f["vuln_type"] for f in res["findings"]}
    assert "oauth_implicit_flow_enabled" not in vts, [f["evidence"] for f in res["findings"]]


@pytest.mark.asyncio
async def test_pure_access_token_response_type_is_flagged_implicit():
    # response_type=token delivers a bearer access token in the fragment — the
    # deprecated implicit grant — and must be flagged.
    async def wellknown(request):
        host = request.host
        return web.json_response({
            "issuer": f"http://{host}",
            "authorization_endpoint": f"http://{host}/authorize",
            "token_endpoint": f"http://{host}/token",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
        })

    app = web.Application()
    app.router.add_get("/.well-known/openid-configuration", wellknown)
    runner, base = await _serve(app)
    try:
        res = await scan_oauth_flows([base])
    finally:
        await runner.cleanup()
    vts = {f["vuln_type"] for f in res["findings"]}
    assert "oauth_implicit_flow_enabled" in vts


@pytest.mark.asyncio
async def test_no_discovery_still_probes_guessed_endpoints_without_fp():
    # No OIDC metadata and a server that never redirects off-origin: nothing fires.
    async def ok(request):
        return web.Response(text="not an oauth server")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", ok)
    runner, base = await _serve(app)
    try:
        res = await scan_oauth_flows([base])
    finally:
        await runner.cleanup()
    assert res["findings"] == []
