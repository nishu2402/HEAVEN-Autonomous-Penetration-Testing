"""Tests for the SAML SSO audit in heaven.vulnscan.auth_scanner.

Metadata parsing is pure and exercised directly; the endpoint/RelayState audit
runs against a fake aiohttp session so no live IdP is needed.
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan import auth_scanner as A


_UNSIGNED_SP = (
    '<EntityDescriptor entityID="https://sp.example.com/meta" '
    'xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
    '<SPSSODescriptor WantAssertionsSigned="false" AuthnRequestsSigned="false">'
    '</SPSSODescriptor></EntityDescriptor>'
)
_SIGNED_SP = (
    '<EntityDescriptor entityID="https://sp.example.com/meta" '
    'xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
    '<SPSSODescriptor WantAssertionsSigned="true" AuthnRequestsSigned="true">'
    '</SPSSODescriptor></EntityDescriptor>'
)


def test_parse_metadata_unsigned():
    p = A._parse_saml_metadata(_UNSIGNED_SP)
    assert p["want_assertions_signed"] is False
    assert p["authn_requests_signed"] is False
    assert p["entity_id"] == "https://sp.example.com/meta"


def test_parse_metadata_signed():
    p = A._parse_saml_metadata(_SIGNED_SP)
    assert p["want_assertions_signed"] is True
    assert p["authn_requests_signed"] is True


def test_parse_metadata_malformed_is_safe():
    p = A._parse_saml_metadata("<not-xml <<<")
    assert p["want_assertions_signed"] is None


# ── fake aiohttp session ────────────────────────────────────────────────────────

class _Content:
    def __init__(self, body: bytes):
        self._b = body

    async def read(self, n: int = -1) -> bytes:
        return self._b[:n] if n and n > 0 else self._b


class _Resp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self.content = _Content(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    def __init__(self, routes):
        # routes: list of (substr, _Resp-factory)
        self._routes = routes

    def get(self, url, **kw):
        for substr, make in self._routes:
            if substr in url:
                return make()
        return _Resp(status=404)


def _run_saml(session):
    return asyncio.run(A._audit_saml(session, "https://sp.example.com/"))


def test_audit_saml_flags_unsigned_and_endpoint():
    session = _Session([
        ("/saml/metadata", lambda: _Resp(
            200, {"Content-Type": "application/xml"}, _UNSIGNED_SP.encode())),
    ])
    findings = _run_saml(session)
    vtypes = {f["vuln_type"] for f in findings}
    assert "saml_endpoint_exposed" in vtypes
    assert "saml_unsigned_assertions" in vtypes
    assert "saml_unsigned_authn_request" in vtypes
    high = next(f for f in findings if f["vuln_type"] == "saml_unsigned_assertions")
    assert high["severity"] == "high"


def test_audit_saml_signed_sp_no_unsigned_finding():
    session = _Session([
        ("/saml/metadata", lambda: _Resp(
            200, {"Content-Type": "application/xml"}, _SIGNED_SP.encode())),
    ])
    findings = _run_saml(session)
    vtypes = {f["vuln_type"] for f in findings}
    assert "saml_endpoint_exposed" in vtypes
    assert "saml_unsigned_assertions" not in vtypes


def test_audit_saml_relaystate_open_redirect():
    def _redirect():
        return _Resp(302, {"Location": "https://evil.attacker.example.com/saml"})

    session = _Session([
        ("/saml/sso", _redirect),
    ])
    findings = _run_saml(session)
    assert any(f["vuln_type"] == "saml_relaystate_redirect" for f in findings)


def test_audit_saml_ignores_non_saml_response():
    session = _Session([
        ("/saml/metadata", lambda: _Resp(200, {"Content-Type": "text/html"},
                                         b"<html>login</html>")),
    ])
    findings = _run_saml(session)
    assert findings == []
