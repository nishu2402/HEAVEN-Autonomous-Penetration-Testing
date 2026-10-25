"""HEAVEN: OAuth 2.0 / OIDC / SAML single-sign-on FLOW-abuse scanner.

The existing auth scanner discovers SSO endpoints and flags an open redirect in a
guessed ``redirect_uri``. This module goes a layer deeper into the flows that
account-takeover bugs actually live in, while keeping HEAVEN's precision
discipline: every finding is backed by evidence the scanner observed, never by a
guess. Two evidence kinds are used here:

* **Metadata facts.** The provider's own ``/.well-known/openid-configuration``
  (and RFC 8414 ``oauth-authorization-server``) document states, in writing,
  which response types, grant types and PKCE methods it supports. A weakness read
  straight out of that document (implicit flow enabled, PKCE not advertised,
  ROPC enabled) is reported with the exact field value as proof.
* **Observed reflections / redirects.** A ``redirect_uri`` bypass is reported
  only when the server actually issues a 3xx whose ``Location`` host is our
  off-origin marker; a password-reset host-header injection only when the
  spoofed host is reflected back into an absolute URL in the response. No
  observed redirect / reflection ⇒ no finding.

Everything is unauthenticated and read-only apart from one synthetic
password-reset POST that uses a non-existent ``…@example.com`` probe address, so
no real user is ever emailed.
"""

from __future__ import annotations

from heaven.net.egress import client_session as _egress_cs  # egress-routed aiohttp

import asyncio
import json
import secrets
import time
import urllib.parse
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    HAS_AIOHTTP = False

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.oauth")

# RFC 2606 / 6761 reserved names, safe, non-routable markers that can never
# belong to the target, so a redirect/reflection to one is unambiguous proof.
_REDIRECT_MARKER = "heaven-oauth-probe.example"
_RESET_MARKER = "heaven-reset-probe.example"

_OIDC_WELL_KNOWN = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
)

# Guessed authorize endpoints, used only when discovery metadata is absent.
_AUTHORIZE_PATHS = (
    "/oauth/authorize", "/oauth2/authorize", "/oauth2/v1/authorize",
    "/connect/authorize", "/auth/realms/master/protocol/openid-connect/auth",
    "/authorize",
)

_RESET_PATHS = (
    "/password/reset", "/reset-password", "/forgot-password", "/forgot_password",
    "/account/forgot", "/users/password", "/api/password/reset",
    "/api/auth/forgot-password", "/wp-login.php?action=lostpassword",
)

_SAML_METADATA_PATHS = (
    "/saml/metadata", "/saml2/metadata", "/saml/metadata.xml",
    "/sso/saml/metadata", "/auth/saml2/metadata",
    "/simplesaml/saml2/idp/metadata.php", "/Shibboleth.sso/Metadata",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
)

_TIMEOUT = 8.0


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, confidence: float, evidence: dict,
             remediation: str, cwe: str = "") -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "cve_id": "",
        "cwe": cwe,
        "evidence": evidence,
        "remediation": remediation,
        "source": "oauth_scanner",
    }


def _origin(url: str) -> str:
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


async def _get(session, url: str, *, headers: Optional[dict] = None,
               allow_redirects: bool = False) -> tuple[int, dict, str]:
    """GET returning (status, headers-dict, bounded-text). Never raises."""
    try:
        async with session.get(url, headers=headers, allow_redirects=allow_redirects,
                               timeout=aiohttp.ClientTimeout(total=_TIMEOUT)) as resp:
            body = await resp.content.read(256 * 1024)
            return resp.status, dict(resp.headers), body.decode("utf-8", "ignore")
    except Exception as e:  # noqa: BLE001 - a failed probe is not a failed scan
        logger.debug("oauth GET %s failed: %s", url, e)
        return 0, {}, ""


# ── OIDC / OAuth discovery metadata ───────────────────────────────────────────

async def _discover(session, origin: str) -> tuple[dict, str]:
    """Return (metadata, doc_url) for the first discovery document found."""
    for path in _OIDC_WELL_KNOWN:
        doc_url = origin + path
        status, _h, text = await _get(session, doc_url)
        if status != 200 or not text:
            continue
        try:
            meta = json.loads(text)
        except (ValueError, TypeError):
            continue
        if isinstance(meta, dict) and (meta.get("authorization_endpoint")
                                       or meta.get("token_endpoint")):
            return meta, doc_url
    return {}, ""


def _metadata_weaknesses(meta: dict, doc_url: str) -> list[dict]:
    """Weaknesses stated in the provider's own discovery document (each fact is
    quoted into the evidence, so the finding is self-proving)."""
    out: list[dict] = []
    resp_types = [str(r).lower() for r in (meta.get("response_types_supported") or [])]
    grant_types = [str(g).lower() for g in (meta.get("grant_types_supported") or [])]
    pkce = meta.get("code_challenge_methods_supported")
    authz = meta.get("authorization_endpoint") or doc_url

    # Implicit flow: an access token delivered in the URL fragment (leaks via
    # Referer, browser history, logs). Deprecated by the OAuth 2.0 Security BCP.
    # Match only response types that return an access token straight from the
    # authorization endpoint: split each value into its space-delimited terms and
    # look for a bare "token" term (as in "token" or "id_token token"). A plain
    # substring test would over-match "id_token" / "code id_token" (standard OIDC
    # response types that return only an ID-token assertion, not a bearer access
    # token, in the fragment) and false-positive on ordinary OIDC providers.
    implicit = [r for r in resp_types if "token" in r.split()]
    if implicit:
        out.append(_finding(
            authz, "oauth_implicit_flow_enabled", "medium",
            "OAuth implicit flow enabled (token delivered in URL fragment)",
            "The authorization server advertises an implicit-flow response type, so "
            "access/ID tokens are returned in the URL fragment where they leak "
            "through Referer headers, browser history and proxy logs. The OAuth 2.0 "
            "Security Best Current Practice deprecates the implicit flow in favour "
            "of authorization code + PKCE.",
            0.8, {"response_types_supported": implicit, "discovery": doc_url,
                  "proof": f"discovery advertises response_types_supported={implicit}"},
            "Disable the implicit flow; use authorization code with PKCE.",
            cwe="CWE-522"))

    # PKCE not advertised, public clients are exposed to authorization-code
    # interception. Conditional on there being public clients, so reported at
    # medium with the exact fact and the caveat in the description.
    if pkce in (None, [], ""):
        out.append(_finding(
            authz, "oauth_pkce_not_advertised", "low",
            "PKCE not advertised in OAuth/OIDC discovery metadata",
            "The discovery document does not list code_challenge_methods_supported, "
            "so PKCE support is not advertised. Public clients (SPAs, mobile apps) "
            "without PKCE are vulnerable to authorization-code interception. Confirm "
            "against the specific client before treating as exploitable.",
            0.45, {"code_challenge_methods_supported": pkce, "discovery": doc_url,
                  "proof": "discovery omits code_challenge_methods_supported"},
            "Require PKCE (S256) for all public clients.",
            cwe="CWE-287"))

    # Resource-owner password credentials grant, discouraged; hands the user's
    # password to the client and defeats MFA / consent.
    if "password" in grant_types:
        out.append(_finding(
            authz, "oauth_ropc_enabled", "low",
            "OAuth resource-owner password credentials (ROPC) grant enabled",
            "The authorization server advertises the 'password' grant type, which "
            "requires clients to handle the user's credentials directly and bypasses "
            "consent and most MFA. The OAuth 2.0 Security BCP recommends removing it.",
            0.75, {"grant_types_supported": grant_types, "discovery": doc_url,
                   "proof": "discovery advertises grant_types_supported includes 'password'"},
            "Remove the password grant; use authorization code with PKCE.",
            cwe="CWE-287"))

    return out


# ── redirect_uri manipulation ─────────────────────────────────────────────────

def _redirect_uri_variants(legit_host: str) -> list[tuple[str, str]]:
    """(label, redirect_uri) pairs. Each tries a different way to smuggle the
    off-origin marker host past a weak redirect_uri validator."""
    m = _REDIRECT_MARKER
    return [
        ("exact_offorigin", f"https://{m}/cb"),
        ("subdomain", f"https://{legit_host}.{m}/cb"),
        ("userinfo", f"https://{legit_host}@{m}/cb"),
        ("scheme_relative", f"//{m}/cb"),
        ("backslash", f"https://{m}\\@{legit_host}/cb"),
    ]


async def _audit_redirect_uri(session, origin: str, authorize_endpoints: list[str]) -> list[dict]:
    """Report a redirect_uri bypass only on an OBSERVED 3xx to the marker host."""
    out: list[dict] = []
    legit_host = urllib.parse.urlparse(origin).netloc
    seen_endpoints: set[str] = set()
    for authz in authorize_endpoints:
        if not authz or authz in seen_endpoints:
            continue
        seen_endpoints.add(authz)
        for label, redirect_uri in _redirect_uri_variants(legit_host):
            state = "heaven" + secrets.token_hex(4)
            q = urllib.parse.urlencode({
                "response_type": "code", "client_id": "heaven-probe",
                "redirect_uri": redirect_uri, "scope": "openid", "state": state,
            })
            status, headers, _body = await _get(session, f"{authz}?{q}")
            if status not in (301, 302, 303, 307, 308):
                continue
            location = headers.get("Location", "") or headers.get("location", "")
            loc_host = urllib.parse.urlparse(location).netloc.lower()
            # Proof: the redirect actually leaves for the marker host.
            if _REDIRECT_MARKER in loc_host:
                out.append(_finding(
                    authz, "oauth_redirect_uri_bypass", "high",
                    f"OAuth redirect_uri validation bypass ({label})",
                    "The authorization endpoint redirected to an attacker-controlled "
                    "host supplied in redirect_uri, proven by the observed Location "
                    "header. An attacker can capture the authorization code (or token) "
                    "and take over the victim's account.",
                    0.9, {"variant": label, "redirect_uri": redirect_uri,
                          "location": location, "state": state,
                          "proof": f"server issued {status} to {location}"},
                    "Match redirect_uri against an exact, pre-registered allow-list; "
                    "never substring/prefix match, and reject userinfo/backslash tricks.",
                    cwe="CWE-601"))
                break  # one proven bypass per endpoint is enough
    return out


# ── password-reset host-header poisoning ──────────────────────────────────────

async def _audit_password_reset_hostheader(session, origin: str,
                                            reset_urls: list[str]) -> list[dict]:
    """A reset link built from an attacker-controlled Host/X-Forwarded-Host sends
    the victim a poisoned link (→ token theft). Reported only when the spoofed
    marker host is reflected into an absolute URL in the response."""
    out: list[dict] = []
    marker = _RESET_MARKER
    spoof_headers = {
        "Host": marker,
        "X-Forwarded-Host": marker,
        "X-Forwarded-Server": marker,
        "X-Host": marker,
    }
    probe_email = f"heaven.reset.{secrets.token_hex(3)}@example.com"
    candidates = list(dict.fromkeys(reset_urls + [origin + p for p in _RESET_PATHS]))
    for reset_url in candidates:
        # GET reflection (some apps echo the host into a pre-filled link).
        status, _h, body = await _get(session, reset_url, headers=spoof_headers)
        reflected = _reflected_marker(body, marker)
        # If the GET did not reflect it, try a synthetic POST (non-existent email).
        if not reflected and status and status < 500:
            try:
                async with session.post(
                    reset_url, headers=spoof_headers,
                    data={"email": probe_email, "username": probe_email},
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=_TIMEOUT)) as resp:
                    pbody = await resp.content.read(256 * 1024)
                    reflected = _reflected_marker(pbody.decode("utf-8", "ignore"), marker)
            except Exception:  # noqa: BLE001
                reflected = ""
        if reflected:
            out.append(_finding(
                reset_url, "password_reset_host_poisoning", "high",
                "Password-reset link host-header poisoning",
                "The application reflected an attacker-controlled Host / "
                "X-Forwarded-Host into an absolute URL, so a password-reset link "
                "built from it would point at the attacker's host. A victim who "
                "clicks it leaks their reset token, enabling account takeover.",
                0.85, {"spoofed_host": marker, "reflection": reflected,
                       "proof": f"the spoofed host {marker} appeared in an absolute "
                                "URL in the response"},
                "Build absolute links from a fixed, configured base URL; never trust "
                "the Host or X-Forwarded-* headers for link generation.",
                cwe="CWE-640"))
            break  # one proven reset-poisoning per origin is enough
    return out


def _reflected_marker(body: str, marker: str) -> str:
    """Return the first absolute-URL occurrence of ``marker`` in ``body``, else ''.

    Requires the marker to appear in a URL context (``//marker`` or ``marker/``
    after a scheme) so a bare echo of the header elsewhere is not mistaken for a
    link-generation sink."""
    if not body or marker not in body:
        return ""
    for needle in (f"https://{marker}", f"http://{marker}", f"//{marker}"):
        idx = body.find(needle)
        if idx != -1:
            return body[idx:idx + len(needle) + 16]
    return ""


# ── SAML assertion-signing posture ────────────────────────────────────────────

def _parse_saml_signing(xml_text: str) -> dict:
    out = {"want_assertions_signed": None, "authn_requests_signed": None,
           "entity_id": "", "is_saml": False}
    try:
        from defusedxml.ElementTree import fromstring as _fromstring
        root = _fromstring(xml_text)
    except Exception:
        return out

    def _ln(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    def _as_bool(v):
        return None if v is None else v.strip().lower() in ("true", "1")

    for el in root.iter():
        ln = _ln(el.tag)
        if ln in ("EntityDescriptor", "EntitiesDescriptor"):
            out["is_saml"] = True
            if not out["entity_id"]:
                out["entity_id"] = el.attrib.get("entityID", "")
        if ln == "SPSSODescriptor":
            b = _as_bool(el.attrib.get("WantAssertionsSigned"))
            if b is not None:
                out["want_assertions_signed"] = b
            b2 = _as_bool(el.attrib.get("AuthnRequestsSigned"))
            if b2 is not None:
                out["authn_requests_signed"] = b2
    return out


async def _audit_saml_signing(session, origin: str) -> list[dict]:
    """From published SAML metadata, flag assertion-signing not being enforced
    (the precondition for XML-signature-wrapping / signature-stripping forgery)."""
    out: list[dict] = []
    for path in _SAML_METADATA_PATHS:
        meta_url = origin + path
        status, _h, text = await _get(session, meta_url)
        if status != 200 or ("EntityDescriptor" not in text
                             and "urn:oasis:names:tc:SAML" not in text):
            continue
        parsed = _parse_saml_signing(text)
        if not parsed["is_saml"]:
            continue
        if parsed["want_assertions_signed"] is False:
            out.append(_finding(
                meta_url, "saml_assertion_signing_not_enforced", "high",
                "SAML assertion signing not enforced (signature-wrapping exposure)",
                "The service provider's published metadata sets "
                "WantAssertionsSigned=false, so it will accept assertions whose "
                "signature is absent or wrapped (XSW). An attacker who can craft or "
                "replay an assertion may authenticate as any user.",
                0.8, {"entity_id": parsed["entity_id"], "metadata": meta_url,
                      "want_assertions_signed": False,
                      "proof": "metadata WantAssertionsSigned=\"false\""},
                "Set WantAssertionsSigned=true and validate the signature over the "
                "whole assertion; reject unsigned or multiply-signed assertions.",
                cwe="CWE-347"))
        break  # audit the first real metadata document only
    return out


# ── public entry ──────────────────────────────────────────────────────────────

async def scan_oauth_flows(urls: list[str], *, time_budget: Optional[float] = None,
                           oast=None, reset_urls: Optional[list[str]] = None) -> dict:
    """Audit OAuth/OIDC/SAML flows across the distinct origins in ``urls``.

    ``reset_urls`` are extra password-reset endpoints discovered by the crawler.
    ``oast`` is accepted for interface parity with the other scanners; the flow
    checks here are in-band (observed redirects / reflections), so it is unused.
    """
    if not HAS_AIOHTTP:
        return {"findings": [], "vulnerabilities": [], "total": 0,
                "error": "aiohttp not installed"}

    origins: list[str] = []
    for u in urls:
        o = _origin(u)
        if o and o not in origins:
            origins.append(o)
    if not origins:
        return {"findings": [], "vulnerabilities": [], "total": 0}

    reset_by_origin: dict[str, list[str]] = {}
    for r in (reset_urls or []):
        o = _origin(r)
        if o:
            reset_by_origin.setdefault(o, []).append(r)

    findings: list[dict] = []
    headers = {"User-Agent": "Mozilla/5.0 (compatible; HEAVEN-OAuthScanner/1.0)"}
    connector = aiohttp.TCPConnector(ssl=False, limit=15)
    ct = aiohttp.ClientTimeout(total=30)
    deadline = (time.monotonic() + time_budget) if time_budget else None

    async with _egress_cs(headers=headers, connector=connector, timeout=ct) as session:
        for origin in origins:
            if deadline and time.monotonic() > deadline:
                logger.warning("oauth scan: time budget reached, returning partial")
                break
            meta, doc_url = await _discover(session, origin)
            authorize_endpoints = []
            if meta.get("authorization_endpoint"):
                authorize_endpoints.append(meta["authorization_endpoint"])
                findings.extend(_metadata_weaknesses(meta, doc_url))
            else:
                authorize_endpoints = [origin + p for p in _AUTHORIZE_PATHS]

            results = await asyncio.gather(
                _audit_redirect_uri(session, origin, authorize_endpoints),
                _audit_password_reset_hostheader(
                    session, origin, reset_by_origin.get(origin, [])),
                _audit_saml_signing(session, origin),
                return_exceptions=True,
            )
            for res in results:
                if isinstance(res, list):
                    findings.extend(res)
                elif isinstance(res, Exception):
                    logger.debug("oauth subtask error: %s", res)

    # De-dup by (target, vuln_type).
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f["target"], f["vuln_type"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    logger.info("OAuth/OIDC/SAML flow audit → %d finding(s) across %d origin(s)",
                len(deduped), len(origins))
    return {"findings": deduped, "vulnerabilities": deduped, "total": len(deduped)}
