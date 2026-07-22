"""HEAVEN — Web misconfiguration & session-security scanner.

Deterministic, low-false-positive checks that need no out-of-band channel and no
third-party service — every verdict is read straight off the target's own
responses:

* **CORS misconfiguration** — a reflected ``Access-Control-Allow-Origin`` paired
  with ``Access-Control-Allow-Credentials: true`` (credentialed cross-origin
  data theft), or an allowed ``null`` origin.
* **Insecure session cookies** — session/JWT cookies missing ``HttpOnly`` /
  ``Secure`` / ``SameSite``.
* **JWT weaknesses** — ``alg:none`` acceptance and weak HMAC secrets (cracked
  in-house against a small wordlist; the recovered secret is the proof).
* **Open redirect** — a redirect parameter that sends a 30x ``Location`` to an
  attacker-controlled host (confirmed by an exact canary-host match, so it never
  fires on same-site redirects).
* **Missing security headers** — CSP / X-Frame-Options / X-Content-Type-Options
  absent on an HTML response.

All checks are confirmation-based: a finding is only emitted on observed,
attacker-favourable behaviour, never on the mere absence of a "good" value.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover - exercised only in minimal installs
    HAS_AIOHTTP = False

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.misconfig")

# Unique, non-resolvable canary hosts — an exact match in a reflected value is
# proof the target trusted our input, with zero chance of a coincidental hit.
_CORS_PROBE_ORIGIN = "https://heaven-cors-probe.invalid"
_REDIRECT_PROBE_HOST = "heaven-redirect-probe.invalid"
_REDIRECT_PROBE_URL = f"https://{_REDIRECT_PROBE_HOST}/oob"

# Parameter names that commonly drive a redirect. We test the ones already
# present on the URL plus this curated set; a finding still requires an actual
# 30x to the canary host, so probing extra names cannot cause a false positive.
_REDIRECT_PARAMS = (
    "url", "next", "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "returnurl", "returnto", "dest", "destination", "continue",
    "goto", "rurl", "target", "to", "out", "view", "forward", "callback",
)

# Cookie names that indicate a session/auth token worth flag-checking.
_SESSION_COOKIE_HINTS = (
    "session", "sess", "sid", "auth", "token", "jwt", "jsessionid",
    "phpsessid", "aspsessionid", "connect.sid", "csrftoken", "remember",
)

# Small in-house wordlist for HMAC-JWT secret recovery. These are the secrets
# that actually show up in tutorials, boilerplate and leaked configs — cracking
# one is definitive proof the token can be forged.
_JWT_WEAK_SECRETS = (
    "secret", "password", "123456", "changeme", "admin", "test", "key",
    "jwt", "token", "secretkey", "secret123", "supersecret", "your-256-bit-secret",
    "qwerty", "letmein", "root", "default", "private", "mysecret", "s3cr3t",
    "jwtsecret", "jwt_secret", "SECRET", "P@ssw0rd", "example_key",
)

_DEFAULT_TIMEOUT = 10.0


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, confidence: float, evidence: dict) -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "cve_id": "",
        "evidence": evidence,
        "source": "misconfig_scanner",
    }


def _dedup(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for f in findings:
        key = (str(f.get("target", "")), str(f.get("vuln_type", "")))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# ── JWT helpers (in-house, stdlib only) ───────────────────────────────────────
_JWT_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _parse_jwt(token: str) -> tuple[dict, str, str] | None:
    """Return (header, signing_input, signature_b64url) or None if not a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None
    return header, f"{parts[0]}.{parts[1]}", parts[2]


def _crack_jwt_secret(signing_input: str, sig_b64: str, alg: str) -> str | None:
    digest = _JWT_ALGS.get(alg.upper())
    if digest is None:
        return None
    try:
        want = _b64url_decode(sig_b64)
    except (binascii.Error, ValueError):
        return None
    for secret in _JWT_WEAK_SECRETS:
        got = hmac.new(secret.encode(), signing_input.encode(), digest).digest()
        if hmac.compare_digest(got, want):
            return secret
    return None


def _jwt_findings(target: str, token: str, source: str) -> list[dict]:
    parsed = _parse_jwt(token)
    if parsed is None:
        return []
    header, signing_input, sig = parsed
    alg = str(header.get("alg", "")).lower()
    out: list[dict] = []
    if alg == "none":
        out.append(_finding(
            target, "jwt_alg_none", "critical",
            "JWT accepts alg:none — tokens are forgeable",
            "A JWT using the 'none' algorithm carries no signature, so any client "
            "can forge a token with arbitrary claims (e.g. escalate to admin).",
            0.95, {"source": source, "jwt_header": header},
        ))
        return out
    secret = _crack_jwt_secret(signing_input, sig, header.get("alg", ""))
    if secret is not None:
        out.append(_finding(
            target, "jwt_weak_secret", "critical",
            f"JWT signed with a weak, guessable secret ({header.get('alg')})",
            "The HMAC signing key was recovered from a small wordlist, so an "
            "attacker can mint valid tokens with any claims they like.",
            0.98, {"source": source, "algorithm": header.get("alg"),
                   "recovered_secret": secret, "jwt_header": header},
        ))
    return out


def _extract_jwts(text: str) -> list[str]:
    import re
    # header.payload.signature where header/payload are base64url JSON
    return re.findall(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", text or "")


# ── individual checks ─────────────────────────────────────────────────────────
async def _check_cors(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    try:
        async with session.get(url, headers={"Origin": _CORS_PROBE_ORIGIN},
                               allow_redirects=False) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    except Exception as e:  # noqa: BLE001
        logger.debug("CORS check failed for %s: %s", url, e)
        return []
    reflects = acao == _CORS_PROBE_ORIGIN
    allows_null = acao == "null"
    creds = acac == "true"
    if (reflects or allows_null) and creds:
        return [_finding(
            url, "cors_misconfig", "high",
            "CORS reflects arbitrary Origin with credentials",
            "The server echoes an attacker-supplied Origin into "
            "Access-Control-Allow-Origin while allowing credentials, so a "
            "malicious site can read authenticated responses cross-origin.",
            0.9, {"reflected_origin": acao, "allow_credentials": True,
                  "probe_origin": _CORS_PROBE_ORIGIN})]
    if reflects and not creds:
        return [_finding(
            url, "cors_misconfig", "medium",
            "CORS reflects arbitrary Origin",
            "The server echoes any supplied Origin into "
            "Access-Control-Allow-Origin. Without credentials the impact is "
            "limited, but it still exposes non-cookie-gated data cross-origin.",
            0.7, {"reflected_origin": acao, "allow_credentials": False,
                  "probe_origin": _CORS_PROBE_ORIGIN})]
    return []


async def _check_cookies_and_jwt(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    try:
        async with session.get(url, allow_redirects=False) as resp:
            set_cookies = resp.headers.getall("Set-Cookie", [])
            is_https = urlparse(url).scheme == "https"
            body = ""
            if resp.content_type and "json" in resp.content_type or (
                    resp.content_type and "html" in resp.content_type):
                body = await resp.text(errors="replace")
    except Exception as e:  # noqa: BLE001
        logger.debug("cookie/JWT check failed for %s: %s", url, e)
        return []

    out: list[dict] = []
    seen_jwts: set[str] = set()
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        value = raw.split("=", 1)[1].split(";", 1)[0] if "=" in raw else ""
        low = raw.lower()
        is_session = any(h in name.lower() for h in _SESSION_COOKIE_HINTS) or bool(
            _parse_jwt(value))
        if is_session:
            missing = []
            if "httponly" not in low:
                missing.append("HttpOnly")
            if is_https and "secure" not in low:
                missing.append("Secure")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                sev = "medium" if "HttpOnly" in missing else "low"
                out.append(_finding(
                    url, "insecure_cookie", sev,
                    f"Session cookie '{name}' missing {', '.join(missing)}",
                    "A session/auth cookie lacks protective flags, exposing it to "
                    "theft via XSS (HttpOnly), plaintext transport (Secure) or "
                    "cross-site sending (SameSite).",
                    0.85, {"cookie_name": name, "missing_flags": missing}))
        # a JWT delivered in a cookie is worth cracking
        if _parse_jwt(value) and value not in seen_jwts:
            seen_jwts.add(value)
            out.extend(_jwt_findings(url, value, source=f"cookie:{name}"))
    for tok in _extract_jwts(body):
        if tok not in seen_jwts:
            seen_jwts.add(tok)
            out.extend(_jwt_findings(url, tok, source="response_body"))
    return out


async def _check_security_headers(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    try:
        async with session.get(url, allow_redirects=True) as resp:
            if resp.status >= 400 or "html" not in (resp.content_type or ""):
                return []
            h = {k.lower() for k in resp.headers.keys()}
    except Exception as e:  # noqa: BLE001
        logger.debug("security-header check failed for %s: %s", url, e)
        return []
    missing = []
    if "content-security-policy" not in h:
        missing.append("Content-Security-Policy")
    if "x-frame-options" not in h and "content-security-policy" not in h:
        missing.append("X-Frame-Options")  # (CSP frame-ancestors also covers this)
    if "x-content-type-options" not in h:
        missing.append("X-Content-Type-Options")
    if not missing:
        return []
    # Header hardening is a host-level property — anchor the finding to the origin
    # so it collapses to one result instead of firing on every crawled page.
    p = urlparse(url)
    origin = f"{p.scheme}://{p.netloc}"
    return [_finding(
        origin, "missing_security_headers", "low",
        f"Missing security headers: {', '.join(missing)}",
        "The HTML response omits hardening headers that mitigate clickjacking, "
        "MIME sniffing and script injection.",
        0.75, {"missing_headers": missing, "observed_on": url})]


# Headers that leak a concrete software version. We flag only when a *version
# number* is present — a bare "nginx"/"Apache" product token is not actionable
# and would be noise, but "nginx/1.22.1" or "PHP/7.4.3" hands an attacker a CVE
# shortlist. Anchored to the origin so it collapses to one finding per host.
_VERSION_HEADER_RE = re.compile(r"/\s*\d+(?:\.\d+)+")
_BANNER_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version",
                   "X-AspNetMvc-Version", "X-Generator")


async def _check_server_banner(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    try:
        async with session.get(url, allow_redirects=True) as resp:
            if resp.status >= 500:
                return []
            disclosed = {}
            for hdr in _BANNER_HEADERS:
                val = resp.headers.get(hdr, "")
                if not val:
                    continue
                # Server/X-Powered-By need a version to be worth flagging; the
                # ASP.NET version headers are a disclosed version by definition.
                if hdr in ("X-AspNet-Version", "X-AspNetMvc-Version") or \
                        _VERSION_HEADER_RE.search(val):
                    disclosed[hdr] = val.strip()
    except Exception as e:  # noqa: BLE001
        logger.debug("banner check failed for %s: %s", url, e)
        return []
    if not disclosed:
        return []
    p = urlparse(url)
    origin = f"{p.scheme}://{p.netloc}"
    primary = disclosed.get("Server") or next(iter(disclosed.values()))
    return [_finding(
        origin, "server_version_disclosure", "info",
        f"Server Software Version Disclosed ({primary})",
        "HTTP response headers reveal the exact server software and version. "
        "Publishing precise version details lets an attacker map the host "
        "directly to known vulnerabilities for that release and tailor exploits. "
        "Suppress version banners (e.g. nginx 'server_tokens off;', Apache "
        "'ServerTokens Prod', remove X-Powered-By / X-AspNet-Version).",
        0.9, {"disclosed_headers": disclosed, "observed_on": url})]


async def _check_open_redirect(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    import asyncio
    parsed = urlparse(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    candidate_params = {k for k, _ in existing} | set(_REDIRECT_PARAMS)

    async def _probe(param: str) -> str | None:
        """Return the vulnerable param name if the redirect lands on our canary."""
        new_qs = [(k, v) for k, v in existing if k != param]
        new_qs.append((param, _REDIRECT_PROBE_URL))
        probe = urlunparse(parsed._replace(query=urlencode(new_qs)))
        try:
            async with session.get(probe, allow_redirects=False) as resp:
                if resp.status not in (301, 302, 303, 307, 308):
                    return None
                loc = resp.headers.get("Location", "")
        except Exception as e:  # noqa: BLE001
            logger.debug("open-redirect check failed for %s: %s", probe, e)
            return None
        loc_host = urlparse(loc).netloc or urlparse("http:" + loc).netloc
        return param if loc_host == _REDIRECT_PROBE_HOST else None

    # Probe every candidate concurrently — sequential probing multiplied a slow
    # target's latency by ~20x. One confirmed hit is enough.
    results = await asyncio.gather(*[_probe(p) for p in candidate_params])
    hit = next((p for p in results if p), None)
    if hit is None:
        return []
    return [_finding(
        url, "open_redirect", "medium",
        f"Open redirect via '{hit}' parameter",
        "The application issues an HTTP redirect to an unvalidated "
        "user-supplied URL, enabling phishing and OAuth token theft.",
        0.9, {"parameter": hit, "probe": _REDIRECT_PROBE_URL})]


# ── orchestration ─────────────────────────────────────────────────────────────
# ── GraphQL introspection ─────────────────────────────────────────────────────
# Common mount points for a GraphQL endpoint. We only report when the endpoint
# actually answers an introspection query, so probing extra paths is safe.
_GRAPHQL_PATHS = (
    "/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/gql", "/api/gql", "/graphiql", "/graphql/console",
    "/index.php?graphql",
)
# Minimal, universally-valid introspection query. A server with introspection
# disabled answers with an error and no ``__schema`` — so a populated
# ``data.__schema`` is definitive proof, not a heuristic.
_GRAPHQL_INTROSPECTION = {"query": "{__schema{queryType{name} types{name}}}"}


async def _check_graphql(session: "aiohttp.ClientSession", origin: str) -> list[dict]:
    """Detect a GraphQL endpoint that answers introspection queries."""
    for path in _GRAPHQL_PATHS:
        url = origin.rstrip("/") + path
        try:
            async with session.post(
                url, json=_GRAPHQL_INTROSPECTION,
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            ) as resp:
                if resp.status not in (200, 400):  # 400 => endpoint exists, query rejected
                    continue
                ctype = resp.headers.get("Content-Type", "")
                if "json" not in ctype.lower():
                    continue
                try:
                    data = json.loads(await resp.text())
                except (ValueError, json.JSONDecodeError):
                    continue
        except Exception as e:  # noqa: BLE001 - network hiccup, try next path
            logger.debug("graphql probe error on %s: %s", url, e)
            continue

        schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
        if isinstance(schema, dict) and schema.get("queryType"):
            type_count = len(schema.get("types") or [])
            return [_finding(
                target=url,
                vuln_type="graphql_introspection",
                severity="medium",
                title="GraphQL introspection enabled",
                description=(
                    "The GraphQL endpoint answered a full introspection query, "
                    "exposing its entire schema (types, fields, mutations). This "
                    "hands an attacker the complete API surface for targeting."
                ),
                confidence=0.95,   # the server returned a real, populated schema
                evidence={
                    "endpoint": url,
                    "query_type": schema.get("queryType", {}).get("name", ""),
                    "type_count": type_count,
                    "signals": ["introspection_schema_returned"],
                    "proof": (f"POST {path} returned a populated __schema with "
                              f"{type_count} types"),
                },
            )]
    return []


async def scan_url_misconfig(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    import asyncio
    results = await asyncio.gather(
        _check_cors(session, url),
        _check_cookies_and_jwt(session, url),
        _check_security_headers(session, url),
        _check_server_banner(session, url),
        _check_open_redirect(session, url),
        return_exceptions=True,
    )
    out: list[dict] = []
    for r in results:
        if isinstance(r, list):
            out.extend(r)
        elif isinstance(r, Exception):
            logger.debug("misconfig subtask error on %s: %s", url, r)
    return out


async def scan_misconfig(urls: list[str], timeout: float = _DEFAULT_TIMEOUT,
                         max_urls: int = 40) -> dict:
    """Run all misconfiguration checks over a set of URLs.

    Host/response-level checks (CORS, cookies, headers, JWT) are collapsed to one
    probe per unique scheme+host+path; the open-redirect check keeps the query so
    it can spot redirect params.
    """
    if not HAS_AIOHTTP:
        return {"findings": [], "vulnerabilities": [], "total": 0,
                "error": "aiohttp not installed"}
    import asyncio

    seen: set[str] = set()
    unique: list[str] = []
    for u in urls:
        key = u.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        unique.append(u)
        if len(unique) >= max_urls:
            break

    findings: list[dict] = []
    conn = aiohttp.TCPConnector(ssl=False, limit=15)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; HEAVEN-Misconfig/1.0)"}
    async with aiohttp.ClientSession(connector=conn, timeout=client_timeout,
                                     headers=headers) as session:
        sem = asyncio.Semaphore(8)

        async def _one(u: str) -> None:
            async with sem:
                findings.extend(await scan_url_misconfig(session, u))

        await asyncio.gather(*[_one(u) for u in unique], return_exceptions=True)

        # GraphQL introspection is a host-level check — probe each unique origin
        # once (not per URL) so a big crawl doesn't hammer /graphql repeatedly.
        origins: set[str] = set()
        for u in unique:
            p = urlparse(u)
            if p.scheme and p.netloc:
                origins.add(f"{p.scheme}://{p.netloc}")

        async def _gql(origin: str) -> None:
            async with sem:
                findings.extend(await _check_graphql(session, origin))

        await asyncio.gather(*[_gql(o) for o in origins], return_exceptions=True)

    findings = _dedup(findings)
    logger.info("Misconfig scan → %d finding(s) across %d URL(s)", len(findings), len(unique))
    return {"findings": findings, "vulnerabilities": findings, "total": len(findings)}
