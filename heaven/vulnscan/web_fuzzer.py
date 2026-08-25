"""
HEAVEN — Web Application Fuzzer
HTTP verb tampering, host header injection, 403 bypass, cache poisoning,
HTTP request smuggling, clickjacking, parameter pollution, hidden field discovery,
content-type confusion, and method override attacks.
"""
from __future__ import annotations
from heaven.net.egress import client_session as _egress_cs  # egress-routed aiohttp

import asyncio
import base64
import re
import secrets
import string
import urllib.parse
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

from heaven.utils.logger import get_logger

logger = get_logger("web_fuzzer")

# Canary markers use a CSPRNG so a target cannot pre-compute / pre-seed them and
# mask reflection, and to satisfy HEAVEN's `weak-random-for-crypto` SAST rule.
_rng = secrets.SystemRandom()


def _dedup(findings: list[dict]) -> list[dict]:
    """Deduplicate by (target, vuln_type) — one finding per unique combination."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for f in findings:
        key = (str(f.get("target", "")), str(f.get("vuln_type", "")))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, confidence: float = 0.80,
             evidence: Optional[dict] = None, cve: str = "") -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "cve_id": cve,
        "evidence": evidence or {},
        "source": "web_fuzzer",
    }


# ── 1. HTTP Verb Tampering ─────────────────────────────────────────────────────
_DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "OPTIONS",
                      "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK",
                      "UNLOCK", "SEARCH"]

async def _fuzz_verb_tampering(session: "aiohttp.ClientSession",
                                url: str) -> list[dict]:
    """
    Test if the server accepts dangerous HTTP methods on protected endpoints.
    TRACE can enable XST (Cross-Site Tracing) to steal cookies.
    PUT/DELETE can allow unauthorized file writes/deletes (WebDAV).
    """
    findings: list[dict] = []
    try:
        async with session.options(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            allow_hdr = resp.headers.get("Allow", "") + resp.headers.get("Public", "")
    except Exception:
        allow_hdr = ""

    # Canary for TRACE echo verification — must appear in echoed request headers
    _xst_canary = "HVNXST" + "".join(_rng.choices(string.ascii_uppercase + string.digits, k=8))
    sem = asyncio.Semaphore(5)

    async def _try_method(method: str) -> None:
        async with sem:
            try:
                req_headers = ({"X-HEAVEN-Probe": _xst_canary} if method == "TRACE" else {})
                async with session.request(method, url, headers=req_headers,
                                           timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status < 405:   # Not "Method Not Allowed"
                        if method == "TRACE":
                            body = await r.text()
                            # True XST: server echoed our unique canary header back
                            if _xst_canary in body:
                                has_sensitive = ("cookie" in body.lower()
                                                 or "authorization" in body.lower())
                                findings.append(_finding(
                                    url,
                                    "xst_trace_enabled" if has_sensitive else "http_trace_enabled",
                                    "high" if has_sensitive else "medium",
                                    "Cross-Site Tracing (XST) — HTTP TRACE Echoes Request Headers"
                                    if has_sensitive else "HTTP TRACE Method Enabled",
                                    (
                                        "TRACE method echoes request headers including Cookie/Authorization. "
                                        "Combined with XSS an attacker can steal HttpOnly cookies."
                                        if has_sensitive else
                                        "TRACE method is accepted and echoes request headers. "
                                        "Disable TRACE in server configuration."
                                    ),
                                    confidence=0.95 if has_sensitive else 0.88,
                                    evidence={"method": "TRACE", "status": r.status,
                                              "canary_echoed": True, "echo": body[:400]},
                                ))
                        elif method in ("PUT", "DELETE") and r.status in (201, 204):
                            # Only an UNAMBIGUOUS WebDAV success proves the method
                            # is honoured destructively: 201 Created (PUT wrote a
                            # file) or 204 No Content (DELETE removed one). A plain
                            # 200 that returns the page HTML is the app ignoring the
                            # method (Apache serves any verb PHP doesn't handle), so
                            # DELETE/PUT → 200 is NOT a dangerous-method finding.
                            findings.append(_finding(
                                url, "dangerous_http_method", "high",
                                f"Dangerous HTTP Method Accepted: {method}",
                                f"Server returns HTTP {r.status} (WebDAV success) for {method} at "
                                f"{url}. This may allow unauthorized file modification or "
                                f"deletion (WebDAV, REST API misconfiguration).",
                                confidence=0.80,
                                evidence={"method": method, "status": r.status},
                            ))
                        elif method == "OPTIONS" and allow_hdr:
                            dangerous = [m for m in _DANGEROUS_METHODS
                                         if m in allow_hdr and m != "OPTIONS"]
                            if dangerous:
                                findings.append(_finding(
                                    url, "dangerous_methods_allowed", "medium",
                                    "Server Advertises Dangerous Methods via OPTIONS",
                                    f"Allow header includes: {', '.join(dangerous)}. "
                                    f"Restrict to GET, POST, HEAD only if unused.",
                                    confidence=0.75,
                                    evidence={"allow": allow_hdr, "dangerous": dangerous},
                                ))
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

    await asyncio.gather(*[_try_method(m) for m in _DANGEROUS_METHODS[:6]])
    return findings


# ── 2. Host Header Injection ───────────────────────────────────────────────────
_ATTACKER_HOST = "evil-heaven-probe.attacker.example"

async def _fuzz_host_header(session: "aiohttp.ClientSession",
                             url: str) -> list[dict]:
    """
    Inject attacker-controlled Host header to detect SSRF, password-reset
    hijacking, cache poisoning, and virtual host confusion.
    """
    findings: list[dict] = []
    parsed = urllib.parse.urlparse(url)
    real_host = parsed.netloc

    test_cases = [
        {"Host": _ATTACKER_HOST},
        {"Host": f"{real_host}:{_ATTACKER_HOST}"},
        {"Host": f"{real_host}@{_ATTACKER_HOST}"},
        {"X-Forwarded-Host": _ATTACKER_HOST},
        {"X-Host": _ATTACKER_HOST},
        {"X-Forwarded-Server": _ATTACKER_HOST},
        {"X-HTTP-Host-Override": _ATTACKER_HOST},
        {"Forwarded": f"host={_ATTACKER_HOST}"},
    ]

    for hdrs in test_cases:
        try:
            async with session.get(url, headers=hdrs, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=8)) as resp:
                body = await resp.text()
                location = resp.headers.get("Location", "")
                # The host must be reflected in a SECURITY-SENSITIVE position, not
                # merely echoed. A redirect Location built from the header, or an
                # absolute URL / link attribute in the body, is exploitable
                # (reset-link hijack, cache poisoning). The host simply DISPLAYED
                # in a page (phpinfo's HTTP_HOST, a debug dump) is not — matching a
                # bare occurrence in the body flagged every such page as "high".
                in_location = _ATTACKER_HOST in location
                in_url_context = (f"//{_ATTACKER_HOST}" in body
                                  or f'="{_ATTACKER_HOST}' in body
                                  or f"='{_ATTACKER_HOST}" in body)
                if in_location or in_url_context:
                    injected_hdr = next(iter(hdrs))
                    findings.append(_finding(
                        url, "host_header_injection", "high",
                        f"Host Header Injection via {injected_hdr}",
                        f"Server used attacker-controlled host ({_ATTACKER_HOST}) to build "
                        f"a redirect or link. Enables password-reset link hijacking, cache "
                        f"poisoning, and SSRF attacks.",
                        confidence=0.90,
                        evidence={
                            "injected_header": injected_hdr,
                            "injected_value": hdrs[injected_hdr],
                            "reflected_in": "location" if in_location else "body_url",
                        },
                    ))
                    break
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
            continue

    return findings


# ── 3. 403 Bypass via IP/Path Tricks ──────────────────────────────────────────
_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "::1"},
    {"X-Forwarded-Host": "localhost"},
]

_PATH_BYPASS_SUFFIXES = [
    "/%2e/", "/.%2e/", "/./", "/../",
    "/%20", "/%09", "/.json", "/.html",
    ";/", "/;/", "//", "/./.",
    "?anything=1", "#", "%00",
]

async def _fuzz_403_bypass(session: "aiohttp.ClientSession",
                            url: str) -> list[dict]:
    """
    Attempt to bypass 403 Forbidden using IP spoofing headers and path manipulation.
    """
    findings: list[dict] = []

    # Check if URL returns 403 first; capture the 403 body for comparison
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
            if r.status != 403:
                return findings
            forbidden_body = await r.text()
            forbidden_len = len(forbidden_body)
    except Exception:
        return findings

    sem = asyncio.Semaphore(5)
    bypassed: list[dict] = []

    async def _try_header_bypass(hdrs: dict) -> None:
        async with sem:
            try:
                async with session.get(url, headers=hdrs,
                                       timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status in (200, 201, 204):
                        body = await r.text()
                        # Confirm actual resource access: body must be meaningfully
                        # different from the 403 response and non-trivial in size
                        if len(body) > 100 and abs(len(body) - forbidden_len) > 50:
                            bypassed.append({"type": "header", "headers": hdrs,
                                             "status": r.status, "body_len": len(body)})
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

    async def _try_path_bypass(suffix: str) -> None:
        async with sem:
            bypass_url = url.rstrip("/") + suffix
            try:
                async with session.get(bypass_url,
                                       timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status in (200, 201, 204):
                        body = await r.text()
                        if len(body) > 100 and abs(len(body) - forbidden_len) > 50:
                            bypassed.append({"type": "path", "suffix": suffix,
                                             "status": r.status, "body_len": len(body)})
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

    await asyncio.gather(
        *[_try_header_bypass(h) for h in _BYPASS_HEADERS],
        *[_try_path_bypass(s) for s in _PATH_BYPASS_SUFFIXES],
    )

    for bypass in bypassed:
        if bypass["type"] == "header":
            hdr_key = next(iter(bypass["headers"]))
            hdr_val = bypass["headers"][hdr_key]
            findings.append(_finding(
                url, "403_bypass_ip_header", "high",
                f"403 Bypass via {hdr_key}: {hdr_val}",
                f"Adding '{hdr_key}: {hdr_val}' bypasses access control and returns "
                f"HTTP {bypass['status']}. Server trusts client-supplied IP headers.",
                confidence=0.88,
                evidence=bypass,
            ))
        else:
            findings.append(_finding(
                url, "403_bypass_path_manipulation", "high",
                f"403 Bypass via Path Manipulation ({bypass['suffix']})",
                f"Appending '{bypass['suffix']}' to the URL bypasses 403 restriction "
                f"(HTTP {bypass['status']}). Path normalization is inconsistent.",
                confidence=0.85,
                evidence=bypass,
            ))
    return findings


# ── 4. Cache Poisoning ─────────────────────────────────────────────────────────
_CACHE_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-For",
    "X-Host", "X-Original-URL", "X-Rewrite-URL",
]

async def _confirm_cache_poisoning(session: "aiohttp.ClientSession", url: str,
                                   hdr: str) -> Optional[dict]:
    """Safely confirm unkeyed-header cache poisoning without touching a shared
    cache. A random ``cb=`` token isolates a throwaway cache entry; we poison it
    with a unique canary via ``hdr`` then fetch the SAME URL with no header — if
    the canary is served back, the cache stored our poisoned response."""
    token = secrets.token_hex(8)
    sep = "&" if urllib.parse.urlparse(url).query else "?"
    busted = f"{url}{sep}cb={token}"
    canary = f"heaven{secrets.token_hex(6)}.invalid"
    try:
        async with session.get(busted, headers={hdr: canary},
                               allow_redirects=False,
                               timeout=aiohttp.ClientTimeout(total=10)) as r1:
            body1 = await r1.text()
            loc1 = r1.headers.get("Location", "")
        if canary not in body1 and canary not in loc1:
            return None  # not reflected on the cache-busted path either
        async with session.get(busted, allow_redirects=False,
                               timeout=aiohttp.ClientTimeout(total=10)) as r2:
            body2 = await r2.text()
            loc2 = r2.headers.get("Location", "")
    except Exception:
        logger.debug("cache-poison confirmation error", exc_info=True)
        return None
    if canary in body2:
        return {"canary": canary, "reflected_in": "response body"}
    if canary in loc2:
        return {"canary": canary, "reflected_in": "Location header"}
    return None


async def _fuzz_cache_poisoning(session: "aiohttp.ClientSession",
                                 url: str) -> list[dict]:
    """
    Detect cache poisoning via unkeyed request headers.
    If a response caches content containing a value from an unkeyed header,
    attackers can poison the cache for all users.
    """
    findings: list[dict] = []
    canary = f"HEAVEN-{_rng.randint(100000, 999999)}"

    for hdr in _CACHE_HEADERS:
        try:
            async with session.get(url, headers={hdr: canary},
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                body = await resp.text()
                cache_control = resp.headers.get("Cache-Control", "")
                age = resp.headers.get("Age", "")
                x_cache = resp.headers.get("X-Cache", "")

                if canary in body:
                    cacheable = "no-store" not in cache_control and "private" not in cache_control
                    # Precision upgrade: prove the poisoning safely. A per-test
                    # cache-buster query isolates a throwaway cache entry only we
                    # touch (never a shared production one); if a CLEAN follow-up
                    # request — no attacker header — is then served our canary,
                    # the cache stored the poisoned response. That is airtight.
                    confirmed = await _confirm_cache_poisoning(session, url, hdr)
                    if confirmed:
                        findings.append(_finding(
                            url, "cache_poisoning_unkeyed_header", "high",
                            f"Web Cache Poisoning via Unkeyed Header ({hdr}) — confirmed",
                            f"Header '{hdr}' is unkeyed and cached: a clean follow-up "
                            f"request with no attacker header was served the injected "
                            f"canary from cache. An attacker can poison the cache to "
                            f"serve malicious content to every user of the resource.",
                            confidence=0.9,
                            evidence={
                                "header": hdr, "canary": confirmed["canary"],
                                "cache_control": cache_control, "x_cache": x_cache,
                                "age": age, "reflected_in": confirmed["reflected_in"],
                                "verification": "cache-served-canary-on-clean-request",
                                "proved": True,
                            },
                        ))
                    else:
                        # Reflection without a confirmed cache hit — a weaker
                        # indicator, not proof. Kept low so it never masquerades
                        # as a confirmed poisoning.
                        findings.append(_finding(
                            url, "cache_poisoning_unkeyed_header",
                            "medium" if cacheable else "low",
                            f"Unkeyed Header Reflection ({hdr}) — potential cache poisoning",
                            f"Header '{hdr}' value is reflected in the response"
                            f"{' and the response appears cacheable' if cacheable else ''}. "
                            f"A clean cache-busted request did not return the canary, so "
                            f"cache poisoning is unconfirmed — verify the cache key manually.",
                            confidence=0.5,
                            evidence={
                                "header": hdr, "canary": canary,
                                "cache_control": cache_control, "x_cache": x_cache,
                                "age": age, "verification": "reflection-only-unconfirmed",
                            },
                        ))
                    break
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
            continue

    # Check for web cache deception (path confusion)
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.path and not parsed.path.endswith((".css", ".js", ".png")):
            decept_url = url.rstrip("/") + "/nonexistent.css"
            async with session.get(decept_url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status == 200:
                    cache_ctrl = r.headers.get("Cache-Control", "")
                    if "public" in cache_ctrl or "max-age" in cache_ctrl:
                        findings.append(_finding(
                            url, "web_cache_deception", "high",
                            "Web Cache Deception — Static Extension Bypass",
                            f"Appending a static extension ({decept_url}) returns authenticated "
                            f"content with caching headers. Attackers can cache and steal private data.",
                            confidence=0.80,
                            evidence={"deception_url": decept_url, "cache_control": cache_ctrl},
                        ))
    except Exception:
        logger.debug("suppressed non-fatal exception", exc_info=True)

    return findings


# ── 5. HTTP Request Smuggling Indicators ───────────────────────────────────────

async def _fuzz_request_smuggling(session: "aiohttp.ClientSession",
                                   url: str) -> list[dict]:
    """
    Probe for HTTP/1.1 request smuggling (CL.TE and TE.CL variants).
    Uses timing differentials — a definitive PoC requires a proxy chain.
    """
    findings: list[dict] = []

    # Baseline: how the server answers a *well-formed* request. Smuggling
    # indicators are only meaningful as a deviation from this — a plain 200 to an
    # ambiguous request is not, by itself, evidence. (Previously these checks
    # keyed off the *response* Content-Length header, which is present on almost
    # every 200, so they fired on nearly every server.)
    #
    # The baseline MUST use the same method as the probes (POST) with a
    # well-formed Content-Length body. If we baselined with GET, a server that
    # simply answers POST differently — 404/405 on a GET-only route, which is the
    # norm — would look like an "anomaly" for every ambiguous POST and trip every
    # check. Same-method baselining isolates the ambiguous *framing* as the only
    # variable.
    try:
        async with session.post(url, data=b"heaven=probe",
                                timeout=aiohttp.ClientTimeout(total=10)) as base:
            baseline_status = base.status
    except Exception:
        return findings  # can't establish a baseline → can't judge an anomaly

    # A server that answers the ambiguous request with a 4xx/5xx is *rejecting*
    # it — the correct, hardened behaviour, and NOT a smuggling indicator. Only a
    # normal (2xx/3xx) answer that also *differs* from the baseline is a weak
    # signal. The old ``status not in (400,501,505)`` gate let a 406/403/etc.
    # from a WAF trip the check on nearly every protected site.
    def _is_normal(code: int) -> bool:
        return 200 <= code < 400

    # CL.TE: send both Content-Length and Transfer-Encoding. RFC 7230 requires CL
    # to be dropped when TE is present; a server that instead answers the
    # ambiguous request *differently* from a normal one is a (weak) indicator.
    try:
        te_headers = {"Transfer-Encoding": "chunked", "Content-Length": "6"}
        body = b"0\r\n\r\nG"  # chunked terminator + smuggled byte
        async with session.post(url, data=body, headers=te_headers,
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
            status = resp.status
            if _is_normal(status) and _is_normal(baseline_status) and status != baseline_status:
                findings.append(_finding(
                    url, "http_smuggling_indicator", "low",
                    "Possible HTTP Request Smuggling Indicator (CL.TE)",
                    f"An ambiguous CL+TE request was answered differently "
                    f"(status {status}) than a normal request (status "
                    f"{baseline_status}). This is a weak indicator only and MUST "
                    f"be verified manually via the real front-end/back-end chain.",
                    confidence=0.35,
                    evidence={"status": status, "baseline_status": baseline_status,
                              "note": "manual verification required"},
                ))
    except Exception:
        logger.debug("suppressed non-fatal exception", exc_info=True)

    # TE header obfuscation: duplicate Transfer-Encoding headers with different
    # case. Again only report a *behavioural deviation* from the baseline.
    try:
        obf_headers = {
            "Transfer-Encoding": "chunked",
            "Transfer-encoding": "identity",   # duplicate with different case
        }
        async with session.post(url, headers=obf_headers, data=b"0\r\n\r\n",
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if (_is_normal(resp.status) and _is_normal(baseline_status)
                    and resp.status != baseline_status):
                findings.append(_finding(
                    url, "http_smuggling_te_obfuscation", "low",
                    "Possible HTTP Request Smuggling — TE Header Obfuscation",
                    f"Duplicate Transfer-Encoding headers with different cases were "
                    f"answered differently (status {resp.status}) than a normal "
                    f"request (status {baseline_status}) — a weak TE.TE indicator "
                    f"that requires manual verification via a proxy chain.",
                    confidence=0.30,
                    evidence={"status": resp.status, "baseline_status": baseline_status,
                              "note": "manual verification required"},
                ))
    except Exception:
        logger.debug("suppressed non-fatal exception", exc_info=True)

    return findings


# ── 5b. Insecure Deserialization Surface ───────────────────────────────────────
# Java serialized stream magic 0xACED0005 → base64 begins "rO0AB".
_JAVA_B64 = "rO0AB"
_JAVA_RAW = b"\xac\xed\x00"
# A PHP serialized object string, e.g. O:8:"stdClass":1:{...}
_PHP_OBJECT_RE = re.compile(r'O:\d+:"[A-Za-z_\\][A-Za-z0-9_\\]*":\d+:\{')


def _looks_java_serialized(value: str) -> bool:
    v = (value or "").strip()
    if _JAVA_B64 in v:
        return True
    try:
        return base64.b64decode(v[:64] + "==", validate=False).startswith(_JAVA_RAW)
    except Exception:  # noqa: BLE001
        return False


async def _fuzz_deserialization(session: "aiohttp.ClientSession",
                                url: str) -> list[dict]:
    """Detect unsafe-deserialization *surface* in HTTP traffic by signature.

    Only fires on a concrete artefact actually present — a Java serialized
    object (content-type or 0xACED magic) or a PHP serialized object string in a
    cookie — so a benign app stays silent. This is an object-injection / RCE
    surface indicator; exploitation needs a gadget chain and is out of scope."""
    findings: list[dict] = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            ctype = resp.headers.get("Content-Type", "").lower()
            body = await resp.text(errors="replace")
            set_cookie = "; ".join(v for k, v in resp.headers.items()
                                   if k.lower() == "set-cookie")
    except Exception:
        logger.debug("suppressed non-fatal exception", exc_info=True)
        return findings

    if "java-serialized-object" in ctype or _JAVA_B64 in body \
            or _looks_java_serialized(set_cookie):
        where = ("Content-Type header" if "java-serialized-object" in ctype
                 else "cookie" if _looks_java_serialized(set_cookie)
                 else "response body")
        findings.append(_finding(
            url, "insecure_deserialization", "high",
            "Java Serialized Object Exposed in HTTP Traffic",
            f"A Java serialized object (magic bytes 0xACED) is present in the "
            f"{where}. If any such value is accepted back from the client and "
            f"deserialized, a gadget chain can achieve remote code execution.",
            confidence=0.75,
            evidence={"indicator": "java_serialized_object", "location": where,
                      "content_type": ctype,
                      "verification": "java-serialization-signature"},
        ))

    if _PHP_OBJECT_RE.search(set_cookie):
        findings.append(_finding(
            url, "insecure_deserialization", "medium",
            "PHP Serialized Object in Cookie (object-injection surface)",
            "A PHP serialized object string is stored in a cookie. If it is "
            "unserialize()'d server-side without integrity protection, an attacker "
            "can tamper with object properties or trigger PHP object injection.",
            confidence=0.6,
            evidence={"indicator": "php_serialized_object", "location": "cookie",
                      "verification": "php-serialization-signature"},
        ))
    return findings


# ── 6. Parameter Pollution & Discovery ─────────────────────────────────────────
_HIDDEN_PARAMS = [
    "debug", "test", "admin", "internal", "format", "output", "type",
    "callback", "jsonp", "redirect", "next", "return", "returnUrl",
    "returnTo", "goto", "url", "ref", "source", "dest", "destination",
    "file", "path", "page", "template", "view", "action", "cmd", "exec",
    "mode", "method", "lang", "locale", "api_key", "key", "token",
    "secret", "password", "pass", "auth", "access", "privilege",
    "role", "level", "id", "uid", "user", "username", "email",
    "include", "import", "load", "read", "write", "upload", "download",
    "config", "conf", "setting", "setup", "install", "update", "delete",
    "verbose", "trace", "log", "backup", "export", "import",
]

async def _fuzz_parameters(session: "aiohttp.ClientSession",
                            url: str) -> list[dict]:
    """
    Discover hidden/sensitive parameters by fuzzing common names.
    Detects parameters that change response (length, status, body content).
    """
    findings: list[dict] = []

    # Baseline
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            base_status = r.status
            base_body   = await r.text()
            base_len    = len(base_body)
    except Exception:
        return findings

    sem = asyncio.Semaphore(10)
    interesting: list[dict] = []

    async def _try_param(param: str) -> None:
        async with sem:
            test_url = url + ("&" if "?" in url else "?") + f"{param}=HEAVEN_PROBE"
            try:
                async with session.get(test_url,
                                       timeout=aiohttp.ClientTimeout(total=8)) as r:
                    body = await r.text()
                    body_len = len(body)
                    # Significant response change = parameter is processed
                    if (r.status != base_status or
                            abs(body_len - base_len) > 100 or
                            "HEAVEN_PROBE" in body):
                        interesting.append({
                            "param": param,
                            "status": r.status,
                            "len_diff": abs(body_len - base_len),
                            "reflected": "HEAVEN_PROBE" in body,
                        })
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

    await asyncio.gather(*[_try_param(p) for p in _HIDDEN_PARAMS])

    for item in interesting:
        param = item["param"]
        # High-severity params
        high_risk = any(kw in param.lower() for kw in
                        ["debug", "admin", "internal", "cmd", "exec", "file",
                         "path", "include", "load", "config", "secret", "key",
                         "token", "password", "pass", "auth"])
        severity = "medium" if high_risk else "low"
        if item["reflected"]:
            severity = "high"  # Reflected = potential injection vector

        findings.append(_finding(
            url, "hidden_parameter_discovered", severity,
            f"Hidden/Sensitive Parameter Discovered: '{param}'",
            f"Parameter '{param}' causes a significant response change "
            f"(status: {item['status']}, len diff: {item['len_diff']}, "
            f"reflected: {item['reflected']}). "
            f"{'Reflected value may be injectable.' if item['reflected'] else ''}"
            f"{'High-risk parameter name — investigate for access control bypass.' if high_risk else ''}",
            confidence=0.72,
            evidence=item,
        ))

    # HTTP Parameter Pollution
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for param in list(qs.keys())[:3]:  # Test first 3 existing params
            pp_url = url + f"&{param}=HEAVEN_PP_PROBE"
            async with session.get(pp_url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text()
                if "HEAVEN_PP_PROBE" in body or r.status != base_status:
                    findings.append(_finding(
                        url, "http_parameter_pollution", "medium",
                        f"HTTP Parameter Pollution — Duplicate '{param}'",
                        f"Duplicate '{param}' parameter causes a different response. "
                        f"May bypass WAF rules, input validation, or produce unexpected behavior.",
                        confidence=0.70,
                        evidence={"param": param, "test_url": pp_url},
                    ))
                    break
    except Exception:
        logger.debug("suppressed non-fatal exception", exc_info=True)

    return findings


# ── 6b. SSI injection (WSTG-INPV-08) ───────────────────────────────────────────
async def _fuzz_ssi(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    """Inject a benign Server-Side-Includes directive into reflected params and
    detect that the server *processed* it (the directive is consumed and an SSI
    variable is rendered) rather than echoing it verbatim."""
    findings: list[dict] = []
    parsed = urllib.parse.urlparse(url)
    params = list(urllib.parse.parse_qs(parsed.query).keys())
    if not params:
        return findings
    # DATE_LOCAL is read-only and side-effect-free; a canary tail lets us confirm
    # the injection point reflected at all.
    canary = "HVNSSI" + "".join(_rng.choices(string.ascii_uppercase, k=6))
    directive = f'<!--#echo var="DATE_LOCAL"-->{canary}'
    sem = asyncio.Semaphore(5)

    async def _try(param: str) -> None:
        async with sem:
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param] = [directive]
            probe = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
            try:
                async with session.get(urllib.parse.urlunparse(probe),
                                       timeout=aiohttp.ClientTimeout(total=8)) as r:
                    body = await r.text()
            except Exception:
                return
            # Vulnerable: our canary is reflected (injection point hit) but the
            # SSI directive itself was CONSUMED (not echoed literally) — meaning
            # the server parsed and executed the include.
            if canary in body and '<!--#echo' not in body and 'echo var=' not in body:
                findings.append(_finding(
                    url, "ssi_injection", "high",
                    f"Server-Side Includes (SSI) injection via '{param}'",
                    "A Server-Side-Includes directive injected into a parameter was "
                    "processed by the server (the directive was consumed and its "
                    "value rendered) rather than echoed literally. SSI injection can "
                    "escalate to command execution via #exec (WSTG-INPV-08).",
                    confidence=0.8,
                    evidence={"parameter": param, "directive": directive[:40],
                              "signal": "SSI directive consumed, canary reflected"}))

    await asyncio.gather(*[_try(p) for p in params[:4]])
    return _dedup(findings)


# ── 6c. IMAP/SMTP header injection (WSTG-INPV-10) ──────────────────────────────
async def _fuzz_mail_header_injection(session: "aiohttp.ClientSession",
                                      url: str) -> list[dict]:
    """Inject CRLF + a mail header into params on a page that looks like a
    contact/mail form, and flag when the payload is reflected unfiltered into the
    response headers (the observable in-band signal of header injection)."""
    findings: list[dict] = []
    parsed = urllib.parse.urlparse(url)
    params = list(urllib.parse.parse_qs(parsed.query).keys())
    # Only probe params likely to feed a mail routine — keeps this targeted.
    mail_params = [p for p in params if re.search(
        r"(?i)mail|email|to|from|subject|cc|bcc|contact|recipient|sender", p)]
    if not mail_params:
        return findings
    canary = "hvn" + "".join(_rng.choices(string.ascii_lowercase, k=6)) + "@heaven.invalid"
    payload = f"test%0d%0aBcc:{canary}"
    sem = asyncio.Semaphore(5)

    async def _try(param: str) -> None:
        async with sem:
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param] = [payload]
            probe = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True, safe="%:@"))
            try:
                async with session.get(urllib.parse.urlunparse(probe),
                                       allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as r:
                    hdr_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            except Exception:
                return
            # If our injected header/canary lands in the RESPONSE headers, the
            # CRLF split was honoured — the mail routine will accept it too.
            if canary in hdr_blob or "bcc:" in hdr_blob.lower():
                findings.append(_finding(
                    url, "smtp_header_injection", "high",
                    f"Mail (SMTP/IMAP) header injection via '{param}'",
                    "A CRLF-delimited mail header injected into a contact/mail "
                    "parameter was reflected unfiltered, indicating the value is "
                    "used to build mail headers without sanitisation — enabling "
                    "Bcc/recipient injection and mail relay (WSTG-INPV-10).",
                    confidence=0.7,
                    evidence={"parameter": param, "injected_header": "Bcc",
                              "canary": canary}))

    await asyncio.gather(*[_try(p) for p in mail_params[:4]])
    return _dedup(findings)


# ── 7. Content-Type Confusion ──────────────────────────────────────────────────

async def _fuzz_content_type(session: "aiohttp.ClientSession",
                              url: str) -> list[dict]:
    """
    Send JSON payloads with wrong Content-Type and vice versa.
    Detect MIME confusion, JSON injection, and type coercion issues.
    """
    findings: list[dict] = []
    json_payload = '{"test": "heaven_probe", "admin": true, "__proto__": {"admin": true}}'

    try:
        # Send JSON body as application/x-www-form-urlencoded
        async with session.post(
            url,
            data=json_payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            body = await resp.text()
            # Only the unique probe token confirms the server echoed OUR JSON.
            # The old '"admin"' clause matched countless normal responses → FP.
            if resp.status < 400 and "heaven_probe" in body:
                findings.append(_finding(
                    url, "content_type_confusion", "medium",
                    "Content-Type Confusion — JSON Accepted as Form Data",
                    "Server parsed JSON body submitted as form-urlencoded. "
                    "May enable parameter injection or type coercion.",
                    confidence=0.75,
                    evidence={"payload": json_payload[:100]},
                ))
    except Exception:
        logger.debug("suppressed non-fatal exception", exc_info=True)

    try:
        # Try XML Content-Type to detect XXE surface
        xml_payload = ('<?xml version="1.0"?>'
                       '<!DOCTYPE test [<!ENTITY h "heaven_probe">]>'
                       '<test>&h;</test>')
        async with session.post(
            url,
            data=xml_payload,
            headers={"Content-Type": "application/xml"},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            body = await resp.text()
            if resp.status < 400:
                if "heaven_probe" in body:
                    findings.append(_finding(
                        url, "xxe_entity_expansion", "critical",
                        "XML External Entity (XXE) — Entity Expansion Confirmed",
                        "Server processed XML and expanded our test entity. "
                        "External entities may allow reading server files and SSRF.",
                        confidence=0.90,
                        evidence={"reflected_entity": "heaven_probe", "status": resp.status},
                    ))
                else:
                    # A 200 alone proves nothing — almost every endpoint returns
                    # 200 to a POST while ignoring the XML body entirely (a static
                    # homepage did, producing a bogus "XXE" High). Only treat the
                    # endpoint as an *XML-processing* surface when the response is
                    # actually XML/SOAP or shows an XML parser error — the only
                    # signals that the body was parsed at all.
                    resp_ctype = resp.headers.get("Content-Type", "").lower()
                    xml_error_sigs = (
                        "saxparse", "not well-formed", "xml parsing error",
                        "xmlexception", "org.xml.sax", "premature end of file",
                        "expected '>'", "<?xml",
                    )
                    # Only a genuine XML/SOAP RESPONSE type counts. A bare "xml"
                    # substring matched every "+xml" suffix (application/xhtml+xml,
                    # image/svg+xml, application/vnd.apple.installer+xml) — ordinary
                    # pages and assets, not proof the server parsed our XML body.
                    xml_response = resp_ctype.startswith(
                        ("application/xml", "text/xml", "application/soap+xml"))
                    processes_xml = (
                        xml_response
                        or any(sig in body.lower() for sig in xml_error_sigs)
                    )
                    if processes_xml:
                        findings.append(_finding(
                            url, "xml_accepted", "low",
                            "Endpoint Accepts and Parses XML Input",
                            "Server parses XML request bodies (XML/SOAP response or "
                            "XML parser error observed). Test for XXE injection with an "
                            "external entity pointing to internal resources.",
                            confidence=0.55,
                            evidence={"status": resp.status,
                                      "response_content_type": resp_ctype or "unknown"},
                        ))
    except Exception:
        logger.debug("suppressed non-fatal exception", exc_info=True)

    return findings


# ── 8. Method Override ────────────────────────────────────────────────────────

async def _fuzz_method_override(session: "aiohttp.ClientSession",
                                 url: str) -> list[dict]:
    """
    Test if server honours X-HTTP-Method-Override to bypass method restrictions.
    Useful for firewalls that block DELETE/PUT but allow POST.
    """
    findings: list[dict] = []
    override_headers = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "_method",
    ]

    # Baseline plain POST — method override only matters if it changes the status.
    try:
        async with session.post(url, timeout=aiohttp.ClientTimeout(total=8)) as base_r:
            base_status = base_r.status
            await base_r.read()  # drain the body so the connection can be reused
    except Exception:
        return findings

    for override in override_headers:
        for method in ("DELETE", "PUT", "PATCH"):
            try:
                hdrs = {override: method}
                async with session.post(url, headers=hdrs,
                                        timeout=aiohttp.ClientTimeout(total=8)) as r:
                    await r.read()  # drain body so the connection can be reused
                    # Fire ONLY on a genuine status CHANGE. A mere body-length
                    # difference is not evidence of method override: two POSTs to a
                    # dynamic page routinely differ by >200 bytes (CSRF tokens,
                    # timestamps, nonces, ads), so the old body-length OR-clause
                    # flagged method-override on every dynamic app — a medium FP on
                    # normal pages. A real override changes what the server DOES,
                    # which shows up as a different (non-error) status.
                    if (r.status not in (404, 405, 501)
                            and r.status != base_status):
                        findings.append(_finding(
                            url, "method_override_accepted", "medium",
                            f"HTTP Method Override Accepted ({override}: {method})",
                            f"Server accepted {override}: {method} header in POST request "
                            f"and returned a different response than a plain POST "
                            f"(status {r.status} vs baseline {base_status}). "
                            f"Firewall/WAF rules for {method} may be bypassable.",
                            confidence=0.78,
                            evidence={"header": override, "method": method,
                                      "status": r.status, "baseline_status": base_status},
                        ))
                        break  # Only report once per override header
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue

    return findings


# ── Main entry point ───────────────────────────────────────────────────────────

async def fuzz_url(url: str, aggressive: bool = False) -> dict:
    """
    Run the full web fuzzing suite against a single URL.

    Args:
        url:        Target URL (with scheme).
        aggressive: Enable parameter discovery (more requests, noisier).
    Returns:
        Standard findings dict.
    """
    if not HAS_AIOHTTP:
        return {"findings": [], "error": "aiohttp not installed"}

    all_findings: list[dict] = []
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; HEAVEN-WebFuzzer/2.0)",
        "Accept": "text/html,application/json,*/*;q=0.8",
    }
    connector = aiohttp.TCPConnector(ssl=False, limit=15)

    async with _egress_cs(headers=headers,
                                     connector=connector) as session:
        tasks = [
            _fuzz_verb_tampering(session, url),
            _fuzz_host_header(session, url),
            _fuzz_403_bypass(session, url),
            _fuzz_cache_poisoning(session, url),
            _fuzz_request_smuggling(session, url),
            _fuzz_deserialization(session, url),
            _fuzz_method_override(session, url),
            _fuzz_content_type(session, url),
            _fuzz_ssi(session, url),
            _fuzz_mail_header_injection(session, url),
        ]
        if aggressive:
            tasks.append(_fuzz_parameters(session, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
            elif isinstance(r, Exception):
                logger.debug(f"fuzzer subtask error: {r}")

    all_findings = _dedup(all_findings)
    crit = sum(1 for f in all_findings if f.get("severity") == "critical")
    high = sum(1 for f in all_findings if f.get("severity") == "high")
    logger.info(f"Web fuzz {url} → {len(all_findings)} issues ({crit}C {high}H)")

    return {
        "target": url,
        "total": len(all_findings),
        "findings": all_findings,
        "vulnerabilities": all_findings,
    }


# Stealth level → (per-host concurrency, inter-request delay seconds). Lower
# levels fan out wider and never pause; higher levels serialise and space
# requests out so the fuzzer is genuinely quieter on the wire.
_FUZZ_STEALTH: dict[str, tuple[int, float]] = {
    "aggressive": (10, 0.0),
    "normal": (5, 0.0),
    "stealth": (3, 0.3),
    "paranoid": (1, 1.0),
}


async def fuzz_targets(urls: list[str], aggressive: Optional[bool] = None,
                       max_urls: int = 40, stealth_level: str = "normal") -> dict:
    """Fuzz multiple URLs concurrently.

    The verb-tampering / host-header / 403-bypass / cache-poisoning / smuggling /
    method-override / content-type checks are host- or path-level — they return
    the same verdict regardless of the query string. Probing every
    payload-varying URL a crawl/dir-fuzz produces was the main cause of this
    phase blowing past its time budget (and emitting hundreds of duplicates).
    Collapse to unique scheme+path (query stripped) and cap the count so the
    phase stays bounded and fast.

    ``stealth_level`` throttles the fuzzer genuinely: it sets the per-host
    concurrency and an inter-request delay, and — unless the caller passes an
    explicit ``aggressive`` — decides whether to run the noisier parameter-
    discovery pass (off for stealth/paranoid).
    """
    concurrency, delay = _FUZZ_STEALTH.get(stealth_level, _FUZZ_STEALTH["normal"])
    if aggressive is None:
        # Parameter discovery fires many extra requests; skip it when the
        # operator asked to stay quiet.
        aggressive = stealth_level not in ("stealth", "paranoid")

    seen: set[str] = set()
    unique: list[str] = []
    for u in urls:
        key = u.split("?", 1)[0].split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        unique.append(u)
        if len(unique) >= max_urls:
            break
    if len(urls) > len(unique):
        logger.info(f"Web fuzz: {len(urls)} URLs collapsed to {len(unique)} unique "
                    f"path(s) (cap {max_urls})")

    sem = asyncio.Semaphore(max(1, concurrency))
    all_findings: list[dict] = []

    async def _one(url: str) -> None:
        async with sem:
            r = await fuzz_url(url, aggressive=aggressive)
            all_findings.extend(r.get("findings", []))
            if delay:
                await asyncio.sleep(delay)

    await asyncio.gather(*[_one(u) for u in unique], return_exceptions=True)
    return {
        "total": len(all_findings),
        "findings": all_findings,
        "vulnerabilities": all_findings,
    }
