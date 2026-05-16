"""
HEAVEN — Web Application Fuzzer
HTTP verb tampering, host header injection, 403 bypass, cache poisoning,
HTTP request smuggling, clickjacking, parameter pollution, hidden field discovery,
content-type confusion, and method override attacks.
"""
from __future__ import annotations

import asyncio
import random
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
    _xst_canary = "HVNXST" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
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
                        elif method in ("PUT", "DELETE"):
                            findings.append(_finding(
                                url, "dangerous_http_method", "high",
                                f"Dangerous HTTP Method Accepted: {method}",
                                f"Server returns HTTP {r.status} for {method} at {url}. "
                                f"This may allow unauthorized file modification or deletion "
                                f"(WebDAV, REST API misconfiguration).",
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
                pass

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
                # Check if our host leaked into the response (absolute URL reflection)
                if _ATTACKER_HOST in body or _ATTACKER_HOST in location:
                    injected_hdr = next(iter(hdrs))
                    findings.append(_finding(
                        url, "host_header_injection", "high",
                        f"Host Header Injection via {injected_hdr}",
                        f"Server reflected attacker-controlled host ({_ATTACKER_HOST}) "
                        f"in response body or Location header. Enables password-reset link "
                        f"hijacking, cache poisoning, and SSRF attacks.",
                        confidence=0.90,
                        evidence={
                            "injected_header": injected_hdr,
                            "injected_value": hdrs[injected_hdr],
                            "reflected_in": "body" if _ATTACKER_HOST in body else "location",
                        },
                    ))
                    break
        except Exception:
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
                pass

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
                pass

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

async def _fuzz_cache_poisoning(session: "aiohttp.ClientSession",
                                 url: str) -> list[dict]:
    """
    Detect cache poisoning via unkeyed request headers.
    If a response caches content containing a value from an unkeyed header,
    attackers can poison the cache for all users.
    """
    findings: list[dict] = []
    canary = f"HEAVEN-{random.randint(100000, 999999)}"

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
                    severity = "high" if cacheable else "medium"
                    findings.append(_finding(
                        url, "cache_poisoning_unkeyed_header", severity,
                        f"Cache Poisoning via Unkeyed Header ({hdr})",
                        f"Header '{hdr}' value reflected in response body. "
                        f"{'Response appears cacheable (no no-store/private). ' if cacheable else ''}"
                        f"An attacker can poison the cache to serve malicious content to all users.",
                        confidence=0.85,
                        evidence={
                            "header": hdr, "canary": canary,
                            "cache_control": cache_control,
                            "x_cache": x_cache, "age": age,
                        },
                    ))
                    break
        except Exception:
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
        pass

    return findings


# ── 5. HTTP Request Smuggling Indicators ───────────────────────────────────────

async def _fuzz_request_smuggling(session: "aiohttp.ClientSession",
                                   url: str) -> list[dict]:
    """
    Probe for HTTP/1.1 request smuggling (CL.TE and TE.CL variants).
    Uses timing differentials — a definitive PoC requires a proxy chain.
    """
    findings: list[dict] = []

    # Check if server accepts Transfer-Encoding: chunked alongside Content-Length (CL.TE indicator)
    try:
        # Send a request with both CL and TE headers — RFC 7230 says CL MUST be removed
        # when TE is present. If both are forwarded, smuggling is possible.
        te_headers = {
            "Transfer-Encoding": "chunked",
            "Content-Length": "6",
        }
        body = b"0\r\n\r\nG"  # Chunked terminator + smuggled byte
        async with session.post(url, data=body, headers=te_headers,
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
            status = resp.status
            # If we get anything other than 400 (malformed), server may be vulnerable
            if status not in (400, 501, 505):
                te_cl = resp.headers.get("Transfer-Encoding", "")
                cl_resp = resp.headers.get("Content-Length", "")
                if te_cl or cl_resp:
                    findings.append(_finding(
                        url, "http_smuggling_indicator", "high",
                        "HTTP Request Smuggling Indicator (CL.TE)",
                        f"Server accepted ambiguous CL+TE headers (status {status}). "
                        f"Manual verification required to confirm smuggling via a proxy chain.",
                        confidence=0.65,
                        evidence={"status": status, "te": te_cl, "cl": cl_resp},
                        cve="CVE-2019-16278",
                    ))
    except Exception:
        pass

    # Check for TE header obfuscation acceptance
    try:
        obf_headers = {
            "Transfer-Encoding": "chunked",
            "Transfer-encoding": "identity",   # duplicate with different case
        }
        async with session.post(url, headers=obf_headers, data=b"0\r\n\r\n",
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status not in (400, 501):
                findings.append(_finding(
                    url, "http_smuggling_te_obfuscation", "high",
                    "HTTP Request Smuggling — TE Header Obfuscation Accepted",
                    "Server accepts duplicate Transfer-Encoding headers with different cases. "
                    "This is an indicator of TE.TE smuggling potential.",
                    confidence=0.60,
                    evidence={"status": resp.status},
                ))
    except Exception:
        pass

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
                pass

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
        pass

    return findings


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
        pass

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
                        evidence={"reflected_entity": "heaven_probe"},
                    ))
                else:
                    findings.append(_finding(
                        url, "xml_accepted", "low",
                        "Endpoint Accepts XML Input",
                        "Server accepted XML Content-Type. Test for XXE injection "
                        "with external entity pointing to internal resources.",
                        confidence=0.65,
                        evidence={"status": resp.status},
                    ))
    except Exception:
        pass

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

    # Baseline plain POST — method override only matters if it changes the response
    try:
        async with session.post(url, timeout=aiohttp.ClientTimeout(total=8)) as base_r:
            base_status = base_r.status
            base_body_len = len(await base_r.text())
    except Exception:
        return findings

    for override in override_headers:
        for method in ("DELETE", "PUT", "PATCH"):
            try:
                hdrs = {override: method}
                async with session.post(url, headers=hdrs,
                                        timeout=aiohttp.ClientTimeout(total=8)) as r:
                    body = await r.text()
                    # Only report if: not a "not allowed" status AND response differs from baseline
                    if (r.status not in (404, 405, 501)
                            and (r.status != base_status
                                 or abs(len(body) - base_body_len) > 200)):
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

    async with aiohttp.ClientSession(headers=headers,
                                     connector=connector) as session:
        tasks = [
            _fuzz_verb_tampering(session, url),
            _fuzz_host_header(session, url),
            _fuzz_403_bypass(session, url),
            _fuzz_cache_poisoning(session, url),
            _fuzz_request_smuggling(session, url),
            _fuzz_method_override(session, url),
            _fuzz_content_type(session, url),
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


async def fuzz_targets(urls: list[str], aggressive: bool = False) -> dict:
    """Fuzz multiple URLs concurrently."""
    sem = asyncio.Semaphore(5)
    all_findings: list[dict] = []

    async def _one(url: str) -> None:
        async with sem:
            r = await fuzz_url(url, aggressive=aggressive)
            all_findings.extend(r.get("findings", []))

    await asyncio.gather(*[_one(u) for u in urls], return_exceptions=True)
    return {
        "total": len(all_findings),
        "findings": all_findings,
        "vulnerabilities": all_findings,
    }
