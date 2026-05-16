"""
HEAVEN — First-pass Injection Discovery
Rapidly tests every input vector (GET params, POST fields, HTTP headers) from the
web crawler for SQL injection and XSS.  Produces candidate findings that are then
promoted to safe_validator for confirmation and, for SQLi, to sqlmap_runner for
deep exploitation.

Three SQLi detection techniques:
  1. Error-based  — trigger DBMS error messages (fast, reliable when errors shown)
  2. Boolean-based — compare true/false condition responses (catches hidden SQLi)
  3. Time-based blind — measure SLEEP()/WAITFOR DELAY response time differential
     (catches fully blind SQLi where neither errors nor data differences are visible)
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.injection")

# ─────────────────────────────────────────────────────────────────
# Probe payloads
# ─────────────────────────────────────────────────────────────────

# SQLi error-based payloads — trigger DBMS error messages
SQLI_ERROR_PROBES: list[tuple[str, str]] = [
    ("'", "generic_quote"),
    ("''", "double_quote"),
    ("1 OR 1=1--", "or_true"),
    ("1' OR '1'='1", "or_string"),
    ("1 AND 1=2--", "and_false"),
    ("1;SELECT 1--", "stacked"),
    ("\\", "backslash"),
    ("1' AND SLEEP(0)--", "sleep_zero"),
    ("1 WAITFOR DELAY '0:0:0'--", "waitfor_zero"),
]

# Boolean-based SQLi: (true_payload, false_payload, probe_name)
# True condition → same response as baseline; False condition → different response
SQLI_BOOL_PROBES: list[tuple[str, str, str]] = [
    ("1 AND 1=1--", "1 AND 1=2--", "and_bool_int"),
    ("1' AND '1'='1'--", "1' AND '1'='2'--", "and_bool_str"),
    ("1) AND (1=1)--", "1) AND (1=2)--", "and_bool_paren"),
    ("1 OR 1=1--", "1 OR 1=2--", "or_bool_int"),
]

# Time-based blind SQLi: (payload, sleep_seconds, probe_name)
# We use short sleep (3s) to keep the scan reasonably fast.
_SLEEP = 3
SQLI_TIME_PROBES: list[tuple[str, int, str]] = [
    (f"1; WAITFOR DELAY '0:0:{_SLEEP}'--",    _SLEEP, "mssql_waitfor"),
    (f"1'; WAITFOR DELAY '0:0:{_SLEEP}'--",   _SLEEP, "mssql_waitfor_str"),
    (f"1 AND SLEEP({_SLEEP})--",              _SLEEP, "mysql_sleep"),
    (f"1' AND SLEEP({_SLEEP})--",             _SLEEP, "mysql_sleep_str"),
    (f"1) AND SLEEP({_SLEEP})--",             _SLEEP, "mysql_sleep_paren"),
    (f"1;SELECT pg_sleep({_SLEEP})--",        _SLEEP, "pgsql_pg_sleep"),
    (f"1';SELECT pg_sleep({_SLEEP})--",       _SLEEP, "pgsql_pg_sleep_str"),
    (f"1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99),{_SLEEP})--", _SLEEP, "oracle_dbms_pipe"),
    (f"1 RLIKE SLEEP({_SLEEP})--",            _SLEEP, "mysql_rlike_sleep"),
]

# Time differential threshold: response must be >= (sleep - 0.5) seconds
_TIME_THRESHOLD_FACTOR = 0.85

# DB error signatures (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
SQLI_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"you have an error in your sql syntax",
        r"warning.*mysql_",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg_query\(\).*failed",
        r"psql.*error",
        r"ora-\d{5}",
        r"microsoft.*odbc.*sql server",
        r"sql server.*error",
        r"sqlite.*exception",
        r"syntax error.*near",
        r"unterminated string",
        r"jdbc.*sql",
        r"com\.mysql\.jdbc",
        r"org\.postgresql",
        r"sqlexception",
    ]
]

# XSS reflection payloads — unique canary-based
_XSS_CANARY = "h3av3n"
XSS_PROBES: list[tuple[str, str]] = [
    (f'<script>alert("{_XSS_CANARY}")</script>', "script_tag"),
    (f'">{_XSS_CANARY}<img src=x onerror=1>', "break_attr"),
    (f"'>{_XSS_CANARY}<svg/onload=1>", "break_single"),
    (f"javascript:{_XSS_CANARY}", "js_uri"),
    (f"<{_XSS_CANARY}>", "bare_tag"),
    (f"&#x3C;{_XSS_CANARY}&#x3E;", "html_encoded"),
]


def _xss_is_executable(payload: str, body: str) -> bool:
    """True only when the XSS payload reflects in a form that can EXECUTE.

    The plain canary appearing in the body proves input reaches output, but a
    correctly-escaping app reflects `&lt;script&gt;...h3av3n...` — the canary is
    still present yet nothing executes. Flagging that is a false positive.
    A finding requires the payload's raw markup (intact `<`,`>`) to survive.
    """
    if _XSS_CANARY not in body:
        return False
    low = body.lower()
    # Dangerous fragments that, reflected verbatim (unescaped), can execute.
    markers = [
        f'<script>alert("{_XSS_CANARY}")'.lower(),
        f"<{_XSS_CANARY}>".lower(),
        "<img src=x onerror=",
        "<svg/onload=",
    ]
    return any(m in low for m in markers)

# Headers worth injecting into for reflected XSS / header injection
INJECTABLE_HEADERS = ["Referer", "X-Forwarded-For", "User-Agent", "X-Original-URL"]

# Keep old name for callers that imported it
SQLI_PROBES = SQLI_ERROR_PROBES

# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _finding_key(target: str, vuln_type: str, param: str) -> str:
    return hashlib.sha256(f"{target}|{vuln_type}|{param}".encode()).hexdigest()[:16]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Return a new URL with `param` replaced by `payload`."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _get(session, url: str, headers: Optional[dict] = None, timeout: float = 8.0) -> tuple[int, str]:
    """Single GET, returns (status, body). Never raises."""
    try:
        async with session.get(
            url,
            headers=headers or {},
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            ssl=False,
        ) as resp:
            body = await resp.text(errors="replace")
            return resp.status, body
    except Exception:
        return 0, ""


async def _post(session, url: str, data: dict, headers: Optional[dict] = None,
                timeout: float = 8.0) -> tuple[int, str]:
    """Single POST, returns (status, body). Never raises."""
    try:
        async with session.post(
            url,
            data=data,
            headers=headers or {},
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            ssl=False,
        ) as resp:
            body = await resp.text(errors="replace")
            return resp.status, body
    except Exception:
        return 0, ""


# ─────────────────────────────────────────────────────────────────
# Core scanner
# ─────────────────────────────────────────────────────────────────

class InjectionScanner:
    """
    Rapid first-pass injection discovery.

    Takes input vectors produced by web_crawler and tests each parameter for
    SQLi and XSS.  All probes are lightweight and non-destructive; actual
    exploitation is delegated to safe_validator / sqlmap_runner.
    """

    def __init__(
        self,
        concurrency: int = 20,
        request_delay: float = 0.0,
        user_agent: str = "HEAVEN-Scanner/1.0",
    ) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._delay = request_delay
        self._headers = {"User-Agent": user_agent}
        self._seen: set[str] = set()
        self._findings: list[dict] = []

    def _add_finding(self, **kwargs) -> None:
        key = _finding_key(
            kwargs.get("target", ""),
            kwargs.get("vuln_type", ""),
            kwargs.get("evidence", {}).get("param", ""),
        )
        if key in self._seen:
            return
        self._seen.add(key)
        self._findings.append(kwargs)

    # ── SQLi discovery ────────────────────────────────────────────

    async def _test_sqli_param(self, session, url: str, param: str,
                                baseline_body: str) -> None:
        # 1. Error-based
        for payload, probe_name in SQLI_ERROR_PROBES:
            injected_url = _inject_param(url, param, payload)
            async with self._sem:
                if self._delay:
                    await asyncio.sleep(self._delay)
                status, body = await _get(session, injected_url, self._headers)

            if not body:
                continue

            for pattern in SQLI_ERROR_PATTERNS:
                if pattern.search(body) and not pattern.search(baseline_body):
                    self._add_finding(
                        target=injected_url,
                        vuln_type="sqli",
                        title=f"SQL Injection (error-based) — param '{param}'",
                        severity="critical",
                        confidence=0.85,
                        evidence={
                            "param": param,
                            "payload": payload,
                            "probe": probe_name,
                            "error_pattern": pattern.pattern,
                            "url": url,
                        },
                        remediation="Use parameterised queries / prepared statements.",
                        cwe="CWE-89",
                    )
                    return  # one confirmed error per param is enough

    async def _test_sqli_boolean_param(self, session, url: str, param: str,
                                       baseline_body: str) -> None:
        """Boolean-based blind SQLi: true condition should match baseline; false should differ."""
        for true_pl, false_pl, probe_name in SQLI_BOOL_PROBES:
            url_true = _inject_param(url, param, true_pl)
            url_false = _inject_param(url, param, false_pl)
            async with self._sem:
                _, body_true = await _get(session, url_true, self._headers)
            async with self._sem:
                _, body_false = await _get(session, url_false, self._headers)

            if not body_true or not body_false:
                continue

            # True payload → similar to baseline; False payload → significantly different
            true_close = abs(len(body_true) - len(baseline_body)) < max(len(baseline_body) * 0.08, 20)
            false_diff = abs(len(body_false) - len(baseline_body)) > max(len(baseline_body) * 0.10, 30)

            if true_close and false_diff:
                self._add_finding(
                    target=url_true,
                    vuln_type="sqli",
                    title=f"SQL Injection (boolean-based blind) — param '{param}'",
                    severity="critical",
                    confidence=0.80,
                    evidence={
                        "param": param,
                        "probe": probe_name,
                        "technique": "boolean_blind",
                        "true_payload": true_pl,
                        "false_payload": false_pl,
                        "baseline_len": len(baseline_body),
                        "true_len": len(body_true),
                        "false_len": len(body_false),
                        "url": url,
                    },
                    remediation="Use parameterised queries / prepared statements.",
                    cwe="CWE-89",
                )
                return

    async def _test_sqli_time_param(self, session, url: str, param: str) -> None:
        """Time-based blind SQLi: inject SLEEP/WAITFOR and measure response time.

        A naturally slow endpoint must not be flagged — the injected delay is
        compared against a measured baseline, and every hit is reproduced once.
        """
        async def _timed(value: str, timeout: float) -> tuple[int, float]:
            t0 = time.monotonic()
            async with self._sem:
                status, _ = await _get(session, _inject_param(url, param, value),
                                       self._headers, timeout=timeout)
            return status, time.monotonic() - t0

        # Baseline = slower of two benign requests, so one slow sample
        # doesn't drag the bar down.
        _, b1 = await _timed("1", 15.0)
        _, b2 = await _timed("1", 15.0)
        baseline = max(b1, b2)

        for payload, sleep_secs, probe_name in SQLI_TIME_PROBES:
            timeout = float(sleep_secs + 8)
            margin = sleep_secs * _TIME_THRESHOLD_FACTOR  # required extra delay
            status, elapsed = await _timed(payload, timeout)

            if status != 0 and elapsed >= baseline + margin:
                # Reproduce — a transient slow response is not an injection.
                status2, elapsed2 = await _timed(payload, timeout)
                if status2 != 0 and elapsed2 >= baseline + margin:
                    self._add_finding(
                        target=_inject_param(url, param, payload),
                        vuln_type="sqli",
                        title=f"SQL Injection (time-based blind) — param '{param}'",
                        severity="critical",
                        confidence=0.88,
                        evidence={
                            "param": param,
                            "payload": payload,
                            "probe": probe_name,
                            "technique": "time_blind",
                            "baseline_sec": round(baseline, 2),
                            "elapsed_sec": round(elapsed, 2),
                            "reproduce_sec": round(elapsed2, 2),
                            "sleep_secs": sleep_secs,
                            "url": url,
                        },
                        remediation="Use parameterised queries / prepared statements.",
                        cwe="CWE-89",
                    )
                    return

    async def _test_sqli_post(self, session, url: str, param: str,
                               baseline_body: str, other_fields: dict) -> None:
        # 1. Error-based
        for payload, probe_name in SQLI_ERROR_PROBES:
            data = {**other_fields, param: payload}
            async with self._sem:
                if self._delay:
                    await asyncio.sleep(self._delay)
                status, body = await _post(session, url, data, self._headers)

            if not body:
                continue

            for pattern in SQLI_ERROR_PATTERNS:
                if pattern.search(body) and not pattern.search(baseline_body):
                    self._add_finding(
                        target=url,
                        vuln_type="sqli",
                        title=f"SQL Injection (POST, error-based) — param '{param}'",
                        severity="critical",
                        confidence=0.85,
                        evidence={
                            "param": param,
                            "payload": payload,
                            "probe": probe_name,
                            "method": "POST",
                            "error_pattern": pattern.pattern,
                        },
                        remediation="Use parameterised queries / prepared statements.",
                        cwe="CWE-89",
                    )
                    return

        # 2. Time-based blind (POST)
        for payload, sleep_secs, probe_name in SQLI_TIME_PROBES[:4]:
            data = {**other_fields, param: payload}
            timeout = float(sleep_secs + 6)
            t_start = time.monotonic()
            async with self._sem:
                status, body = await _post(session, url, data, self._headers, timeout=timeout)
            elapsed = time.monotonic() - t_start

            if elapsed >= sleep_secs * _TIME_THRESHOLD_FACTOR and status != 0:
                self._add_finding(
                    target=url,
                    vuln_type="sqli",
                    title=f"SQL Injection (POST, time-based blind) — param '{param}'",
                    severity="critical",
                    confidence=0.88,
                    evidence={
                        "param": param,
                        "payload": payload,
                        "probe": probe_name,
                        "technique": "time_blind",
                        "method": "POST",
                        "elapsed_sec": round(elapsed, 2),
                    },
                    remediation="Use parameterised queries / prepared statements.",
                    cwe="CWE-89",
                )
                return

    # ── XSS discovery ─────────────────────────────────────────────

    async def _test_xss_param(self, session, url: str, param: str) -> None:
        for payload, probe_name in XSS_PROBES:
            injected_url = _inject_param(url, param, payload)
            async with self._sem:
                if self._delay:
                    await asyncio.sleep(self._delay)
                status, body = await _get(session, injected_url, self._headers)

            if _xss_is_executable(payload, body):
                self._add_finding(
                    target=injected_url,
                    vuln_type="xss",
                    title=f"Reflected XSS — param '{param}'",
                    severity="high",
                    confidence=0.80,
                    evidence={
                        "param": param,
                        "payload": payload,
                        "probe": probe_name,
                        "url": url,
                        "reflected": True,
                    },
                    remediation="Encode all user-supplied output. Apply CSP.",
                    cwe="CWE-79",
                )
                return

    async def _test_xss_post(self, session, url: str, param: str,
                              other_fields: dict) -> None:
        for payload, probe_name in XSS_PROBES:
            data = {**other_fields, param: payload}
            async with self._sem:
                if self._delay:
                    await asyncio.sleep(self._delay)
                status, body = await _post(session, url, data, self._headers)

            if _xss_is_executable(payload, body):
                self._add_finding(
                    target=url,
                    vuln_type="xss",
                    title=f"Reflected XSS (POST) — param '{param}'",
                    severity="high",
                    confidence=0.80,
                    evidence={
                        "param": param,
                        "payload": payload,
                        "probe": probe_name,
                        "method": "POST",
                        "reflected": True,
                    },
                    remediation="Encode all user-supplied output. Apply CSP.",
                    cwe="CWE-79",
                )
                return

    # ── Header injection ──────────────────────────────────────────

    async def _test_header_injection(self, session, url: str) -> None:
        """Test injectable HTTP headers for XSS reflection."""
        for header_name in INJECTABLE_HEADERS:
            for payload, probe_name in XSS_PROBES[:2]:  # quick check only
                headers = {**self._headers, header_name: payload}
                async with self._sem:
                    status, body = await _get(session, url, headers=headers)

                if _XSS_CANARY in body:
                    self._add_finding(
                        target=url,
                        vuln_type="xss",
                        title=f"Reflected XSS via {header_name} header",
                        severity="high",
                        confidence=0.75,
                        evidence={
                            "header": header_name,
                            "payload": payload,
                            "probe": probe_name,
                        },
                        remediation="Do not reflect HTTP headers in responses unescaped.",
                        cwe="CWE-79",
                    )
                    break

    # ── Per-URL orchestration ─────────────────────────────────────

    async def _scan_url(self, session, url: str, forms: list[dict] | None = None) -> None:
        """Scan a single URL — GET params + POST forms."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        # GET param baseline
        if qs:
            _, baseline = await _get(session, url, self._headers)
            tasks = []
            for param in qs:
                tasks.append(self._test_sqli_param(session, url, param, baseline))
                tasks.append(self._test_sqli_boolean_param(session, url, param, baseline))
                tasks.append(self._test_sqli_time_param(session, url, param))
                tasks.append(self._test_xss_param(session, url, param))
            await asyncio.gather(*tasks)

        # POST forms
        if forms:
            for form in forms:
                action = form.get("action") or url
                if not action.startswith("http"):
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    action = base + ("/" if not action.startswith("/") else "") + action

                fields: dict = {}
                for field_info in form.get("fields", []):
                    name = field_info.get("name", "")
                    if name:
                        fields[name] = field_info.get("value", "test")

                if not fields:
                    continue

                _, baseline = await _post(session, action, fields, self._headers)

                tasks = []
                for param in list(fields.keys()):
                    others = {k: v for k, v in fields.items() if k != param}
                    tasks.append(self._test_sqli_post(session, action, param, baseline, others))
                    tasks.append(self._test_xss_post(session, action, param, others))
                await asyncio.gather(*tasks)

        # Header injection check (once per URL)
        await self._test_header_injection(session, url)

    # ── Public API ────────────────────────────────────────────────

    async def scan(
        self,
        targets: list[str],
        crawl_data: Optional[dict] = None,
        forms_by_url: Optional[dict[str, list]] = None,
    ) -> dict:
        """
        Main entry point.

        Args:
            targets: list of URLs to probe (from crawler or orchestrator).
            crawl_data: raw crawler result dict — used to pull forms/input vectors.
            forms_by_url: pre-extracted {url: [form_dict, ...]} mapping.

        Returns:
            {'findings': [...], 'urls_tested': int, 'error': None}
        """
        if aiohttp is None:
            return {"findings": [], "urls_tested": 0, "error": "aiohttp not installed"}

        # Merge form data from crawl_data if provided
        merged_forms: dict[str, list] = dict(forms_by_url or {})
        if crawl_data:
            for page in crawl_data.get("pages", []):
                page_url = page.get("url", "")
                if page_url and page.get("forms"):
                    merged_forms.setdefault(page_url, []).extend(page["forms"])
            # Some crawlers store forms at top-level
            for form in crawl_data.get("forms", []):
                action = form.get("action", "")
                if action:
                    merged_forms.setdefault(action, []).append(form)

        # De-duplicate target list
        seen_urls: set[str] = set()
        unique_targets: list[str] = []
        for t in targets:
            if t and t not in seen_urls:
                seen_urls.add(t)
                unique_targets.append(t)

        logger.info(f"InjectionScanner: testing {len(unique_targets)} URLs")

        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self._scan_url(session, url, forms=merged_forms.get(url))
                for url in unique_targets
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"InjectionScanner: {len(self._findings)} candidate findings across {len(unique_targets)} URLs")
        return {
            "findings": self._findings,
            "urls_tested": len(unique_targets),
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# Convenience wrapper used by the orchestrator
# ─────────────────────────────────────────────────────────────────

async def scan_for_injections(
    targets: list[str],
    crawl_data: Optional[dict] = None,
    forms_by_url: Optional[dict] = None,
    concurrency: int = 20,
    request_delay: float = 0.0,
    stealth_level: str = "normal",
) -> dict:
    """
    Top-level function called from the orchestrator.

    stealth_level maps to concurrency/delay:
      aggressive  → concurrency=40, delay=0
      normal      → concurrency=20, delay=0
      stealth     → concurrency=10, delay=0.5
      paranoid    → concurrency=5,  delay=2.0
    """
    level_map = {
        "aggressive": (40, 0.0),
        "normal": (20, 0.0),
        "stealth": (10, 0.5),
        "paranoid": (5, 2.0),
    }
    concurrency, delay = level_map.get(stealth_level, (20, 0.0))

    scanner = InjectionScanner(concurrency=concurrency, request_delay=delay)
    return await scanner.scan(targets, crawl_data=crawl_data, forms_by_url=forms_by_url)
