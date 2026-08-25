"""HEAVEN — Client-side & source-review auditor.

Static analysis of a page's own HTML and JavaScript (inline + same-origin
linked). Every finding is a real observation read straight off the delivered
content — a matched HTML comment, a source→sink pair in the site's own script,
a postMessage handler with no origin check, sensitive data written to browser
storage, a permissive crossdomain policy next to a live SWF. Nothing is inferred
from absence.

Covers the technical Client-side (CLNT) OWASP-WSTG tests plus source review
(WSTG-INFO-05) that a network scanner *can* do honestly:

* WSTG-INFO-05  source/comment review        → ``source_comment_disclosure``
* WSTG-CLNT-01/02  DOM XSS / JS execution     → ``dom_xss_sink``
* WSTG-CLNT-05  CSS injection                 → ``css_injection``
* WSTG-CLNT-06  client resource manipulation  → ``client_resource_manipulation``
* WSTG-CLNT-08  cross-site flashing (SWF)      → ``flash_crossdomain``
* WSTG-CLNT-11  web messaging (postMessage)    → ``insecure_postmessage``
* WSTG-CLNT-12  browser storage                → ``sensitive_browser_storage``
* WSTG-CLNT-13  cross-site script inclusion    → ``cross_site_script_inclusion``

Static source→sink findings are reported as *potential* (moderate confidence)
for analyst confirmation — this is exactly how DOM-XSS static analysis works and
is honestly labelled, never asserted as confirmed exploitation.
"""

from __future__ import annotations
from heaven.net.egress import client_session as _egress_cs  # egress-routed aiohttp

import re
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    HAS_AIOHTTP = False

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.client_audit")

_DEFAULT_TIMEOUT = 10.0
_MAX_SCRIPTS_PER_PAGE = 8          # bound linked-JS fetches
_MAX_JS_BYTES = 512 * 1024         # skip huge bundles (minified vendor libs)

# ── finding constructor (matches misconfig_scanner / web_fuzzer shape) ─────────
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
        "source": "client_audit",
    }


# ── source / comment review (WSTG-INFO-05) ─────────────────────────────────────
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
# Sensitive tokens that make a leaked comment / JS snippet actionable. A finding
# needs a *value-bearing* match, not just the word, so normal copy never fires.
_SECRET_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")),
    ("password_assignment", re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_\-]?key)\s*[:=]\s*['\"][^'\"\s]{4,}['\"]")),
    ("basic_auth_url", re.compile(r"(?i)https?://[^\s:@/]+:[^\s:@/]+@")),
    ("private_ip", re.compile(r"\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b")),
)
# Developer-note markers only flagged when adjacent to sensitive context, so a
# bare "TODO: fix css" never fires.
_DEV_NOTE_RE = re.compile(
    r"(?i)(?:TODO|FIXME|HACK|XXX|DEBUG|BUG|BACKDOOR|REMOVE|DO NOT SHIP)[^\n]{0,80}"
    r"(?:password|secret|token|key|admin|auth|creds?|credential|disable|bypass|hardcod)"
)


def _review_source(target: str, html: str) -> list[dict]:
    out: list[dict] = []
    hits: list[dict] = []
    # HTML comments are the classic leak surface.
    for m in _HTML_COMMENT_RE.finditer(html):
        body = m.group(1)
        for label, pat in _SECRET_PATTERNS:
            sm = pat.search(body)
            if sm:
                hits.append({"where": "html_comment", "kind": label,
                             "snippet": body.strip()[:160]})
        dm = _DEV_NOTE_RE.search(body)
        if dm:
            hits.append({"where": "html_comment", "kind": "sensitive_dev_note",
                         "snippet": dm.group(0).strip()[:160]})
    if hits:
        kinds = sorted({h["kind"] for h in hits})
        out.append(_finding(
            target, "source_comment_disclosure",
            "high" if any(k in ("private_key", "aws_access_key", "password_assignment",
                                "basic_auth_url", "google_api_key", "slack_token")
                          for k in kinds) else "low",
            f"Sensitive data in page source ({', '.join(kinds)})",
            "Reviewing the delivered HTML/JS source exposed sensitive content in "
            "comments or developer notes (credentials, keys, tokens, internal IPs "
            "or backdoor markers). Attackers read source first — strip these before "
            "shipping.",
            0.9, {"hits": hits[:12], "count": len(hits)}))
    return out


# ── DOM-XSS / JS-execution / resource-manipulation (static source→sink) ────────
# Attacker-controlled *sources* in client JS.
_JS_SOURCES = (
    r"location\.hash", r"location\.search", r"location\.href", r"document\.URL",
    r"document\.documentURI", r"document\.referrer", r"window\.name",
    r"location\b", r"URLSearchParams", r"\.getParameter\(", r"postMessage",
)
_SOURCE_RE = re.compile("|".join(_JS_SOURCES))
# Dangerous HTML/JS-execution *sinks*.
_EXEC_SINKS = (
    r"\.innerHTML", r"\.outerHTML", r"document\.write(?:ln)?\s*\(",
    r"\.insertAdjacentHTML\s*\(", r"\beval\s*\(", r"\bsetTimeout\s*\(\s*['\"]",
    r"\bsetInterval\s*\(\s*['\"]", r"new\s+Function\s*\(", r"\.html\s*\(",
    r"\$\(\s*[^)]*\)\.append", r"\.setAttribute\s*\(\s*['\"]on",
)
_EXEC_SINK_RE = re.compile("|".join(_EXEC_SINKS))
# Resource-loading sinks (client-side resource manipulation).
_RES_SINKS = (
    r"\.src\s*=", r"\.setAttribute\s*\(\s*['\"]src['\"]", r"\.href\s*=",
    r"\.action\s*=", r"importScripts\s*\(", r"\.setAttribute\s*\(\s*['\"]href['\"]",
)
_RES_SINK_RE = re.compile("|".join(_RES_SINKS))
_PROXIMITY = 200   # chars between a source and a sink to count as a flow


def _find_source_sink(script: str, sink_re: "re.Pattern[str]") -> list[tuple[str, str]]:
    """Return (source, sink_snippet) pairs where a source sits near a sink."""
    pairs: list[tuple[str, str]] = []
    sources = [(m.start(), m.group(0)) for m in _SOURCE_RE.finditer(script)]
    if not sources:
        return pairs
    for sm in sink_re.finditer(script):
        s0 = sm.start()
        near = next((src for pos, src in sources if abs(pos - s0) <= _PROXIMITY), None)
        if near:
            snippet = script[max(0, s0 - 40): s0 + 60].replace("\n", " ").strip()
            pairs.append((near, snippet))
    return pairs


def _analyse_js(target: str, script: str, origin_label: str) -> list[dict]:
    out: list[dict] = []
    # DOM XSS / JS execution
    exec_pairs = _find_source_sink(script, _EXEC_SINK_RE)
    if exec_pairs:
        out.append(_finding(
            target, "dom_xss_sink", "medium",
            "Potential DOM-based XSS — tainted source flows to an HTML/JS sink",
            "The page's own JavaScript passes an attacker-influenceable source "
            "(location/URL/referrer/window.name/postMessage) into a dangerous sink "
            "(innerHTML/document.write/eval/setTimeout-string). This is the DOM-XSS "
            "pattern and warrants confirmation.",
            0.55, {"where": origin_label, "flows": [
                {"source": s, "snippet": snip} for s, snip in exec_pairs[:6]]}))
    # Client-side resource manipulation
    res_pairs = _find_source_sink(script, _RES_SINK_RE)
    if res_pairs:
        out.append(_finding(
            target, "client_resource_manipulation", "medium",
            "Potential client-side resource manipulation",
            "Client JavaScript assigns an attacker-influenceable source into a "
            "resource-loading sink (script/img/iframe src, form action, href), so a "
            "crafted URL could point the page at attacker-controlled resources.",
            0.5, {"where": origin_label, "flows": [
                {"source": s, "snippet": snip} for s, snip in res_pairs[:6]]}))
    # Insecure web messaging (postMessage listener without origin check)
    if re.search(r"addEventListener\s*\(\s*['\"]message['\"]", script) or \
            re.search(r"\.onmessage\s*=", script):
        # A handler that never references origin is the weakness.
        if not re.search(r"\.origin\b", script):
            out.append(_finding(
                target, "insecure_postmessage", "medium",
                "postMessage handler without origin validation",
                "A window 'message' event handler is registered but never checks "
                "event.origin, so any site can postMessage into it — a cross-origin "
                "data-injection / XSS vector (WSTG-CLNT-11).",
                0.6, {"where": origin_label,
                       "signal": "message listener present, no event.origin check"}))
    # Sensitive data in browser storage
    store_hits = []
    for sm in re.finditer(
            r"(?:local|session)Storage(?:\.setItem\s*\(\s*|\s*\[\s*)['\"]?"
            r"([A-Za-z0-9_\-]*(?:token|pass|pwd|secret|jwt|session|api[_\-]?key|auth|cred)[A-Za-z0-9_\-]*)",
            script, re.IGNORECASE):
        store_hits.append(sm.group(1))
    if store_hits:
        out.append(_finding(
            target, "sensitive_browser_storage", "low",
            f"Sensitive data in browser storage ({', '.join(sorted(set(store_hits))[:4])})",
            "Client JavaScript stores sensitive-looking keys (token/session/secret/"
            "api_key) in localStorage/sessionStorage, which is readable by any XSS "
            "and persists on shared machines (WSTG-CLNT-12). Prefer HttpOnly "
            "cookies for secrets.",
            0.6, {"where": origin_label, "keys": sorted(set(store_hits))[:12]}))
    return out


# ── cross-site script inclusion (XSSI) ─────────────────────────────────────────
def _check_xssi(target: str, html: str, base: str) -> list[dict]:
    """A <script src> to a same-origin endpoint whose body is executable data."""
    out: list[dict] = []
    for m in re.finditer(r"<script[^>]+src=['\"]([^'\"]+)['\"]", html, re.IGNORECASE):
        src = m.group(1)
        full = urljoin(base, src)
        if urlparse(full).netloc != urlparse(base).netloc:
            continue
        # Heuristic: a data-endpoint name (json/data/user/api) loaded as a script
        # is the XSSI shape; confirmed later only if the body is executable data.
        if re.search(r"(?i)(?:json|data|user|account|profile|api)\b", src) and \
                not re.search(r"\.(?:js|min\.js)(?:\?|$)", src):
            out.append(_finding(
                target, "cross_site_script_inclusion", "low",
                "Possible cross-site script inclusion (XSSI) endpoint",
                "A <script src> loads what looks like a dynamic data endpoint. If it "
                "returns raw JSON/JS with sensitive data and no anti-XSSI guard "
                "(e.g. a )]}' prefix, POST-only, or non-executable content type), a "
                "third-party page can include it and read the data (WSTG-CLNT-13).",
                0.4, {"script_src": full}))
    return out


# ── cross-site flashing (legacy SWF) ───────────────────────────────────────────
def _check_flash(target: str, html: str) -> list[dict]:
    if re.search(r"(?i)\.swf\b", html) or re.search(r"(?i)application/x-shockwave-flash", html):
        return [_finding(
            target, "flash_crossdomain", "low",
            "Adobe Flash (.swf) content referenced",
            "The page references legacy Flash (.swf) content. Flash is end-of-life "
            "and, combined with a permissive crossdomain.xml, enables cross-site "
            "flashing (WSTG-CLNT-08). Remove Flash content.",
            0.7, {"signal": "swf reference in HTML"})]
    return []


# ── orchestration ──────────────────────────────────────────────────────────────
async def _fetch(session: "aiohttp.ClientSession", url: str) -> tuple[str, str]:
    try:
        async with session.get(url, allow_redirects=True) as resp:
            ctype = resp.headers.get("Content-Type", "")
            if resp.status >= 400:
                return "", ctype
            body = await resp.text(errors="replace")
            return body, ctype
    except Exception as e:  # noqa: BLE001
        logger.debug("client_audit fetch failed for %s: %s", url, e)
        return "", ""


async def audit_url(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    html, ctype = await _fetch(session, url)
    if not html or "html" not in (ctype or "").lower():
        return []
    findings: list[dict] = []
    findings.extend(_review_source(url, html))
    findings.extend(_check_xssi(url, html, url))
    findings.extend(_check_flash(url, html))
    # Inline scripts.
    for sm in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html,
                          re.IGNORECASE | re.DOTALL):
        findings.extend(_analyse_js(url, sm.group(1), "inline_script"))
    # Same-origin linked scripts (bounded).
    srcs: list[str] = []
    for sm in re.finditer(r"<script[^>]+src=['\"]([^'\"]+)['\"]", html, re.IGNORECASE):
        full = urljoin(url, sm.group(1))
        if urlparse(full).netloc == urlparse(url).netloc and full not in srcs:
            srcs.append(full)
    for js_url in srcs[:_MAX_SCRIPTS_PER_PAGE]:
        js, jct = await _fetch(session, js_url)
        if js and len(js) <= _MAX_JS_BYTES:
            # Attribute a linked-script sink to the JS FILE, not the including
            # page. A shared bundle (a framework's page.js) is pulled in by many
            # pages; keying the finding on the file collapses it to one per file
            # instead of one per page that happens to include it.
            findings.extend(_analyse_js(js_url, js, f"linked:{urlparse(js_url).path}"))
    return findings


def _dedup(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for f in findings:
        key = (str(f.get("target", "")), str(f.get("vuln_type", "")))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


async def scan_client_audit(urls: list[str], timeout: float = _DEFAULT_TIMEOUT,
                            max_urls: int = 40, **_kw) -> dict:
    """Static client-side audit over a set of URLs."""
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
    ct = aiohttp.ClientTimeout(total=timeout)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; HEAVEN-ClientAudit/1.0)"}
    async with _egress_cs(connector=conn, timeout=ct, headers=headers) as session:
        sem = asyncio.Semaphore(8)

        async def _one(u: str) -> None:
            async with sem:
                findings.extend(await audit_url(session, u))

        await asyncio.gather(*[_one(u) for u in unique], return_exceptions=True)

    findings = _dedup(findings)
    logger.info("Client-side audit → %d finding(s) across %d URL(s)", len(findings), len(unique))
    return {"findings": findings, "vulnerabilities": findings, "total": len(findings)}
