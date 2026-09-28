"""
HEAVEN — Async Web Crawler
Maps endpoints, extracts JS files, identifies input vectors, and fingerprints technology.
"""

from __future__ import annotations
from heaven.net.egress import client_session as _egress_cs  # egress-routed aiohttp

import asyncio
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional, cast
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlsplit

from heaven.recon.evasion_engine import EvasionEngine, profile_for
from heaven.utils.logger import get_logger

logger = get_logger("recon.web")


# ── Session-destroying URLs ────────────────────────────────────────────────
# An authenticated crawler that follows a logout link logs ITSELF out: the
# server tears down the session, and every subsequent request — plus every other
# scanner that shares the same session (injection / fuzzer / auth) — is then
# bounced to the login page. Coverage and detection silently collapse, and
# because requests fire concurrently, *whether* the logout lands before or after
# a given scanner is timing-dependent → non-deterministic, unreproducible scans.
# This is the classic authenticated-scan pitfall (DVWA's /logout.php is the
# textbook case). We never enqueue, fetch, or emit these URLs. Matching is on
# path segments / query values so a normal page that merely contains the
# substring (e.g. /about) is unaffected.
# A path *segment* (between slashes, minus any extension) that means "end the
# session". Matched per-segment so an incidental substring never trips it:
# /checkout, /hangout, /login, /legend, /sessions all stay in scope.
_SESSION_KILL_SEGMENT_RE = re.compile(
    r"^(?:"
    r"log[_\-]?out\w*|log[_\-]?off\w*|"          # logout, log-out, logoutUser, logoff
    r"sign[_\-]?out\w*|sign[_\-]?off\w*|"        # signout, sign-out, signoff
    r"deauth(?:enticate)?\w*|disconnect|"
    r"end[_\-]?session|revoke[_\-]?session|"
    r"session[_\-](?:destroy|end|kill|logout|invalidate|terminate)"  # session_destroy
    r")$",
    re.IGNORECASE,
)
# "session" followed by a kill verb as the *next* path segment: /session/destroy.
_SESSION_KILL_AFTER = {"destroy", "end", "kill", "logout", "invalidate", "terminate"}
# A query VALUE that means logout: ?action=logout, ?do=logoff, &op=signout.
_SESSION_KILL_VALUES = {
    "logout", "log_out", "log-out", "logoff", "log_off", "signout",
    "sign_out", "sign-out", "signoff", "deauth", "disconnect",
}


def _canonical_link(url: str) -> str:
    """Drop the ``#fragment`` from a link (for the HTTP crawler).

    A fragment is a client-side anchor: the browser never sends it to the server,
    so ``page.php#section-a`` and ``page.php#section-b`` are the SAME server
    resource. Without stripping it, a page whose body links to many in-page
    anchors (phpinfo's ~40 ``#module_*`` table-of-contents links are the classic
    case) is crawled — and then fully re-scanned by every downstream web audit —
    once per fragment, burning the scan budget and risking duplicate findings
    keyed on the fragmented URL. The HTTP crawler cannot render a client-side
    route anyway, so it strips every fragment, hash-routes included.
    """
    return urldefrag(url).url


def _canonical_link_spa(url: str) -> str:
    """Fragment stripping for the browser (Playwright) crawler.

    Same as :func:`_canonical_link`, but PRESERVES a client-side route fragment
    (``#/path`` or ``#!path``): a rendering crawler navigates those to genuinely
    distinct SPA views (``#/admin`` vs ``#/search`` are different pages), so
    collapsing them would lose coverage. A plain same-page anchor (``#section``)
    renders nothing new, so it still collapses — the phpinfo dedup still applies.
    """
    frag = urldefrag(url).fragment
    if frag.startswith("/") or frag.startswith("!"):
        return url
    return urldefrag(url).url


def _is_session_destroying(url: str) -> bool:
    """True if fetching ``url`` would likely end the current auth session.

    Inspects path segments (``/logout.php``, ``/user/sign-out``,
    ``/api/session/destroy``) and query values (``?action=logout``). Pure and
    side-effect free.
    """
    if not url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    segs = [s for s in (parts.path or "").split("/") if s]
    for i, seg in enumerate(segs):
        stem = seg.rsplit(".", 1)[0]  # logout.php -> logout
        if _SESSION_KILL_SEGMENT_RE.match(seg) or _SESSION_KILL_SEGMENT_RE.match(stem):
            return True
        if seg.lower() == "session" and i + 1 < len(segs):
            nxt = segs[i + 1].rsplit(".", 1)[0].lower()
            if nxt in _SESSION_KILL_AFTER:
                return True
    for _k, v in parse_qsl(parts.query or ""):
        if v.strip().lower() in _SESSION_KILL_VALUES:
            return True
    return False


@dataclass
class WebEndpoint:
    url: str
    status_code: int = 0
    content_type: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    input_vectors: list[dict] = field(default_factory=list)
    headers: dict = field(default_factory=dict)


JS_ENDPOINT_PATTERNS = [
    r"""['"](/api/[^'"]+)['"]""",
    r"""fetch\(['"](/?[^'"]+)['"]""",
    r"""\.(?:get|post|put|delete)\(['"](/?[^'"]+)['"]""",
    r"""endpoint['":\s]+['"](/?[^'"]+)['"]""",
]

# ── SPA framework markers ───────────────────────────────────────────────────
# A JavaScript-heavy single-page app renders its routes, forms and links in the
# browser, so this static (aiohttp) crawler sees only the empty shell and misses
# the real endpoint surface. Detecting a framework marker in the shell lets
# ``crawl_targets`` escalate to the Playwright renderer (``crawl_url_js``), which
# executes the JS and enumerates the rendered surface — the endpoints downstream
# injection / XSS / access-control scanners would otherwise never receive. Each
# marker is a literal substring a real SPA shell emits (not inferred), so the
# escalation is evidence-gated, never speculative.
_SPA_MARKERS: list[tuple[str, str]] = [
    ("ng-version", "Angular"), ("<app-root", "Angular"), ("ng-app", "AngularJS"),
    ("data-reactroot", "React"), ("react-dom", "React"), ("__next_data__", "Next.js"),
    ("/_next/static", "Next.js"), ("__nuxt__", "Nuxt"), ("_nuxt/", "Nuxt"),
    ("data-server-rendered", "Vue"), ("__vue__", "Vue"),
    ('id="svelte"', "Svelte"), ("data-sveltekit", "SvelteKit"),
    ("window.__initial_state__", "SPA"),
]


def _detect_spa_frameworks(body: str) -> list[str]:
    """Return SPA framework tags whose literal marker appears in the shell HTML."""
    low = body.lower()
    found: list[str] = []
    for marker, tech in _SPA_MARKERS:
        if marker in low and tech not in found:
            found.append(tech)
    return found


_SPA_TECHS = {"Angular", "AngularJS", "React", "Next.js", "Nuxt", "Vue",
              "Svelte", "SvelteKit", "SPA"}


def _endpoints_look_spa(endpoints: list["WebEndpoint"]) -> bool:
    """True if the statically crawled shell carries an SPA framework marker."""
    return any(t in _SPA_TECHS for ep in endpoints for t in ep.technologies)


def _merge_endpoint(dst: "WebEndpoint", src: "WebEndpoint") -> None:
    """Merge a rendered endpoint's forms / input-vectors / js into ``dst``.

    Used when the Playwright render produces the SAME URL as the static crawl but
    with additional client-rendered forms and input vectors. Dedupes so the merge
    never inflates the surface with repeats."""
    seen_iv: set[tuple] = {(iv.get("url"), iv.get("method"), iv.get("param"))
                           for iv in dst.input_vectors}
    for iv in src.input_vectors:
        iv_key = (iv.get("url"), iv.get("method"), iv.get("param"))
        if iv.get("param") and iv_key not in seen_iv:
            dst.input_vectors.append(iv)
            seen_iv.add(iv_key)
    seen_forms: set[tuple] = {(f.get("action"), f.get("method")) for f in dst.forms}
    for f in src.forms:
        f_key = (f.get("action"), f.get("method"))
        if f_key not in seen_forms:
            dst.forms.append(f)
            seen_forms.add(f_key)
    for js in src.js_files:
        if js not in dst.js_files:
            dst.js_files.append(js)
    for tech in src.technologies:
        if tech not in dst.technologies:
            dst.technologies.append(tech)


def _chromium_available() -> bool:
    """Whether a usable Playwright Chromium is present (cached probe).

    Returns False on any error so SPA escalation is a strict opt-in that never
    breaks a crawl when the browser bundle is not installed."""
    try:
        from heaven.utils.runtime_capabilities import _cached_chromium_status
        ok, _ = _cached_chromium_status()
        return bool(ok)
    except Exception:
        return False


def _auto_install_browser_enabled() -> bool:
    """Whether the operator opted in to on-demand browser provisioning.

    The SPA renderer needs the ~150 MB Chromium bundle, which HEAVEN never
    downloads silently (a large fetch is always an explicit choice, matching the
    ``no auto-download without consent`` rule). Setting
    ``HEAVEN_AUTO_INSTALL_BROWSER=1`` is that consent: a scan that then meets a
    SPA on a host missing the browser provisions it once, so the client-rendered
    surface is never quietly missed."""
    import os
    return os.environ.get("HEAVEN_AUTO_INSTALL_BROWSER", "").strip().lower() in {
        "1", "true", "yes", "on"}


# Provision the browser at most once per process: a fleet of SPA targets must
# not each retry a 150 MB download. False until an attempt has run.
_browser_provision_attempted = False


def _ensure_chromium_once() -> bool:
    """Best-effort, one-shot on-demand provisioning of the Playwright browser.

    Returns True only when a usable Chromium is present afterwards. Never raises
    and never attempts more than once per process, so a run with many SPA
    targets and no browser stays fast and predictable."""
    global _browser_provision_attempted
    if _chromium_available():
        return True
    if _browser_provision_attempted:
        return False
    _browser_provision_attempted = True
    try:
        from heaven.utils.runtime_capabilities import ensure_chromium
        ok, detail = ensure_chromium(on_output=lambda ln: logger.info("playwright: %s", ln))
        if ok:
            logger.info("Playwright Chromium provisioned on demand: %s", detail)
        else:
            logger.warning("On-demand Playwright provisioning failed: %s", detail)
        return bool(ok)
    except Exception as exc:  # noqa: BLE001 — provisioning must never break a scan
        logger.warning("On-demand Playwright provisioning error: %s", exc)
        return False


def _spa_render_gap_note(
    url: str, frameworks: list[str],
    recovered_endpoints: int = 0, recovered_vectors: int = 0,
    browser_failed: bool = False,
) -> dict[str, Any]:
    """An honest, actionable coverage note for a SPA the crawl could not fully see.

    Emitted (never a finding) in two cases: a JS framework is detected but no
    headless browser is available (``browser_failed=False``), or a browser WAS
    reported available but the render actually failed and static JS recovery also
    came up empty (``browser_failed=True``) — the dangerous case, because the app
    looks 'clean' when really its client-rendered surface was never reached. The
    recovered counts make the honest state explicit either way."""
    fw = ", ".join(frameworks) if frameworks else "SPA"
    if browser_failed:
        impact = (f"{fw} detected. A headless-browser render was attempted but FAILED "
                  f"and static JS recovery found {recovered_endpoints} endpoint(s) / "
                  f"{recovered_vectors} vector(s) — the client-rendered attack surface "
                  "was likely NOT reached, so findings are probably UNDER-REPORTED")
        remediation = ("repair the Playwright browser: `heaven install-tools` (or "
                       "`playwright install chromium`); a JS SPA scanned without a "
                       "working renderer sees only the shell, not the real app")
    else:
        impact = (f"{fw} detected. Its request surface was recovered statically from "
                  f"the JS bundles ({recovered_endpoints} endpoint(s), "
                  f"{recovered_vectors} input vector(s)), but DOM-rendered routes and "
                  "runtime-built forms may still be UNDER-REPORTED without the "
                  "headless-browser renderer")
        remediation = ("run `heaven install-tools` (or `playwright install chromium`) "
                       "for full DOM-render fidelity, or set "
                       "HEAVEN_AUTO_INSTALL_BROWSER=1 to provision it on demand")
    return {
        "type": "spa_render_reduced_fidelity",
        "url": url,
        "frameworks": frameworks,
        "browser_failed": browser_failed,
        "recovered_endpoints": recovered_endpoints,
        "recovered_input_vectors": recovered_vectors,
        "impact": impact,
        "remediation": remediation,
    }

TECH_FINGERPRINTS = {
    "X-Powered-By": {"Express": "Express.js", "PHP": "PHP", "ASP.NET": "ASP.NET"},
    "Server": {"nginx": "Nginx", "Apache": "Apache", "Microsoft-IIS": "IIS"},
}


async def crawl_url(
    url: str, max_depth: int = 3, max_pages: int = 200,
    timeout: float = 10.0, semaphore: Optional[asyncio.Semaphore] = None,
    evasion_headers: Optional[dict] = None,
    auth_config: Optional[dict] = None,
) -> list[WebEndpoint]:
    """BFS web crawler that maps endpoints and extracts input vectors."""
    import aiohttp
    from bs4 import BeautifulSoup

    sem = semaphore or asyncio.Semaphore(50)
    visited: set[str] = set()
    endpoints: list[WebEndpoint] = []
    queue: deque[tuple[str, int]] = deque([(url, 0)])
    base_domain = urlparse(url).netloc

    _cookies: dict = {}
    _extra_headers: dict = {}
    if auth_config:
        _cookies = auth_config.get("cookies", {})
        _extra_headers = auth_config.get("headers", {})
        if auth_config.get("bearer_token"):
            _extra_headers["Authorization"] = f"Bearer {auth_config['bearer_token']}"

    async with _egress_cs(
        headers={**(evasion_headers or {}), **_extra_headers},
        cookies=_cookies,
        timeout=aiohttp.ClientTimeout(total=timeout),
        connector=aiohttp.TCPConnector(ssl=False, limit=50),
    ) as session:
        while queue and len(visited) < max_pages:
            current_url, depth = queue.popleft()
            current_url = _canonical_link(current_url)  # a seed may carry a #fragment
            if current_url in visited or depth > max_depth:
                continue
            if _is_session_destroying(current_url):
                # Never fetch a logout/session-kill URL — it would end the
                # authenticated session for this crawl and every scanner sharing it.
                continue
            visited.add(current_url)

            async with sem:
                try:
                    async with session.get(current_url, allow_redirects=True) as resp:
                        ep = WebEndpoint(url=current_url, status_code=resp.status)
                        ep.content_type = resp.headers.get("Content-Type", "")
                        ep.server = resp.headers.get("Server", "")
                        ep.headers = dict(resp.headers)

                        # Tech fingerprinting
                        for header, sigs in TECH_FINGERPRINTS.items():
                            val = resp.headers.get(header, "")
                            for sig, tech in sigs.items():
                                if sig.lower() in val.lower():
                                    ep.technologies.append(tech)

                        if "text/html" in ep.content_type:
                            body = await resp.text(errors="replace")
                            soup = BeautifulSoup(body, "html.parser")

                            # Extract links for BFS
                            for a in soup.find_all("a", href=True):
                                href = a.get("href")
                                link = _canonical_link(urljoin(current_url, str(href or "")))
                                if _is_session_destroying(link):
                                    continue  # don't log ourselves out mid-crawl
                                if urlparse(link).netloc == base_domain and link not in visited:
                                    queue.append((link, depth + 1))

                            # Extract JS files
                            for script in soup.find_all("script", src=True):
                                src = script.get("src")
                                js = urljoin(current_url, str(src or ""))
                                ep.js_files.append(js)

                            # Extract forms and input vectors
                            for form in soup.find_all("form"):
                                form_data: dict[str, Any] = {
                                    "action": urljoin(current_url, str(form.get("action", ""))),
                                    "method": str(form.get("method", "GET")).upper(),
                                    "inputs": [],
                                }
                                form_inputs = cast(list[dict[str, str]], form_data["inputs"])
                                for inp in form.find_all(["input", "textarea", "select"]):
                                    input_info = {
                                        "name": str(inp.get("name", "")),
                                        "type": str(inp.get("type", "text")),
                                        "id": str(inp.get("id", "")),
                                    }
                                    form_inputs.append(input_info)
                                    if inp.get("name"):
                                        ep.input_vectors.append({
                                            "type": "form_input",
                                            "url": form_data["action"],
                                            "method": form_data["method"],
                                            "param": str(inp.get("name", "")),
                                            "input_type": str(inp.get("type", "text")),
                                        })
                                ep.forms.append(form_data)

                            # URL params as input vectors
                            parsed = urlparse(current_url)
                            if parsed.query:
                                for param in parsed.query.split("&"):
                                    name = param.split("=")[0]
                                    ep.input_vectors.append({
                                        "type": "url_param", "url": current_url,
                                        "method": "GET", "param": name,
                                    })

                            # Meta generator
                            gen = soup.find("meta", attrs={"name": "generator"})
                            if gen and gen.get("content"):
                                ep.technologies.append(str(gen.get("content", "")))

                            # SPA framework markers → lets crawl_targets escalate
                            # to the JS renderer so client-rendered routes/forms
                            # are not missed on Angular/React/Vue/Next apps.
                            for tech in _detect_spa_frameworks(body):
                                if tech not in ep.technologies:
                                    ep.technologies.append(tech)

                        endpoints.append(ep)

                except Exception as e:
                    logger.debug(f"Crawl error on {current_url}: {e}")

    logger.info(f"Crawled {len(endpoints)} pages on {base_domain}")
    return endpoints


async def extract_js_endpoints(js_urls: list[str], timeout: float = 10.0) -> list[str]:
    """Fetch and analyse JS bundles to discover API endpoints.

    Each match is resolved to an **absolute, same-origin URL** against the
    bundle it was found in (see :func:`heaven.feedback.resolve_js_endpoint`):
    a route named in ``https://app.tld/static/main.js`` becomes
    ``https://app.tld/api/...``. Third-party and noise matches (event names,
    MIME types, template placeholders, CDN assets) are dropped, so what comes
    back is a clean set of in-scope endpoints the injection / API scanners can
    consume directly.
    """
    import aiohttp

    from heaven.feedback import resolve_js_endpoint

    discovered: set[str] = set()
    async with _egress_cs(
        timeout=aiohttp.ClientTimeout(total=timeout),
        connector=aiohttp.TCPConnector(ssl=False),
    ) as session:
        for js_url in js_urls[:50]:
            try:
                async with session.get(js_url) as resp:
                    if resp.status != 200:
                        continue
                    content = await resp.text(errors="replace")
                    for pattern in JS_ENDPOINT_PATTERNS:
                        for raw in re.findall(pattern, content):
                            resolved = resolve_js_endpoint(raw, js_url)
                            if resolved:
                                discovered.add(_canonical_link(resolved))
            except Exception as e:
                logger.debug(f"JS endpoint extraction error for {js_url}: {e}")
                continue
    return sorted(discovered)


# ── Static SPA request-surface recovery (NO browser required) ───────────────
# A JS-rendered app's real attack surface — the endpoints it calls and the
# PARAMETERS it sends — is written into its JavaScript bundles as string and
# object literals. A DOM render (Playwright) recovers this by *executing* the
# app, but that needs the ~150 MB Chromium bundle. This analyser recovers the
# same request surface in pure Python: fetch the bundles, read the literals. So
# a JS app's attack surface is NEVER gated on that download — the browser render
# becomes a higher-fidelity superset, not a precondition. It reports only what
# the source literally constructs (same-origin endpoints, real payload keys) and
# emits ``input_vectors`` — never a finding: the downstream injection / API /
# access-control scanners still actively confirm every candidate.
_JS_SURFACE_MAX_BUNDLES = 50
_JS_SURFACE_MAX_BYTES = 2_000_000       # bound regex time on huge minified bundles
_JS_SURFACE_MAX_ENDPOINTS = 300
_JS_SURFACE_MAX_PARAMS = 25

# Calls whose URL (and often method) can be read straight from the source. Each
# yields (explicit_method_or_None, raw_url). ``resolve_js_endpoint`` then keeps
# only same-origin, non-asset paths, so a bare word / MIME type / CDN asset /
# template literal (``${…}``) is dropped — the surface stays same-origin + real.
_JS_FETCH_RE = re.compile(r"""\bfetch\(\s*['"]([^'"\s]+)['"]""", re.IGNORECASE)
_JS_METHODCALL_RE = re.compile(
    r"""[\w$.]*\.(get|post|put|delete|patch)\(\s*['"]([^'"\s]+)['"]""", re.IGNORECASE)
_JS_XHR_OPEN_RE = re.compile(
    r"""\.open\(\s*['"](GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"\s]+)['"]""",
    re.IGNORECASE)
_JS_URLKEY_RE = re.compile(r"""\b(?:url|endpoint)\s*:\s*['"](/[^'"\s]+)['"]""", re.IGNORECASE)

# Payload objects whose KEYS are real request parameters — the app's own API
# contract, which survives minification because the server expects those exact
# names (variable names get mangled; contract keys cannot). Restricted to a flat
# ``{…}`` (no nested braces) so extraction is bounded and low-noise.
_JS_PAYLOAD_RE = re.compile(
    r"""(?:JSON\.stringify\(\s*\{([^{}]*)\}"""       # group 1: JSON.stringify({...})
    r"""|(?:body|data|params)\s*:\s*\{([^{}]*)\}"""  # group 2: body/data/params: {...}
    r"""|,\s*\{([^{}]*)\})""",                       # group 3: positional data arg — $.post(u,{...})
    re.IGNORECASE)
_JS_KEY_RE = re.compile(r"""['"]?([A-Za-z_$][\w$]*)['"]?\s*:""")
_JS_SHORTHAND_RE = re.compile(r"""(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?=[,}]|$)""")
_JS_INLINE_METHOD_RE = re.compile(r"""(?:\bmethod|\btype)\s*:\s*['"]([A-Za-z]+)['"]""",
                                  re.IGNORECASE)
_JS_BODY_HINT_RE = re.compile(r"""JSON\.stringify|\bbody\s*:""", re.IGNORECASE)

# Object keys that are HTTP-client configuration, never a user-supplied parameter.
_JS_NON_PARAM = {
    "method", "headers", "header", "body", "credentials", "mode", "cache",
    "redirect", "referrer", "referrerpolicy", "signal", "integrity", "keepalive",
    "url", "params", "data", "timeout", "responsetype", "withcredentials",
    "baseurl", "type", "contenttype", "datatype", "async", "crossdomain",
    "accept", "authorization", "observe", "reportprogress",
}


def _iter_js_calls(content: str):
    """Yield ``(explicit_method_or_None, raw_url, window)`` for each HTTP call.

    ``window`` is a bounded slice of source around the call, from which the
    method and payload parameter names are read. Pure and side-effect free."""
    for m in _JS_FETCH_RE.finditer(content):
        yield None, m.group(1), content[m.end():m.end() + 400]
    for m in _JS_METHODCALL_RE.finditer(content):
        yield m.group(1), m.group(2), content[m.end():m.end() + 400]
    for m in _JS_XHR_OPEN_RE.finditer(content):
        yield m.group(1), m.group(2), content[m.end():m.end() + 400]
    for m in _JS_URLKEY_RE.finditer(content):
        # Sibling keys of a request-config object can sit either side of ``url:``.
        yield None, m.group(1), content[max(0, m.start() - 200):m.end() + 400]


def _params_from_window(window: str) -> list[str]:
    """Extract real request-parameter names from a call's payload objects."""
    keys: list[str] = []
    for m in _JS_PAYLOAD_RE.finditer(window):
        inner = m.group(1) or m.group(2) or m.group(3) or ""
        keys.extend(km.group(1) for km in _JS_KEY_RE.finditer(inner))
        keys.extend(sm.group(1) for sm in _JS_SHORTHAND_RE.finditer(inner))
    out: list[str] = []
    seen: set[str] = set()
    for k in keys:
        if k.lower() in _JS_NON_PARAM or len(k) > 40 or k in seen:
            continue
        seen.add(k)
        out.append(k)
        if len(out) >= _JS_SURFACE_MAX_PARAMS:
            break
    return out


async def extract_js_surface(
    js_urls: list[str], timeout: float = 10.0, evasion_headers: Optional[dict] = None,
) -> list[WebEndpoint]:
    """Recover a SPA's request surface (endpoints + methods + PARAMETERS) from its
    JS bundles, in pure Python, with no browser.

    Fetches each bundle and reconstructs the HTTP calls the app makes at runtime:
    the endpoint URL, its method, and the body / query parameter names. These are
    the input vectors a DOM render would surface via rendered forms — recovered
    here without the ~150 MB browser download, so the JS-rendered attack surface
    is never quietly missed on a host that lacks Chromium. Only endpoints that
    carry at least one parameter are returned (a bare URL is already covered by
    :func:`extract_js_endpoints`); the result is additive and deduped. Never
    raises for a single bad bundle — a fetch/parse error skips that bundle only.
    """
    import aiohttp

    from heaven.feedback import resolve_js_endpoint

    by_url: dict[str, WebEndpoint] = {}
    async with _egress_cs(
        headers=evasion_headers or {},
        timeout=aiohttp.ClientTimeout(total=timeout),
        connector=aiohttp.TCPConnector(ssl=False),
    ) as session:
        for js_url in js_urls[:_JS_SURFACE_MAX_BUNDLES]:
            try:
                async with session.get(js_url) as resp:
                    if resp.status != 200:
                        continue
                    # Never re-mine an HTML shell a server hands back for an
                    # unknown ".js" path — only real scripts (or untyped bodies).
                    if "html" in resp.headers.get("Content-Type", "").lower():
                        continue
                    content = (await resp.text(errors="replace"))[:_JS_SURFACE_MAX_BYTES]
            except Exception as e:  # noqa: BLE001 — one bad bundle must not abort the rest
                logger.debug(f"JS surface fetch error for {js_url}: {e}")
                continue

            for explicit_method, raw_url, window in _iter_js_calls(content):
                if len(by_url) >= _JS_SURFACE_MAX_ENDPOINTS:
                    break
                resolved = resolve_js_endpoint(raw_url, js_url)
                if not resolved:
                    continue
                params = _params_from_window(window)
                q_params = [k for k, _ in parse_qsl(urlsplit(resolved).query)]
                if not params and not q_params:
                    continue  # bare URL — already covered by extract_js_endpoints
                inline = _JS_INLINE_METHOD_RE.search(window)
                method = (explicit_method or (inline.group(1) if inline else None)
                          or ("POST" if _JS_BODY_HINT_RE.search(window) else "GET")).upper()
                ep = by_url.get(resolved)
                if ep is None:
                    ep = WebEndpoint(url=resolved, status_code=0, technologies=["js-derived"])
                    by_url[resolved] = ep
                seen = {(iv.get("method"), iv.get("param")) for iv in ep.input_vectors}
                for p in params:
                    if (method, p) not in seen:
                        ep.input_vectors.append({
                            "type": "api_param" if method != "GET" else "url_param",
                            "url": resolved, "method": method, "param": p,
                            "source": "js-static"})
                        seen.add((method, p))
                for p in q_params:
                    if ("GET", p) not in seen:
                        ep.input_vectors.append({
                            "type": "url_param", "url": resolved, "method": "GET",
                            "param": p, "source": "js-static"})
                        seen.add(("GET", p))
    if by_url:
        total = sum(len(e.input_vectors) for e in by_url.values())
        logger.info(f"Static SPA analysis: {len(by_url)} endpoint(s), "
                    f"{total} input vector(s) recovered from JS bundles (no browser)")
    return list(by_url.values())


async def discover_apis(base_url: str, timeout: float = 10.0, evasion_headers: Optional[dict] = None) -> list[WebEndpoint]:
    """Hunt for OpenAPI/Swagger specs and parse them into endpoints."""
    import aiohttp
    import json
    from urllib.parse import urljoin
    
    api_paths = ["/swagger.json", "/openapi.json", "/v3/api-docs", "/api/v1/swagger.json", "/api/swagger.json", "/docs-json"]
    endpoints = []
    
    async with _egress_cs(
        headers=evasion_headers or {},
        timeout=aiohttp.ClientTimeout(total=timeout),
        connector=aiohttp.TCPConnector(ssl=False)
    ) as session:
        for path in api_paths:
            target_url = urljoin(base_url, path)
            try:
                async with session.get(target_url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        try:
                            spec = json.loads(content)
                            if "openapi" in spec or "swagger" in spec:
                                logger.info(f"Discovered OpenAPI spec at {target_url}")
                                
                                paths = spec.get("paths", {})
                                for api_path, methods in paths.items():
                                    ep_url = urljoin(base_url, api_path)
                                    ep = WebEndpoint(url=ep_url, status_code=200, server="API")
                                    
                                    for method, details in methods.items():
                                        if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                            for param in details.get("parameters", []):
                                                ep.input_vectors.append({
                                                    "type": "api_param",
                                                    "url": ep_url,
                                                    "method": method.upper(),
                                                    "param": param.get("name", ""),
                                                    "input_type": param.get("in", "query")
                                                })
                                    endpoints.append(ep)
                                return endpoints
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.debug(f"API discovery failed on {target_url}: {e}")
                
    return endpoints


async def crawl_targets(urls: list[str], stealth_level: str = "normal",
                        auth_config: Optional[dict] = None, **kwargs) -> dict[str, Any]:
    """Main entry point for web crawling (called by orchestrator)."""
    if not urls:
        logger.info("No URLs specified: skipping web crawl")
        return {"endpoints": [], "js_endpoints": [], "input_vectors": 0}

    # Resolve the FULL profile for this level (timing + concurrency), not a bare
    # EvasionProfile(stealth_level=…) — the bare form leaves every delay at 0 and
    # would make stealth a no-op for the crawl.
    profile = profile_for(stealth_level)
    engine = EvasionEngine(profile)

    all_endpoints: list[WebEndpoint] = []
    all_js: list[str] = []
    # Honest coverage notes (never findings): what surface a scan could NOT
    # reach and how to arm it. Surfaced so a skipped SPA render is disclosed.
    coverage_notes: list[dict[str, Any]] = []
    # Concurrency scales with the level: paranoid=10 … stealth=50 … aggressive=1000.
    sem = asyncio.Semaphore(max(1, profile.max_concurrent))

    for url in urls:
        await engine.apply_evasion_delay()
        headers = engine.get_http_headers()
        eps = await crawl_url(url, semaphore=sem, evasion_headers=headers, auth_config=auth_config)
        # SPA escalation: a JS-rendered app hides its routes/forms/input-vectors
        # from the static shell crawl. We recover that surface in two layers,
        # additive and deduped:
        #   (1) STATIC (always, no browser): mine the JS bundles for the app's
        #       request surface — endpoints + methods + PARAMETERS — in pure
        #       Python. This is what a DOM render would expose via rendered forms,
        #       recovered with NO 150 MB download, so the surface is never gated
        #       on an optional dependency.
        #   (2) RENDER (superset, when a browser is present or opted in): execute
        #       the app for the highest-fidelity DOM enumeration.
        # When no browser is available the static layer has already done the
        # recovery, so we DISCLOSE only the residual (DOM-only) gap — never a
        # silent no-op, and never a hard dependency.
        if _endpoints_look_spa(eps):
            frameworks = sorted({t for e in eps for t in e.technologies if t in _SPA_TECHS})
            by_url = {ep.url: ep for ep in eps}

            def _merge_rendered(rendered: list[WebEndpoint]) -> tuple[int, int]:
                new_count = added_vectors = 0
                for r in rendered:
                    existing = by_url.get(r.url)
                    if existing is None:
                        eps.append(r)
                        by_url[r.url] = r
                        new_count += 1
                        added_vectors += len(r.input_vectors)
                    else:
                        before = len(existing.input_vectors)
                        _merge_endpoint(existing, r)
                        added_vectors += len(existing.input_vectors) - before
                return new_count, added_vectors

            # (1) Browser-free static recovery from the JS bundles.
            spa_js = list(dict.fromkeys(j for e in eps for j in e.js_files))
            static_endpoints = static_vectors = 0
            if spa_js:
                try:
                    derived = await extract_js_surface(spa_js, evasion_headers=headers)
                    static_endpoints, static_vectors = _merge_rendered(derived)
                    if static_endpoints or static_vectors:
                        logger.info(
                            "SPA static analysis on %s: +%d endpoints, +%d input "
                            "vectors recovered from JS bundles without a browser",
                            url, static_endpoints, static_vectors)
                except Exception as exc:  # noqa: BLE001 — recovery must never break the crawl
                    logger.debug(f"SPA static analysis skipped for {url}: {exc}")

            # (2) Optional higher-fidelity DOM render.
            ready = _chromium_available()
            if not ready and _auto_install_browser_enabled():
                ready = _ensure_chromium_once()  # consented on-demand provision
            render_new = render_vectors = 0
            render_failed = False
            if ready:
                try:
                    rendered = await crawl_url_js(
                        url, max_pages=40, auth_config=auth_config,
                        evasion_headers=headers)
                    render_new, render_vectors = _merge_rendered(rendered)
                    if render_new or render_vectors:
                        logger.info(
                            f"SPA render on {url}: +{render_new} client-rendered routes, "
                            f"+{render_vectors} input vectors beyond the static analysis")
                except Exception as exc:
                    render_failed = True
                    logger.debug(f"SPA render skipped for {url}: {exc}")
            if not ready:
                # No browser: the static pass already recovered the request surface.
                # Disclose only the residual DOM-only gap (info, not warning — this
                # is reduced fidelity, not a missed surface) with the one-command arm.
                logger.info(
                    "SPA framework(s) %s on %s analysed statically (+%d endpoints, "
                    "+%d input vectors from JS). For full DOM-render fidelity arm the "
                    "browser: `heaven install-tools`, or HEAVEN_AUTO_INSTALL_BROWSER=1.",
                    ", ".join(frameworks) or "SPA", url, static_endpoints, static_vectors)
                coverage_notes.append(
                    _spa_render_gap_note(url, frameworks, static_endpoints, static_vectors))
            elif (static_endpoints + static_vectors + render_new + render_vectors) == 0:
                # A browser was ready but the SPA yielded NO surface beyond the shell —
                # whether the render raised (render_failed) or returned nothing, and
                # static JS recovery came up empty too. This is the silent-miss case:
                # without this note a JS app that was never really reached looks
                # 'clean'. An SPA essentially always has client-rendered routes, so an
                # empty result means the crawl could not see the app, not that it is
                # small. Warn and disclose rather than hide it.
                logger.warning(
                    "SPA on %s yielded no surface beyond the shell (render_failed=%s) — "
                    "the client-rendered app was NOT reached; findings under-reported.",
                    url, render_failed)
                coverage_notes.append(_spa_render_gap_note(
                    url, frameworks, static_endpoints, static_vectors, browser_failed=True))
        api_eps = await discover_apis(url, evasion_headers=headers)
        all_endpoints.extend(eps)
        all_endpoints.extend(api_eps)
        for ep in eps:
            all_js.extend(ep.js_files)

    js_endpoints = await extract_js_endpoints(list(set(all_js)))

    total_vectors = sum(len(ep.input_vectors) for ep in all_endpoints)
    logger.info(f"Web crawl: {len(all_endpoints)} pages, {total_vectors} input vectors, {len(js_endpoints)} JS endpoints")

    # Preserve the actual form structures per URL so downstream scanners that
    # reason over whole forms (auth_scanner's CSRF / session-fixation audits,
    # idor_scanner) can consume them. The endpoint summary keeps only a form
    # COUNT, which is why those audits used to receive nothing. Normalise the
    # crawler's `inputs` list to the `fields` key every consumer reads.
    url_forms: dict[str, list[dict]] = {}
    for ep in all_endpoints:
        for f in ep.forms:
            url_forms.setdefault(ep.url, []).append({
                "action": f.get("action") or ep.url,
                "method": (f.get("method") or "GET"),
                "fields": f.get("inputs") or f.get("fields") or [],
            })

    return {
        "endpoints": [
            {"url": ep.url, "status": ep.status_code, "server": ep.server,
             "technologies": ep.technologies, "forms": len(ep.forms),
             "input_vectors": ep.input_vectors, "js_files": ep.js_files}
            for ep in all_endpoints
        ],
        "js_endpoints": js_endpoints,
        "input_vectors": total_vectors,
        "url_forms": url_forms,
        # Honest disclosure of surface the crawl could not reach (e.g. a SPA whose
        # JS could not be rendered because no browser is installed). Empty when
        # nothing was skipped, so consumers can treat it as a plain list.
        "coverage_notes": coverage_notes,
    }


async def crawl_url_js(
    url: str,
    max_depth: int = 2,
    max_pages: int = 50,
    auth_config: Optional[dict] = None,
    evasion_headers: Optional[dict] = None,
) -> list[WebEndpoint]:
    """
    Playwright-based crawler for JavaScript-heavy SPAs.
    Falls back to aiohttp crawl_url if Playwright is not installed.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.debug("Playwright not installed: falling back to aiohttp crawler")
        return await crawl_url(url, max_depth=max_depth, max_pages=max_pages,
                               evasion_headers=evasion_headers, auth_config=auth_config)

    endpoints: list[WebEndpoint] = []
    visited: set[str] = set()
    base_domain = urlparse(url).netloc

    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"]
    extra_headers = dict(evasion_headers or {})
    if auth_config:
        extra_headers.update(auth_config.get("headers", {}))
        if auth_config.get("bearer_token"):
            extra_headers["Authorization"] = f"Bearer {auth_config['bearer_token']}"

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=launch_args)
            context = await browser.new_context(
                extra_http_headers=extra_headers,
                ignore_https_errors=True,
            )
            if auth_config and auth_config.get("cookies"):
                cookie_list = [
                    {"name": k, "value": v, "domain": base_domain, "path": "/"}
                    for k, v in auth_config["cookies"].items()
                ]
                # These dicts carry exactly Playwright's cookie fields; cast to
                # satisfy the SetCookieParam TypedDict (not publicly importable).
                await context.add_cookies(cast("list[Any]", cookie_list))

            queue = [(url, 0)]
            while queue and len(visited) < max_pages:
                current_url, depth = queue.pop(0)
                # Browser crawler: collapse same-page anchors but keep SPA routes.
                current_url = _canonical_link_spa(current_url)
                if current_url in visited or depth > max_depth:
                    continue
                if _is_session_destroying(current_url):
                    continue  # never fetch a logout/session-kill URL while authed
                visited.add(current_url)

                try:
                    page = await context.new_page()
                    response = await page.goto(current_url, wait_until="networkidle", timeout=15000)
                    status = response.status if response else 0

                    ep = WebEndpoint(url=current_url, status_code=status)

                    # Extract links from rendered DOM
                    links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                    for link in links:
                        link = _canonical_link_spa(link)  # keep SPA routes, drop anchors
                        if _is_session_destroying(link):
                            continue  # don't log ourselves out mid-crawl
                        parsed = urlparse(link)
                        if parsed.netloc == base_domain and link not in visited:
                            queue.append((link, depth + 1))

                    # Extract forms
                    forms = await page.eval_on_selector_all("form", """forms => forms.map(f => ({
                        action: f.action, method: f.method,
                        inputs: Array.from(f.elements).map(el => ({name: el.name, type: el.type}))
                    }))""")
                    ep.forms = forms
                    ep.input_vectors = [
                        {"url": current_url, "method": f.get("method", "GET"),
                         "param": inp.get("name", ""), "type": inp.get("type", "text")}
                        for f in forms for inp in f.get("inputs", []) if inp.get("name")
                    ]

                    # Extract JS files
                    js_srcs = await page.eval_on_selector_all(
                        "script[src]", "els => els.map(e => e.src)"
                    )
                    ep.js_files = [s for s in js_srcs if s]

                    endpoints.append(ep)
                    await page.close()
                except Exception as page_err:
                    logger.debug(f"Playwright page error {current_url}: {page_err}")

            await browser.close()
    except Exception as exc:
        logger.warning(f"Playwright crawl failed for {url}: {exc}: falling back to aiohttp")
        return await crawl_url(url, max_depth=max_depth, max_pages=max_pages,
                               evasion_headers=evasion_headers, auth_config=auth_config)

    return endpoints
