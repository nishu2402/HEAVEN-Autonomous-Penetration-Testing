"""HEAVEN — CMS (WordPress) security & hardening scanner.

Professional web-application assessments of WordPress sites routinely flag a
small, high-signal set of hardening failures that generic web detectors miss
because they are *WordPress-specific*:

* **Admin panel exposed to the Internet** — ``/wp-login.php`` / ``/wp-admin/``
  reachable without any network ACL, inviting brute-force and credential
  stuffing (CWE-307).
* **XML-RPC enabled** — ``/xmlrpc.php`` accepting remote procedure calls, and in
  particular the ``pingback.ping`` method, which is abused for SSRF, port
  scanning and brute-force amplification (CWE-918 / CWE-799).
* **Version disclosure** — the exact WordPress version leaked via the generator
  meta tag or ``/readme.html``, handing an attacker a precise CVE shortlist.
* **Username enumeration** — ``/wp-json/wp/v2/users`` or the ``?author=<id>``
  redirect leaking real login names for a targeted password attack (CWE-200).

Every check is **confirmation-based and strictly read-only**. WordPress is only
declared present on a positive fingerprint, and a finding is emitted only when
the server actually exhibits the weakness (a real login form is served, the
XML-RPC endpoint really lists ``pingback.ping``, a real username is returned).
The XML-RPC probe sends ``system.listMethods`` — it never issues an actual
``pingback.ping`` — so it cannot be used to make the target attack anyone.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover - exercised only in minimal installs
    HAS_AIOHTTP = False

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.cms")

_DEFAULT_TIMEOUT = 10.0
_UA = "Mozilla/5.0 (compatible; HEAVEN-CMS/1.0)"

# A WordPress login form always carries these markers; requiring the form fields
# (not just the word "login") keeps this from firing on an arbitrary /wp-login
# soft-404 page.
_WP_LOGIN_MARKERS = ("user_login", "wp-submit", "loginform")
# Fingerprints that positively identify WordPress. Any one strong signal is
# enough; we never guess from a bare path.
_WP_BODY_SIGNALS = ("/wp-content/", "/wp-includes/", "wp-json", "wp-embed")
_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_WP_VERSION_RE = re.compile(r"WordPress\s+([0-9]+(?:\.[0-9]+){1,2})", re.I)
# readme.html ships "<br /> Version 6.4.2" style markup.
_README_VERSION_RE = re.compile(r"[Vv]ersion\s+([0-9]+(?:\.[0-9]+){1,2})")


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, confidence: float, evidence: dict,
             cve_id: str = "") -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "cve_id": cve_id,
        "evidence": evidence,
        "source": "cms_scanner",
    }


async def _get(session: "aiohttp.ClientSession", url: str, *, method: str = "GET",
               data: str | None = None, headers: dict | None = None):
    """Single read-only request. Returns (status, headers, text) or None."""
    try:
        async with session.request(
            method, url, data=data, headers=headers, allow_redirects=False,
        ) as resp:
            body = ""
            ctype = resp.headers.get("Content-Type", "")
            # Only read a body for text-ish responses, capped to keep it cheap.
            if any(t in ctype.lower() for t in ("html", "xml", "json", "text")) or not ctype:
                body = (await resp.text(errors="replace"))[:200_000]
            return resp.status, dict(resp.headers), body
    except Exception as e:  # noqa: BLE001 - network hiccup / unreachable path
        logger.debug("CMS probe failed for %s: %s", url, e)
        return None


async def _fingerprint_wordpress(session, origin: str, home) -> tuple[bool, str, dict]:
    """Return (is_wordpress, version, evidence). ``home`` is the homepage
    (status, headers, body) tuple or None."""
    signals: list[str] = []
    version = ""
    headers: dict = {}
    body = ""
    if home:
        _status, headers, body = home
        low = body.lower()
        for sig in _WP_BODY_SIGNALS:
            if sig in low:
                signals.append(f"body:{sig}")
        # X-Pingback header points straight at xmlrpc.php on WordPress.
        xpb = headers.get("X-Pingback") or headers.get("x-pingback")
        if xpb and "xmlrpc" in xpb.lower():
            signals.append("header:X-Pingback")
        m = _GENERATOR_RE.search(body)
        if m and "wordpress" in m.group(1).lower():
            signals.append("meta:generator")
            vm = _WP_VERSION_RE.search(m.group(1))
            if vm:
                version = vm.group(1)
    # A definitive confirmation path: /wp-login.php serving the WP login form.
    login = await _get(session, origin + "/wp-login.php")
    login_form = bool(login and login[0] == 200
                      and sum(mk in login[2] for mk in _WP_LOGIN_MARKERS) >= 2)
    if login_form:
        signals.append("path:/wp-login.php")
    is_wp = bool(signals)
    ev = {"signals": signals}
    return is_wp, version, ev


async def _check_admin_exposed(session, origin: str) -> list[dict]:
    """Admin login panel reachable from the scanning position (no ACL)."""
    login = await _get(session, origin + "/wp-login.php")
    served_form = bool(login and login[0] == 200
                       and sum(mk in login[2] for mk in _WP_LOGIN_MARKERS) >= 2)
    # /wp-admin/ 30x-redirecting to wp-login is the other canonical signal.
    admin = await _get(session, origin + "/wp-admin/")
    admin_redirects = bool(admin and admin[0] in (301, 302, 303, 307, 308)
                           and "wp-login.php" in admin[1].get("Location", ""))
    if not (served_form or admin_redirects):
        return []
    return [_finding(
        origin + "/wp-login.php", "admin_panel_exposed", "high",
        "WordPress Admin Panel Exposed to the Internet",
        "The WordPress administrative login (/wp-login.php, /wp-admin) is "
        "reachable without any network restriction. An exposed admin panel is a "
        "direct target for brute-force and credential-stuffing attacks against "
        "privileged accounts, and materially raises the risk of full site "
        "compromise. Restrict it to trusted IPs / a VPN.",
        0.9,
        {"login_form_served": served_form, "wp_admin_redirects_to_login": admin_redirects,
         "url": origin + "/wp-login.php"},
        cve_id="")]


# A minimal, well-formed XML-RPC listMethods call. This is READ-ONLY — it only
# asks the server which methods it exposes; it never invokes pingback.ping.
_XMLRPC_LIST = (
    "<?xml version=\"1.0\"?><methodCall>"
    "<methodName>system.listMethods</methodName>"
    "<params></params></methodCall>"
)


async def _check_xmlrpc(session, origin: str) -> list[dict]:
    url = origin + "/xmlrpc.php"
    # GET on a live WP xmlrpc endpoint returns 405 with a tell-tale banner.
    probe = await _get(session, url)
    if not probe:
        return []
    status, _headers, body = probe
    banner = "XML-RPC server accepts POST requests only" in body
    if status not in (200, 405) and not banner:
        return []
    # Read-only listMethods POST to confirm it truly answers RPC + whether the
    # abused pingback method is present.
    post = await _get(session, url, method="POST", data=_XMLRPC_LIST,
                      headers={"Content-Type": "text/xml"})
    methods: list[str] = []
    answers_rpc = False
    if post and post[0] == 200 and "methodResponse" in post[2]:
        answers_rpc = True
        methods = re.findall(r"<string>([^<]+)</string>", post[2])
    if not (banner or answers_rpc):
        return []
    has_pingback = any("pingback.ping" in m for m in methods)
    if has_pingback:
        return [_finding(
            url, "xmlrpc_enabled", "high",
            "WordPress XML-RPC Enabled with pingback.ping",
            "The XML-RPC interface (/xmlrpc.php) is enabled and exposes the "
            "pingback.ping method. pingback.ping is routinely abused to make the "
            "server issue outbound requests (SSRF / internal port scanning), to "
            "amplify brute-force attempts via system.multicall, and for "
            "reflective denial-of-service. Disable XML-RPC, or at minimum remove "
            "the pingback methods.",
            0.9,
            {"answers_rpc": answers_rpc, "pingback_ping": True,
             "method_count": len(methods), "url": url})]
    # RPC is reachable but pingback not confirmed present — still worth a medium.
    return [_finding(
        url, "xmlrpc_enabled", "medium",
        "WordPress XML-RPC Endpoint Enabled",
        "The XML-RPC interface (/xmlrpc.php) is enabled and answering remote "
        "procedure calls. Even without pingback, XML-RPC broadens the attack "
        "surface (brute-force via system.multicall) and is best disabled unless "
        "actively required.",
        0.8,
        {"answers_rpc": answers_rpc, "pingback_ping": False,
         "method_count": len(methods), "url": url})]


async def _check_version_disclosure(session, origin: str, generator_version: str) -> list[dict]:
    version = generator_version
    source = "meta generator" if version else ""
    if not version:
        readme = await _get(session, origin + "/readme.html")
        if readme and readme[0] == 200 and "wordpress" in readme[2].lower():
            m = _README_VERSION_RE.search(readme[2])
            if m:
                version = m.group(1)
                source = "/readme.html"
    if not version:
        return []
    return [_finding(
        origin, "wordpress_version_disclosure", "low",
        f"WordPress Version Disclosed ({version})",
        "The exact WordPress version is exposed via "
        f"{source}. Publishing the precise version lets an attacker map the site "
        "straight to known CVEs for that release. Suppress the generator tag and "
        "remove /readme.html.",
        0.85,
        {"wordpress_version": version, "source": source})]


async def _check_user_enum(session, origin: str) -> list[dict]:
    users: list[str] = []
    # REST route — the modern, high-signal enumeration vector.
    api = await _get(session, origin + "/wp-json/wp/v2/users")
    if api and api[0] == 200 and "json" in api[1].get("Content-Type", "").lower():
        for m in re.finditer(r'"slug"\s*:\s*"([^"]+)"', api[2]):
            if m.group(1) not in users:
                users.append(m.group(1))
    # Fallback: ?author=1 → 30x to /author/<login>/
    if not users:
        a = await _get(session, origin + "/?author=1")
        if a and a[0] in (301, 302):
            loc = a[1].get("Location", "")
            mm = re.search(r"/author/([^/]+)/?", loc)
            if mm:
                users.append(mm.group(1))
    if not users:
        return []
    return [_finding(
        origin, "wordpress_user_enumeration", "low",
        f"WordPress Username Enumeration ({len(users)} account(s) exposed)",
        "Valid WordPress login names are disclosed via the REST users route "
        "(/wp-json/wp/v2/users) or the ?author= redirect. Knowing real usernames "
        "turns a password-guessing attack from two-factor (guess user + pass) "
        "into single-factor, and pairs directly with the exposed admin panel. "
        "Restrict the REST users endpoint and block author enumeration.",
        0.85,
        {"usernames": users[:25], "count": len(users)})]


async def scan_origin_cms(session, origin: str) -> list[dict]:
    home = await _get(session, origin + "/")
    is_wp, version, fp_ev = await _fingerprint_wordpress(session, origin, home)
    if not is_wp:
        return []
    logger.debug("WordPress fingerprinted at %s (%s)", origin, fp_ev.get("signals"))
    import asyncio
    results = await asyncio.gather(
        _check_admin_exposed(session, origin),
        _check_xmlrpc(session, origin),
        _check_version_disclosure(session, origin, version),
        _check_user_enum(session, origin),
        return_exceptions=True,
    )
    out: list[dict] = []
    for r in results:
        if isinstance(r, list):
            out.extend(r)
        elif isinstance(r, Exception):
            logger.debug("CMS subtask error on %s: %s", origin, r)
    return out


async def scan_cms(urls: list[str], timeout: float = _DEFAULT_TIMEOUT,
                   max_origins: int = 20) -> dict:
    """Run WordPress/CMS hardening checks over the origins behind ``urls``.

    Checks are host-level, so URLs are collapsed to unique ``scheme://host``
    origins (one probe set per site). Returns the standard scanner result shape.
    """
    if not HAS_AIOHTTP:
        return {"findings": [], "vulnerabilities": [], "total": 0,
                "error": "aiohttp not installed"}
    import asyncio

    origins: list[str] = []
    seen: set[str] = set()
    for u in urls:
        p = urlparse(u if "://" in u else "http://" + u)
        if not p.netloc:
            continue
        origin = f"{p.scheme}://{p.netloc}"
        if origin in seen:
            continue
        seen.add(origin)
        origins.append(origin)
        if len(origins) >= max_origins:
            break

    if not origins:
        return {"findings": [], "vulnerabilities": [], "total": 0}

    findings: list[dict] = []
    conn = aiohttp.TCPConnector(ssl=False, limit=15)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(connector=conn, timeout=client_timeout,
                                     headers={"User-Agent": _UA}) as session:
        sem = asyncio.Semaphore(6)

        async def _one(origin: str) -> None:
            async with sem:
                findings.extend(await scan_origin_cms(session, origin))

        await asyncio.gather(*[_one(o) for o in origins], return_exceptions=True)

    # Collapse duplicates (same origin+vuln_type) across overlapping URLs.
    seen_k: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for f in findings:
        k = (str(f.get("target", "")), str(f.get("vuln_type", "")))
        if k not in seen_k:
            seen_k.add(k)
            deduped.append(f)

    logger.info("CMS scan → %d finding(s) across %d origin(s)", len(deduped), len(origins))
    return {"findings": deduped, "vulnerabilities": deduped, "total": len(deduped)}
