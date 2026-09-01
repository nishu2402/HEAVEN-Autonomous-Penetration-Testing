"""HEAVEN — Web-tier technology fingerprinting from HTTP response headers.

Network reconnaissance (nmap) identifies the *listener* on a web port — usually
the front server ("Apache httpd 2.2.8") — but the application stack *behind* it
(the PHP/ASP.NET runtime, the OpenSSL the server links, the CMS) is disclosed in
HTTP response headers, not in the TCP banner. ``X-Powered-By: PHP/5.2.4``,
``Server: Apache/2.2.8 ... OpenSSL/0.9.8g PHP/5.2.4`` and ``X-AspNet-Version``
each name a concrete component **with a version**.

The EOL scanner (:mod:`heaven.vulnscan.eol_scanner`) and the CVE mapper
(:mod:`heaven.vulnscan.cve_mapper`) already know how to turn a
``(product, version)`` into a CWE-1104 end-of-life finding or a version-matched
CVE — but they read only nmap-derived ``open_ports[].product/version``. So an
end-of-life PHP disclosed purely in a header was previously invisible to both.

This module closes that gap without new dependencies or a new detection engine:
it extracts structured web components from response headers (**only when a real
version is present** — a bare ``Server: nginx`` is not actionable and is
ignored), synthesises host records from them, and feeds those through the two
*existing* pipelines. The resulting findings flow through the normal
validation → report → inventory → kill-chain → methodology path automatically.

Design principle (unchanged): **no fabrication.** A component is emitted only
when the header carries a concrete dotted version; an EOL/CVE finding fires only
when that real version is at/below a published cutoff, exactly as it would for an
nmap-detected service.
"""

from __future__ import annotations
from heaven.net.egress import client_session as _egress_cs  # egress-routed aiohttp

import re
from typing import Any, Awaitable, Callable, Mapping, Optional
from urllib.parse import urlparse

from heaven.utils.logger import get_logger

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:  # pragma: no cover
    _AIOHTTP = False

logger = get_logger("recon.web_tech")

# A "name/version" token, e.g. "PHP/5.2.4", "Apache/2.2.8", "OpenSSL/0.9.8g".
# At least major.minor is required — a bare "nginx" or "Apache/2" is too coarse
# to map to an EOL date or a CVE window, so it is deliberately not captured.
_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*?)/\s*v?(\d+(?:\.\d+){1,3})")
_BARE_VERSION_RE = re.compile(r"\s*v?(\d+(?:\.\d+)+)")
_GENERATOR_RE = re.compile(r"\s*([A-Za-z][\w.+-]*)\s+v?(\d+(?:\.\d+)*)")

# Header token name (lowercased) → (inventory label, detection product/service
# key). The detection key is what the EOL table and the inline CVE DB match on —
# "php", "openssl", "nginx" and "tomcat" are real keys there, so those components
# gain both EOL and CVE findings; "apache"/"iis" match the EOL table (and are
# handled by the CVE mapper's own server pipeline). Ambiguous sub-modules
# (mod_ssl, mod_perl, DAV, Passenger, Coyote) are intentionally omitted: their
# version tracks the parent and would only add noise.
_KNOWN_PRODUCTS: dict[str, tuple[str, str]] = {
    "apache":         ("Apache httpd", "apache"),
    "apache2":        ("Apache httpd", "apache"),
    "httpd":          ("Apache httpd", "apache"),
    "nginx":          ("nginx", "nginx"),
    "openssl":        ("OpenSSL", "openssl"),
    "php":            ("PHP", "php"),
    "php-fpm":        ("PHP", "php"),
    "microsoft-iis":  ("Microsoft IIS", "iis"),
    "iis":            ("Microsoft IIS", "iis"),
    "lighttpd":       ("lighttpd", "lighttpd"),
    "tomcat":         ("Apache Tomcat", "tomcat"),
    "jetty":          ("Eclipse Jetty", "jetty"),
    "openssh":        ("OpenSSH", "openssh"),
    "perl":           ("Perl", "perl"),
    "python":         ("Python", "python"),
    "drupal":         ("Drupal", "drupal"),
    "wordpress":      ("WordPress", "wordpress"),
    "joomla":         ("Joomla", "joomla"),
}

# Response headers that carry a versioned component. Server / X-Powered-By may
# each list several tokens; the ASP.NET version headers are a bare version.
_TOKENIZED_HEADERS = ("Server", "X-Powered-By")
_ASPNET_HEADERS = ("X-AspNet-Version", "X-AspNetMvc-Version")


def _ci_get(headers: Mapping[str, str]) -> Callable[[str], str]:
    """Return a case-insensitive getter over ``headers``.

    aiohttp's ``resp.headers`` is already case-insensitive (CIMultiDict); a plain
    ``dict`` (used by tests and by callers that captured headers themselves) is
    not, so fold to lowercase keys once and look up there.
    """
    try:
        # CIMultiDict / anything with case-insensitive .get already works.
        if hasattr(headers, "getone") or hasattr(headers, "getall"):
            return lambda k: str(headers.get(k, "") or "")  # type: ignore[union-attr]
    except Exception as e:  # noqa: BLE001 — fall back to the folded-dict getter
        logger.debug("case-insensitive header probe failed, folding: %s", e)
    folded = {str(k).lower(): str(v) for k, v in dict(headers).items()}
    return lambda k: folded.get(k.lower(), "") or ""


def _component(label: str, service: str, version: str, source_header: str,
               banner: str, url: str) -> dict:
    return {
        "product": label,
        "service": service,
        "version": version,
        "source_header": source_header,
        "banner": banner,
        "url": url,
    }


def extract_web_components(headers: Mapping[str, str], *, url: str = "") -> list[dict]:
    """Turn HTTP response headers into versioned web components.

    Returns a list of ``{product, service, version, source_header, banner, url}``
    dicts — one per distinct ``(service, version)`` disclosed. A component is
    emitted **only** when a concrete dotted version is present; header values
    without a version (``Server: nginx``) yield nothing, by design.
    """
    if not headers:
        return []
    get = _ci_get(headers)
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _add(label: str, service: str, version: str, hdr: str, banner: str) -> None:
        key = (service, version)
        if key in seen:
            return
        seen.add(key)
        out.append(_component(label, service, version, hdr, banner, url))

    # 1. Server / X-Powered-By — one or more "name/version" tokens.
    for hdr in _TOKENIZED_HEADERS:
        val = get(hdr)
        if not val:
            continue
        for name, ver in _TOKEN_RE.findall(val):
            info = _KNOWN_PRODUCTS.get(name.lower())
            if not info:
                continue
            label, service = info
            _add(label, service, ver, hdr, f"{name}/{ver}")

    # 2. ASP.NET version headers — the value *is* the version by definition.
    for hdr in _ASPNET_HEADERS:
        m = _BARE_VERSION_RE.match(get(hdr))
        if m:
            _add("ASP.NET", "asp.net", m.group(1), hdr, f"ASP.NET/{m.group(1)}")

    # 3. X-Generator — CMS/framework banners like "Drupal 7 (https://...)".
    gen = get("X-Generator")
    if gen:
        m = _GENERATOR_RE.match(gen)
        if m and m.group(2):
            name, ver = m.group(1), m.group(2)
            info = _KNOWN_PRODUCTS.get(name.lower())
            label, service = info if info else (name, name.lower())
            _add(label, service, ver, "X-Generator", f"{name}/{ver}")

    return out


def _origin_key(url: str) -> tuple[str, int, str]:
    """(host, port, scheme) for a URL, with default ports resolved."""
    p = urlparse(url if "://" in url else f"http://{url}")
    scheme = (p.scheme or "http").lower()
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    return host, port, scheme


async def _default_header_fetch(session: "aiohttp.ClientSession", url: str,
                                timeout: float) -> Optional[Mapping[str, str]]:
    """GET *url* and return its response headers; ``None`` on any error."""
    try:
        async with session.get(
            url, allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status >= 500:
                return None
            # Materialise into a plain dict so the value outlives the response.
            return {k: v for k, v in resp.headers.items()}
    except Exception as e:  # noqa: BLE001 - best-effort recon
        logger.debug("web-tech header fetch failed for %s: %s", url, e)
        return None


async def scan_web_tech(
    urls: list[str],
    *,
    session: Any = None,
    header_fetcher: Optional[Callable[[str], Awaitable[Optional[Mapping[str, str]]]]] = None,
    max_urls: int = 25,
    timeout: float = 8.0,
    live_feed: Any = None,
) -> dict:
    """Fingerprint web components across *urls* and raise EOL + CVE findings.

    For each distinct ``host:port`` origin, one request captures the response
    headers, from which versioned components are extracted. Those components are
    synthesised into host records and run through the **existing** EOL scanner
    (CWE-1104) and CVE mapper, so an end-of-life or CVE-bearing PHP/OpenSSL/etc.
    disclosed only in a header is now surfaced exactly like an nmap-detected one.

    Returns the standard scanner shape plus inventory context::

        {"findings":   [...EOL findings...],
         "vulnerabilities": [...CVE findings...],
         "web_components": [...flat component list...],
         "hosts":       [{ip, host, web_components:[...]}, ...],  # for inventory
         "total":       int}

    ``header_fetcher`` (an ``async url -> headers|None`` callable) is injectable
    so the extraction + pipeline wiring can be tested without a live server.
    """
    if not urls:
        return {"findings": [], "vulnerabilities": [], "web_components": [],
                "hosts": [], "total": 0}

    # Dedup by origin so http://h/ and http://h/page hit the host once.
    origins: dict[tuple[str, int, str], str] = {}
    for u in urls:
        if not isinstance(u, str) or not u.strip():
            continue
        key = _origin_key(u)
        if not key[0]:
            continue
        origins.setdefault(key, u if "://" in u else f"http://{u}")
        if len(origins) >= max_urls:
            break

    if not origins:
        return {"findings": [], "vulnerabilities": [], "web_components": [],
                "hosts": [], "total": 0}

    # Resolve the fetcher: injected (tests) or a self-managed aiohttp session.
    own_session = False
    fetch = header_fetcher
    if fetch is None:
        if not _AIOHTTP:
            logger.debug("web-tech scan skipped: aiohttp unavailable")
            return {"findings": [], "vulnerabilities": [], "web_components": [],
                    "hosts": [], "total": 0}
        if session is None:
            session = _egress_cs(
                connector=aiohttp.TCPConnector(ssl=False, limit=10),
                headers={"User-Agent": "HEAVEN-WebTech/1.0"},
            )
            own_session = True

        async def fetch(u: str) -> Optional[Mapping[str, str]]:  # type: ignore[misc]
            return await _default_header_fetch(session, u, timeout)

    comps_by_host: dict[str, list[dict]] = {}
    ports_by_host: dict[str, list[dict]] = {}
    flat_components: list[dict] = []
    edge_findings: list[dict] = []
    seen_edge: set[tuple[str, str]] = set()

    try:
        for (host, port, _scheme), url in origins.items():
            headers = await fetch(url)
            if not headers:
                continue
            # Zero-extra-request edge/VPN appliance KEV fingerprint from the root
            # response's headers/cookies (Citrix, Ivanti, FortiOS, PAN, Exchange, F5).
            try:
                from heaven.vulnscan.edge_kev import match_edge_kev_headers
                for ef in match_edge_kev_headers(headers, target=host):
                    fam = ef.get("evidence", {}).get("family", ef.get("vuln_type"))
                    if (host, fam) not in seen_edge:
                        seen_edge.add((host, fam))
                        edge_findings.append(ef)
            except Exception:
                logger.debug("edge-KEV header match failed", exc_info=True)
            comps = extract_web_components(headers, url=url)
            for c in comps:
                comps_by_host.setdefault(host, []).append(c)
                flat_components.append({**c, "host": host, "port": port})
                # A throwaway port record the detection pipelines understand.
                ports_by_host.setdefault(host, []).append({
                    "port": port, "protocol": "tcp", "state": "open",
                    "service": c["service"], "product": c["service"],
                    "version": c["version"], "banner": "", "source": "web",
                })
    finally:
        if own_session and session is not None:
            await session.close()

    if not flat_components:
        # No versioned component, but an edge appliance may still have been
        # fingerprinted from its cookies/headers — keep those.
        return {"findings": edge_findings, "vulnerabilities": [],
                "web_components": [], "hosts": [], "total": len(edge_findings)}

    # Detection host records (WITH synthetic ports) drive EOL + CVE; they are
    # *not* returned under "hosts" so the orchestrator's separate CVE-mapping
    # phase does not re-map them (and inventory does not gain phantom ports).
    detect_hosts = [{"host": h, "ip": h, "open_ports": ports}
                    for h, ports in ports_by_host.items()]

    findings: list[dict] = []
    vulnerabilities: list[dict] = []

    try:
        from heaven.vulnscan.eol_scanner import scan_eol_from_net
        eol = await scan_eol_from_net({"hosts": detect_hosts})
        findings = list(eol.get("findings", []))
    except Exception as e:  # noqa: BLE001
        logger.debug("web-tech EOL sub-scan failed: %s", e)

    try:
        from heaven.vulnscan.cve_mapper import map_vulnerabilities
        vulnerabilities = await map_vulnerabilities(detect_hosts, live_feed=live_feed)
    except Exception as e:  # noqa: BLE001
        logger.debug("web-tech CVE sub-scan failed: %s", e)

    # Stamp provenance so the report reads honestly: the *version* that drove
    # these findings was disclosed in an HTTP response header. This is a distinct
    # axis from the CVE mapper's own ``source`` (e.g. ``inline_db`` — the origin
    # of the CVE *match*), so we never clobber that: detection_source records how
    # the version was observed, source records how the CVE was matched.
    for f in findings:
        f.setdefault("evidence", {})
        if isinstance(f["evidence"], dict):
            f["evidence"].setdefault("detection_source", "http_response_header")
    for v in vulnerabilities:
        v.setdefault("detection_source", "http_response_header")

    # Inventory host records carry ONLY the human-readable component list (no
    # ports) so normalize_assets merges them into the real host without colliding
    # with its nmap-proven port rows.
    inv_hosts = [{"host": h, "ip": h, "web_components": comps}
                 for h, comps in comps_by_host.items()]

    logger.info("Web-tech scan → %d component(s), %d EOL + %d CVE finding(s) "
                "across %d host(s)", len(flat_components), len(findings),
                len(vulnerabilities), len(comps_by_host))

    findings = edge_findings + findings
    return {
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "web_components": flat_components,
        "hosts": inv_hosts,
        "total": len(findings) + len(vulnerabilities),
    }
