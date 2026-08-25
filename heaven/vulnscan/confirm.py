"""
HEAVEN — Active Confirmation dispatcher (one entry point for *every* finding).

The web "Active Confirmation" panel and the CLI both call :func:`confirm_finding`
to answer a single question honestly for **any** finding: *can we prove this is
real, right now, against the live target — without doing anything destructive?*

Design goals
------------
1. **Genuine.** Where a safe, read-only proof exists for the finding's class we
   actually run it against the target and report the observable we saw:

   * **Injection** (SQLi / command-injection / SSRF / XSS) → the exploit-proof
     dispatcher (:mod:`heaven.vulnscan.exploit_proof`) — a real canary/callback.
   * **Known-CVE behaviour** (Apache path-traversal, Shellshock, …) → the safe
     read-only probe registry (:mod:`heaven.vulnscan.active_verifier`).
   * **HTTP-observable misconfig** (missing security headers, directory listing,
     an exposed file, permissive CORS, an open redirect, an exposed management
     endpoint) → one read-only GET, and we re-check the exact condition in the
     fresh response.
   * **TLS/SSL** (expired / self-signed cert, weak protocol, …) → a fresh TLS
     handshake via the project's SSL scanner; confirmed only if the *same* issue
     reappears live.
   * **Exposed network service / port** (databases, telnet, RDP, docker socket,
     …) → a plain TCP connect that proves the port is reachable now.

2. **Honest.** A finding class with no safe automated proof is **never** reported
   as "not proven" as if a probe had run and failed. It returns
   ``status="not_applicable"`` with a specific reason and a manual next step —
   distinct from ``unconfirmed`` (a probe ran but could not reproduce the issue,
   e.g. it was patched or is unreachable from here). A finding already Confirmed
   by its original evidence returns ``already_confirmed`` when no live re-check
   applies. Nothing is ever fabricated.

3. **Safe.** Every probe is read-only and bounded (short timeouts, a couple of
   requests). Traffic is only sent when ``authorized=True`` (the web endpoint
   passes this because the operator holds the ``vuln.validate`` permission; the
   CLI requires ``--i-have-authorization``). Without it we return
   ``status="unauthorized"`` and touch nothing.

Return contract (:class:`ConfirmResult`)
----------------------------------------
``status`` — ``confirmed`` | ``already_confirmed`` | ``unconfirmed`` |
``not_applicable`` | ``unauthorized`` | ``unavailable``.
``proved`` — True only when a fresh probe produced an unambiguous observable.
Plus ``method`` / ``technique`` / ``summary`` / ``detail`` / ``evidence``.

On a fresh proof the finding is mutated in place (``validated=True``,
``confidence`` up to 0.99, ``evidence.validation_result="confirmed"``, and the
record appended to ``evidence.active_confirmation``) so a persisted-and-reloaded
finding still reads Confirmed via :func:`heaven.utils.cvss.is_confirmed_finding`.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:  # pragma: no cover - optional dependency
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.cvss import is_confirmed_finding
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.confirm")


# ═══════════════════════════════════════════════════════════════════════════
# RESULT
# ═══════════════════════════════════════════════════════════════════════════

# Status vocabulary — kept as constants so callers/tests never typo a literal.
CONFIRMED = "confirmed"                # a fresh probe proved it now
ALREADY_CONFIRMED = "already_confirmed"  # original evidence already proves it
UNCONFIRMED = "unconfirmed"            # a probe ran but could not reproduce it
NOT_APPLICABLE = "not_applicable"      # no safe automated proof for this class
UNAUTHORIZED = "unauthorized"          # operator has not authorized active probes
UNAVAILABLE = "unavailable"            # a dependency/target detail is missing


@dataclass
class ConfirmResult:
    status: str
    proved: bool = False
    method: str = "none"
    technique: str = ""
    summary: str = ""
    detail: str = ""
    reprobed: bool = False
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "proved": self.proved,
            "method": self.method,
            "technique": self.technique,
            "summary": self.summary,
            "detail": self.detail,
            "reprobed": self.reprobed,
            "evidence": self.evidence,
        }


# ═══════════════════════════════════════════════════════════════════════════
# FINDING SHAPE HELPERS
# ═══════════════════════════════════════════════════════════════════════════


def _ev(finding: dict[str, Any]) -> dict[str, Any]:
    ev = finding.get("evidence")
    return ev if isinstance(ev, dict) else {}


def _vt(finding: dict[str, Any]) -> str:
    return str(finding.get("vuln_type") or finding.get("type") or "").strip().lower()


def _finding_url(finding: dict[str, Any]) -> str:
    """The full HTTP(S) URL to probe, if this finding is web-shaped."""
    ev = _ev(finding)
    for cand in (finding.get("target"), ev.get("url"), ev.get("endpoint"), finding.get("url")):
        s = str(cand or "").strip()
        if s.startswith(("http://", "https://")):
            return s.rstrip()
    return ""


def _host_port(finding: dict[str, Any]) -> tuple[str, int]:
    """Best-effort ``(host, port)`` for TCP/TLS probes.

    Reads an explicit ``host``/``port`` (CVE-mapper findings carry these in
    evidence), else parses ``target`` as a URL or ``host:port`` string.
    """
    ev = _ev(finding)
    host = str(finding.get("host") or ev.get("host") or "").strip()
    port_raw = finding.get("port") or ev.get("port")
    try:
        port = int(port_raw) if port_raw not in (None, "", 0) else 0
    except (TypeError, ValueError):
        port = 0

    target = str(finding.get("target") or "").strip()
    if not host and target:
        if target.startswith(("http://", "https://")):
            p = urlparse(target)
            host = p.hostname or ""
            if not port:
                port = p.port or (443 if p.scheme == "https" else 80)
        elif ":" in target and "/" not in target:
            h, _, pr = target.rpartition(":")
            host = h or target
            try:
                port = port or int(pr)
            except ValueError:
                pass
        else:
            host = target
    return host, port


def _finding_cve(finding: dict[str, Any]) -> str:
    ev = _ev(finding)
    return str(finding.get("cve") or finding.get("cve_id") or ev.get("cve") or "").strip().upper()


# ═══════════════════════════════════════════════════════════════════════════
# CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════

# Injection classes the exploit-proof dispatcher can actually fire a canary for.
_EXPLOIT_TOKENS = ("sqli", "sql_injection", "cmdi", "command_injection", "rce",
                   "ssrf", "xss")

# Standard security headers and the keywords that name them in a finding.
_SECURITY_HEADERS: dict[str, tuple[str, ...]] = {
    "strict-transport-security": ("hsts", "strict-transport", "transport-security"),
    "content-security-policy": ("content-security", "csp"),
    "x-frame-options": ("x-frame", "frame-options", "clickjack"),
    "x-content-type-options": ("x-content-type", "content-type-options", "nosniff", "mime-sniff"),
    "referrer-policy": ("referrer-policy", "referrer"),
    "permissions-policy": ("permissions-policy", "feature-policy"),
}


def classify(finding: dict[str, Any]) -> str:
    """Route a finding to a confirmation family (see module docstring)."""
    vt = _vt(finding)
    title = str(finding.get("title") or "").lower()
    blob = f"{vt} {title}"
    url = _finding_url(finding)
    host, port = _host_port(finding)

    # 1. Injection with a real exploit prover.
    if any(tok in vt for tok in _EXPLOIT_TOKENS):
        return "exploit"

    # 2. Known-CVE safe behavioural probe.
    from heaven.vulnscan import active_verifier
    if _finding_cve(finding) in active_verifier._PROBES:
        return "cve_probe"

    # 3. TLS/SSL — a cert/protocol issue on a service we can re-handshake.
    _TLS = ("cert_expired", "cert_expiring", "self_signed", "weak_cipher",
            "tls10", "tls11", "no_forward_secrecy", "forward_secrecy",
            "sha1_signature", "heartbleed", "poodle", "beast", "freak",
            "logjam", "drown", "sweet32", "ssl", "starttls")
    if any(tok in vt for tok in _TLS) and host:
        return "tls"

    # 4. HTTP-observable classes (need a live URL to GET).
    if url:
        if "cors" in vt:
            return "http_cors"
        if "redirect" in vt:
            return "http_redirect"
        if "directory_listing" in vt or "dir_listing" in vt or "autoindex" in blob:
            return "http_dirlisting"
        if any(k in vt for k in ("header", "hsts", "clickjack")) or any(
            kw in blob for grp in _SECURITY_HEADERS.values() for kw in grp
        ):
            return "http_header"
        if any(k in vt for k in ("sensitive_file", "secret_exposure", "exposed",
                                 "backup", "info_disclosure", "git", "env_file",
                                 "config_exposure", "actuator", "introspection",
                                 "swagger", "kubelet", "etcd", "cadvisor",
                                 "registry", "docker_api")):
            return "http_endpoint"

    # 5. Exposed network service / port — a plain TCP reachability proof.
    if host and port and any(
        k in vt for k in ("service", "database", "db_exposed", "exposed",
                          "telnet", "snmp", "ftp", "rdp", "smb", "socket",
                          "port", "hardening", "wireless_mgmt", "ldap", "redis",
                          "memcached", "mongo", "elastic")
    ):
        return "tcp"

    # 6. No safe automated proof for this class.
    return "manual"


# ═══════════════════════════════════════════════════════════════════════════
# LOW-LEVEL SAFE PROBES
# ═══════════════════════════════════════════════════════════════════════════


async def _http_get(session: Any, url: str, *, headers: Optional[dict] = None,
                    allow_redirects: bool = True, timeout: float = 8.0
                    ) -> tuple[int, dict[str, str], str]:
    """Read-only GET → ``(status, headers, body)``; never raises."""
    try:
        async with session.get(
            url, headers=headers or {}, allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            body = await resp.text(errors="replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, body
    except Exception as exc:  # noqa: BLE001 — a failed probe is not fatal
        logger.debug("confirm GET failed for %s: %s", url, exc)
        return 0, {}, ""


async def _http_get_final(session: Any, url: str, *, timeout: float = 8.0
                          ) -> tuple[int, dict[str, str], str, str]:
    """Read-only GET following redirects → ``(status, headers, body, final_url)``.

    Unlike :func:`_http_get` this also reports the URL the request *finally*
    landed on, so a catch-all that redirects an unknown/sensitive path to the
    homepage can be told apart from the resource genuinely being served."""
    try:
        async with session.get(
            url, allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            body = await resp.text(errors="replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, body, str(resp.url)
    except Exception as exc:  # noqa: BLE001 — a failed probe is not fatal
        logger.debug("confirm GET(final) failed for %s: %s", url, exc)
        return 0, {}, "", ""


def _norm_body(body: str) -> str:
    """Whitespace-collapsed, length-bounded body for soft-404 equality checks."""
    import re as _re
    return _re.sub(r"\s+", " ", body or "").strip()[:3000]


async def _tcp_reachable(host: str, port: int, timeout: float = 6.0) -> bool:
    """True if a TCP connection to ``host:port`` succeeds (immediately closed)."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 — connection already proven; close is best-effort
            logger.debug("confirm TCP close failed for %s:%s", host, port, exc_info=True)
        return True
    except Exception as exc:  # noqa: BLE001 — closed/filtered port is a valid answer
        logger.debug("confirm TCP connect failed for %s:%s: %s", host, port, exc)
        return False


def _new_session() -> Any:
    from heaven.recon.auth_session import aiohttp_session_kwargs
    return aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=10),
        **aiohttp_session_kwargs(),
    )


# ═══════════════════════════════════════════════════════════════════════════
# FAMILY CONFIRMERS  (each strictly read-only)
# ═══════════════════════════════════════════════════════════════════════════


def _which_header(finding: dict[str, Any]) -> Optional[str]:
    """The specific security header a finding is about, if identifiable."""
    blob = f"{_vt(finding)} {str(finding.get('title') or '').lower()} " \
           f"{str(_ev(finding).get('header') or '').lower()}"
    for header, keywords in _SECURITY_HEADERS.items():
        if any(kw in blob for kw in keywords):
            return header
    return None


async def _confirm_http_header(session: Any, finding: dict[str, Any]) -> ConfirmResult:
    url = _finding_url(finding)
    status, hdrs, _ = await _http_get(session, url)
    if status == 0:
        return ConfirmResult(UNCONFIRMED, method="http-recheck", reprobed=True,
                             summary="Target did not respond to the re-check request.",
                             detail=f"GET {url} returned no response — it may be down "
                                    "or unreachable from the scan origin right now.")
    header = _which_header(finding)
    if header:
        present = header in hdrs
        if header == "strict-transport-security" and "short" in _vt(finding) and present:
            # hsts_short_maxage: header present but the max-age is too small.
            max_age = _parse_max_age(hdrs.get(header, ""))
            weak = max_age < 31536000
            return ConfirmResult(
                CONFIRMED if weak else UNCONFIRMED, proved=weak,
                method="http-recheck", technique="header_recheck", reprobed=True,
                summary=(f"HSTS max-age is {max_age}s (< 1 year) on the live response."
                         if weak else "HSTS now advertises a max-age ≥ 1 year."),
                detail=f"GET {url} → Strict-Transport-Security: {hdrs.get(header)!r}",
                evidence=[{"request": f"GET {url}", "header": header,
                           "observed": hdrs.get(header, ""), "max_age": max_age}])
        proved = not present
        return ConfirmResult(
            CONFIRMED if proved else UNCONFIRMED, proved=proved,
            method="http-recheck", technique="header_recheck", reprobed=True,
            summary=(f"The '{header}' header is absent on the live response — confirmed."
                     if proved else f"The '{header}' header is present now — could not confirm."),
            detail=(f"GET {url} → no {header} header." if proved
                    else f"GET {url} → {header}: {hdrs.get(header)!r} (may have been remediated)."),
            evidence=[{"request": f"GET {url}", "header": header,
                       "present": present, "value": hdrs.get(header, "")}])
    # Generic security-headers finding: confirm if any standard header is missing.
    missing = [h for h in _SECURITY_HEADERS if h not in hdrs]
    proved = bool(missing)
    return ConfirmResult(
        CONFIRMED if proved else UNCONFIRMED, proved=proved,
        method="http-recheck", technique="header_recheck", reprobed=True,
        summary=(f"{len(missing)} standard security header(s) missing on the live response."
                 if proved else "All standard security headers are present now."),
        detail=("Missing: " + ", ".join(missing)) if proved else f"GET {url} carried every standard header.",
        evidence=[{"request": f"GET {url}", "missing_headers": missing}])


def _parse_max_age(hsts_value: str) -> int:
    for part in hsts_value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip())
            except ValueError:
                return 0
    return 0


async def _confirm_http_dirlisting(session: Any, finding: dict[str, Any]) -> ConfirmResult:
    url = _finding_url(finding)
    status, _, body = await _http_get(session, url)
    low = body.lower()
    proved = status == 200 and ("index of /" in low or "<title>index of" in low
                                or "directory listing for" in low)
    return ConfirmResult(
        CONFIRMED if proved else UNCONFIRMED, proved=proved,
        method="http-recheck", technique="directory_listing_recheck", reprobed=True,
        summary=("Directory index served on the live response — confirmed."
                 if proved else "No directory index in the live response."),
        detail=f"GET {url} → HTTP {status}"
               + (" with an autoindex page." if proved else " (no listing signature)."),
        evidence=[{"request": f"GET {url}", "response_status": status,
                   "response_excerpt": body[:200]}])


# File paths whose bodies carry an unmistakable signature we can require.
_FILE_SIGNATURES: dict[str, tuple[str, ...]] = {
    ".git/config": ("[core]", "repositoryformatversion"),
    ".env": ("=",),
    "wp-config": ("DB_PASSWORD", "DB_NAME"),
    ".htpasswd": (":$",),
    "id_rsa": ("PRIVATE KEY",),
}

# Management / DB-admin tools whose exposed page carries an unmistakable body
# signature. If a probed path *names* one of these but the served body isn't
# actually that tool (e.g. a catch-all served the site homepage instead), the
# tool is NOT exposed — this kills the classic "/phpmyadmin/ → homepage" false
# positive. Keyed by a path fragment; matched case-insensitively.
_TOOL_SIGNATURES: dict[str, tuple[str, ...]] = {
    "phpmyadmin": ("phpmyadmin", "pma_", "set_session"),
    "adminer": ("adminer", "adminer.org"),
    "phpinfo": ("phpinfo()", "php version"),
}


def _required_signature(url: str) -> tuple[str, tuple[str, ...]]:
    """The content signature a path *must* exhibit to count as exposed, if any.

    Returns ``(label, markers)`` for a path that names a known file/tool whose
    genuine body is unmistakable, else ``("", ())`` — for which we fall back to
    the soft-404 / redirect checks instead of a body signature."""
    low = url.lower()
    for frag, sigs in _TOOL_SIGNATURES.items():
        if frag in low:
            return frag, sigs
    for frag, sigs in _FILE_SIGNATURES.items():
        if frag in low:
            return frag, sigs
    return "", ()


async def _confirm_http_endpoint(session: Any, finding: dict[str, Any]) -> ConfirmResult:
    """Exposed file or management endpoint: prove it is genuinely served now.

    Read-only, false-positive-safe. A finding is confirmed only when the live
    resource is truly served at its own URL — not when a catch-all / soft-404
    redirects the probe to the site homepage (the common SPA/framework default),
    and not when a path that names a specific tool serves something that isn't it.
    """
    from urllib.parse import urljoin, urlparse
    url = _finding_url(finding)
    status, hdrs, body, final_url = await _http_get_final(session, url)
    if status == 0:
        return ConfirmResult(
            UNCONFIRMED, method="http-recheck", technique="endpoint_recheck", reprobed=True,
            summary="Target did not respond to the re-check request.",
            detail=f"GET {url} returned no response — it may be down or unreachable now.",
            evidence=[{"request": f"GET {url}", "response_status": status}])
    if status != 200:
        return ConfirmResult(
            UNCONFIRMED, method="http-recheck", technique="endpoint_recheck", reprobed=True,
            summary=f"Endpoint returned HTTP {status} on the live re-check (not 200).",
            detail=f"GET {url} → HTTP {status} — the resource is not being served now "
                   "(access may have been restricted, or it never was this host).",
            evidence=[{"request": f"GET {url}", "response_status": status}])

    ctype = hdrs.get("content-type", "")
    req_p, fin_p = urlparse(url), urlparse(final_url or url)
    req_path = (req_p.path or "/").rstrip("/") or "/"
    fin_path = (fin_p.path or "/").rstrip("/") or "/"
    same_host = (fin_p.hostname or "").lower() == (req_p.hostname or "").lower()
    landed_on_root = fin_path in ("", "/")
    redirected_home = (not same_host or fin_path != req_path) and landed_on_root

    # Soft-404 calibration: a sibling path that cannot exist. If the endpoint's
    # body is identical to a known-nonexistent one, the server is a catch-all and
    # nothing is actually exposed at this path.
    import secrets as _secrets
    junk_url = urljoin(url if url.endswith("/") else url + "/",
                       f"heaven-{_secrets.token_hex(6)}.nope")
    _js, _jh, junk_body, _jf = await _http_get_final(session, junk_url)
    same_as_junk = bool(junk_body) and _norm_body(junk_body) == _norm_body(body)

    # Required content signature for a named file/tool.
    label, sigs = _required_signature(url)
    low_body = body.lower()
    signature_hit = label if (sigs and any(s.lower() in low_body for s in sigs)) else ""
    signature_missing = bool(sigs) and not signature_hit

    tech = "file_exposure_recheck" if label else "endpoint_recheck"
    ev = [{"request": f"GET {url}", "response_status": status,
           "final_url": final_url, "bytes": len(body),
           "signature": signature_hit, "response_excerpt": body[:200]}]

    # ── Disqualifiers (any one → not exposed) ─────────────────────────────────
    if same_as_junk:
        return ConfirmResult(
            UNCONFIRMED, method="http-recheck", technique=tech, reprobed=True,
            summary="Response is identical to a known-nonexistent path — the server "
                    "is a catch-all (soft-404); nothing is exposed here.",
            detail=f"GET {url} → HTTP 200 but its body matches a random nonexistent "
                   f"sibling path, so this is the catch-all page, not a real resource.",
            evidence=ev)
    if redirected_home:
        return ConfirmResult(
            UNCONFIRMED, method="http-recheck", technique=tech, reprobed=True,
            summary="The probe was redirected to the site homepage — the resource is "
                    "not exposed at its own URL.",
            detail=f"GET {url} → HTTP 200 only after redirecting to {final_url} "
                   "(the homepage / catch-all), so the requested resource is not served.",
            evidence=ev)
    if signature_missing:
        return ConfirmResult(
            UNCONFIRMED, method="http-recheck", technique=tech, reprobed=True,
            summary=f"Served a 200 but the body is not {label} (no signature match) — "
                    "this looks like a catch-all page, not the tool/file itself.",
            detail=f"GET {url} → HTTP 200, {len(body)} bytes, but none of the expected "
                   f"{label} content markers are present, so it is not actually exposed.",
            evidence=ev)
    # An error/login page masquerading as 200 — but a *matched* tool/file
    # signature means the body genuinely IS the artefact (a real phpMyAdmin login
    # page contains "login"), so the signature wins over this generic heuristic.
    looks_like_html_error = (not signature_hit
                             and "<html" in body[:400].lower()
                             and any(w in low_body[:2000] for w in
                                     ("not found", "404", "sign in", "login")))
    if looks_like_html_error:
        return ConfirmResult(
            UNCONFIRMED, method="http-recheck", technique=tech, reprobed=True,
            summary="Endpoint returned 200 but the body looks like an error/login page.",
            detail=f"GET {url} → HTTP 200, {len(body)} bytes, content-type {ctype or 'unknown'}.",
            evidence=ev)

    return ConfirmResult(
        CONFIRMED, proved=True,
        method="http-recheck", technique=tech, reprobed=True,
        summary=("Resource is served (HTTP 200"
                 + (f", matched {signature_hit} signature" if signature_hit else "")
                 + ") — confirmed."),
        detail=f"GET {url} → HTTP 200, {len(body)} bytes, content-type {ctype or 'unknown'}.",
        evidence=ev)


async def _confirm_http_cors(session: Any, finding: dict[str, Any]) -> ConfirmResult:
    url = _finding_url(finding)
    probe_origin = "https://heaven-confirm.example"
    status, hdrs, _ = await _http_get(session, url, headers={"Origin": probe_origin})
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "").lower() == "true"
    reflected = acao == probe_origin
    wildcard = acao == "*"
    proved = reflected or (wildcard and acac)
    if reflected and acac:
        summary = "Server reflects an arbitrary Origin AND allows credentials — confirmed."
    elif reflected:
        summary = "Server reflects an arbitrary Origin in ACAO — confirmed."
    elif wildcard and acac:
        summary = "ACAO '*' combined with credentials — confirmed."
    else:
        summary = "The live response did not reflect the probe Origin — could not confirm."
    return ConfirmResult(
        CONFIRMED if proved else UNCONFIRMED, proved=proved,
        method="http-recheck", technique="cors_recheck", reprobed=True,
        summary=summary,
        detail=f"GET {url} with Origin: {probe_origin} → "
               f"Access-Control-Allow-Origin: {acao!r}, "
               f"Access-Control-Allow-Credentials: {acac}",
        evidence=[{"request": f"GET {url}", "sent_origin": probe_origin,
                   "acao": acao, "acac": acac, "status": status}])


async def _confirm_http_redirect(session: Any, finding: dict[str, Any]) -> ConfirmResult:
    url = _finding_url(finding)
    status, hdrs, _ = await _http_get(session, url, allow_redirects=False)
    location = hdrs.get("location", "")
    off_site = False
    if location:
        loc = urlparse(location)
        src = urlparse(url)
        # Off-site if the Location points at an absolute URL on a different host.
        off_site = bool(loc.netloc) and loc.netloc != src.netloc
    proved = 300 <= status < 400 and off_site
    return ConfirmResult(
        CONFIRMED if proved else UNCONFIRMED, proved=proved,
        method="http-recheck", technique="open_redirect_recheck", reprobed=True,
        summary=("Live response 3xx-redirects off-site — confirmed."
                 if proved else "No off-site redirect observed on the live response."),
        detail=f"GET {url} → HTTP {status}, Location: {location!r}",
        evidence=[{"request": f"GET {url}", "response_status": status,
                   "location": location, "off_site": off_site}])


async def _confirm_tls(finding: dict[str, Any]) -> ConfirmResult:
    """Re-run the project's SSL scanner and confirm the same issue reappears."""
    host, port = _host_port(finding)
    if not host:
        return ConfirmResult(UNAVAILABLE, method="tls-recheck",
                             summary="No host to run a TLS handshake against.",
                             detail="This finding has no resolvable host:port for a TLS re-check.")
    if not port or port in (80, 8080):
        port = 443
    from heaven.vulnscan.ssl_scanner import scan_ssl
    try:
        fresh = await scan_ssl(host, port)
    except Exception as exc:  # noqa: BLE001
        logger.debug("confirm TLS scan failed for %s:%s: %s", host, port, exc)
        return ConfirmResult(UNCONFIRMED, method="tls-recheck", reprobed=True,
                             summary="TLS handshake failed on the re-check.",
                             detail=f"Could not complete a TLS handshake with {host}:{port} — "
                                    "the service may be down or no longer speaks TLS here.")
    fresh_types = {str(f.get("vuln_type") or "").lower() for f in fresh.get("findings", [])}
    vt = _vt(finding)
    proved = vt in fresh_types
    return ConfirmResult(
        CONFIRMED if proved else UNCONFIRMED, proved=proved,
        method="tls-recheck", technique="tls_rehandshake", reprobed=True,
        summary=(f"A fresh TLS handshake with {host}:{port} still shows '{vt}' — confirmed."
                 if proved else
                 f"A fresh TLS handshake with {host}:{port} no longer shows '{vt}'."),
        detail="Re-ran the SSL/TLS scanner against the live service. Live issues: "
               + (", ".join(sorted(fresh_types)) or "none"),
        evidence=[{"host": host, "port": port, "live_tls_issues": sorted(fresh_types)}])


async def _confirm_tcp(finding: dict[str, Any]) -> ConfirmResult:
    host, port = _host_port(finding)
    if not host or not port:
        return ConfirmResult(UNAVAILABLE, method="tcp-connect",
                             summary="No host:port to test for reachability.",
                             detail="This exposed-service finding has no resolvable host:port.")
    reachable = await _tcp_reachable(host, port)
    return ConfirmResult(
        CONFIRMED if reachable else UNCONFIRMED, proved=reachable,
        method="tcp-connect", technique="tcp_connect", reprobed=True,
        summary=(f"TCP connect to {host}:{port} succeeded — the service is reachable, confirmed."
                 if reachable else
                 f"TCP connect to {host}:{port} failed — not reachable from the scan origin now."),
        detail=f"Opened a TCP connection to {host}:{port} and closed it immediately "
               "(no data sent). A successful connect proves the port is exposed.",
        evidence=[{"host": host, "port": port, "tcp_connect": reachable}])


# ═══════════════════════════════════════════════════════════════════════════
# MANUAL-GUIDANCE FALLBACK
# ═══════════════════════════════════════════════════════════════════════════

# Short, honest "how would a human confirm this?" note per finding family, so a
# not_applicable result is still actionable rather than a dead end.
_MANUAL_HINTS: dict[str, str] = {
    "spf": "Confirm with `dig TXT <domain>` — the absence of a v=spf1 record is itself the proof.",
    "dmarc": "Confirm with `dig TXT _dmarc.<domain>` — a missing/relaxed record is directly observable.",
    "dkim": "Confirm the DKIM selector record via `dig TXT <selector>._domainkey.<domain>`.",
    "dnssec": "Confirm with `dig +dnssec <domain>` and check for RRSIG/DS records.",
    "mta_sts": "Confirm by fetching https://mta-sts.<domain>/.well-known/mta-sts.txt.",
    "smtp": "Confirm by connecting to the MX with `openssl s_client -starttls smtp` / an SMTP transcript.",
    "jwt": "Confirm by decoding a captured token and testing the alg/secret in a controlled request.",
    "race_condition": "Confirm by replaying the request concurrently (e.g. Turbo Intruder) in a test account.",
    "request_smuggling": "Confirm with a differential CL.TE/TE.CL probe pair against a staging copy.",
    "mass_assignment": "Confirm by submitting an extra privileged field with a low-privilege test account.",
    "no_rate_limit": "Confirm by measuring accepted request rate against the documented limit.",
    "subdomain_takeover": "Confirm by checking the dangling CNAME target and claiming it in a controlled account.",
    "default_credentials": "Confirm by an authorized login attempt with the documented default credentials.",
    "vulnerable_dependency": "Already evidence-backed: the dependency+version match is the proof (SCA).",
    "idor": "Confirm by requesting another object id with a second authorized test account.",
    "broken_access_control": "Confirm by replaying a privileged request as a low-privilege test account.",
    "k8s": "Confirm with an authorized `kubectl`/API call from the documented network position.",
    "azure": "Confirm via an authorized Microsoft Graph / az call against the tenant.",
    "adfs": "Confirm by fetching the federation metadata endpoint and checking the advertised methods.",
}


def _manual_hint(finding: dict[str, Any]) -> str:
    vt = _vt(finding)
    for key, hint in _MANUAL_HINTS.items():
        if key in vt:
            return hint
    return ("Verify manually against the target with a controlled, authorized test "
            "that reproduces the reported condition, then attach the transcript as evidence.")


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════


def _record(finding: dict[str, Any], result: ConfirmResult) -> None:
    """Attach the confirmation record to the finding and promote on a fresh proof."""
    ev = finding.get("evidence")
    if not isinstance(ev, dict):
        ev = {}
    history = ev.setdefault("active_confirmation", [])
    if isinstance(history, list):
        history.append({
            "at": round(time.time()),
            "status": result.status,
            "proved": result.proved,
            "method": result.method,
            "technique": result.technique,
            "summary": result.summary,
        })
    if result.proved:
        # The live probe IS ground truth — promote to Confirmed and stamp the
        # evidence so a persisted-then-reloaded finding still reads Confirmed.
        finding["validated"] = True
        finding["proved"] = True
        finding["confidence"] = max(float(finding.get("confidence") or 0.0), 0.99)
        ev["validation_result"] = "confirmed"
    finding["evidence"] = ev


async def confirm_finding(finding: dict[str, Any], *, authorized: bool = False,
                          external_callback_url: str = "") -> dict[str, Any]:
    """Actively confirm a single finding. See module docstring for the contract.

    Returns a dict: ``{**ConfirmResult.to_dict(), "family": <str>,
    "finding": <mutated finding>}``. Never raises.
    """
    family = classify(finding)

    # ── Injection → real exploit-proof canary/callback ──────────────────────
    if family == "exploit":
        result = await _confirm_via_exploit(finding, authorized=authorized,
                                            external_callback_url=external_callback_url)
        _record(finding, result)
        return {**result.to_dict(), "family": family, "finding": finding}

    # ── Known-CVE safe behavioural probe ────────────────────────────────────
    if family == "cve_probe":
        result = await _confirm_via_cve_probe(finding, authorized=authorized)
        _record(finding, result)
        return {**result.to_dict(), "family": family, "finding": finding}

    # Everything below sends live traffic to the target → authorization-gated.
    if family in ("http_header", "http_dirlisting", "http_endpoint", "http_cors",
                  "http_redirect", "tls", "tcp"):
        if not authorized:
            result = ConfirmResult(
                UNAUTHORIZED, method="none",
                summary="Active confirmation is not authorized.",
                detail="Sending a probe to the target requires the operator to hold "
                       "written authorization (the vuln.validate permission / "
                       "--i-have-authorization). Nothing was sent.")
            return {**result.to_dict(), "family": family, "finding": finding}
        if family in ("http_header", "http_dirlisting", "http_endpoint",
                      "http_cors", "http_redirect"):
            if aiohttp is None:
                result = ConfirmResult(UNAVAILABLE, method="http-recheck",
                                       summary="HTTP client (aiohttp) is not installed.",
                                       detail="Install aiohttp to enable HTTP re-check confirmation.")
                return {**result.to_dict(), "family": family, "finding": finding}
            result = await _confirm_http_family(family, finding)
            _record(finding, result)
            return {**result.to_dict(), "family": family, "finding": finding}
        if family == "tls":
            result = await _confirm_tls(finding)
            _record(finding, result)
            return {**result.to_dict(), "family": family, "finding": finding}
        if family == "tcp":
            result = await _confirm_tcp(finding)
            _record(finding, result)
            return {**result.to_dict(), "family": family, "finding": finding}

    # ── No safe automated proof for this class ──────────────────────────────
    already = is_confirmed_finding(finding)
    if already:
        result = ConfirmResult(
            ALREADY_CONFIRMED, method="none",
            summary="This finding is already Confirmed by its original evidence.",
            detail="Its detection method is itself the proof (e.g. a matched "
                   "dependency version, a direct DNS/config observation, or an "
                   "earlier validated probe), so no separate exploit applies.")
    else:
        result = ConfirmResult(
            NOT_APPLICABLE, method="none",
            summary="No safe automated exploit applies to this finding class.",
            detail=_manual_hint(finding))
    return {**result.to_dict(), "family": family, "finding": finding}


async def _confirm_http_family(family: str, finding: dict[str, Any]) -> ConfirmResult:
    session = _new_session()
    try:
        if family == "http_header":
            return await _confirm_http_header(session, finding)
        if family == "http_dirlisting":
            return await _confirm_http_dirlisting(session, finding)
        if family == "http_cors":
            return await _confirm_http_cors(session, finding)
        if family == "http_redirect":
            return await _confirm_http_redirect(session, finding)
        return await _confirm_http_endpoint(session, finding)
    finally:
        try:
            await session.close()
        except Exception:  # noqa: BLE001
            logger.debug("confirm session close failed", exc_info=True)


async def _confirm_via_exploit(finding: dict[str, Any], *, authorized: bool,
                               external_callback_url: str) -> ConfirmResult:
    ev = _ev(finding)
    has_param = bool(ev.get("parameter") or ev.get("param"))
    vt = _vt(finding)
    # sqlmap needs no explicit parameter; the others need an injectable one.
    if "sqli" not in vt and not has_param:
        return ConfirmResult(
            NOT_APPLICABLE, method="exploit",
            summary="No injectable parameter recorded — cannot fire a safe canary.",
            detail="This injection finding has no parameter/method in its evidence, "
                   "so the exploit-proof canary has nothing to target. Re-run the "
                   "scan with the injectable request captured, or verify manually.")
    if not authorized:
        return ConfirmResult(
            UNAUTHORIZED, method="exploit",
            summary="Active exploitation is not authorized.",
            detail="Firing an exploitation canary requires operator authorization "
                   "(vuln.validate permission). Nothing was sent.")
    from heaven.vulnscan.exploit_proof import prove_finding
    out = await prove_finding(finding, authorized=authorized,
                              external_callback_url=external_callback_url or "")
    proofs = (out.get("evidence") or {}).get("exploit_proof", []) or []
    last = proofs[-1] if proofs else {}
    proved = bool(out.get("proved"))
    if proved:
        summary = "Exploitation canary fired — the flaw is proven exploitable."
    elif last:
        summary = "Exploitation ran but the canary did not fire — could not prove it."
    else:
        summary = "Exploitation could not run for this finding."
    return ConfirmResult(
        CONFIRMED if proved else UNCONFIRMED, proved=proved,
        method="exploit", technique=str(last.get("technique") or ""),
        reprobed=bool(proofs),
        summary=summary,
        detail=str(last.get("notes") or "See exploit_proof evidence for the transcript."),
        evidence=proofs[-3:] if isinstance(proofs, list) else [])


async def _confirm_via_cve_probe(finding: dict[str, Any], *, authorized: bool) -> ConfirmResult:
    from heaven.vulnscan.active_verifier import verify_finding
    cve = _finding_cve(finding)
    if not authorized:
        return ConfirmResult(
            UNAUTHORIZED, method="active-probe",
            summary="The safe CVE probe is not authorized.",
            detail=f"A read-only behavioural probe for {cve} requires operator "
                   "authorization (vuln.validate permission). Nothing was sent.")
    out = await verify_finding(finding, authorized=authorized)
    rec = (out.get("evidence") or {}).get("active_verification") or {}
    proved = bool(rec.get("proved"))
    probed = bool(rec.get("probed"))
    if proved:
        summary = f"Safe read-only probe confirmed {cve} — promoted to Confirmed."
    elif probed:
        summary = f"Probe for {cve} ran but produced no observable — remains Potential."
    else:
        summary = rec.get("reason") or f"No probe outcome for {cve}."
    return ConfirmResult(
        CONFIRMED if proved else UNCONFIRMED, proved=proved,
        method="active-probe", technique=str(rec.get("technique") or ""),
        reprobed=probed,
        summary=summary,
        detail=str(rec.get("notes") or rec.get("reason") or ""),
        evidence=[rec.get("proof")] if rec.get("proof") else [])
