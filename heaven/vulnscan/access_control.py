"""HEAVEN — Broken Access Control audit (multi-role differential).

Broken Access Control is OWASP #1, and the only way to test it *without* false
positives is to compare what different privilege tiers can actually retrieve. A
single-session scan can't: a page returning 200 tells you nothing about whether
the requester was *supposed* to see it. This module fetches the same URL under up
to three identities and reasons about the **differential**:

  * **privileged** — the primary authenticated session (what the crawler used,
    typically an admin/high-privilege login). This is the "ground truth" of what
    the protected content looks like.
  * **low-priv**   — an optional second, deliberately lower-privilege session
    (``--low-priv-cookie-file`` / ``--low-priv-auth``).
  * **anonymous**  — no credentials at all (always tested).

A finding is only raised on a *proven* differential:

  1. **Proven (high) — authorization not enforced.** The app *does* protect the
     resource (anonymous is denied: 401/403/login-redirect) **yet a lower-
     privilege session retrieves content identical to the privileged view.** The
     app checks that you're logged in but not *who* you are. Ground truth, so the
     confidence is high.

  2. **Detected (medium, "verify") — privileged path served anonymously.** A
     URL whose path is privilege-scoped (``/admin`` /``/manage`` /``/internal`` …)
     returns identical content to an anonymous request. This is heuristic — the
     page *might* be intentionally public — so it is medium severity, explicitly
     labelled for manual verification, never inflated.

Public pages (every tier gets the same content and nothing is ever denied) raise
**nothing** — that is the trap this design exists to avoid. All requests are
read-only GETs; the module never mutates target state.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Optional
from urllib.parse import urlparse

from heaven.recon.evasion_engine import EvasionEngine, profile_for
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.access_control")

# Path segments that denote privileged / administrative functionality. Used only
# to gate the *heuristic* (medium) finding — never the proven one.
_PRIV_PATH_RE = re.compile(
    r"/(admin|administrator|manage|management|manager|internal|config|"
    r"configuration|settings|setup|dashboard|console|users?|accounts?|"
    r"staff|backend|sysadmin|superuser|root|privileged|api/admin|wp-admin)(/|$|\?)",
    re.IGNORECASE,
)

# Markers that a "200" body is really a login / access-denied page, not the
# protected resource. If any appears, the tier is treated as DENIED.
_LOGIN_MARKERS = (
    'type="password"', "type='password'", "name=\"password\"", "name='password'",
    "please log in", "please login", "sign in to continue", "you must be logged in",
    "access denied", "not authorized", "unauthorized", "forbidden",
    "authentication required", "login required", "session expired",
)

_MIN_BODY = 64          # below this, a body is too thin to compare meaningfully
_SIMILAR = 0.90         # SequenceMatcher ratio above which two bodies are "same"


@dataclass
class _Resp:
    status: int
    body: str
    granted: bool          # True = the protected resource was actually served


def _looks_like_login(body: str) -> bool:
    low = body.lower()
    return any(m in low for m in _LOGIN_MARKERS)


def _classify(status: int, body: str) -> _Resp:
    """Decide whether a response represents the protected resource being served
    (granted) or the app denying access (denied)."""
    if status == 0:
        return _Resp(status, body, granted=False)
    # Explicit denials + redirects (almost always to a login page).
    if status in (401, 403) or status in (301, 302, 303, 307, 308):
        return _Resp(status, body, granted=False)
    if status >= 400:
        return _Resp(status, body, granted=False)
    granted = (
        status == 200
        and len(body.strip()) >= _MIN_BODY
        and not _looks_like_login(body)
    )
    return _Resp(status, body, granted=granted)


def _norm(body: str) -> str:
    return re.sub(r"\s+", " ", body).strip()


def _similar(a: str, b: str) -> float:
    a, b = _norm(a), _norm(b)
    if not a or not b:
        return 0.0
    # Length guard first — cheap and rejects obviously different pages before the
    # O(n²) matcher. Compare a bounded prefix so huge pages stay fast.
    la, lb = len(a), len(b)
    if min(la, lb) / max(la, lb) < 0.6:
        return 0.0
    return SequenceMatcher(None, a[:4000], b[:4000]).quick_ratio()


async def _fetch(session: Any, url: str, timeout: float) -> _Resp:
    import aiohttp
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False, ssl=False,
        ) as resp:
            body = await resp.text(errors="replace")
            return _classify(resp.status, body)
    except Exception:
        return _Resp(0, "", granted=False)


def _session_kwargs(sess: Any) -> dict[str, Any]:
    """Build aiohttp.ClientSession kwargs for a specific AuthSession (or {} for
    an anonymous session)."""
    if sess is None:
        return {}
    out: dict[str, Any] = {}
    if getattr(sess, "cookies", None):
        out["cookies"] = dict(sess.cookies)
    if getattr(sess, "headers", None):
        out["headers"] = dict(sess.headers)
    return out


async def scan_access_control(
    urls: list[str], *,
    privileged: Any = None, low_priv: Any = None,
    stealth_level: str = "normal", timeout: float = 8.0, max_urls: int = 60,
) -> dict[str, Any]:
    """Run the multi-role access-control differential over ``urls``.

    ``privileged``/``low_priv`` are ``AuthSession`` objects (or ``None``). When
    ``privileged`` is ``None`` the audit is skipped — without a known-good
    privileged baseline there is nothing to diff against, and guessing would
    produce false positives.
    """
    try:
        import aiohttp
    except ImportError:
        return {"findings": [], "tested": 0, "skipped": "aiohttp missing"}

    if privileged is None:
        from heaven.recon.auth_session import get_active_session
        privileged = get_active_session()
    if low_priv is None:
        from heaven.recon.auth_session import get_low_priv_session
        low_priv = get_low_priv_session()

    if privileged is None or not (getattr(privileged, "cookies", None) or
                                  getattr(privileged, "headers", None)):
        return {"findings": [], "tested": 0,
                "skipped": "no privileged session — access-control diff needs an "
                           "authenticated baseline (--cookie-file / --auth)"}

    # Dedupe on scheme+netloc+path (query variants are the same resource here).
    seen: set[str] = set()
    picked: list[str] = []
    for u in urls:
        p = urlparse(u)
        if not p.scheme.startswith("http"):
            continue
        key = f"{p.scheme}://{p.netloc}{p.path}"
        if key not in seen:
            seen.add(key)
            picked.append(u)
        if len(picked) >= max_urls:
            break
    if not picked:
        return {"findings": [], "tested": 0}

    profile = profile_for(stealth_level)
    engine = EvasionEngine(profile)
    headers = engine.get_http_headers()

    priv_kw = _session_kwargs(privileged)
    low_kw = _session_kwargs(low_priv) if low_priv is not None else None

    findings: list[dict[str, Any]] = []
    connector_limit = max(1, min(8, profile.max_concurrent))

    async def _one(sess_kwargs: Optional[dict], url: str) -> _Resp:
        merged: dict[str, Any] = {
            "headers": {**headers, **(sess_kwargs or {}).get("headers", {})}}
        if sess_kwargs and sess_kwargs.get("cookies"):
            merged["cookies"] = sess_kwargs["cookies"]
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=connector_limit),
            **merged,
        ) as s:
            return await _fetch(s, url, timeout)

    sem = asyncio.Semaphore(connector_limit)

    async def _audit_url(url: str) -> Optional[dict[str, Any]]:
        async with sem:
            await engine.apply_evasion_delay()
            priv = await _one(priv_kw, url)
            # No privileged access → nothing protected to compare; skip.
            if not priv.granted:
                return None
            anon = await _one(None, url)
            low = await _one(low_kw, url) if low_kw is not None else None

            # ── Rule 1: proven authorization failure (app protects, low-priv gets in)
            if low is not None and low.granted:
                anon_denied = not anon.granted
                if anon_denied and _similar(priv.body, low.body) >= _SIMILAR:
                    return _finding(
                        url, severity="high", confidence=0.86, proven=True,
                        title="Broken access control — lower-privilege user reaches "
                              "protected content",
                        detail=("The application enforces authentication (an "
                                "anonymous request is denied) but not authorization: "
                                "a lower-privilege session retrieved content "
                                "identical to the privileged view."),
                        evidence={
                            "privileged_status": priv.status,
                            "low_priv_status": low.status,
                            "anonymous_status": anon.status,
                            "content_similarity": round(_similar(priv.body, low.body), 3),
                        },
                    )

            # ── Rule 2: heuristic — privileged-scoped path served anonymously
            if anon.granted and _PRIV_PATH_RE.search(urlparse(url).path or ""):
                sim = _similar(priv.body, anon.body)
                if sim >= _SIMILAR:
                    return _finding(
                        url, severity="medium", confidence=0.55, proven=False,
                        title="Privileged-looking endpoint served without authentication",
                        detail=("This administrative/privileged path returns the same "
                                "content to an anonymous request as to the "
                                "authenticated session. Verify it is intended to be "
                                "public — if not, it is missing authentication."),
                        evidence={
                            "privileged_status": priv.status,
                            "anonymous_status": anon.status,
                            "content_similarity": round(sim, 3),
                            "path_matched_privileged_pattern": True,
                        },
                    )
            return None

    results = await asyncio.gather(*[_audit_url(u) for u in picked])
    for r in results:
        if r:
            findings.append(r)

    if findings:
        logger.info("access-control audit: %d finding(s) across %d URL(s)",
                    len(findings), len(picked))
    return {"findings": findings, "tested": len(picked)}


def _finding(url: str, *, severity: str, confidence: float, proven: bool,
             title: str, detail: str, evidence: dict[str, Any]) -> dict[str, Any]:
    ev = dict(evidence)
    ev["url"] = url
    ev["verification"] = ("proven by response differential"
                          if proven else "detected — verify manually")
    return {
        "vuln_type": "broken_access_control",
        "type": "broken_access_control",
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "proved": proven,
        "target": url,
        "cwe": "CWE-284",
        "owasp": "A01:2021 Broken Access Control",
        "description": detail,
        "evidence": ev,
    }
