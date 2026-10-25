"""HEAVEN: business-logic abuse scanner.

Two logic-flaw classes that scanners usually miss because they are not a bad
*character* in a parameter but a bad *value* or a bad *order of operations*:

* **Numeric / quantity tampering**, a price, quantity, amount or discount field
  that the server trusts without validating sign or bound. HEAVEN sends an
  invalid value (a negative quantity, a negative/underflowed price) and reports
  only when that invalid value is REFLECTED back as accepted in the response,
  next to where the benign control value was reflected. No reflection ⇒ no
  finding, so a field the server silently ignores or rejects is never flagged.

* **Workflow step-skip**, a later step of an ordered flow (``…/step3``,
  ``…/confirm``, ``…/complete``) that can be reached directly, with no session
  having completed the earlier steps, and answers with its own success content
  instead of bouncing back to the start or to login. Reported conservatively:
  only when an earlier step of the SAME flow was also discovered (so the ordering
  is real) and the later step neither redirects or 401/403s nor echoes the
  earlier step.

Everything is read-mostly and evidence-first, matching the rest of HEAVEN: a
finding carries the exact reflected value or the observed status/own-content as
proof, never a heuristic hunch.
"""

from __future__ import annotations

from heaven.net.egress import client_session as _egress_cs  # egress-routed aiohttp

import re
import time
import urllib.parse
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    HAS_AIOHTTP = False

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.logic")

# Parameters whose value is a business quantity the server should bound-check.
_NUMERIC_PARAM = re.compile(
    r"(qty|quantity|amount|amt|price|cost|total|subtotal|sum|balance|credit|"
    r"points|discount|rebate|count|units|stock|limit|value)",
    re.IGNORECASE)

# Ordered-workflow step markers; the number/keyword encodes position in the flow.
# All keyword matches are word-bounded (``\b``) so a step word is only recognised
# as a whole path token: without that, substring matches fire on ordinary public
# URLs ("review" inside "/reviews", "complete" inside "/autocomplete", "success"
# inside "/success-stories", "finish" inside "/finished"), flooding content sites
# with phantom step-skip findings.
_STEP_RE = re.compile(r"\b(step|stage|phase)[-_/]?(\d+)\b", re.IGNORECASE)
_LATE_STEP = re.compile(r"\b(confirm|complete|review|finish|success|receipt|"
                        r"thank[-_]?you|place[-_]?order)\b",
                        re.IGNORECASE)
_EARLY_STEP = re.compile(r"\b(cart|basket|step[-_/]?1|stage[-_/]?1|start|begin|"
                         r"login|signin|address|shipping)\b", re.IGNORECASE)

# Content that means the late step BOUNCED (the guard worked) rather than serving
# its own success page, a direct request that lands on login, an empty cart, a
# not-found or an access-denied page is not a step-skip.
_BOUNCE_MARKERS = (
    "sign in", "log in", "login", "please authenticate", "step 1",
    "add to cart", "your cart is empty", "not found", "page not found",
    "404", "does not exist", "access denied", "forbidden", "unauthorized",
)
# Positive confirmation vocabulary a genuinely-skipped late step renders. Requiring
# it stops a bare 200 page (a soft-404, a marketing page) from being read as a
# completed workflow step.
_SUCCESS_MARKERS = (
    "confirm", "complete", "success", "receipt", "thank", "order",
    "payment", "placed", "approved", "finished",
)

_TIMEOUT = 8.0


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, confidence: float, evidence: dict,
             remediation: str, cwe: str = "") -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "cve_id": "",
        "cwe": cwe,
        "evidence": evidence,
        "remediation": remediation,
        "source": "logic_scanner",
    }


def _reflects(body: str, value: str) -> bool:
    """A bounded, word-ish reflection test, the value must appear delimited, so a
    coincidental substring inside a longer number/token does not count."""
    if not body or not value:
        return False
    return re.search(r"(?<![\w.-])" + re.escape(value) + r"(?![\w.-])", body) is not None


# Validation-rejection vocabulary. A page that re-renders a form at HTTP 200 with
# the invalid value echoed AND a rejection message is NOT accepting the value, so
# treating that echo as "accepted" is a false positive. We suppress only when the
# marker is present in the tampered response but NOT in the benign one, so a page
# whose template always contains the word (e.g. a persistent "error console"
# widget) does not mask a genuine finding.
_REJECT_MARKERS = (
    "invalid", "not allowed", "not permitted", "must be", "cannot be",
    "can't be", "out of range", "too large", "too small", "enter a valid",
    "not a valid", "rejected", "positive number", "greater than", "at least",
)


def _rejected_only_in_tampered(benign_body: str, tampered_body: str) -> bool:
    """True when the tampered response carries a validation-rejection message the
    benign response does not, the server flagged the value as invalid."""
    b = benign_body.lower()
    t = tampered_body.lower()
    return any(m in t and m not in b for m in _REJECT_MARKERS)


async def _get(session, url: str) -> tuple[int, str]:
    try:
        async with session.get(url, allow_redirects=False,
                               timeout=aiohttp.ClientTimeout(total=_TIMEOUT)) as resp:
            body = await resp.content.read(256 * 1024)
            return resp.status, body.decode("utf-8", "ignore")
    except Exception as e:  # noqa: BLE001
        logger.debug("logic GET %s failed: %s", url, e)
        return 0, ""


async def _post(session, url: str, data: dict) -> tuple[int, str, dict]:
    try:
        async with session.post(url, data=data, allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=_TIMEOUT)) as resp:
            body = await resp.content.read(256 * 1024)
            return resp.status, body.decode("utf-8", "ignore"), dict(resp.headers)
    except Exception as e:  # noqa: BLE001
        logger.debug("logic POST %s failed: %s", url, e)
        return 0, "", {}


# ── numeric / quantity tampering ──────────────────────────────────────────────

async def _audit_numeric_get(session, url: str) -> list[dict]:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    out: list[dict] = []
    for name, value in params:
        if not _NUMERIC_PARAM.search(name):
            continue
        benign = value if value.strip().lstrip("-").isdigit() and value.strip() != "" else "2"
        tampered = "-1"
        if benign == tampered:
            benign = "2"
        base_qs = [(k, v) for k, v in params if k != name]
        _bstat, bbody = await _get(session, urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(base_qs + [(name, benign)]))))
        tstat, tbody = await _get(session, urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(base_qs + [(name, tampered)]))))
        # Fire only when: the field is genuinely reflected (benign echoed), the
        # tampered negative is ALSO echoed back as accepted, the server answered
        # 2xx, and the tampered response is not a validation rejection, i.e. it
        # took the invalid value into the business flow.
        if (200 <= tstat < 300 and _reflects(bbody, benign) and _reflects(tbody, tampered)
                and not _rejected_only_in_tampered(bbody, tbody)):
            out.append(_finding(
                url, "numeric_tampering", "medium",
                f"Numeric/quantity tampering accepted in '{name}'",
                "A negative value supplied in a quantity/price parameter was "
                "accepted and reflected back by the server, which validates neither "
                "the sign nor the bound. Depending on the flow this can yield a "
                "negative charge, free items, or an inflated balance.",
                0.7, {"parameter": name, "benign": benign, "tampered": tampered,
                      "status": tstat,
                      "proof": f"the server accepted and reflected {name}={tampered}"},
                "Validate numeric inputs server-side (type, sign and range) and "
                "recompute totals from trusted data, never from client-supplied "
                "amounts.",
                cwe="CWE-20"))
    return out


async def _audit_numeric_post(session, url: str, form: dict) -> list[dict]:
    fields = {}
    numeric_names = []
    for fi in form.get("fields", []):
        name = fi.get("name") or ""
        if not name:
            continue
        fields[name] = fi.get("value", "1")
        if _NUMERIC_PARAM.search(name):
            numeric_names.append(name)
    if not fields or not numeric_names:
        return []
    action = form.get("action") or url
    if not action.startswith("http"):
        p = urllib.parse.urlparse(url)
        action = f"{p.scheme}://{p.netloc}" + ("" if action.startswith("/") else "/") + action
    out: list[dict] = []
    for name in numeric_names:
        benign = {**fields, name: "2"}
        tampered = {**fields, name: "-1"}
        _bs, bbody, _bh = await _post(session, action, benign)
        tstat, tbody, _th = await _post(session, action, tampered)
        if (200 <= tstat < 300 and _reflects(bbody, "2") and _reflects(tbody, "-1")
                and not _rejected_only_in_tampered(bbody, tbody)):
            out.append(_finding(
                action, "numeric_tampering", "medium",
                f"Numeric/quantity tampering accepted in '{name}' (POST)",
                "A negative value POSTed in a quantity/price field was accepted and "
                "reflected by the server, which validates neither sign nor bound.",
                0.7, {"parameter": name, "method": "POST", "tampered": "-1",
                      "status": tstat,
                      "proof": f"the server accepted and reflected {name}=-1"},
                "Validate numeric inputs server-side and recompute totals from "
                "trusted data, never from client-supplied amounts.",
                cwe="CWE-20"))
    return out


# ── workflow step-skip ────────────────────────────────────────────────────────

async def _audit_step_skip(session, urls: list[str]) -> list[dict]:
    """Flag a late-stage step reachable with no earlier step completed.

    Conservative: requires an EARLIER step of the same origin to have been
    discovered too (so the flow ordering is real), and only fires when the late
    step answers 2xx with its own content and does not redirect / 401 / 403 /
    bounce to the earlier step."""
    out: list[dict] = []
    by_origin: dict[str, list[str]] = {}
    for u in urls:
        p = urllib.parse.urlparse(u)
        by_origin.setdefault(f"{p.scheme}://{p.netloc}", []).append(u)

    for origin, group in by_origin.items():
        has_early = any(_EARLY_STEP.search(u) for u in group) or any(
            _STEP_RE.search(u) and (_STEP_RE.search(u).group(2) == "1") for u in group)
        if not has_early:
            continue
        for u in group:
            is_late = bool(_LATE_STEP.search(u)) or (
                (_STEP_RE.search(u) is not None)
                and _STEP_RE.search(u).group(2) not in ("0", "1"))
            if not is_late:
                continue
            status, body = await _get(session, u)  # a bare session: no prior step
            if not (200 <= status < 300) or not body:
                continue  # redirect / 401 / 403 / empty → the guard is working
            # It must look like the step's OWN success content, not a bounce that
            # rendered the login/earlier page (or a soft-404) at 200.
            low = body.lower()
            if any(k in low for k in _BOUNCE_MARKERS):
                continue
            # Require positive confirmation content: a bare 200 with no success
            # vocabulary is not proof the workflow step actually completed.
            if not any(k in low for k in _SUCCESS_MARKERS):
                continue
            out.append(_finding(
                u, "workflow_step_skip", "medium",
                "Workflow step-skip: later step reachable directly",
                "A later step of an ordered workflow returned its own success "
                "content when requested directly, with no earlier step completed in "
                "the session and no redirect to login or the start of the flow. The "
                "flow does not enforce step order server-side.",
                0.55, {"status": status, "origin": origin,
                       "proof": f"GET {u} returned {status} with step content and no "
                                "redirect to an earlier step"},
                "Enforce workflow order server-side: verify every prerequisite step "
                "is recorded against the session before serving a later step.",
                cwe="CWE-840"))
    return out


# ── public entry ──────────────────────────────────────────────────────────────

async def scan_business_logic(urls: list[str],
                              forms_by_url: Optional[dict[str, list]] = None,
                              *, time_budget: Optional[float] = None) -> dict:
    """Audit business-logic abuse (numeric tampering + workflow step-skip)."""
    if not HAS_AIOHTTP:
        return {"findings": [], "vulnerabilities": [], "total": 0,
                "error": "aiohttp not installed"}
    forms_by_url = forms_by_url or {}
    uniq: list[str] = []
    seen: set[str] = set()
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            uniq.append(u)
    if not uniq:
        return {"findings": [], "vulnerabilities": [], "total": 0}

    findings: list[dict] = []
    headers = {"User-Agent": "Mozilla/5.0 (compatible; HEAVEN-LogicScanner/1.0)"}
    connector = aiohttp.TCPConnector(ssl=False, limit=15)
    ct = aiohttp.ClientTimeout(total=30)
    deadline = (time.monotonic() + time_budget) if time_budget else None

    # Reuse the active auth session so flows behind login are exercised.
    try:
        from heaven.recon.auth_session import aiohttp_session_kwargs
        auth_kw = aiohttp_session_kwargs()
    except Exception:  # noqa: BLE001
        auth_kw = {}

    async with _egress_cs(headers=headers, connector=connector, timeout=ct,
                          **auth_kw) as session:
        for u in uniq:
            if deadline and time.monotonic() > deadline:
                logger.warning("logic scan: time budget reached, returning partial")
                break
            if urllib.parse.urlparse(u).query:
                findings.extend(await _audit_numeric_get(session, u))
            for form in forms_by_url.get(u, []):
                findings.extend(await _audit_numeric_post(session, u, form))
        if not (deadline and time.monotonic() > deadline):
            findings.extend(await _audit_step_skip(session, uniq))

    # De-dup by (target, vuln_type, parameter).
    seen_keys: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f["target"], f["vuln_type"], f["evidence"].get("parameter", ""))
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    logger.info("Business-logic audit → %d finding(s) across %d URL(s)",
                len(deduped), len(uniq))
    return {"findings": deduped, "vulnerabilities": deduped, "total": len(deduped)}
