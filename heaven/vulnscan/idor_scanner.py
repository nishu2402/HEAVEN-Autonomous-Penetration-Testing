"""
HEAVEN — IDOR (Insecure Direct Object Reference) Scanner
Detects broken object-level authorization — one of the most common and highest-
severity web vulnerabilities (OWASP API Security Top 10: API1).

Techniques used
───────────────
1. ID enumeration  — increment/decrement numeric IDs found in URL path segments
   and GET/POST parameters; compare authenticated vs unauthenticated responses.
2. UUID guessing   — replace UUID segments with all-zero UUIDs and known guessable
   values.
3. Type coercion   — try string IDs as integers and vice-versa.
4. Horizontal privilege escalation — if two session tokens are supplied, swap
   object ownership checks.
5. Mass assignment — POST extra fields (admin, role, user_id, is_admin) and check
   if they are reflected back.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.idor")

# ─────────────────────────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────────────────────────

_RE_INT_SEGMENT = re.compile(r"^(\d{1,18})$")
_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_RE_OBJECT_PARAM = re.compile(
    r"^(id|user_?id|account_?id|order_?id|invoice_?id|file_?id|"
    r"document_?id|record_?id|item_?id|product_?id|customer_?id|"
    r"profile_?id|ticket_?id|msg_?id|message_?id|post_?id|comment_?id|"
    r"txn_?id|transaction_?id|uuid|guid|ref|reference|key|token|hash|"
    r"object_?id|resource_?id|entity_?id)$",
    re.IGNORECASE,
)

# Common query parameters that often carry object IDs
SENSITIVE_PARAMS = {
    "id", "user_id", "userId", "account_id", "accountId",
    "order_id", "orderId", "invoice_id", "invoiceId",
    "file_id", "fileId", "document_id", "documentId",
    "item_id", "itemId", "product_id", "productId",
    "customer_id", "customerId", "profile_id", "profileId",
    "ticket_id", "ticketId", "msg_id", "msgId",
    "post_id", "postId", "comment_id", "commentId",
    "transaction_id", "txn_id", "ref", "reference",
    "uuid", "guid", "key",
}

# Mass assignment probe fields
MASS_ASSIGNMENT_FIELDS = [
    "admin", "is_admin", "isAdmin", "role", "user_id", "userId",
    "account_id", "accountId", "privilege", "level", "group",
    "email_verified", "active", "status", "verified",
    "subscription", "plan", "credits", "balance",
]

NULL_UUID = "00000000-0000-0000-0000-000000000000"
SEQUENTIAL_UUIDS = [
    "00000000-0000-0000-0000-000000000001",
    "11111111-1111-1111-1111-111111111111",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
]


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _body_hash(body: str) -> str:
    return hashlib.md5(body.encode(errors="replace"), usedforsecurity=False).hexdigest()


def _body_differs(a: str, b: str, min_size: int = 50) -> bool:
    """True if bodies are meaningfully different (not just whitespace or tiny diffs)."""
    if abs(len(a) - len(b)) > 50:
        return True
    return _body_hash(a) != _body_hash(b) and len(a) > min_size


# ── Evidence gating (precision-first IDOR classification) ─────────────────────
# A *different* 200 body when an ID is changed is NORMAL for any enumerable
# resource (/product/1 vs /product/2) and is NOT, by itself, IDOR. Escalating it
# to a high-severity finding was a heavy false-positive source. Real IDOR needs an
# authorization signal: either a cross-user/anon session reads the object (handled
# by _test_horizontal_privesc / _test_unauth_access) or the alternate object
# actually leaks another record's sensitive data. Absent both, it is only an
# informational "enumerable reference" worth manual review.

_SENSITIVE_MARKERS: list[re.Pattern] = [
    re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I),               # email
    re.compile(r'"(ssn|social_security|passport|national_id|tax_id)"\s*:', re.I),
    re.compile(r'"(phone|mobile|telephone)"\s*:\s*"?\+?\d', re.I),
    re.compile(r'"(api[_-]?key|secret|access[_-]?token|refresh[_-]?token|'
               r'password|passwd|pwd)"\s*:', re.I),
    re.compile(r'"(credit_?card|card_?number|cvv|cvc|iban|account_?number|routing)"\s*:', re.I),
    re.compile(r'"(first_?name|last_?name|full_?name|address|dob|date_of_birth|'
               r'salary|balance)"\s*:', re.I),
]


def _sensitive_markers(body: str) -> list[str]:
    """Return snippets of any sensitive-data markers found in a response body —
    the signal that an altered-ID response actually exposed a record's private
    data rather than merely returning a different (possibly public) object."""
    found: list[str] = []
    for rx in _SENSITIVE_MARKERS:
        m = rx.search(body or "")
        if m:
            found.append(m.group(0)[:48])
        if len(found) >= 5:
            break
    return found


def _idor_verdict(orig_status: int, orig_body: str,
                  test_status: int, test_body: str):
    """Classify an ID-swap result. Returns (vuln_type, severity, confidence, extra)
    or None when there is no signal at all.

    * different 200 body + sensitive data leaked → real IDOR (data exposure), medium
    * different 200 body, nothing sensitive       → informational enumerable ref
    """
    if not (test_status == 200 and orig_status == 200
            and _body_differs(orig_body, test_body)):
        return None
    markers = _sensitive_markers(test_body)
    if markers:
        return ("idor", "medium", 0.6,
                {"signals": ["sensitive_data_exposed"], "sensitive_markers": markers})
    return ("enumerable_reference", "info", 0.4,
            {"signals": ["object_enumerable"],
             "note": ("A different object was returned for the altered ID, but no "
                      "sensitive data was observed and object-level authorization "
                      "was not proven. Verify access control manually.")})


def _field_value_bound(body: str, field: str, value: str) -> bool:
    """True when an injected mass-assignment field appears *bound to its value* in
    the response (JSON key/value or form echo) — not merely the field name showing
    up as incidental page text (e.g. the word "admin" in a nav menu), which was a
    false-positive source."""
    if not body:
        return False
    f, v = re.escape(field), re.escape(value)
    patterns = [
        rf'"{f}"\s*:\s*"?{v}"?',   # "admin":"1"  /  "admin":1
        rf'"{f}"\s*:\s*true',       # "admin":true
        rf'\b{f}\s*=\s*{v}\b',      # admin=1
    ]
    return any(re.search(p, body, re.I) for p in patterns)


async def _get(session, url: str, headers: dict, timeout: float = 10.0) -> tuple[int, str]:
    try:
        async with session.get(
            url, headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True, ssl=False,
        ) as resp:
            return resp.status, await resp.text(errors="replace")
    except Exception:
        return 0, ""


async def _post(session, url: str, data: dict, headers: dict, timeout: float = 10.0) -> tuple[int, str]:
    try:
        async with session.post(
            url, json=data, headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True, ssl=False,
        ) as resp:
            return resp.status, await resp.text(errors="replace")
    except Exception:
        return 0, ""


def _replace_path_segment(url: str, old: str, new: str) -> str:
    parsed = urlparse(url)
    parts = parsed.path.split("/")
    new_parts = [new if p == old else p for p in parts]
    return urlunparse(parsed._replace(path="/".join(new_parts)))


def _replace_qs_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


# ─────────────────────────────────────────────────────────────────
# Core scanner
# ─────────────────────────────────────────────────────────────────

class IDORScanner:

    def __init__(
        self,
        concurrency: int = 20,
        auth_headers: Optional[dict] = None,
        alt_auth_headers: Optional[dict] = None,
        request_delay: float = 0.0,
    ) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        # Stealth throttle: seconds to pause while holding a concurrency slot, so
        # higher stealth levels genuinely space IDOR probes out on the wire.
        self._delay = request_delay
        self._base_headers = {
            "User-Agent": "HEAVEN-Scanner/1.0",
            **(auth_headers or {}),
        }
        self._alt_headers = {
            "User-Agent": "HEAVEN-Scanner/1.0",
            **(alt_auth_headers or {}),
        } if alt_auth_headers else None
        # Whether a *real* auth token backs base_headers. The unauth-access check
        # is only meaningful when we actually have auth to strip — otherwise
        # "authed" and "unauthed" requests are identical and it fires on every
        # id'd URL (a critical-severity false positive in the default scan).
        self._has_auth = bool(auth_headers)
        self._findings: list[dict] = []
        self._seen: set[str] = set()

    @asynccontextmanager
    async def _slot(self):
        """Acquire a concurrency slot and apply the stealth inter-request delay.

        Sleeping *inside* the semaphore holds the slot, which rate-limits the
        scanner as a whole — the intended, genuine effect of a higher stealth
        level. At the default (delay=0) it is exactly equivalent to the bare
        semaphore, so aggressive/normal keep full speed.
        """
        await self._sem.acquire()
        try:
            if self._delay:
                await asyncio.sleep(self._delay)
            yield
        finally:
            self._sem.release()

    def _add(self, **kwargs) -> None:
        key = hashlib.sha256(
            f"{kwargs.get('target')}|{kwargs.get('evidence', {}).get('probe_type')}|{kwargs.get('evidence', {}).get('param')}".encode()
        ).hexdigest()[:16]
        if key not in self._seen:
            self._seen.add(key)
            self._findings.append(kwargs)

    # ── Path segment ID enumeration ───────────────────────────────

    async def _test_path_ids(self, session, url: str) -> None:
        """Replace numeric path segments with adjacent integers."""
        parsed = urlparse(url)
        segments = parsed.path.split("/")

        for i, seg in enumerate(segments):
            if not _RE_INT_SEGMENT.match(seg):
                continue
            original = int(seg)
            for candidate in [original - 1, original + 1, original + 100,
                               original - 100, 1, 2, 9999]:
                if candidate <= 0:
                    continue
                test_url = _replace_path_segment(url, seg, str(candidate))
                async with self._slot():
                    orig_status, orig_body = await _get(session, url, self._base_headers)
                    test_status, test_body = await _get(session, test_url, self._base_headers)

                verdict = _idor_verdict(orig_status, orig_body, test_status, test_body)
                if verdict:
                    vt, sev, conf, extra = verdict
                    title = (f"IDOR — path ID enumeration (/{seg}/ → /{candidate}/)"
                             if vt == "idor" else
                             f"Enumerable object reference — path /{seg}/ → /{candidate}/")
                    self._add(
                        target=test_url,
                        vuln_type=vt,
                        title=title,
                        severity=sev,
                        confidence=conf,
                        evidence={
                            "probe_type": "path_id",
                            "param": f"path_segment[{i}]",
                            "original_url": url,
                            "test_url": test_url,
                            "original_id": seg,
                            "tested_id": str(candidate),
                            "status": test_status,
                            **extra,
                        },
                        remediation=(
                            "Implement object-level authorization checks. "
                            "Verify that the authenticated user owns or has permission to access "
                            "the requested resource before returning it."
                        ),
                        cwe="CWE-639",
                    )
                    return  # one hit per segment is enough

    # ── Query parameter ID enumeration ────────────────────────────

    async def _test_param_ids(self, session, url: str) -> None:
        """Replace sensitive GET parameters with adjacent integer values."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        for param, values in qs.items():
            val = values[0] if values else ""

            # Numeric ID parameter
            if _RE_INT_SEGMENT.match(val):
                original = int(val)
                for candidate in [original - 1, original + 1, original + 100, 1, 2]:
                    if candidate <= 0:
                        continue
                    test_url = _replace_qs_param(url, param, str(candidate))
                    async with self._slot():
                        orig_status, orig_body = await _get(session, url, self._base_headers)
                        test_status, test_body = await _get(session, test_url, self._base_headers)

                    verdict = _idor_verdict(orig_status, orig_body, test_status, test_body)
                    if verdict:
                        vt, sev, conf, extra = verdict
                        title = (f"IDOR — parameter enumeration (?{param}={candidate})"
                                 if vt == "idor" else
                                 f"Enumerable object reference — ?{param}={candidate}")
                        self._add(
                            target=test_url,
                            vuln_type=vt,
                            title=title,
                            severity=sev,
                            confidence=conf,
                            evidence={
                                "probe_type": "param_id",
                                "param": param,
                                "original_url": url,
                                "test_url": test_url,
                                "original_value": val,
                                "tested_value": str(candidate),
                                "status": test_status,
                                **extra,
                            },
                            remediation=(
                                "Validate that the requesting user is authorized to access "
                                f"the resource identified by '{param}'. "
                                "Use indirect references mapped server-side."
                            ),
                            cwe="CWE-639",
                        )
                        break

            # UUID parameter
            elif _RE_UUID.match(val):
                for uuid_candidate in [NULL_UUID] + SEQUENTIAL_UUIDS:
                    if uuid_candidate == val:
                        continue
                    test_url = _replace_qs_param(url, param, uuid_candidate)
                    async with self._slot():
                        orig_status, orig_body = await _get(session, url, self._base_headers)
                        test_status, test_body = await _get(session, test_url, self._base_headers)

                    verdict = _idor_verdict(orig_status, orig_body, test_status, test_body)
                    if verdict:
                        vt, sev, conf, extra = verdict
                        title = (f"IDOR — UUID enumeration (?{param})" if vt == "idor"
                                 else f"Enumerable object reference — UUID ?{param}")
                        self._add(
                            target=test_url,
                            vuln_type=vt,
                            title=title,
                            severity=sev,
                            confidence=conf,
                            evidence={
                                "probe_type": "uuid_enum",
                                "param": param,
                                "tested_uuid": uuid_candidate,
                                "original_url": url,
                                **extra,
                            },
                            remediation=(
                                "Verify user authorization before returning resources by UUID. "
                                "UUIDs are not a security control — they must be paired with authz checks."
                            ),
                            cwe="CWE-639",
                        )
                        break

    # ── Horizontal privilege escalation (dual-session) ─────────────

    async def _test_horizontal_privesc(self, session, url: str) -> None:
        """
        If two auth tokens are provided, request resource with alt token and
        compare — if user B can read user A's resource, that is IDOR.
        """
        if not self._alt_headers:
            return

        parsed = urlparse(url)
        segments = parsed.path.split("/")
        has_id = any(_RE_INT_SEGMENT.match(s) or _RE_UUID.match(s) for s in segments)
        qs = parse_qs(parsed.query)
        has_param_id = any(
            _RE_OBJECT_PARAM.match(p) and (_RE_INT_SEGMENT.match(v[0]) or _RE_UUID.match(v[0]))
            for p, v in qs.items()
        )

        if not has_id and not has_param_id:
            return

        async with self._slot():
            status_a, body_a = await _get(session, url, self._base_headers)
            status_b, body_b = await _get(session, url, self._alt_headers)

        if (status_a == 200 and status_b == 200
                and not _body_differs(body_a, body_b)):
            # Both tokens get the same response → same object
            self._add(
                target=url,
                vuln_type="idor",
                title="IDOR — Horizontal privilege escalation (dual-session access)",
                severity="critical",
                confidence=0.92,
                evidence={
                    "probe_type": "horizontal_privesc",
                    "param": "session_token",
                    "detail": "Alternate user token can access this resource with identical response",
                },
                remediation=(
                    "Ensure server-side ownership checks are applied to every object request. "
                    "Never rely solely on the object ID for authorization."
                ),
                cwe="CWE-639",
            )

    # ── Mass assignment probe ─────────────────────────────────────

    async def _test_mass_assignment(self, session, url: str, forms: list[dict]) -> None:
        """POST extra privilege-escalating fields and check if reflected."""
        for form in forms:
            action = form.get("action") or url
            method = (form.get("method") or "POST").upper()
            if method != "POST":
                continue

            # Build base data from form fields
            base_data: dict = {
                f.get("name", ""): f.get("value", "test")
                for f in form.get("fields", [])
                if f.get("name")
            }

            # Inject mass assignment fields
            for extra_field in MASS_ASSIGNMENT_FIELDS:
                probe_data = {**base_data, extra_field: "1"}
                async with self._slot():
                    status, body = await _post(session, action, probe_data, self._base_headers)

                # A real mass-assignment tell is the injected field being *bound to
                # its value* in the response (e.g. `"admin":"1"`), not the field
                # name merely appearing as page text (the word "admin" is in most
                # HTML) — that substring match was a false-positive source.
                if _field_value_bound(body, extra_field, "1") and status in (200, 201):
                    self._add(
                        target=action,
                        vuln_type="mass_assignment",
                        title=f"Mass Assignment — field '{extra_field}' reflected",
                        severity="high",
                        confidence=0.75,
                        evidence={
                            "probe_type": "mass_assignment",
                            "param": extra_field,
                            "method": "POST",
                            "injected_value": "1",
                        },
                        remediation=(
                            f"Whitelist allowed fields server-side. "
                            f"Do not bind '{extra_field}' from user input. "
                            "Use a DTO/allowlist pattern rather than direct model binding."
                        ),
                        cwe="CWE-915",
                    )
                    break

    # ── Unauthenticated access check ──────────────────────────────

    async def _test_unauth_access(self, session, url: str) -> None:
        """Request a URL without auth — if a *protected* object still returns, flag it.

        Only meaningful when we actually hold an auth token to strip: without one,
        the "authed" and "unauthed" requests are identical, so every id'd 200 URL
        would look like unauth access (a critical-severity false positive). And an
        identical body that carries no sensitive data is just a public page, not a
        broken-access-control finding.
        """
        if not self._has_auth:
            return
        parsed = urlparse(url)
        has_id = any(_RE_INT_SEGMENT.match(s) or _RE_UUID.match(s)
                     for s in parsed.path.split("/"))
        if not has_id:
            return

        no_auth = {"User-Agent": "HEAVEN-Scanner/1.0"}
        async with self._slot():
            auth_status, auth_body = await _get(session, url, self._base_headers)
            unauth_status, unauth_body = await _get(session, url, no_auth)

        if (auth_status == 200 and unauth_status == 200
                and not _body_differs(auth_body, unauth_body)
                and _sensitive_markers(unauth_body)):
            self._add(
                target=url,
                vuln_type="idor",
                title="Unauthenticated Object Access (IDOR without auth)",
                severity="critical",
                confidence=0.88,
                evidence={
                    "probe_type": "unauth_access",
                    "param": "Authorization",
                    "detail": "Resource returns identical response without authentication header",
                },
                remediation=(
                    "Require authentication for all resource endpoints. "
                    "Return 401 or 403 when no valid token is supplied."
                ),
                cwe="CWE-306",
            )

    # ── Public API ────────────────────────────────────────────────

    async def scan(
        self,
        targets: list[str],
        forms_by_url: Optional[dict[str, list]] = None,
    ) -> dict:
        """
        Run IDOR tests against all targets.

        Args:
            targets: list of URLs with IDs (from crawler or orchestrator).
            forms_by_url: {url: [form_dict, ...]} for mass-assignment probes.

        Returns:
            {'findings': [...], 'urls_tested': int, 'error': None}
        """
        if aiohttp is None:
            return {"findings": [], "urls_tested": 0, "error": "aiohttp not installed"}

        seen_urls: set[str] = set()
        unique = [u for u in targets if u and u not in seen_urls and not seen_urls.add(u)]  # type: ignore[func-returns-value]

        logger.info(f"IDORScanner: testing {len(unique)} URLs")

        connector = aiohttp.TCPConnector(ssl=False, limit=40)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for url in unique:
                forms = (forms_by_url or {}).get(url, [])
                tasks.append(self._test_path_ids(session, url))
                tasks.append(self._test_param_ids(session, url))
                tasks.append(self._test_horizontal_privesc(session, url))
                tasks.append(self._test_unauth_access(session, url))
                if forms:
                    tasks.append(self._test_mass_assignment(session, url, forms))
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"IDORScanner: {len(self._findings)} findings")
        return {
            "findings": self._findings,
            "urls_tested": len(unique),
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# Orchestrator entry point
# ─────────────────────────────────────────────────────────────────

async def scan_for_idor(
    targets: list[str],
    forms_by_url: Optional[dict] = None,
    auth_headers: Optional[dict] = None,
    alt_auth_headers: Optional[dict] = None,
    concurrency: int = 20,
    stealth_level: str = "normal",
) -> dict:
    """Top-level function called from the orchestrator."""
    # (concurrency, inter-request delay seconds) per stealth level — higher
    # stealth fans out less AND spaces probes out, matching the other scanners.
    level_map = {
        "aggressive": (40, 0.0),
        "normal": (20, 0.0),
        "stealth": (10, 0.3),
        "paranoid": (5, 1.0),
    }
    concurrency, request_delay = level_map.get(stealth_level, (concurrency, 0.0))

    # Pick up the active auth session (`heaven scan --auth` / --cookie-file) when
    # the caller didn't pass explicit headers, so the unauth-access and
    # horizontal-privesc checks have a real token to work with.
    if auth_headers is None:
        auth_headers = _active_auth_headers()

    scanner = IDORScanner(
        concurrency=concurrency,
        auth_headers=auth_headers,
        alt_auth_headers=alt_auth_headers,
        request_delay=request_delay,
    )
    return await scanner.scan(targets, forms_by_url=forms_by_url)


def _active_auth_headers() -> Optional[dict]:
    """Convert the process-wide active AuthSession into a header dict (custom
    headers plus its cookies folded into a ``Cookie`` header). Returns None when
    no session is configured."""
    try:
        from heaven.recon.auth_session import get_active_session
    except ImportError:
        return None
    sess = get_active_session()
    if not sess:
        return None
    hdrs = dict(sess.headers or {})
    if sess.cookies:
        hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in sess.cookies.items())
    return hdrs or None
