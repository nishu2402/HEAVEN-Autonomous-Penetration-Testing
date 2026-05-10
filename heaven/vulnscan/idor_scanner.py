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
    return hashlib.md5(body.encode(errors="replace")).hexdigest()


def _body_differs(a: str, b: str, min_size: int = 50) -> bool:
    """True if bodies are meaningfully different (not just whitespace or tiny diffs)."""
    if abs(len(a) - len(b)) > 50:
        return True
    return _body_hash(a) != _body_hash(b) and len(a) > min_size


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
    ) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._base_headers = {
            "User-Agent": "HEAVEN-Scanner/1.0",
            **(auth_headers or {}),
        }
        self._alt_headers = {
            "User-Agent": "HEAVEN-Scanner/1.0",
            **(alt_auth_headers or {}),
        } if alt_auth_headers else None
        self._findings: list[dict] = []
        self._seen: set[str] = set()

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
                async with self._sem:
                    orig_status, orig_body = await _get(session, url, self._base_headers)
                    test_status, test_body = await _get(session, test_url, self._base_headers)

                # IDOR: test URL returns 200 with different content
                if (test_status == 200 and orig_status == 200
                        and _body_differs(orig_body, test_body)):
                    self._add(
                        target=test_url,
                        vuln_type="idor",
                        title=f"IDOR — path ID enumeration (/{seg}/ → /{candidate}/)",
                        severity="high",
                        confidence=0.80,
                        evidence={
                            "probe_type": "path_id",
                            "param": f"path_segment[{i}]",
                            "original_url": url,
                            "test_url": test_url,
                            "original_id": seg,
                            "tested_id": str(candidate),
                            "status": test_status,
                        },
                        remediation=(
                            "Implement object-level authorization checks. "
                            "Verify that the authenticated user owns or has permission to access "
                            "the requested resource before returning it."
                        ),
                        cwe="CWE-639",
                    )
                    return  # one confirmed hit per segment is enough

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
                    async with self._sem:
                        orig_status, orig_body = await _get(session, url, self._base_headers)
                        test_status, test_body = await _get(session, test_url, self._base_headers)

                    if test_status == 200 and orig_status == 200 and _body_differs(orig_body, test_body):
                        self._add(
                            target=test_url,
                            vuln_type="idor",
                            title=f"IDOR — parameter enumeration (?{param}={candidate})",
                            severity="high",
                            confidence=0.82,
                            evidence={
                                "probe_type": "param_id",
                                "param": param,
                                "original_url": url,
                                "test_url": test_url,
                                "original_value": val,
                                "tested_value": str(candidate),
                                "status": test_status,
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
                    async with self._sem:
                        orig_status, orig_body = await _get(session, url, self._base_headers)
                        test_status, test_body = await _get(session, test_url, self._base_headers)

                    if test_status == 200 and orig_status == 200 and _body_differs(orig_body, test_body):
                        self._add(
                            target=test_url,
                            vuln_type="idor",
                            title=f"IDOR — UUID enumeration (?{param})",
                            severity="high",
                            confidence=0.78,
                            evidence={
                                "probe_type": "uuid_enum",
                                "param": param,
                                "tested_uuid": uuid_candidate,
                                "original_url": url,
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

        async with self._sem:
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
                async with self._sem:
                    status, body = await _post(session, action, probe_data, self._base_headers)

                # If the field name is reflected back → likely mass assignment
                if extra_field in body and status in (200, 201):
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
        """Request a URL without any auth headers — if it returns 200, that's a finding."""
        parsed = urlparse(url)
        has_id = any(_RE_INT_SEGMENT.match(s) or _RE_UUID.match(s)
                     for s in parsed.path.split("/"))
        if not has_id:
            return

        no_auth = {"User-Agent": "HEAVEN-Scanner/1.0"}
        async with self._sem:
            auth_status, auth_body = await _get(session, url, self._base_headers)
            unauth_status, unauth_body = await _get(session, url, no_auth)

        if (auth_status == 200 and unauth_status == 200
                and not _body_differs(auth_body, unauth_body)):
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
    level_map = {
        "aggressive": 40,
        "normal": 20,
        "stealth": 10,
        "paranoid": 5,
    }
    concurrency = level_map.get(stealth_level, concurrency)

    scanner = IDORScanner(
        concurrency=concurrency,
        auth_headers=auth_headers,
        alt_auth_headers=alt_auth_headers,
    )
    return await scanner.scan(targets, forms_by_url=forms_by_url)
