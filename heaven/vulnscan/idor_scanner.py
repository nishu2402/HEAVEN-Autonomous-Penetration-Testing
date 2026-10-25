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
from heaven.net.egress import client_session as _egress_cs  # egress-routed aiohttp

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
from heaven.vulnscan import proof_capture

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


def _sensitive_markers(body: str, *, limit: int = 8,
                       strong_only: bool = False) -> list[str]:
    """Return distinct snippets of any sensitive-data markers in a response body —
    the signal that an altered-ID response actually exposed a record's private
    data rather than merely returning a different (possibly public) object.

    Every distinct match is collected (not just the first per pattern) so the
    IDOR verdict can diff the altered-object response against the attacker's own:
    a marker present in BOTH (a site-wide footer email, a published contact
    address) is page furniture, not another user's record, and must not count.

    ``strong_only`` drops the bare-email pattern (``_SENSITIVE_MARKERS[0]``),
    which matches a contact address anywhere in free text. The unauthenticated-
    access check has no second response to diff furniture away against (its auth
    and unauth bodies are identical by construction), so a site-wide footer email
    on a public page would otherwise read as a protected record. It instead
    requires a *structured record* marker (a JSON key such as ``"ssn":`` /
    ``"first_name":`` / ``"credit_card":``) that does not appear on an ordinary
    public page carrying only a contact email."""
    found: list[str] = []
    seen: set[str] = set()
    for rx in (_SENSITIVE_MARKERS[1:] if strong_only else _SENSITIVE_MARKERS):
        for m in rx.finditer(body or ""):
            snippet = m.group(0)[:48]
            if snippet not in seen:
                seen.add(snippet)
                found.append(snippet)
            if len(found) >= limit:
                return found
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
    # Only sensitive values that appear in the ALTERED-id response but NOT in the
    # attacker's own (original) response signal a cross-record leak. Markers common
    # to both responses — a site-wide footer email, a contact phone number — are
    # page furniture present on every object and would otherwise flag ordinary
    # public enumeration (e.g. /product/1 → /product/2) as a false IDOR.
    orig_markers = set(_sensitive_markers(orig_body))
    new_markers = [m for m in _sensitive_markers(test_body) if m not in orig_markers]
    if new_markers:
        return ("idor", "medium", 0.6,
                {"signals": ["sensitive_data_exposed"], "sensitive_markers": new_markers})
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
            status, body = resp.status, await resp.text(errors="replace")
            proof_capture.record(url, status, body)
            return status, body
    except Exception:
        return 0, ""


async def _post(session, url: str, data: dict, headers: dict, timeout: float = 10.0) -> tuple[int, str]:
    try:
        async with session.post(
            url, json=data, headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True, ssl=False,
        ) as resp:
            status, body = resp.status, await resp.text(errors="replace")
            proof_capture.record(url, status, body)
            return status, body
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
                    title = (f"IDOR: path ID enumeration (/{seg}/ → /{candidate}/)"
                             if vt == "idor" else
                             f"Enumerable object reference: path /{seg}/ → /{candidate}/")
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
                        title = (f"IDOR: parameter enumeration (?{param}={candidate})"
                                 if vt == "idor" else
                                 f"Enumerable object reference: ?{param}={candidate}")
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
                        title = (f"IDOR: UUID enumeration (?{param})" if vt == "idor"
                                 else f"Enumerable object reference: UUID ?{param}")
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
                                "UUIDs are not a security control, they must be paired with authz checks."
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

        if not (status_a == 200 and status_b == 200
                and not _body_differs(body_a, body_b)):
            return

        # Both authenticated users see the same object — but that is only IDOR if
        # the resource is genuinely access-controlled. Confirm an UNAUTHENTICATED
        # request is denied (or served different content) first: if an anonymous
        # client gets the same body, the resource is public/shared (a catalog item,
        # a published page) and two users seeing it is expected, not a broken-
        # authorization finding. This mirrors the anon-denied proof the multi-role
        # access_control audit requires and removes a critical-severity false
        # positive on shared, ID-bearing endpoints.
        no_auth = {"User-Agent": "HEAVEN-Scanner/1.0"}
        async with self._slot():
            status_anon, body_anon = await _get(session, url, no_auth)
        if status_anon == 200 and not _body_differs(body_a, body_anon):
            return  # resource is public, not an authorization break

        self._add(
            target=url,
            vuln_type="idor",
            title="IDOR: Horizontal privilege escalation (dual-session access)",
            severity="critical",
            confidence=0.92,
            evidence={
                "probe_type": "horizontal_privesc",
                "param": "session_token",
                "anonymous_status": status_anon,
                "detail": "Alternate user token reads this access-controlled resource "
                          "with an identical response (an anonymous request is denied).",
            },
            remediation=(
                "Ensure server-side ownership checks are applied to every object request. "
                "Never rely solely on the object ID for authorization."
            ),
            cwe="CWE-639",
        )

    # ── Cross-identity BOLA with ground truth ─────────────────────

    def _id_sites(self, url: str) -> list[tuple[str, str, int]]:
        """Return (kind, original_id, int_value) for each enumerable integer ID
        in ``url`` (path segment or object-ish query param). UUIDs are skipped
        here because they cannot be walked to a neighbour deterministically."""
        sites: list[tuple[str, str, int]] = []
        parsed = urlparse(url)
        for seg in parsed.path.split("/"):
            if _RE_INT_SEGMENT.match(seg):
                sites.append(("path", seg, int(seg)))
        for param, values in parse_qs(parsed.query, keep_blank_values=True).items():
            v = values[0] if values else ""
            if _RE_OBJECT_PARAM.match(param) and _RE_INT_SEGMENT.match(v):
                sites.append((f"param:{param}", v, int(v)))
        return sites

    def _with_id(self, url: str, kind: str, original: str, new: str) -> str:
        if kind == "path":
            return _replace_path_segment(url, original, new)
        return _replace_qs_param(url, kind.split(":", 1)[1], new)

    async def _test_cross_identity_bola(self, session, url: str) -> None:
        """True BOLA with a ground-truth RECIPROCAL cross-read.

        Beyond the same-URL swap heuristic: user A owns object X (the URL's own
        id); we walk to a neighbouring id Y that user B can read. We then prove
        the authorization boundary is broken in BOTH directions — A reads Y with
        exactly B's authenticated view of it, and B reads X with exactly A's view
        of it — while X and Y are genuinely distinct objects (their raw bodies are
        not equal) and anonymous requests to both are denied. The reciprocal
        cross-read cannot be explained by shared authenticated content (that would
        make X and Y identical, excluded here) nor by one account simply owning
        both, so it is a confirmed object-level authorization break, not a guess.

        Exact (whitespace-normalised) inequality tells X from Y, so a per-user
        record that differs only in its data fields is still recognised as a
        distinct object; the ``_body_differs`` tolerance is used only for the
        cross-view MATCHES, where small per-request noise (nonces, timestamps)
        must not break the comparison."""
        if not self._alt_headers:
            return
        sites = self._id_sites(url)
        if not sites:
            return

        def _n(b: str) -> str:
            return " ".join((b or "").split())

        kind, original, value = sites[0]
        async with self._slot():
            status_ax, body_ax = await _get(session, url, self._base_headers)  # A's own X
        if status_ax != 200 or not body_ax:
            return

        for cand in (value + 1, value - 1):
            if cand <= 0 or cand == value:
                continue
            y_url = self._with_id(url, kind, original, str(cand))
            async with self._slot():
                status_by, body_by = await _get(session, y_url, self._alt_headers)  # B's own Y
            if status_by != 200 or not body_by:
                continue
            # X and Y must be genuinely DIFFERENT objects (exact inequality, so a
            # shared/cloned page — identical for both users — is excluded, while a
            # templated per-user record that differs only in data still qualifies).
            if _n(body_ax) == _n(body_by):
                continue
            async with self._slot():
                status_ay, body_ay = await _get(session, y_url, self._base_headers)  # A reads Y
                status_bx, body_bx = await _get(session, url, self._alt_headers)     # B reads X
                status_anon_y, body_anon_y = await _get(
                    session, y_url, {"User-Agent": "HEAVEN-Scanner/1.0"})
                status_anon_x, body_anon_x = await _get(
                    session, url, {"User-Agent": "HEAVEN-Scanner/1.0"})
            # Both objects must be access-controlled (anon denied or different).
            if status_anon_y == 200 and not _body_differs(body_by, body_anon_y):
                continue
            if status_anon_x == 200 and not _body_differs(body_ax, body_anon_x):
                continue
            # Reciprocal cross-read: A sees B's Y and B sees A's X, each matching
            # the owner's authenticated view (tolerant of per-request noise).
            a_reads_y = status_ay == 200 and not _body_differs(body_ay, body_by)
            b_reads_x = status_bx == 200 and not _body_differs(body_bx, body_ax)
            if a_reads_y and b_reads_x:
                self._add(
                    target=y_url,
                    vuln_type="bola",
                    title="BOLA: cross-identity object access (reciprocal, ground-truth)",
                    severity="critical",
                    confidence=0.96,
                    evidence={
                        "probe_type": "cross_identity_bola",
                        "param": kind,
                        "own_object_url": url,
                        "other_object_url": y_url,
                        "own_id": original,
                        "other_id": str(cand),
                        "anonymous_status_x": status_anon_x,
                        "anonymous_status_y": status_anon_y,
                        "proof": (
                            f"user A read object {cand} with exactly user B's "
                            f"authenticated view, and user B read object {original} "
                            "with exactly user A's view (two distinct, access-"
                            "controlled objects; anonymous access denied) — a "
                            "confirmed object-level authorization break."),
                    },
                    remediation=(
                        "Enforce object-level authorization on every request: verify "
                        "the authenticated principal owns or is granted the specific "
                        "object id before returning it. Do not rely on the id alone."),
                    cwe="CWE-639",
                )
                return

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
                        title=f"Mass Assignment: field '{extra_field}' reflected",
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
        broken-access-control finding. The sensitive-data gate requires a
        *structured record* marker (``strong_only``) rather than a bare email: a
        public id'd page (``/blog/42``) that merely shows a contact address in its
        footer returns the same body with or without auth and would otherwise fire
        this critical finding, which is page furniture, not a protected object.
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
                and _sensitive_markers(unauth_body, strong_only=True)):
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
        time_budget: Optional[float] = None,
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
        async with _egress_cs(connector=connector) as session:
            tasks = []
            for url in unique:
                forms = (forms_by_url or {}).get(url, [])
                tasks.append(self._test_path_ids(session, url))
                tasks.append(self._test_param_ids(session, url))
                tasks.append(self._test_horizontal_privesc(session, url))
                tasks.append(self._test_cross_identity_bola(session, url))
                tasks.append(self._test_unauth_access(session, url))
                if forms:
                    tasks.append(self._test_mass_assignment(session, url, forms))
            # Budget-aware: each probe appends to self._findings as it finishes,
            # so probes completed before the soft deadline are kept; the rest are
            # cancelled instead of the orchestrator's hard timeout dropping all of
            # them (same salvage as the injection sweep).
            from heaven.utils.fanout import gather_budgeted
            _done, truncated = await gather_budgeted(
                tasks, time_budget=time_budget)

        logger.info(f"IDORScanner: {len(self._findings)} findings")
        out: dict = {
            "findings": self._findings,
            "urls_tested": len(unique),
            "urls_requested": len(unique),
            "error": None,
        }
        if truncated:
            out["budget_exhausted"] = True
            logger.warning(
                "IDORScanner: soft budget reached; %d of %d probe(s) completed, "
                "returning partial findings", len(_done), len(tasks))
        return out


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
    time_budget: Optional[float] = None,
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
    return await scanner.scan(targets, forms_by_url=forms_by_url,
                              time_budget=time_budget)


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
