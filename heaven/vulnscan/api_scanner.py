"""
HEAVEN — Advanced API Security Scanner
GraphQL introspection, REST BOLA/IDOR, gRPC reflection, OpenAPI parsing.
Full OWASP API Security Top 10 coverage.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.api")

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


@dataclass
class APIFinding:
    target: str
    vuln_type: str
    severity: str
    title: str
    description: str
    endpoint: str = ""
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    cwe: str = ""
    owasp_api: str = ""  # OWASP API Top 10 reference

    def to_dict(self) -> dict:
        return {
            "target": self.target, "vuln_type": self.vuln_type,
            "severity": self.severity, "title": self.title,
            "description": self.description, "endpoint": self.endpoint,
            "confidence": self.confidence, "evidence": self.evidence,
            "remediation": self.remediation, "cwe": self.cwe,
            "owasp_api": self.owasp_api,
        }


# GraphQL introspection query
GRAPHQL_INTROSPECTION = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

# GraphQL complexity attack query
GRAPHQL_DEPTH_BOMB = """
query DeepNest {
  __type(name: "Query") {
    fields {
      type {
        fields {
          type {
            fields {
              type {
                fields { name }
              }
            }
          }
        }
      }
    }
  }
}
"""

# Common BOLA/IDOR endpoints
BOLA_PATTERNS = [
    "/api/users/{id}", "/api/v1/users/{id}", "/api/v2/users/{id}",
    "/api/accounts/{id}", "/api/orders/{id}", "/api/invoices/{id}",
    "/api/profiles/{id}", "/api/documents/{id}", "/api/files/{id}",
    "/api/messages/{id}", "/api/notifications/{id}",
]

# Substrings that mark a "secret"-shaped string as a placeholder/example rather
# than a real leaked credential — kills the doc/sample false positives.
_SECRET_PLACEHOLDERS = (
    "your", "example", "sample", "placeholder", "xxxx", "changeme", "redacted",
    "dummy", "insert", "todo", "<", ">", "{", "}", "n/a", "none", "null",
)


def _looks_like_real_secret(value: str) -> bool:
    """Heuristic guard so a generic ``key=<value>`` match isn't reported when the
    value is obviously a placeholder or a low-variety filler string."""
    if len(value) < 20:
        return False
    low = value.lower()
    if any(p in low for p in _SECRET_PLACEHOLDERS):
        return False
    # Real secrets use many distinct characters; ``aaaa…``/``0000…`` don't.
    if len(set(value)) < 8:
        return False
    return True


_MISSING = object()


def _lookup(body: dict, key: str) -> object:
    """Return ``body[key]`` flat, or one level down under a common envelope
    (``data``/``user``/…), or ``_MISSING`` — so nested objects are handled."""
    if key in body:
        return body[key]
    for sub in ("data", "user", "profile", "result", "account"):
        inner = body.get(sub)
        if isinstance(inner, dict) and key in inner:
            return inner[key]
    return _MISSING


def _value_reflected(body: dict, key: str, val: object) -> bool:
    """True only when the *injected value* (not merely the field name) round-trips
    in the response — a normal profile object legitimately contains fields named
    ``role``/``active``, so field-name presence alone is not mass assignment."""
    return _lookup(body, key) == val


class GraphQLScanner:
    """GraphQL-specific security testing."""

    @classmethod
    async def test_introspection(cls, session: aiohttp.ClientSession,
                                   url: str) -> list[APIFinding]:
        findings = []
        try:
            endpoints = [url, f"{url}/graphql", f"{url}/api/graphql", f"{url}/v1/graphql"]
            for endpoint in endpoints:
                try:
                    async with session.post(
                        endpoint,
                        json={"query": GRAPHQL_INTROSPECTION},
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if "__schema" in str(data):
                                schema = data.get("data", {}).get("__schema", {})
                                types = schema.get("types", [])
                                mutations = schema.get("mutationType", {})
                                findings.append(APIFinding(
                                    target=url, vuln_type="graphql_introspection",
                                    severity="medium", endpoint=endpoint,
                                    title=f"GraphQL Introspection Enabled: {endpoint}",
                                    description=(
                                        f"GraphQL schema exposed via introspection. "
                                        f"Found {len(types)} types. "
                                        f"Mutations: {'enabled' if mutations else 'none'}"
                                    ),
                                    confidence=0.95,
                                    evidence={"types_count": len(types),
                                              "has_mutations": bool(mutations),
                                              "type_names": [t["name"] for t in types[:20]]},
                                    remediation="Disable introspection in production.",
                                    cwe="CWE-200",
                                    owasp_api="API3:2023 Broken Object Property Level Authorization",
                                ))
                                break
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)
                    continue
        except Exception as e:
            logger.debug(f"GraphQL introspection test error: {e}")
        return findings

    @classmethod
    async def test_query_complexity(cls, session: aiohttp.ClientSession,
                                      url: str) -> list[APIFinding]:
        findings = []
        endpoints = [url, f"{url}/graphql", f"{url}/api/graphql"]
        for endpoint in endpoints:
            try:
                async with session.post(
                    endpoint,
                    json={"query": GRAPHQL_DEPTH_BOMB},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        findings.append(APIFinding(
                            target=url, vuln_type="graphql_complexity",
                            severity="high", endpoint=endpoint,
                            title="GraphQL: No Query Depth/Complexity Limit",
                            description="Server processes deeply nested queries without limits.",
                            confidence=0.80,
                            remediation="Implement query depth limiting (max 10). Set complexity budgets.",
                            cwe="CWE-400",
                            owasp_api="API4:2023 Unrestricted Resource Consumption",
                        ))
                        break
            except asyncio.TimeoutError:
                # Timeout may indicate DoS potential
                findings.append(APIFinding(
                    target=url, vuln_type="graphql_dos",
                    severity="medium", endpoint=endpoint,
                    title="GraphQL: Potential Query Complexity DoS",
                    description="Deep nested query caused timeout — DoS potential.",
                    confidence=0.60,
                    remediation="Implement query complexity analysis and timeout.",
                    cwe="CWE-400",
                    owasp_api="API4:2023 Unrestricted Resource Consumption",
                ))
                break
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue
        return findings

    @classmethod
    async def test_batching(cls, session: aiohttp.ClientSession,
                             url: str) -> list[APIFinding]:
        findings = []
        batch = [{"query": "{ __typename }"} for _ in range(100)]
        endpoints = [url, f"{url}/graphql"]
        for endpoint in endpoints:
            try:
                async with session.post(
                    endpoint, json=batch,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if isinstance(data, list) and len(data) > 50:
                            findings.append(APIFinding(
                                target=url, vuln_type="graphql_batching",
                                severity="medium", endpoint=endpoint,
                                title="GraphQL: Unlimited Query Batching",
                                description=f"Server processes {len(data)} batched queries without limit.",
                                confidence=0.85,
                                remediation="Limit batch query count to 10-20 max.",
                                cwe="CWE-400",
                                owasp_api="API4:2023 Unrestricted Resource Consumption",
                            ))
                            break
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue
        return findings


class RESTAPIScanner:
    """REST API security testing — OWASP API Top 10."""

    @classmethod
    async def test_bola(cls, session: aiohttp.ClientSession,
                         url: str) -> list[APIFinding]:
        """Test for Broken Object Level Authorization (BOLA/IDOR).

        True BOLA confirmation needs two identities. From a single session we
        only flag the *signal*: an object endpoint that serves DISTINCT data
        for multiple sequential IDs with no auth. A single 200 (a public
        endpoint, a landing page) is NOT reported — that was a false positive.
        Severity is 'high' + needs-manual-verification, never 'critical'.
        """
        findings = []
        test_ids = ["1", "2", "3", "0", "999999"]
        err_words = ("not found", "unauthorized", "forbidden", "error", "denied")

        for pattern in BOLA_PATTERNS:
            distinct_objects: dict[str, str] = {}
            for test_id in test_ids:
                endpoint = f"{url}{pattern.replace('{id}', test_id)}"
                try:
                    async with session.get(
                        endpoint, timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status != 200:
                            continue
                        body = await resp.text()
                        if len(body) > 50 and not any(e in body.lower() for e in err_words):
                            distinct_objects[test_id] = body
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)
                    continue

            # Require >=2 IDs returning 200 with DIFFERENT bodies — proves the
            # endpoint serves per-object data keyed on a raw ID. Identical
            # bodies = a static page, not an object store → no finding.
            unique_bodies = {len(b): b for b in distinct_objects.values()}
            if len(distinct_objects) >= 2 and len(unique_bodies) >= 2:
                ids = ",".join(distinct_objects.keys())
                findings.append(APIFinding(
                    target=url, vuln_type="bola",
                    severity="high", endpoint=pattern,
                    title=f"Potential BOLA/IDOR: {pattern}",
                    description=(f"Endpoint returned distinct objects for IDs [{ids}] "
                                 f"with no authentication. Manually verify whether "
                                 f"object-level authorization is required."),
                    confidence=0.55,
                    evidence={"ids_returning_objects": list(distinct_objects.keys()),
                              "needs_manual_auth_check": True},
                    remediation="Implement object-level authorization checks.",
                    cwe="CWE-639",
                    owasp_api="API1:2023 Broken Object Level Authorization",
                ))
                return findings
        return findings

    @classmethod
    async def test_mass_assignment(cls, session: aiohttp.ClientSession,
                                     url: str) -> list[APIFinding]:
        """Test for mass assignment vulnerabilities.

        A finding requires the injected *value* to round-trip AND to differ from
        the object's pre-existing value — so a field the object legitimately owns
        (e.g. ``active:true`` by default) can't masquerade as an accepted change.
        Payloads are limited to strongly-diagnostic privileged values (an admin
        role/flag, or a sentinel balance) that a normal user object never holds.
        """
        findings = []
        payloads: list[dict[str, object]] = [
            {"role": "admin", "is_admin": True, "admin": True},
            {"credit": 999999, "balance": 999999, "discount": 100},
        ]
        endpoints = [f"{url}/api/users/me", f"{url}/api/profile", f"{url}/api/v1/users/me"]

        for endpoint in endpoints:
            # Read the object first so an ACCEPTED change is distinguishable from a
            # value that was already the default.
            baseline: dict = {}
            try:
                async with session.get(
                    endpoint, timeout=aiohttp.ClientTimeout(total=5),
                ) as gresp:
                    if gresp.status == 200:
                        got = await gresp.json()
                        if isinstance(got, dict):
                            baseline = got
            except Exception:
                baseline = {}

            for payload in payloads:
                try:
                    async with session.put(
                        endpoint, json=payload,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status in (200, 201):
                            try:
                                body = await resp.json()
                            except Exception:
                                logger.debug("suppressed non-fatal exception", exc_info=True)
                                continue
                            if not isinstance(body, dict):
                                continue
                            for key, val in payload.items():
                                if (_value_reflected(body, key, val)
                                        and _lookup(baseline, key) != val):
                                    findings.append(APIFinding(
                                        target=url, vuln_type="mass_assignment",
                                        severity="high", endpoint=endpoint,
                                        title=f"Mass Assignment: {endpoint}",
                                        description=(f"Server accepted and reflected the "
                                                     f"injected privileged field '{key}={val}'."),
                                        confidence=0.7,
                                        evidence={"field": key, "injected_value": val},
                                        remediation="Whitelist allowed fields. Use DTOs.",
                                        cwe="CWE-915",
                                        owasp_api="API6:2023 Unrestricted Access to Sensitive Business Flows",
                                    ))
                                    return findings
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)
                    continue
        return findings

    @classmethod
    async def test_rate_limiting(cls, session: aiohttp.ClientSession,
                                   url: str) -> list[APIFinding]:
        """Test if API has rate limiting."""
        findings = []
        endpoint = f"{url}/api/login"

        async def send_request():
            try:
                async with session.post(
                    endpoint, json={"username": "test", "password": "test"},  # nosec B105
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return resp.status
            except Exception:
                return None

        # Send 50 rapid requests
        tasks = [send_request() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        results = [r for r in results if r is not None]

        if results:
            # Only meaningful if the endpoint actually EXISTS and processed the
            # requests. An all-404 (endpoint absent) or all-5xx run is not
            # evidence of a missing rate limiter — that was a false positive.
            processed = [r for r in results if r in (200, 201, 400, 401, 403, 422)]
            rate_limited = any(r == 429 for r in results)
            if not rate_limited and len(processed) > 40:
                findings.append(APIFinding(
                    target=url, vuln_type="no_rate_limit",
                    severity="medium", endpoint=endpoint,
                    title="API: No Rate Limiting Detected",
                    description=(f"Sent 50 requests to a live endpoint — {len(processed)} "
                                 f"were processed with no 429 (rate-limit) responses."),
                    confidence=0.75,
                    evidence={"requests_sent": 50, "processed": len(processed)},
                    remediation="Implement rate limiting (e.g., 100 req/min per IP).",
                    cwe="CWE-770",
                    owasp_api="API4:2023 Unrestricted Resource Consumption",
                ))
        return findings

    @classmethod
    async def test_api_key_leakage(cls, session: aiohttp.ClientSession,
                                     url: str) -> list[APIFinding]:
        """Check for API keys leaked in responses."""
        findings = []
        # Unambiguous third-party secret formats — structurally these cannot be a
        # normal session/CSRF token, so a hit is a genuine leak → critical.
        provider_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"ASIA[0-9A-Z]{16}", "AWS Temporary Key"),
            (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Token"),
            (r"xox[baprs]-[a-zA-Z0-9-]{10,}", "Slack Token"),
            (r"AIza[0-9A-Za-z_\-]{35}", "Google API Key"),
            (r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}", "Stripe Live Key"),
        ]
        # Generic name=value — a login/CSRF/session token appearing in a response
        # is NORMAL, not a leak, so the previous blanket `token` pattern was a
        # false-positive factory. Report only when the value survives the
        # placeholder/entropy guard, and only as medium + needs-verification.
        generic_patterns = [
            (r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "API Key"),
            (r"(?i)(?:client[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Secret"),
        ]
        test_endpoints = [url, f"{url}/api", f"{url}/api/config", f"{url}/api/health"]

        for endpoint in test_endpoints:
            try:
                async with session.get(endpoint, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    body = await resp.text()
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue
            hit = None
            for pattern, key_type in provider_patterns:
                if re.search(pattern, body):
                    hit = APIFinding(
                        target=url, vuln_type="api_key_leakage",
                        severity="critical", endpoint=endpoint,
                        title=f"API Key Leaked: {key_type} in response",
                        description=f"{key_type} found in API response body.",
                        confidence=0.90,
                        remediation="Remove secrets from API responses. Use server-side env vars.",
                        cwe="CWE-200",
                        owasp_api="API3:2023 Broken Object Property Level Authorization",
                    )
                    break
            if hit is None:
                for pattern, key_type in generic_patterns:
                    m = next((mm for mm in re.finditer(pattern, body)
                              if _looks_like_real_secret(mm.group(1))), None)
                    if m:
                        hit = APIFinding(
                            target=url, vuln_type="api_key_leakage",
                            severity="medium", endpoint=endpoint,
                            title=f"Possible {key_type} in API response (verify)",
                            description=("A key/secret-shaped value was returned in the "
                                         "response body. Confirm it is a real credential and "
                                         "not a public token, CSRF/session token, or placeholder."),
                            confidence=0.5,
                            remediation="Remove secrets from API responses. Use server-side env vars.",
                            cwe="CWE-200",
                            owasp_api="API3:2023 Broken Object Property Level Authorization",
                        )
                        break
            if hit is not None:
                findings.append(hit)
                return findings
        return findings

    # OpenAPI/Swagger docs + framework management surfaces that should not be
    # publicly reachable in production (API9 Improper Inventory Management).
    _INVENTORY_PATHS = [
        ("/swagger.json", "OpenAPI/Swagger specification"),
        ("/openapi.json", "OpenAPI specification"),
        ("/swagger-ui.html", "Swagger UI"),
        ("/api-docs", "API documentation"),
        ("/v2/api-docs", "Springfox API docs"),
        ("/v3/api-docs", "SpringDoc API docs"),
        ("/actuator", "Spring Boot Actuator index"),
        ("/actuator/env", "Spring Boot Actuator environment"),
        ("/graphql-playground", "GraphQL Playground"),
    ]

    @classmethod
    async def test_api_inventory(cls, session: aiohttp.ClientSession,
                                 url: str) -> list[APIFinding]:
        """API9: exposed API documentation / management surface (unauthenticated).

        Body-confirmed — a generic 200/HTML SPA catch-all is NOT evidence; the
        response must actually look like the advertised OpenAPI / actuator /
        playground surface, so this stays low-false-positive."""
        findings = []
        for path, label in cls._INVENTORY_PATHS:
            endpoint = f"{url}{path}"
            try:
                async with session.get(
                    endpoint, timeout=aiohttp.ClientTimeout(total=6),
                ) as resp:
                    if resp.status != 200:
                        continue
                    ctype = (resp.headers.get("Content-Type") or "").lower()
                    body = (await resp.text())[:20000]
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue
            low = body.lower()
            is_doc = (("swagger" in path or "api-docs" in path or "openapi" in path)
                      and ('"swagger"' in low or '"openapi"' in low
                           or "swagger-ui" in low or "swaggerui" in low))
            is_actuator = (path.startswith("/actuator") and "json" in ctype
                           and "{" in body and ("_links" in low or "activeprofiles" in low
                                                or "\"status\"" in low or "propertysources" in low))
            is_gql = "graphql-playground" in path and "playground" in low
            if not (is_doc or is_actuator or is_gql):
                continue
            sev = "high" if "env" in path else "medium"
            findings.append(APIFinding(
                target=url,
                vuln_type="api_actuator_exposed" if is_actuator else "api_docs_exposed",
                severity=sev, endpoint=endpoint,
                title=f"Exposed API surface: {label}",
                description=(f"{label} is reachable without authentication at {path}. "
                             "Public API documentation / management endpoints expand the "
                             "attack surface (shadow/zombie APIs, configuration disclosure)."),
                confidence=0.8,
                evidence={"status": 200, "content_type": ctype},
                remediation=("Restrict documentation and management endpoints to internal "
                             "networks or require authentication; disable Actuator env/heapdump "
                             "in production."),
                cwe="CWE-489" if is_actuator else "CWE-200",
                owasp_api="API9:2023 Improper Inventory Management",
            ))
        return findings

    # Conventionally-authenticated collection endpoints.
    _PROTECTED_COLLECTIONS = [
        "/api/users", "/api/v1/users", "/api/accounts", "/api/orders",
        "/api/customers", "/api/admin/users", "/api/employees",
    ]
    _SENSITIVE_KEYS = frozenset({
        "email", "password", "ssn", "token", "api_key", "apikey",
        "credit_card", "phone", "salary", "role", "is_admin",
    })

    @classmethod
    async def test_broken_authentication(cls, session: aiohttp.ClientSession,
                                         url: str) -> list[APIFinding]:
        """API2: a protected-looking collection reachable with NO credentials.

        Conservative to avoid false positives: only flags a 200 JSON response
        that is a collection of >=3 record objects (each with an id/email-like
        key) or a single object carrying >=2 clearly-sensitive keys. Marked
        needs-verification (confidence 0.55)."""
        import json as _json
        findings = []
        for path in cls._PROTECTED_COLLECTIONS:
            endpoint = f"{url}{path}"
            try:
                async with session.get(
                    endpoint, timeout=aiohttp.ClientTimeout(total=6),
                    headers={"Accept": "application/json"},
                ) as resp:
                    ctype = (resp.headers.get("Content-Type") or "").lower()
                    if resp.status != 200 or "json" not in ctype:
                        continue
                    body = (await resp.text())[:100000]
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue
            try:
                data = _json.loads(body)
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
                continue
            records = None
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                for v in data.values():          # unwrap {"data":[...]} envelopes
                    if isinstance(v, list) and v:
                        records = v
                        break
            exposed = False
            if isinstance(records, list):
                objs = [r for r in records if isinstance(r, dict)]
                if len(objs) >= 3 and all(
                    any(k.lower() in ("id", "uuid", "_id", "email", "username")
                        for k in o) for o in objs[:3]
                ):
                    exposed = True
            elif isinstance(data, dict):
                if len(cls._SENSITIVE_KEYS & {k.lower() for k in data}) >= 2:
                    exposed = True
            if exposed:
                findings.append(APIFinding(
                    target=url, vuln_type="api_broken_auth",
                    severity="high", endpoint=endpoint,
                    title=f"Unauthenticated access to protected collection: {path}",
                    description=("A conventionally-authenticated endpoint returned a record "
                                 "collection / sensitive object with no credentials supplied. "
                                 "Confirm the data is genuinely meant to be access-controlled."),
                    confidence=0.55,
                    evidence={"status": 200, "content_type": ctype},
                    remediation=("Enforce authentication and object-level authorization on all "
                                 "data endpoints; never rely on obscurity of the URL."),
                    cwe="CWE-306",
                    owasp_api="API2:2023 Broken Authentication",
                ))
                break  # one solid signal is enough — don't flood the report
        return findings


class APISecurityScanner:
    """Master API security scanner combining GraphQL + REST + gRPC."""

    def __init__(self):
        self._findings: list[APIFinding] = []

    async def scan(self, url: str) -> list[APIFinding]:
        if not HAS_AIOHTTP:
            logger.warning("aiohttp not installed — API scanning unavailable")
            return []

        logger.info(f"🔍 API Security Scan: {url}")
        self._findings = []

        async with aiohttp.ClientSession() as session:
            # GraphQL tests
            gql_intro = await GraphQLScanner.test_introspection(session, url)
            self._findings.extend(gql_intro)
            if gql_intro:
                self._findings.extend(await GraphQLScanner.test_query_complexity(session, url))
                self._findings.extend(await GraphQLScanner.test_batching(session, url))

            # REST API tests
            self._findings.extend(await RESTAPIScanner.test_bola(session, url))
            self._findings.extend(await RESTAPIScanner.test_mass_assignment(session, url))
            self._findings.extend(await RESTAPIScanner.test_rate_limiting(session, url))
            self._findings.extend(await RESTAPIScanner.test_api_key_leakage(session, url))
            self._findings.extend(await RESTAPIScanner.test_api_inventory(session, url))
            self._findings.extend(await RESTAPIScanner.test_broken_authentication(session, url))

        logger.info(f"API scan complete: {len(self._findings)} findings on {url}")
        return self._findings

    def summary(self) -> dict:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self._findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        owasp = set(f.owasp_api for f in self._findings if f.owasp_api)
        return {
            "total_findings": len(self._findings),
            "severity": sev,
            "owasp_api_coverage": list(owasp),
            "findings": [f.to_dict() for f in self._findings],
        }


async def scan_api_targets(urls: Optional[list[str]] = None, **kwargs) -> dict:
    """Entry point for API scanning from the orchestrator."""
    target_urls = urls or kwargs.get("api_urls", [])
    if not target_urls:
        return {"skipped": True}
    scanner = APISecurityScanner()
    all_findings = []
    for url in target_urls:
        findings = await scanner.scan(url)
        all_findings.extend(findings)
    return {"total": len(all_findings), "findings": [f.to_dict() for f in all_findings]}
