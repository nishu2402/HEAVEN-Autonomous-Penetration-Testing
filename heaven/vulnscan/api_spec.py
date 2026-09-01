"""HEAVEN — spec-driven API surface discovery.

A crawler only sees the endpoints something links to. A real API pentest starts
from the *contract*: the OpenAPI / Swagger document, a Postman collection, or a
GraphQL introspection result enumerate **every** operation the service exposes,
including the ones no page references. This module turns any of those into a
uniform list of :class:`APIOperation` records and expands them to concrete,
same-origin URLs the existing API / injection scanners can test — so coverage is
driven by the spec, not by whatever the crawl happened to reach.

It also builds an **authorization matrix**: role × operation. Given the security
requirement each operation declares (or ``None`` for an unauthenticated one), the
planner produces every (role, operation) pair worth exercising; the analyser then
flags the two classic API access-control breaks from the observed status codes:

  * **BFLA** (Broken Function Level Authorization, OWASP API5) — a lower-privilege
    role successfully invokes an operation it should not reach.
  * **Missing authentication** (OWASP API2) — an operation that declares a
    security requirement answers an anonymous caller with success.

Parsing and analysis are **pure and deterministic** — no network, no optional
heavy dependency (YAML is used only if present; JSON always works). Live
execution of the matrix is done by the caller passing a request-runner callable,
so the same analyser is unit-testable without a server.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.api_spec")

# A placeholder value substituted into a templated path segment so the URL is
# concrete and requestable. Deterministic (not random) so runs are reproducible.
_PATH_PLACEHOLDER = "1"

# Path-parameter styles we normalise to a single form: OpenAPI ``{id}`` and the
# Express/Flask ``:id`` colon style both become ``{id}``.
_COLON_PARAM = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_BRACE_PARAM = re.compile(r"\{([^}/]+)\}")


@dataclass(frozen=True)
class APIOperation:
    """One operation drawn from a spec, format-independent."""
    method: str                      # GET / POST / ...
    path: str                        # /users/{id}
    operation_id: str = ""
    summary: str = ""
    # Names of the security schemes this operation requires. An empty tuple means
    # the spec declares the operation as needing NO authentication.
    security: tuple[str, ...] = ()
    query_params: tuple[str, ...] = ()
    path_params: tuple[str, ...] = ()
    has_body: bool = False
    source: str = ""                 # openapi / postman / graphql

    @property
    def requires_auth(self) -> bool:
        return bool(self.security)

    def concrete_path(self, values: Optional[dict[str, str]] = None) -> str:
        """Fill path-template params with supplied values (or the placeholder)."""
        values = values or {}

        def _sub(m: "re.Match[str]") -> str:
            name = m.group(1)
            return str(values.get(name, _PATH_PLACEHOLDER))

        return _BRACE_PARAM.sub(_sub, self.path)


@dataclass
class APISpec:
    """A parsed API contract: its operations plus the base URL(s) they live on."""
    operations: list[APIOperation] = field(default_factory=list)
    base_urls: list[str] = field(default_factory=list)
    title: str = ""
    version: str = ""
    fmt: str = ""

    def to_urls(self, base_url: Optional[str] = None,
                values: Optional[dict[str, str]] = None) -> list[str]:
        """Concrete, de-duplicated same-origin URLs for every operation.

        ``base_url`` overrides the spec's own server list (needed when the spec
        ships a relative or example server). Query parameters are appended with
        placeholder values so a parameter-aware scanner has something to fuzz."""
        bases = [base_url] if base_url else (self.base_urls or [""])
        seen: set[str] = set()
        out: list[str] = []
        for base in bases:
            base = (base or "").rstrip("/")
            for op in self.operations:
                path = op.concrete_path(values)
                url = f"{base}{path}" if base else path
                # GraphQL args travel in the POST body, not the URL query string.
                if op.query_params and op.source != "graphql":
                    qs = "&".join(f"{p}={_PATH_PLACEHOLDER}" for p in op.query_params)
                    url = f"{url}{'&' if '?' in url else '?'}{qs}"
                if url not in seen:
                    seen.add(url)
                    out.append(url)
        return out


# ── format detection + top-level loader ──────────────────────────────────────

def _coerce_doc(source: Any) -> Any:
    """Accept a dict (already parsed), or JSON / YAML text, and return the doc."""
    if isinstance(source, (dict, list)):
        return source
    text = str(source)
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    try:
        import yaml  # optional; only needed for YAML specs
        return yaml.safe_load(text)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"could not parse API spec as JSON or YAML: {e}") from e


def load_api_spec(source: Any, base_url: Optional[str] = None) -> APISpec:
    """Parse any supported API contract (auto-detected) into an :class:`APISpec`.

    Supports OpenAPI/Swagger v2 + v3 (JSON or YAML), Postman collection v2, and a
    GraphQL introspection result. Raises ``ValueError`` on an unrecognised doc."""
    doc = _coerce_doc(source)
    if not isinstance(doc, dict):
        raise ValueError("API spec is not a JSON/YAML object")
    if "swagger" in doc or "openapi" in doc:
        return parse_openapi(doc, base_url=base_url)
    if isinstance(doc.get("info"), dict) and "item" in doc:
        return parse_postman(doc, base_url=base_url)
    # GraphQL introspection: {"data": {"__schema": ...}} or {"__schema": ...}
    if "__schema" in doc or (isinstance(doc.get("data"), dict)
                             and "__schema" in doc["data"]):
        return parse_graphql_introspection(doc, base_url=base_url)
    raise ValueError("unrecognised API spec (not OpenAPI, Postman, or GraphQL)")


# ── OpenAPI / Swagger (v2 + v3) ──────────────────────────────────────────────

_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def _openapi_base_urls(doc: dict, base_url: Optional[str]) -> list[str]:
    if base_url:
        return [base_url]
    # v3 servers[].url
    servers = doc.get("servers")
    if isinstance(servers, list):
        urls = [str(s.get("url", "")).rstrip("/") for s in servers
                if isinstance(s, dict) and s.get("url")]
        # Skip templated/relative-only servers with no scheme.
        concrete = [u for u in urls if urlparse(u).scheme]
        if concrete:
            return concrete
    # v2 host + basePath + schemes
    host = str(doc.get("host", "")).strip()
    if host:
        scheme = "https"
        schemes = doc.get("schemes")
        if isinstance(schemes, list) and schemes:
            scheme = "https" if "https" in schemes else str(schemes[0])
        base_path = str(doc.get("basePath", "")).rstrip("/")
        return [f"{scheme}://{host}{base_path}"]
    return []


def _security_scheme_names(entries: Any) -> tuple[str, ...]:
    """OpenAPI ``security`` is a list of ``{schemeName: [scopes]}`` maps."""
    names: list[str] = []
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                names.extend(str(k) for k in entry.keys())
    return tuple(dict.fromkeys(names))  # de-dupe, order-preserving


def parse_openapi(doc: dict, base_url: Optional[str] = None) -> APISpec:
    info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
    spec = APISpec(base_urls=_openapi_base_urls(doc, base_url),
                   title=str(info.get("title", "")),
                   version=str(info.get("version", "")), fmt="openapi")
    global_security = _security_scheme_names(doc.get("security"))
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return spec
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            # An operation-level `security: []` explicitly means "no auth".
            if "security" in op:
                sec = _security_scheme_names(op.get("security"))
            else:
                sec = global_security
            q_params, p_params, has_body = _openapi_params(op, item)
            spec.operations.append(APIOperation(
                method=method.upper(), path=str(path),
                operation_id=str(op.get("operationId", "")),
                summary=str(op.get("summary", "")),
                security=sec, query_params=q_params, path_params=p_params,
                has_body=has_body, source="openapi"))
    return spec


def _openapi_params(op: dict, item: dict) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    """Collect query + path parameter names and whether the op takes a body.
    Parameters can sit on the operation or be shared on the path item."""
    q: list[str] = []
    p: list[str] = []
    params = []
    for src in (item.get("parameters"), op.get("parameters")):
        if isinstance(src, list):
            params.extend(x for x in src if isinstance(x, dict))
    for prm in params:
        loc, name = str(prm.get("in", "")), str(prm.get("name", ""))
        if not name:
            continue
        if loc == "query":
            q.append(name)
        elif loc == "path":
            p.append(name)
    has_body = ("requestBody" in op) or any(
        str(x.get("in", "")) == "body" for x in params)
    return tuple(dict.fromkeys(q)), tuple(dict.fromkeys(p)), has_body


# ── Postman collection v2 ────────────────────────────────────────────────────

def parse_postman(doc: dict, base_url: Optional[str] = None) -> APISpec:
    info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
    spec = APISpec(base_urls=[base_url] if base_url else [],
                   title=str(info.get("name", "")), fmt="postman")
    bases: set[str] = set()

    def _walk(items: Any) -> None:
        if not isinstance(items, list):
            return
        for it in items:
            if not isinstance(it, dict):
                continue
            if "item" in it:            # a folder — recurse
                _walk(it.get("item"))
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method", "GET")).upper()
            url = req.get("url")
            raw, path, host = _postman_url(url)
            if host and not base_url:
                bases.add(host)
            q_params = _postman_query(url)
            has_body = bool(req.get("body"))
            # Postman marks auth per-request or inherits; treat presence of an
            # `auth` block (or an Authorization header) as "requires auth".
            sec = ("postman-auth",) if _postman_has_auth(req) else ()
            spec.operations.append(APIOperation(
                method=method, path=path or raw,
                operation_id=str(it.get("name", "")),
                summary=str(it.get("name", "")), security=sec,
                query_params=q_params, has_body=has_body, source="postman"))

    _walk(doc.get("item"))
    if not spec.base_urls and bases:
        spec.base_urls = sorted(bases)
    return spec


def _postman_url(url: Any) -> tuple[str, str, str]:
    """Return (raw, path, host-origin) for a Postman url field (str or object)."""
    if isinstance(url, str):
        pr = urlparse(url)
        origin = f"{pr.scheme}://{pr.netloc}" if pr.scheme else ""
        return url, pr.path or "/", origin
    if isinstance(url, dict):
        raw = str(url.get("raw", ""))
        pr = urlparse(raw)
        origin = f"{pr.scheme}://{pr.netloc}" if pr.scheme else ""
        segs = url.get("path")
        if isinstance(segs, list):
            path = "/" + "/".join(str(s) for s in segs)
        else:
            path = pr.path or "/"
        # Normalise Postman :id path variables to {id}.
        path = _COLON_PARAM.sub(r"{\1}", path)
        return raw, path, origin
    return "", "", ""


def _postman_query(url: Any) -> tuple[str, ...]:
    if isinstance(url, dict) and isinstance(url.get("query"), list):
        return tuple(str(q.get("key")) for q in url["query"]
                     if isinstance(q, dict) and q.get("key"))
    if isinstance(url, str) and "?" in url:
        from urllib.parse import parse_qs
        return tuple(parse_qs(urlparse(url).query).keys())
    return ()


def _postman_has_auth(req: dict) -> bool:
    if isinstance(req.get("auth"), dict):
        return True
    headers = req.get("header")
    if isinstance(headers, list):
        return any(isinstance(h, dict)
                   and str(h.get("key", "")).lower() == "authorization"
                   for h in headers)
    return False


# ── GraphQL introspection ────────────────────────────────────────────────────

def parse_graphql_introspection(doc: dict, base_url: Optional[str] = None) -> APISpec:
    schema = doc.get("__schema")
    if schema is None and isinstance(doc.get("data"), dict):
        schema = doc["data"].get("__schema")
    spec = APISpec(base_urls=[base_url] if base_url else [], fmt="graphql")
    if not isinstance(schema, dict):
        return spec
    type_map = {t.get("name"): t for t in schema.get("types", [])
                if isinstance(t, dict)}
    for kind, root_key in (("query", "queryType"), ("mutation", "mutationType"),
                           ("subscription", "subscriptionType")):
        root = schema.get(root_key)
        if not isinstance(root, dict):
            continue
        tdef = type_map.get(root.get("name"))
        if not isinstance(tdef, dict):
            continue
        for fld in tdef.get("fields", []) or []:
            if not isinstance(fld, dict) or not fld.get("name"):
                continue
            args = tuple(str(a.get("name")) for a in (fld.get("args") or [])
                         if isinstance(a, dict) and a.get("name"))
            # Mutations conventionally require auth; queries may be public. We do
            # not guess — GraphQL has no per-field security in introspection — so
            # security is left empty (the caller can still run the auth matrix).
            spec.operations.append(APIOperation(
                method="POST", path="/graphql",
                operation_id=f"{kind}.{fld['name']}",
                summary=str(fld.get("description") or fld["name"]),
                query_params=args, has_body=True, source="graphql"))
    return spec


# ── Authorization matrix (role × operation) ──────────────────────────────────

@dataclass(frozen=True)
class AuthMatrixCase:
    """One (role, operation) pair to exercise. ``role`` is a caller label; an
    empty role means the anonymous / unauthenticated caller."""
    role: str
    operation: APIOperation
    # Whether this role is *expected* to be authorized for the operation. Unknown
    # by default (None) — the analyser only flags unambiguous breaks.
    expected_allowed: Optional[bool] = None


def plan_auth_matrix(spec: APISpec, roles: list[str],
                     privileged_roles: Optional[set[str]] = None
                     ) -> list[AuthMatrixCase]:
    """Every (role, operation) pair worth testing, plus an anonymous row for each
    operation that declares a security requirement. ``privileged_roles`` (if
    given) marks which roles are *expected* to be allowed on auth-required ops so
    the analyser can flag a non-privileged role that nonetheless succeeds."""
    priv = privileged_roles or set()
    cases: list[AuthMatrixCase] = []
    for op in spec.operations:
        for role in roles:
            expected: Optional[bool] = None
            if op.requires_auth:
                expected = True if role in priv else (False if priv else None)
            cases.append(AuthMatrixCase(role=role, operation=op,
                                        expected_allowed=expected))
        if op.requires_auth:
            # Anonymous must NOT succeed on an auth-required operation.
            cases.append(AuthMatrixCase(role="", operation=op,
                                        expected_allowed=False))
    return cases


def _status_is_success(status: int) -> bool:
    return 200 <= status < 300


def _status_is_denied(status: int) -> bool:
    return status in (401, 403)


def analyze_auth_result(case: AuthMatrixCase, status: int) -> Optional[dict]:
    """Given an observed HTTP status for a matrix case, return a finding dict for
    an access-control break, or ``None`` if the response is consistent with the
    policy. Pure — the caller performs the actual request."""
    op = case.operation
    endpoint = f"{op.method} {op.path}"
    if not case.role:
        # Anonymous caller on an auth-required operation.
        if op.requires_auth and _status_is_success(status):
            return {
                "vuln_type": "api_broken_auth",
                "severity": "high",
                "title": f"Missing authentication on {endpoint}",
                "description": (
                    f"The operation {endpoint} declares a security requirement "
                    f"({', '.join(op.security)}) but returned HTTP {status} to an "
                    f"unauthenticated request. The endpoint is reachable with no "
                    f"credentials."),
                "endpoint": endpoint, "confidence": 0.9,
                "owasp_api": "API2:2023 Broken Authentication",
                "evidence": {"status": status, "role": "anonymous",
                             "security": list(op.security)},
            }
        return None
    # A role that is NOT expected to be allowed but succeeds → BFLA.
    if case.expected_allowed is False and _status_is_success(status):
        return {
            "vuln_type": "api_bfla",
            "severity": "high",
            "title": f"Broken function-level authorization on {endpoint}",
            "description": (
                f"Role '{case.role}', which is not authorized for {endpoint}, "
                f"invoked it successfully (HTTP {status}). Function-level access "
                f"control is not enforced for this role."),
            "endpoint": endpoint, "confidence": 0.85,
            "owasp_api": "API5:2023 Broken Function Level Authorization",
            "evidence": {"status": status, "role": case.role,
                         "security": list(op.security)},
        }
    return None


async def run_auth_matrix(
        cases: list[AuthMatrixCase],
        request: Callable[[str, APIOperation, str], Any],
        base_url: str = "") -> list[dict]:
    """Execute a planned matrix. ``request(role, operation, url)`` is an awaitable
    supplied by the caller that performs the call as ``role`` and returns an HTTP
    status int (or an object with a ``.status`` attribute). Returns the list of
    access-control findings. Kept dependency-injected so it is testable without a
    live server and honours HEAVEN's egress routing when the caller wires it."""
    findings: list[dict] = []
    for case in cases:
        op = case.operation
        url = urljoin(base_url + "/", op.concrete_path().lstrip("/")) if base_url \
            else op.concrete_path()
        try:
            res = await request(case.role, op, url)
        except Exception as e:  # noqa: BLE001 — one failed call never aborts the matrix
            logger.debug("auth-matrix call failed (%s %s): %s", case.role, url, e)
            continue
        status = getattr(res, "status", res)
        try:
            status = int(status)
        except (TypeError, ValueError):
            continue
        hit = analyze_auth_result(case, status)
        if hit:
            hit.setdefault("target", url)
            findings.append(hit)
    return findings


__all__ = [
    "APIOperation", "APISpec", "load_api_spec",
    "parse_openapi", "parse_postman", "parse_graphql_introspection",
    "AuthMatrixCase", "plan_auth_matrix", "analyze_auth_result", "run_auth_matrix",
]
