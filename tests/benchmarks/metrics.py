"""
HEAVEN benchmark — metrics layer
Scanner-agnostic: matches findings against ground truth and computes
precision / recall / F1, both overall and per category.

The two data types live here because the metrics module is the canonical
contract — every reporter consumes BenchmarkResult, every adapter
(HEAVEN, Burp, ZAP, ...) produces a list[Finding].
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# ═══════════════════════════════════════════
# CATEGORY NORMALISATION
# Every scanner names its findings differently. We map raw vuln_type
# strings to a small set of canonical categories so HEAVEN's
# "sqli_boolean" and Burp's "SQL injection" both land in "sqli".
# ═══════════════════════════════════════════

CANONICAL_CATEGORIES = {
    "sqli", "xss", "cmdi", "lfi", "rfi", "ssrf", "ssti", "xxe",
    "csrf", "open_redirect", "weak_auth", "file_upload", "idor",
    "info_disclosure", "auth_bypass", "deserialization",
    "broken_access_control", "security_misconfig",
    # Session/transport & out-of-band classes added with the v1.0 detector
    # expansion (misconfig_scanner + oob_scanner). Kept as distinct categories
    # so the per-category benchmark table credits each one individually.
    "cors", "jwt", "insecure_cookie",
    # Client-side DOM XSS (a source→sink flow in the page's own JavaScript),
    # tracked apart from reflected/stored server-side XSS.
    "dom_xss",
    # ── Network / service tier (the MSF2-class benchmark) ──────────────────
    # These score host/port findings, not URL routes. A "vulnerable_service" is
    # a CVE/exploit-tagged network service (vsftpd backdoor, Samba usermap RCE,
    # distccd, OpenSSH/ProFTPD/Apache/MySQL CVE clusters). The rest split out the
    # distinct service-tier weaknesses so each scores on its own line.
    "vulnerable_service", "backdoor", "cleartext_service", "eol_software",
    "exposed_service", "smb_signing", "smb_null_session", "anonymous_access",
    # ── API tier (OWASP API Security Top 10, the api_scanner benchmark) ─────
    # These score API endpoints, not host:port. Each OWASP-API class scores on
    # its own line: object-level auth (BOLA/API1), broken function/endpoint auth
    # (API2), mass assignment (API3/API6), a leaked secret in a response (API3),
    # exposed docs / management surfaces (API9), and the GraphQL resource classes.
    "bola", "mass_assignment", "api_secret_leak", "api_docs_exposed",
    "api_actuator_exposed", "api_broken_auth",
    "graphql_introspection", "graphql_dos", "graphql_batching",
}

_TYPE_TO_CATEGORY: dict[str, str] = {
    # SQLi family
    "sqli": "sqli", "sql_injection": "sqli", "sqli_blind": "sqli",
    "sqli_error": "sqli", "sqli_union": "sqli", "sqli_boolean": "sqli",
    "sqli_time": "sqli", "blind_sqli": "sqli", "sql injection": "sqli",
    "boolean-based blind sql injection": "sqli",
    "time-based blind sql injection": "sqli",
    # XSS family
    "xss": "xss", "xss_reflected": "xss", "xss_stored": "xss",
    "xss_dom": "xss", "reflected_xss": "xss", "stored_xss": "xss",
    "cross-site scripting": "xss", "cross-site scripting (reflected)": "xss",
    "cross-site scripting (stored)": "xss",
    # Command injection / RCE
    "cmdi": "cmdi", "command_injection": "cmdi", "rce": "cmdi",
    "os_command_injection": "cmdi", "remote_code_execution": "cmdi",
    "os command injection": "cmdi",
    # Path traversal / LFI
    "lfi": "lfi", "local_file_inclusion": "lfi", "path_traversal": "lfi",
    "directory_traversal": "lfi", "file path traversal": "lfi",
    "path traversal": "lfi",
    # Remote file inclusion
    "rfi": "rfi", "remote_file_inclusion": "rfi",
    # SSRF
    "ssrf": "ssrf", "server_side_request_forgery": "ssrf",
    "server-side request forgery": "ssrf",
    # SSTI
    "ssti": "ssti", "server_side_template_injection": "ssti",
    "server-side template injection": "ssti",
    # XXE
    "xxe": "xxe", "xml_external_entity": "xxe",
    "xml external entity injection": "xxe",
    # CSRF
    "csrf": "csrf", "cross_site_request_forgery": "csrf",
    "cross-site request forgery": "csrf",
    # Open redirect
    "open_redirect": "open_redirect", "unvalidated_redirect": "open_redirect",
    "open redirection": "open_redirect", "external service interaction (http)": "open_redirect",
    # CORS misconfiguration
    "cors": "cors", "cors_misconfig": "cors", "cors_misconfiguration": "cors",
    "cross-origin resource sharing": "cors", "permissive cors": "cors",
    # JWT weaknesses (alg:none, crackable HMAC secret)
    "jwt": "jwt", "jwt_alg_none": "jwt", "jwt_none_algorithm": "jwt",
    "jwt_weak_secret": "jwt", "jwt_weak": "jwt", "weak_jwt": "jwt",
    "json web token": "jwt",
    # Insecure session cookies (missing HttpOnly / Secure / SameSite)
    "insecure_cookie": "insecure_cookie", "cookie_no_httponly": "insecure_cookie",
    "cookie_missing_flags": "insecure_cookie", "insecure_session_cookie": "insecure_cookie",
    "cookie without httponly flag": "insecure_cookie",
    "cookie without secure flag": "insecure_cookie",
    # Missing hardening headers → security misconfiguration
    "missing_security_headers": "security_misconfig",
    "security headers": "security_misconfig",
    "missing headers": "security_misconfig",
    # Clickjacking (missing X-Frame-Options / CSP frame-ancestors) is a
    # security misconfiguration (OWASP A02) — same class as the header bundle.
    "clickjacking": "security_misconfig",
    "clickjacking_no_xfo": "security_misconfig",
    # Authentication weaknesses
    "weak_auth": "weak_auth", "weak_credentials": "weak_auth",
    "default_credentials": "weak_auth", "no_rate_limit": "weak_auth",
    "brute_force": "weak_auth", "no_account_lockout": "weak_auth",
    "account_lockout_missing": "weak_auth", "missing_rate_limit": "weak_auth",
    # File upload
    "file_upload": "file_upload", "unrestricted_file_upload": "file_upload",
    # IDOR
    "idor": "idor", "insecure_direct_object_reference": "idor",
    # Misc
    "info_disclosure": "info_disclosure", "information_disclosure": "info_disclosure",
    # Server/framework version leaked in a response header is information
    # disclosure (OWASP A05 Security Misconfiguration). Mapped so a real header
    # leak is credited against a labelled info_disclosure entry rather than being
    # scored as a false positive.
    "server_version_disclosure": "info_disclosure",
    "technology_disclosure": "info_disclosure",
    "auth_bypass": "auth_bypass", "authentication_bypass": "auth_bypass",
    "deserialization": "deserialization", "insecure_deserialization": "deserialization",
    "broken_access_control": "broken_access_control",
    "security_misconfig": "security_misconfig",
    # More missing/weak HTTP security headers → Security Misconfiguration (A05),
    # complementing the header keys above. All real, server-wide gaps; credited
    # against a labelled security_misconfig entry rather than scored as FPs.
    "csp_missing": "security_misconfig", "missing_csp": "security_misconfig",
    "x_frame_options_missing": "security_misconfig",
    "no_x_content_type": "security_misconfig", "x_content_type_missing": "security_misconfig",
    "no_referrer_policy": "security_misconfig", "referrer_policy_missing": "security_misconfig",
    "no_permissions_policy": "security_misconfig",
    "permissions_policy_missing": "security_misconfig",
    # More session-cookie flags → insecure cookie (HttpOnly is mapped above).
    "cookie_no_secure": "insecure_cookie", "cookie_no_samesite": "insecure_cookie",
    "cookie_security": "insecure_cookie",
    # An exposed file / path discloses information (A05 Security Misconfiguration
    # / information disclosure).
    "sensitive_file": "info_disclosure", "directory_listing": "info_disclosure",
    # Client-side DOM XSS sink flows.
    "dom_xss_sink": "dom_xss", "dom_xss": "dom_xss", "dom_based_xss": "dom_xss",
    # ── Network / service tier (MSF2-class) ────────────────────────────────
    # CVE / exploit-tagged network services. cve_mapper emits the generic
    # "vulnerable_service" for every version-matched service CVE (vsftpd
    # backdoor, Samba usermap, distccd, OpenSSH/ProFTPD/Apache/MySQL clusters);
    # the version-unconfirmed roll-up is "potential_vulnerable_service".
    "vulnerable_service": "vulnerable_service",
    "potential_vulnerable_service": "vulnerable_service",
    # Unauthenticated backdoor shell (ingreslock 1524, and any planted shell).
    "backdoor_shell": "backdoor", "backdoor": "backdoor",
    # Plaintext-credential protocols (FTP/Telnet/rexec/rlogin/rsh).
    "cleartext_service": "cleartext_service",
    # End-of-life / unsupported software (its own line, not folded into misconfig
    # so the service tier credits each EOL package distinctly).
    "unsupported_software": "eol_software", "eol_software": "eol_software",
    "end_of_life_software": "eol_software",
    # A dangerous service reachable from the network: exposed DB, Java RMI,
    # distributed Ruby, world-readable NFS export.
    "database_exposed": "exposed_service", "dangerous_service_exposed": "exposed_service",
    "nfs_export_exposed": "exposed_service", "service_exposed": "exposed_service",
    # SMB weaknesses (host-level; no distinct port on the finding).
    "smb_signing_not_required": "smb_signing", "smb_signing": "smb_signing",
    "smb_null_session": "smb_null_session",
    # Anonymous / unauthenticated access to a service (anonymous FTP).
    "ftp_anonymous": "anonymous_access", "anonymous_ftp": "anonymous_access",
    "anonymous_access": "anonymous_access",
    # Service-tier credential weaknesses all land on weak_auth (distinct ports
    # keep them separate): DB default creds, VNC default password, Tomcat
    # manager default creds, SSH default creds.
    "weak_db_credentials": "weak_auth", "vnc_weak_credentials": "weak_auth",
    "tomcat_manager_default_creds": "weak_auth",
    # SMB host/domain banner is information disclosure.
    "domain_information": "info_disclosure", "smb_host_information": "info_disclosure",
    # ── API tier (heaven/vulnscan/api_scanner.py vuln_types) ────────────────
    # OWASP API1 Broken Object Level Authorization (BOLA/IDOR at the object).
    "bola": "bola",
    # OWASP API3/API6 Mass Assignment (an injected privileged field round-trips).
    "mass_assignment": "mass_assignment",
    # OWASP API3 — a real third-party secret returned in a response body.
    "api_key_leakage": "api_secret_leak",
    # OWASP API9 Improper Inventory Management — publicly reachable docs / mgmt.
    "api_docs_exposed": "api_docs_exposed",
    "api_actuator_exposed": "api_actuator_exposed",
    # OWASP API2 Broken Authentication — a protected collection served with no creds.
    "api_broken_auth": "api_broken_auth",
    # GraphQL: schema exposed via introspection (API3) and the two resource-
    # consumption classes (API4) — a deep query with no cost limit / a timeout,
    # and unbounded query batching.
    "graphql_introspection": "graphql_introspection",
    "graphql_complexity": "graphql_dos", "graphql_dos": "graphql_dos",
    "graphql_batching": "graphql_batching",
    # (no_rate_limit is already mapped to weak_auth above — the API "no rate
    # limit on /api/login" finding scores on the weak_auth line.)
}


def normalize_category(vuln_type: str) -> str:
    """Map a raw scanner vuln_type string to a canonical category."""
    if not vuln_type:
        return ""
    key = vuln_type.strip().lower()
    if key in _TYPE_TO_CATEGORY:
        return _TYPE_TO_CATEGORY[key]
    # Best-effort: split on underscores and try the first token
    head = key.split("_")[0]
    return _TYPE_TO_CATEGORY.get(head, key)


def parse_service_port(target: str) -> Optional[int]:
    """Extract the service port from a HEAVEN finding ``target`` string.

    Network findings target a ``host:port`` (``192.168.0.162:445``,
    ``ssh://192.168.0.162:22``); host-level facts target a bare host
    (``192.168.0.162``) and have no port. Returns the port int, or ``None`` for
    a bare host / a web URL with a path (the web matcher ignores port anyway).
    """
    if not target:
        return None
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    # Drop any path/query so a web URL's port isn't mistaken for a service port.
    t = t.split("/", 1)[0].split("?", 1)[0]
    if t.startswith("["):            # [ipv6]:port
        tail = t.split("]:", 1)[1] if "]:" in t else ""
    elif t.count(":") == 1:          # host:port (ipv4 / hostname)
        tail = t.rsplit(":", 1)[1]
    else:                            # bare host, or bare ipv6 → no service port
        tail = ""
    return int(tail) if tail.isdigit() else None


# ═══════════════════════════════════════════
# FINDING / GROUND-TRUTH TYPES
# ═══════════════════════════════════════════


@dataclass
class Finding:
    """One finding produced by a scanner. Tool-agnostic shape."""
    url: str
    vuln_type: str
    parameter: str = ""
    confidence: float = 0.0
    severity: str = ""
    # Service port for network-tier findings (parsed from a host:port target).
    # None for host-level facts and for web URLs (the web matcher ignores it).
    port: Optional[int] = None
    # The specific API route an API-tier finding is about (``/api/users/{id}``,
    # ``/graphql``, ``/openapi.json``). API findings all share one base ``target``,
    # so the route lives in the finding's ``endpoint`` field, not in ``url``.
    endpoint: str = ""

    @property
    def category(self) -> str:
        return normalize_category(self.vuln_type)

    @classmethod
    def from_heaven(cls, d: dict[str, Any]) -> "Finding":
        """Adapt a HEAVEN finding dict (engagement DB row or summary entry)."""
        evidence = d.get("evidence") or {}
        if not isinstance(evidence, dict):
            try:
                evidence = json.loads(evidence) if isinstance(evidence, str) else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                evidence = {}
        target = d.get("target", "") or d.get("url", "")
        return cls(
            url=target,
            vuln_type=d.get("vuln_type", "") or d.get("type", ""),
            parameter=evidence.get("parameter", "") or evidence.get("param", ""),
            confidence=float(d.get("confidence", 0) or 0),
            severity=d.get("severity", ""),
            port=parse_service_port(target),
            endpoint=d.get("endpoint", "") or "",
        )


@dataclass
class GroundTruthEntry:
    """A single labeled vulnerability in a benchmark target."""
    id: str
    endpoint: str
    method: str
    parameter: Optional[str]
    category: str
    subtypes_ok: list[str]
    owasp: str
    cwe: str
    severity: str
    difficulty: str
    detection_required: bool
    notes: str = ""
    # ── Network/service tier ──────────────────────────────────────────────
    # tier="web" (default) → match by URL path + category (unchanged behaviour).
    # tier="network" → match by (service port, category); a null ``port`` means
    # a host-level fact (SMB signing/null session, host banner) matched on
    # category alone against a finding that likewise carries no port.
    tier: str = "web"
    port: Optional[int] = None
    # tier="api" → match by (API route, category). ``endpoint`` is treated as a
    # substring of the finding's endpoint/url (so a GT route ``/api/users/`` matches
    # a finding on ``/api/users/{id}``); an empty ``endpoint`` matches on category
    # alone.


@dataclass
class GroundTruth:
    """A full ground-truth file describing one benchmark target."""
    target_app: str
    version: str
    base_url: str
    vulnerabilities: list[GroundTruthEntry]
    docker_image: str = ""
    auth: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "GroundTruth":
        try:
            import yaml  # PyYAML — added to dev deps; not required at runtime
        except ImportError as e:
            raise RuntimeError(
                "PyYAML required to load benchmark ground truth. Install: pip install pyyaml"
            ) from e
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        # A file-level ``tier`` sets the default for every entry (so a network
        # ground truth doesn't repeat ``tier: network`` on all 40 rows); an
        # individual entry may still override it.
        default_tier = str(data.get("tier", "web"))
        entries = [
            GroundTruthEntry(
                id=v["id"],
                endpoint=v.get("endpoint", ""),
                method=v.get("method", "GET").upper(),
                parameter=v.get("parameter"),
                category=v["category"],
                subtypes_ok=list(v.get("subtypes_ok") or []),
                owasp=v.get("owasp", ""),
                cwe=v.get("cwe", ""),
                severity=v.get("severity", "medium"),
                difficulty=v.get("difficulty", "low"),
                detection_required=bool(v.get("detection_required", True)),
                notes=v.get("notes", ""),
                tier=str(v.get("tier", default_tier)),
                port=v.get("port"),
            )
            for v in data.get("vulnerabilities") or []
        ]
        for entry in entries:
            if entry.category not in CANONICAL_CATEGORIES:
                raise ValueError(
                    f"Ground-truth entry '{entry.id}' has unknown category "
                    f"'{entry.category}'. Add it to CANONICAL_CATEGORIES in "
                    f"tests/benchmarks/metrics.py or fix the YAML."
                )
        return cls(
            target_app=data["target_app"],
            version=str(data.get("version", "")),
            base_url=data["base_url"],
            vulnerabilities=entries,
            docker_image=data.get("docker_image", ""),
            auth=data.get("auth") or {},
        )

    @property
    def required_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.detection_required)


# ═══════════════════════════════════════════
# MATCHER
# ═══════════════════════════════════════════


def matches(finding: Finding, gt: GroundTruthEntry) -> bool:
    """True if `finding` plausibly corresponds to ground-truth entry `gt`.

    Web tier (``gt.tier == "web"``, the default) — all must hold:
      1. The finding URL contains the GT endpoint path.
      2. The finding's canonical category equals GT's category.
      3. If GT specifies a parameter AND the finding reports one, they match.
         (We tolerate missing parameter info on the finding side because not
         every scanner attributes findings to a specific input.)

    Network tier (``gt.tier == "network"``) — a service finding is a host:port,
    not a route, so match on (port, category):
      1. The finding's canonical category equals GT's category.
      2. If GT names a port, the finding must be on that port. If GT's port is
         null (a host-level fact — SMB signing, host banner), the finding must
         likewise be host-level (carry no port), so a port-specific finding on
         the same host cannot spuriously satisfy it.

    API tier (``gt.tier == "api"``) — API findings share one base target and carry
    the route in ``endpoint``, so match on category plus the GT route appearing in
    the finding's endpoint/url (an empty GT route matches on category alone).
    """
    if gt.tier == "network":
        if finding.category != gt.category:
            return False
        if gt.port is None:
            return finding.port is None
        return finding.port == gt.port

    if gt.tier == "api":
        # API findings share one base target; the route is in ``endpoint``. Match
        # on category, and on the GT route appearing in the finding's endpoint (or
        # url, since some detectors put the full route there). An empty GT route
        # matches on category alone (a host-wide API fact).
        if finding.category != gt.category:
            return False
        if not gt.endpoint:
            return True
        haystack = f"{finding.endpoint or ''} {finding.url or ''}"
        return gt.endpoint in haystack

    if not gt.endpoint or gt.endpoint not in (finding.url or ""):
        return False
    if finding.category != gt.category:
        return False
    if gt.parameter and finding.parameter:
        if finding.parameter.lower() != gt.parameter.lower():
            return False
    return True


# ═══════════════════════════════════════════
# RESULT TYPE
# ═══════════════════════════════════════════


@dataclass
class BenchmarkResult:
    """Outcome of one benchmark run."""
    target_app: str
    total_gt: int
    total_required: int
    detected_gt_ids: set[str] = field(default_factory=set)
    detected_required_ids: set[str] = field(default_factory=set)
    matched_finding_count: int = 0
    unmatched_finding_count: int = 0
    # Per-category counters: cat → {tp_gt, fn_gt, fp_findings, total_findings}
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    unmatched_findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0

    # ── derived metrics ──────────────────────────────────────────────────

    @property
    def detected_count(self) -> int:
        return len(self.detected_gt_ids)

    @property
    def missed_required_count(self) -> int:
        # required_count - detected_required_count
        return self.total_required - len(self.detected_required_ids)

    @property
    def precision(self) -> float:
        """TP / (TP + FP) — fraction of findings that were real."""
        tp = self.matched_finding_count
        fp = self.unmatched_finding_count
        denom = tp + fp
        return tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN) — fraction of REQUIRED GT entries we detected.

        We compute recall against detection_required entries only, so
        opportunistic findings (e.g., stored XSS, file upload) don't drag
        the headline number down for scanners that don't probe for them.
        """
        if self.total_required == 0:
            return 0.0
        return len(self.detected_required_ids) / self.total_required

    @property
    def recall_overall(self) -> float:
        """Recall across ALL GT entries (including nice-to-haves)."""
        if self.total_gt == 0:
            return 0.0
        return self.detected_count / self.total_gt

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)


# ═══════════════════════════════════════════
# EVALUATE
# ═══════════════════════════════════════════


def evaluate(findings: list[Finding], gt: GroundTruth,
             duration_seconds: float = 0.0) -> BenchmarkResult:
    """Run all findings against all GT entries, return a BenchmarkResult."""
    detected_gt_ids: set[str] = set()
    detected_required_ids: set[str] = set()
    matched_count = 0
    unmatched: list[Finding] = []
    per_cat: dict[str, dict[str, int]] = {}

    # Findings → GT matching
    for f in findings:
        matched_any = False
        for entry in gt.vulnerabilities:
            if matches(f, entry):
                detected_gt_ids.add(entry.id)
                if entry.detection_required:
                    detected_required_ids.add(entry.id)
                matched_any = True
                # Don't break — one finding may correspond to multiple GT
                # entries (e.g., same endpoint at different difficulty levels)
        if matched_any:
            matched_count += 1
        else:
            unmatched.append(f)

        cat = f.category
        cat_bucket = per_cat.setdefault(
            cat, {"findings": 0, "matched": 0, "unmatched": 0}
        )
        cat_bucket["findings"] += 1
        if matched_any:
            cat_bucket["matched"] += 1
        else:
            cat_bucket["unmatched"] += 1

    # Attribute missed GT entries to their category for the FN side
    for entry in gt.vulnerabilities:
        cat_bucket = per_cat.setdefault(
            entry.category,
            {"findings": 0, "matched": 0, "unmatched": 0},
        )
        cat_bucket.setdefault("gt_total", 0)
        cat_bucket.setdefault("gt_detected", 0)
        cat_bucket["gt_total"] += 1
        if entry.id in detected_gt_ids:
            cat_bucket["gt_detected"] += 1

    return BenchmarkResult(
        target_app=gt.target_app,
        total_gt=len(gt.vulnerabilities),
        total_required=gt.required_count,
        detected_gt_ids=detected_gt_ids,
        detected_required_ids=detected_required_ids,
        matched_finding_count=matched_count,
        unmatched_finding_count=len(unmatched),
        per_category=per_cat,
        unmatched_findings=unmatched,
        duration_seconds=duration_seconds,
    )


# ═══════════════════════════════════════════
# MULTI-RUN AGGREGATION
# Publication requires "X% ± Y%" — single-run numbers are unreliable
# for tools that have randomness (multi-armed bandit explore step,
# timing-based detection noise).
# ═══════════════════════════════════════════


@dataclass
class AggregatedResult:
    target_app: str
    runs: int
    mean_precision: float
    std_precision: float
    mean_recall: float
    std_recall: float
    mean_f1: float
    std_f1: float
    mean_duration_s: float
    std_duration_s: float
    # Per-category recall mean (the most useful publication number)
    per_category_recall: dict[str, float]
    # The min/max number of required GT entries missed across runs
    missed_required_min: int
    missed_required_max: int


def _stdev(xs: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    return statistics.stdev(xs)


def aggregate(runs: list[BenchmarkResult]) -> AggregatedResult:
    """Combine N runs into mean ± stddev for publication."""
    if not runs:
        raise ValueError("aggregate() requires at least one run")
    target = runs[0].target_app

    precisions = [r.precision for r in runs]
    recalls = [r.recall for r in runs]
    f1s = [r.f1 for r in runs]
    durations = [r.duration_seconds for r in runs]
    missed = [r.missed_required_count for r in runs]

    # Per-category recall: for each category present in any run, average
    # gt_detected / gt_total
    cats: set[str] = set()
    for r in runs:
        cats.update(r.per_category.keys())
    per_cat_recall: dict[str, float] = {}
    for cat in sorted(cats):
        ratios = []
        for r in runs:
            bucket = r.per_category.get(cat, {})
            total = bucket.get("gt_total", 0)
            detected = bucket.get("gt_detected", 0)
            if total:
                ratios.append(detected / total)
        if ratios:
            per_cat_recall[cat] = sum(ratios) / len(ratios)

    return AggregatedResult(
        target_app=target,
        runs=len(runs),
        mean_precision=sum(precisions) / len(precisions),
        std_precision=_stdev(precisions),
        mean_recall=sum(recalls) / len(recalls),
        std_recall=_stdev(recalls),
        mean_f1=sum(f1s) / len(f1s),
        std_f1=_stdev(f1s),
        mean_duration_s=sum(durations) / len(durations) if durations else 0.0,
        std_duration_s=_stdev(durations),
        per_category_recall=per_cat_recall,
        missed_required_min=min(missed),
        missed_required_max=max(missed),
    )
