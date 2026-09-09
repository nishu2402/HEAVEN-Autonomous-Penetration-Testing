"""
HEAVEN — Vulnerability Correlation & Combination Advisor.

A real pentester rarely reports findings in isolation. The value is in
recognising that two or three *individually* moderate issues, when combined,
form a single materially worse problem. A local file read plus an unrestricted
upload is not "two highs" — together they are remote code execution. This module
is the piece that spots those combinations and says so, explicitly, then hands
the operator the concrete, target-grounded steps to prove and exploit the chain.

Given a set of findings (from a scan, the engagement store, or a list the
operator submits), the engine:

  * matches them against a curated set of well-established amplification
    patterns (each one a combination offensive-security practitioners genuinely
    treat as greater than the sum of its parts),
  * emits one ``CombinationFinding`` per genuine match, naming the emergent
    vulnerability, the elevated severity, the constituent findings it is built
    from, why the combination is worse, the prerequisites that must hold, an
    ordered exploitation/validation playbook rendered against the *real* URLs,
    parameters and ports of the matched findings, and the single cheapest link
    to break,
  * scores each combination for actionability and priority so an operator can
    see what to attempt first,
  * NEVER fabricates. A combination is surfaced only when every required slot is
    filled by a *distinct* real finding and the emergent severity is strictly
    higher than the strongest constituent (otherwise there is nothing to
    "elevate" and it is not reported). Confidence tracks the weakest link, and a
    combination is only "Confirmed" when every constituent finding is confirmed.
    The playbook is written as benign, bounded, in-scope proof steps, never as a
    claim that exploitation has already happened.

Design notes:
  * Deterministic and dependency-free — no LLM required. It reuses the existing
    severity/CVSS/confirmation helpers so its output is consistent with the rest
    of the platform (``heaven.utils.cvss``).
  * The playbook and prerequisites are *templated* against each matched
    finding's evidence: a ``{s0.url}`` / ``{s1.param}`` token is replaced with
    the real value pulled from the finding when known, or a clearly-marked
    ``<placeholder>`` when the scan did not capture it — so a step is always
    honest about what is known versus what the operator must still supply.
  * This is distinct from ``heaven.vulnscan.attack_chain`` (which builds
    recon → impact *paths*) and ``heaven.ai.attack_chain_planner`` (which orders
    per-host steps). Those answer "how would an attacker move?"; this answers
    "which of my findings should be merged and re-rated upward, why, and how do
    I prove it against this target?".
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from heaven.utils.cvss import is_confirmed_finding, score_from_label
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.correlation")

# Canonical qualitative severity ranking. Kept local so this module does not
# depend on a private constant elsewhere; identical ordering to the rest of the
# platform (info < low < medium < high < critical).
_SEV_RANK: dict[str, int] = {"info": 0, "none": 0, "low": 1, "medium": 2,
                             "moderate": 2, "high": 3, "critical": 4}
_RANK_SEV: dict[int, str] = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _sev_rank(severity: Any) -> int:
    return _SEV_RANK.get(str(severity or "").strip().lower(), 0)


def _host_of(finding: dict) -> str:
    """Best-effort host/origin key for a finding, so same-host combinations are
    only formed from findings that actually share an exploitation surface."""
    raw = str(finding.get("target") or finding.get("url")
              or finding.get("host") or finding.get("asset") or "").strip()
    if not raw:
        return "unknown-host"
    if "://" in raw:
        return (urlparse(raw).hostname or raw).strip() or "unknown-host"
    return raw.split("/", 1)[0].split(":", 1)[0].strip() or "unknown-host"


def _haystack(finding: dict) -> str:
    """Lowercased text used for keyword matching a finding to a component slot."""
    return " ".join(
        str(finding.get(k, "")) for k in ("vuln_type", "type", "title", "cve_id", "name")
    ).lower()


def _confidence_of(finding: dict) -> float:
    """A finding's confidence in [0,1], defaulting to 0.5 when unstated so a
    combination is neither over- nor under-stated on missing data."""
    try:
        c = float(finding.get("confidence") or 0.0)
    except (TypeError, ValueError):
        c = 0.0
    return c if c > 0 else 0.5


# ── Evidence extraction ──────────────────────────────────────────────────────
# The whole point of "actually helps with the target" is that a combination's
# steps reference the finding's REAL attack surface. This pulls the concrete
# bits (url, parameter, port, method, CVE) out of a finding so the playbook can
# be rendered against them. Everything is best-effort and honest: a field that
# was not captured stays empty and renders as an explicit placeholder.

# Keys various detectors use to record the vulnerable parameter / injection point.
_PARAM_KEYS = ("parameter", "param", "vuln_param", "vulnerable_parameter",
               "injection_point", "field", "inputName", "input_name")
_PORT_KEYS = ("port", "dst_port", "service_port", "remote_port")
_METHOD_KEYS = ("method", "http_method", "verb")
_SCHEME_DEFAULT_PORT = {"http": "80", "https": "443", "ftp": "21", "ssh": "22"}


def _evidence(finding: dict) -> dict[str, str]:
    """Extract concrete, target-specific evidence fields from a finding.

    Returns a dict of string fields (empty when unknown) used to render the
    playbook/prerequisite templates: ``url``, ``host``, ``port``, ``path``,
    ``param``, ``method``, ``cve``, ``url_with_param`` and ``title``.
    """
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    url = str(finding.get("target") or finding.get("url") or finding.get("host") or "").strip()
    parsed = urlparse(url) if "://" in url else None
    host = _host_of(finding)

    port = ""
    if parsed is not None and parsed.port:
        port = str(parsed.port)
    if not port:
        for k in _PORT_KEYS:
            v = finding.get(k) or ev.get(k)
            if v:
                port = str(v)
                break
    if not port and parsed is not None:
        port = _SCHEME_DEFAULT_PORT.get((parsed.scheme or "").lower(), "")

    path = parsed.path if parsed is not None else ""

    param = ""
    for k in _PARAM_KEYS:
        v = finding.get(k) or ev.get(k)
        if v:
            param = str(v)
            break
    if not param and parsed is not None and parsed.query:
        param = parsed.query.split("&", 1)[0].split("=", 1)[0]

    method = ""
    for k in _METHOD_KEYS:
        v = finding.get(k) or ev.get(k)
        if v:
            method = str(v).upper()
            break

    cve = str(finding.get("cve_id") or finding.get("cve") or "").strip()

    base = url.split("?", 1)[0]
    if url and param:
        url_with_param = f"{base}?{param}="
    elif url:
        url_with_param = f"{base}?<param>="
    else:
        url_with_param = ""

    return {
        "url": url,
        "host": host if host and host != "unknown-host" else "",
        "port": port,
        "path": path,
        "param": param,
        "method": method,
        "cve": cve,
        "url_with_param": url_with_param,
        "title": str(finding.get("title") or finding.get("vuln_type")
                     or finding.get("type") or ""),
    }


# Placeholder shown when a template references a field the scan did not capture,
# so a step stays readable and honestly signals "operator supplies this".
_FIELD_FALLBACK: dict[str, str] = {
    "url": "<target-URL>",
    "url_with_param": "<target-URL>?<param>=",
    "host": "<host>",
    "port": "<port>",
    "path": "<path>",
    "param": "<param>",
    "method": "<method>",
    "cve": "<CVE>",
    "title": "the finding",
}

_TOKEN_RE = re.compile(r"\{s(\d+)\.([a-z_]+)\}")


def _render(template: str, evidences: list[dict[str, str]]) -> str:
    """Render a ``{sN.field}`` template against per-slot evidence dicts.

    ``sN`` indexes the matched findings in the rule's slot order; ``field`` is
    an evidence key. A known value is substituted verbatim; an unknown one falls
    back to an explicit ``<placeholder>`` so the step never silently lies.
    """
    def repl(m: "re.Match[str]") -> str:
        idx = int(m.group(1))
        fld = m.group(2)
        if 0 <= idx < len(evidences):
            val = evidences[idx].get(fld, "")
            if val:
                return val
        return _FIELD_FALLBACK.get(fld, m.group(0))

    return _TOKEN_RE.sub(repl, template)


# ── Component predicate ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class Component:
    """One required slot in an amplification rule.

    ``slot`` is a human label for the role; ``any_of`` is the set of lowercase
    keywords, any one of which (as a substring of the finding's type/title/CVE)
    makes a finding eligible to fill the slot.
    """
    slot: str
    any_of: tuple[str, ...]

    def matches(self, finding: dict) -> bool:
        hay = _haystack(finding)
        return any(k in hay for k in self.any_of)


@dataclass(frozen=True)
class AmplificationRule:
    """A curated combination whose emergent severity exceeds its parts."""
    rule_id: str
    name: str                       # the emergent (combined) vulnerability name
    components: tuple[Component, ...]
    combined_severity: str          # emergent severity if the combination holds
    impact: str                     # business impact of the emergent issue
    rationale: str                  # why the combination is worse than the parts
    mitre: tuple[str, ...] = ()
    cwe: str = ""
    owasp: str = ""
    cross_host: bool = False        # slots may span hosts (e.g. credential reuse)
    phase: str = ""                 # where the emergent issue sits in a kill chain
    prerequisites: tuple[str, ...] = ()   # conditions that must hold to chain
    playbook: tuple[str, ...] = ()         # ordered, templated proof/exploit steps


# ── Curated amplification rules ──────────────────────────────────────────────
# Every rule encodes a combination that real-world testers treat as a distinct,
# higher-impact vulnerability. Keywords are chosen to match HEAVEN's own finding
# vocabulary so rules fire on genuine findings. The playbook/prerequisites are
# rendered against each matched finding's real evidence at build time. Steps are
# written as benign, bounded, in-scope proof actions. Ordered roughly by impact.

AMPLIFICATION_RULES: tuple[AmplificationRule, ...] = (
    AmplificationRule(
        rule_id="lfi_upload_rce",
        name="Local File Inclusion + File Upload → Remote Code Execution",
        components=(
            Component("File read / inclusion",
                      ("lfi", "local_file", "path_traversal", "directory_traversal",
                       "file_inclusion")),
            Component("Unrestricted upload",
                      ("file_upload", "unrestricted_upload", "arbitrary_file_upload",
                       "upload")),
        ),
        combined_severity="critical",
        impact=("An attacker uploads a script to a known path and then includes/"
                "executes it through the inclusion flaw, gaining code execution on "
                "the server."),
        rationale=("Neither issue is code execution alone: the upload lands a file "
                   "but may not be directly reachable, and the inclusion reads files "
                   "but has nothing malicious to read. Together they close the loop "
                   "into reliable RCE."),
        mitre=("T1190", "T1505.003"),
        cwe="CWE-434",
        owasp="A03:2021 Injection",
        phase="Exploitation → Code Execution",
        prerequisites=(
            "The uploaded file lands at a path the inclusion flaw can reach on the same host.",
            "The server executes the uploaded content (for example a PHP handler is enabled) "
            "or the inclusion evaluates the file it includes.",
        ),
        playbook=(
            "Upload a benign marker (for example a script that prints a unique token) via "
            "the upload endpoint (POST to {s1.url}) and record the stored path from the response.",
            "Verify the inclusion reads attacker-influenced paths: request {s0.url_with_param}/etc/passwd "
            "and confirm file contents come back.",
            "Chain them: set the inclusion parameter to the uploaded file's path (for example "
            "{s0.url_with_param}<uploaded-path>) and confirm the marker token executes, proving code execution.",
            "Within scope, run a single proof command through the execution and capture its output as evidence.",
        ),
    ),
    AmplificationRule(
        rule_id="traversal_logpoison_rce",
        name="File Inclusion + Log/Header Injection → RCE via Log Poisoning",
        components=(
            Component("File read / inclusion",
                      ("lfi", "local_file", "path_traversal", "directory_traversal",
                       "file_inclusion")),
            Component("Log or header injection",
                      ("log_injection", "log_poison", "header_injection",
                       "crlf_injection", "response_splitting")),
        ),
        combined_severity="critical",
        impact=("Attacker-controlled data written into a server log is then executed "
                "by including that log through the inclusion flaw, yielding code "
                "execution."),
        rationale=("Log/header injection alone is usually rated low, and the inclusion "
                   "flaw alone only reads files. Combined, the log becomes a writable "
                   "code sink the inclusion can execute."),
        mitre=("T1190", "T1565.001"),
        cwe="CWE-98",
        owasp="A03:2021 Injection",
        phase="Exploitation → Code Execution",
        prerequisites=(
            "A server log or header sink is writable with attacker-controlled data.",
            "The inclusion flaw can read that log path and the server evaluates its contents.",
        ),
        playbook=(
            "Poison the log: send a request whose logged field (for example the User-Agent) carries "
            "an inert marker payload to {s1.url}.",
            "Confirm the inclusion can read the log: request {s0.url_with_param}<server-log-path> "
            "(for example an access log) and verify the marker appears in the response.",
            "Confirm execution: include the poisoned log through {s0.url_with_param} and check the marker runs.",
            "Capture the executed marker output as proof; do not leave a persistent payload behind.",
        ),
    ),
    AmplificationRule(
        rule_id="ssrf_internal_pivot",
        name="SSRF + Exposed Internal Service → Internal/Cloud Compromise",
        components=(
            Component("Server-side request forgery",
                      ("ssrf", "server_side_request")),
            Component("Reachable internal target",
                      ("cloud_metadata", "metadata_service", "public_s3", "iam",
                       "exposed_database", "database_exposure", "mongodb", "redis",
                       "elasticsearch", "admin_panel", "management_interface",
                       "internal_service")),
        ),
        combined_severity="critical",
        impact=("The SSRF is aimed at the exposed internal service or cloud metadata "
                "endpoint, turning a blind request into internal data access, cloud "
                "credential theft, or internal service compromise."),
        rationale=("An SSRF with nothing valuable to reach is often only medium. A "
                   "reachable metadata endpoint or unauthenticated internal datastore "
                   "gives it a high-value target, so the pair is a critical pivot."),
        mitre=("T1190", "T1552.005"),
        cwe="CWE-918",
        owasp="A10:2021 Server-Side Request Forgery",
        phase="Lateral Movement / Cloud Compromise",
        prerequisites=(
            "The SSRF can reach the internal target's network location from the vulnerable server.",
            "The internal target ({s1.title}) is unauthenticated or trusts requests from the vulnerable host.",
        ),
        playbook=(
            "Point the SSRF at a benign in-scope listener you control via {s0.url_with_param} to confirm "
            "outbound requests actually fire.",
            "Aim the SSRF at the reachable internal target ({s1.url}, or the cloud metadata endpoint) through "
            "{s0.url_with_param} and capture the response.",
            "If a cloud metadata endpoint responds, retrieve only enough to demonstrate credential exposure; "
            "do not use the credentials beyond proof.",
            "Document the internal data or service reached as evidence of the pivot.",
        ),
    ),
    AmplificationRule(
        rule_id="sqli_admin_rce",
        name="SQL Injection + Exposed Admin Interface → Full Application Takeover",
        components=(
            Component("SQL injection", ("sqli", "sql_injection")),
            Component("Exposed admin surface",
                      ("admin_panel", "exposed_admin", "admin_interface",
                       "management_interface")),
        ),
        combined_severity="critical",
        impact=("Credentials or session material extracted through the injection are "
                "replayed against the reachable admin interface, escalating a data-read "
                "flaw into full administrative control (and often RCE)."),
        rationale=("SQLi gives data; an exposed admin panel gives a place to use it. "
                   "Together they convert read access into authenticated takeover."),
        mitre=("T1190", "T1078"),
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        phase="Privilege Escalation → Takeover",
        prerequisites=(
            "The injection yields credentials, session tokens, or writable data usable "
            "against the admin surface.",
            "The admin interface ({s1.url}) is reachable from the tester's position.",
        ),
        playbook=(
            "Confirm the injection at {s0.url_with_param} (for example a boolean or time-based test) and "
            "enumerate the users/credentials table.",
            "Recover or crack an administrative credential, or extract a valid session token.",
            "Authenticate to the admin interface at {s1.url} with the recovered material.",
            "Demonstrate a single privileged action (read-only where possible) as proof of takeover.",
        ),
    ),
    AmplificationRule(
        rule_id="authbypass_sensitive_action",
        name="Missing/Broken Authentication + Sensitive Function → Unauthorized Compromise",
        components=(
            Component("Authentication gap",
                      ("auth_bypass", "authentication_bypass", "broken_auth",
                       "missing_auth", "unauthenticated", "no_authentication")),
            Component("Sensitive function",
                      ("file_upload", "unrestricted_upload", "admin_panel",
                       "management_interface", "command_injection", "rce",
                       "deserial", "arbitrary_file")),
        ),
        combined_severity="critical",
        impact=("A powerful function that should be gated behind authentication is "
                "reachable without it, so any anonymous attacker can drive it directly "
                "to code execution or destructive action."),
        rationale=("A missing auth check on a read-only page is minor; on an upload, "
                   "admin, or command endpoint it removes the last barrier to a "
                   "critical action."),
        mitre=("T1190",),
        cwe="CWE-306",
        owasp="A01:2021 Broken Access Control",
        phase="Initial Access → Exploitation",
        prerequisites=(
            "The sensitive function ({s1.title}) performs a powerful action (upload, admin, or command).",
            "The authentication gap exposes that function without valid credentials.",
        ),
        playbook=(
            "Reproduce the authentication gap at {s0.url} without credentials.",
            "Reach the sensitive function directly at {s1.url} over the same unauthenticated path.",
            "Drive the function to its impact (for example upload then execute, or invoke the admin/command "
            "action) with an inert proof payload.",
            "Record that no authentication was required at any step.",
        ),
    ),
    AmplificationRule(
        rule_id="defaultcreds_exposed_service",
        name="Default/Weak Credentials + Exposed Admin or Service → Full Compromise",
        components=(
            Component("Weak or default credentials",
                      ("default_cred", "default_password", "weak_password",
                       "weak_cred", "guessable", "reused_password")),
            Component("Exposed privileged surface",
                      ("admin_panel", "exposed_admin", "management_interface",
                       "ssh", "rdp", "winrm", "smb", "database_exposure",
                       "exposed_database", "ftp", "telnet")),
        ),
        combined_severity="critical",
        impact=("The guessable credential is used against the exposed administrative "
                "interface or remote service, granting an attacker a legitimate "
                "privileged session."),
        rationale=("A weak password matters only where it can be used. An internet-"
                   "reachable admin panel or remote-access service turns it into an "
                   "immediate authenticated foothold."),
        mitre=("T1078", "T1110"),
        cwe="CWE-1392",
        owasp="A07:2021 Identification and Authentication Failures",
        phase="Initial Access",
        prerequisites=(
            "The exposed service ({s1.title}) accepts the weak/default credential set.",
            "The service is reachable from the tester's network position.",
        ),
        playbook=(
            "Confirm the service is reachable at {s1.url} (port {s1.port} where applicable).",
            "Authenticate with the identified default/weak credentials.",
            "On success, capture a benign proof (a banner, a whoami, or a directory listing) of the "
            "privileged session.",
            "Do not pivot further than needed to prove access.",
        ),
    ),
    AmplificationRule(
        rule_id="xss_csrf_account_takeover",
        name="Stored XSS + CSRF/Weak Session Cookie → Account or Admin Takeover",
        components=(
            Component("Cross-site scripting",
                      ("xss", "cross_site_script", "stored_xss", "persistent_xss")),
            Component("Session/request-forgery weakness",
                      ("csrf", "cross_site_request", "cookie_no_samesite",
                       "samesite", "cookie_no_httponly", "session_fixation")),
        ),
        combined_severity="critical",
        impact=("Script injected into an authenticated view rides the victim's session "
                "(unprotected by SameSite/CSRF defences) to perform privileged actions "
                "or seize the account, up to and including an administrator's."),
        rationale=("XSS that can act on a session, on a site whose cookies and state-"
                   "changing requests are not CSRF/SameSite protected, is a reliable "
                   "account-takeover primitive rather than a contained script bug."),
        mitre=("T1539", "T1550.004"),
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        phase="Account Takeover",
        prerequisites=(
            "The XSS executes in an authenticated context (it can read the session or act as the user).",
            "State-changing requests lack CSRF tokens or SameSite protection ({s1.title}).",
        ),
        playbook=(
            "Confirm the XSS fires in an authenticated view via {s0.url} with an inert payload "
            "(for example a benign DOM change).",
            "Confirm the target's state-changing requests are not CSRF/SameSite protected at {s1.url}.",
            "Build a proof payload that performs a harmless authenticated action (for example reading the "
            "account email) to demonstrate session use.",
            "Document the account-takeover primitive without altering the victim account.",
        ),
    ),
    AmplificationRule(
        rule_id="secret_reuse_lateral",
        name="Exposed Secret + Reachable Remote Service → Credential Reuse & Lateral Movement",
        components=(
            Component("Exposed credential or secret",
                      ("hardcoded_secret", "exposed_credential", "exposed_secret",
                       "api_key", "private_key", "credential_leak")),
            Component("Reachable authenticated service",
                      ("ssh", "rdp", "winrm", "smb", "database_exposure",
                       "exposed_database", "ftp", "vpn")),
        ),
        combined_severity="high",
        impact=("A leaked key or password is replayed against the reachable service, "
                "giving the attacker a valid session on another host and a path to "
                "move laterally."),
        rationale=("A secret in isolation may be dismissed as informational; a service "
                   "it can authenticate to makes it an active foothold and pivot."),
        mitre=("T1552", "T1021"),
        cwe="CWE-522",
        owasp="A07:2021 Identification and Authentication Failures",
        cross_host=True,
        phase="Lateral Movement",
        prerequisites=(
            "The leaked secret ({s0.title}) is valid and authenticates to the reachable service.",
            "The service ({s1.title}) is reachable from the tester's position.",
        ),
        playbook=(
            "Extract the exposed secret from {s0.url} and identify its type (API key, password, private key).",
            "Confirm the remote service is reachable at {s1.url} (port {s1.port} where applicable).",
            "Authenticate to the service with the leaked secret and capture a benign proof of the session.",
            "Record the lateral movement path from {s0.host} to {s1.host}.",
        ),
    ),
    AmplificationRule(
        rule_id="exposure_secret_credentialed",
        name="Directory Listing/Backup Exposure + Exposed Secret → Credentialed Access",
        components=(
            Component("Content/backup exposure",
                      ("directory_listing", "dir_listing", "backup_file",
                       "exposed_file", "sensitive_file", "git_exposure",
                       "source_disclosure", ".git")),
            Component("Exposed secret",
                      ("hardcoded_secret", "exposed_credential", "exposed_secret",
                       "api_key", "private_key", "credential_leak")),
        ),
        combined_severity="high",
        impact=("Browsable files or a leaked backup expose a working secret, which an "
                "attacker uses for authenticated access to the application or its "
                "backend services."),
        rationale=("An open directory or a leaked backup is only as bad as what it "
                   "reveals. When it reveals live credentials, an information leak "
                   "becomes a foothold."),
        mitre=("T1552.001",),
        cwe="CWE-538",
        owasp="A05:2021 Security Misconfiguration",
        phase="Credential Access",
        prerequisites=(
            "The exposed content ({s0.title}) actually contains a live secret.",
            "The secret grants access to the application or a backend service.",
        ),
        playbook=(
            "Browse the exposed content at {s0.url} and locate the leaked secret.",
            "Validate the secret is live by authenticating to the relevant service or API.",
            "Demonstrate one authenticated action as proof, and flag the secret for immediate rotation.",
        ),
    ),
    AmplificationRule(
        rule_id="idor_enumeration_massdata",
        name="IDOR/BOLA + User or Object Enumeration → Mass Data Exposure",
        components=(
            Component("Broken object-level access",
                      ("idor", "bola", "broken_object", "insecure_direct_object")),
            Component("Enumeration/disclosure primitive",
                      ("user_enumeration", "username_enumeration", "id_enumeration",
                       "information_disclosure", "info_disclosure",
                       "excessive_data_exposure")),
        ),
        combined_severity="high",
        impact=("The enumeration primitive supplies the valid identifiers the IDOR "
                "needs, so a single-record access flaw becomes bulk extraction of "
                "every user's data."),
        rationale=("An IDOR you cannot enumerate leaks one record at a time; paired "
                   "with an enumeration source it becomes a mass-data-exposure engine."),
        mitre=("T1213",),
        cwe="CWE-639",
        owasp="A01:2021 Broken Access Control",
        phase="Collection / Data Exposure",
        prerequisites=(
            "The enumeration primitive ({s1.title}) yields valid identifiers the IDOR accepts.",
            "The IDOR at {s0.url} returns another user's data for those identifiers.",
        ),
        playbook=(
            "Use the enumeration source at {s1.url} to collect a small set of valid identifiers.",
            "Access the IDOR at {s0.url_with_param}<id> with an identifier that is not yours and confirm "
            "you receive another user's record.",
            "Demonstrate scale with a bounded sample (for example five records) rather than full extraction.",
            "Record the count of records reachable to quantify impact.",
        ),
    ),
    AmplificationRule(
        rule_id="open_redirect_oauth_ato",
        name="Open Redirect + OAuth/SSO/Token Flow → Token Theft & Account Takeover",
        components=(
            Component("Open redirect", ("open_redirect", "unvalidated_redirect")),
            Component("Token-bearing flow",
                      ("oauth", "sso", "saml", "jwt", "token", "auth_code")),
        ),
        combined_severity="high",
        impact=("The open redirect is used as the OAuth/SSO callback target, so the "
                "authorization code or token is delivered to the attacker, letting "
                "them assume the victim's session."),
        rationale=("An open redirect is normally low-impact phishing aid. On a site "
                   "with a token-bearing auth flow it becomes a token-exfiltration "
                   "channel and an account-takeover vector."),
        mitre=("T1528", "T1566"),
        cwe="CWE-601",
        owasp="A01:2021 Broken Access Control",
        phase="Credential Access → Account Takeover",
        prerequisites=(
            "The token-bearing flow ({s1.title}) uses a redirect/callback the open redirect can influence.",
            "The redirect target is not strictly allowlisted.",
        ),
        playbook=(
            "Confirm the open redirect at {s0.url_with_param} sends users to an arbitrary destination.",
            "Identify the OAuth/SSO callback parameter in the flow at {s1.url}.",
            "Craft an authorization request whose callback resolves through the open redirect to an in-scope "
            "collector you control.",
            "Confirm the code/token is delivered to the collector, proving token theft; do not use it against "
            "a real account.",
        ),
    ),
    AmplificationRule(
        rule_id="cors_xss_data_theft",
        name="CORS Misconfiguration + XSS/Sensitive API → Cross-Origin Data Theft",
        components=(
            Component("Permissive CORS",
                      ("cors", "cross_origin", "access_control_allow_origin")),
            Component("Reachable sensitive response",
                      ("xss", "cross_site_script", "sensitive_data",
                       "excessive_data_exposure", "information_disclosure",
                       "api_key")),
        ),
        combined_severity="high",
        impact=("A permissive cross-origin policy lets attacker-controlled script read "
                "authenticated responses, turning reflected data or an injected script "
                "into silent cross-origin exfiltration."),
        rationale=("A CORS wildcard with credentials, or an origin-reflecting policy, "
                   "is only dangerous when there is sensitive data or script to read "
                   "across it. Together they enable cross-origin theft."),
        mitre=("T1539",),
        cwe="CWE-942",
        owasp="A05:2021 Security Misconfiguration",
        phase="Collection / Exfiltration",
        prerequisites=(
            "The CORS policy reflects arbitrary origins, or uses a wildcard with credentials.",
            "There is sensitive authenticated data or injectable script ({s1.title}) to read across the origin.",
        ),
        playbook=(
            "Confirm the CORS policy at {s0.url} reflects an attacker origin with credentials allowed.",
            "From an attacker origin, issue a credentialed cross-origin request to the sensitive endpoint ({s1.url}).",
            "Confirm the response body is readable cross-origin and capture a redacted sample as proof.",
        ),
    ),
    AmplificationRule(
        rule_id="subdomain_takeover_session",
        name="Subdomain Takeover + Domain-Scoped Cookies/OAuth → Session & Token Theft",
        components=(
            Component("Subdomain takeover",
                      ("subdomain_takeover", "dangling_dns", "dangling_cname")),
            Component("Domain-scoped trust",
                      ("cookie_no_samesite", "samesite", "domain_cookie", "oauth",
                       "sso", "saml", "cookie_scope")),
        ),
        combined_severity="high",
        impact=("Controlling a subdomain lets the attacker receive domain-scoped "
                "cookies or act as a trusted OAuth/SSO origin, harvesting sessions and "
                "tokens for the parent domain."),
        rationale=("A dangling subdomain is a nuisance until the domain hands it trust. "
                   "Domain-wide cookies or a trusting auth flow turn it into a session-"
                   "theft platform."),
        mitre=("T1584.001", "T1539"),
        cwe="CWE-350",
        owasp="A05:2021 Security Misconfiguration",
        phase="Credential Access → Session Theft",
        prerequisites=(
            "The dangling subdomain ({s0.host}) can be claimed by the tester.",
            "Cookies or an OAuth/SSO trust are scoped to the parent domain and reach the subdomain.",
        ),
        playbook=(
            "Confirm the dangling DNS/CNAME at {s0.host} points to a claimable provider resource.",
            "Claim the resource in scope and serve a benign proof page.",
            "Demonstrate that domain-scoped cookies or the trusting auth flow ({s1.title}) send data to the "
            "controlled subdomain.",
            "Capture the received session/token material as proof without reusing it.",
        ),
    ),
    AmplificationRule(
        rule_id="clickjacking_csrf_forced_action",
        name="Clickjacking + Weak CSRF Protection → Forced Privileged Action",
        components=(
            Component("Framing allowed",
                      ("clickjack", "x_frame", "frame_ancestors", "missing_x_frame",
                       "ui_redress")),
            Component("Unprotected state change",
                      ("csrf", "cross_site_request", "no_csrf_token",
                       "state_changing")),
        ),
        combined_severity="high",
        impact=("The page can be framed and its state-changing actions lack CSRF "
                "protection, so a victim can be tricked into performing a privileged "
                "action without consent."),
        rationale=("Missing frame protection or a missing CSRF token is individually "
                   "modest. Together they let an attacker script a victim's clicks into "
                   "real, unauthorised changes."),
        mitre=("T1189",),
        cwe="CWE-1021",
        owasp="A05:2021 Security Misconfiguration",
        phase="Exploitation → Forced Action",
        prerequisites=(
            "The page at {s0.url} can be framed (no X-Frame-Options / frame-ancestors).",
            "Its state-changing action lacks CSRF protection ({s1.title}).",
        ),
        playbook=(
            "Confirm the page frames in a test document (no framing protection) using {s0.url}.",
            "Confirm the state-changing request at {s1.url} succeeds without a CSRF token from a cross-site context.",
            "Build a proof-of-concept frame that overlays the sensitive control and demonstrates a forced, "
            "consented-looking click.",
            "Use a harmless action for the proof; do not perform a destructive change.",
        ),
    ),
    AmplificationRule(
        rule_id="jwt_forge_privesc",
        name="Forgeable JWT + Privileged Endpoint → Privilege Escalation",
        components=(
            Component("Forgeable token",
                      ("alg_none", "alg:none", "jwt_none", "jwt_weak", "weak_jwt_secret",
                       "weak_signing", "jwt_key_confusion", "unsigned_jwt")),
            Component("Claim-authorized surface",
                      ("admin_panel", "management_interface", "privileged",
                       "role_based", "authorization", "broken_access")),
        ),
        combined_severity="critical",
        impact=("A token an attacker can forge, checked by an endpoint that authorizes "
                "on its claims, lets the attacker mint an administrative session and "
                "escalate privilege at will."),
        rationale=("A weak JWT alone is a signing flaw; a privileged endpoint alone is "
                   "expected to be gated. Together, the gate trusts a signature the "
                   "attacker controls."),
        mitre=("T1548", "T1078"),
        cwe="CWE-347",
        owasp="A07:2021 Identification and Authentication Failures",
        phase="Privilege Escalation",
        prerequisites=(
            "The JWT can be forged (alg:none accepted, a weak/known signing secret, or key confusion).",
            "A privileged endpoint ({s1.title}) authorizes based on JWT claims.",
        ),
        playbook=(
            "Capture a valid JWT from the flow at {s0.url} and identify the weakness (alg:none, weak secret, "
            "or kid/jku abuse).",
            "Forge a token that elevates a claim (for example role → admin) using the identified weakness.",
            "Replay the forged token against the privileged endpoint at {s1.url} and confirm elevated access.",
            "Demonstrate one privileged read as proof.",
        ),
    ),
    AmplificationRule(
        rule_id="cleartext_creds_mitm",
        name="Cleartext Credential Transport + Login Form → Credential Interception",
        components=(
            Component("Cleartext credential transport",
                      ("cleartext_transmission", "cleartext_credential",
                       "cleartext_password", "http_login", "password_over_http",
                       "insecure_transmission", "no_tls_login")),
            Component("Credential entry point",
                      ("login_form", "password_field", "basic_auth",
                       "authentication_form", "login_endpoint")),
        ),
        combined_severity="high",
        impact=("Credentials submitted over an unencrypted channel can be read by any "
                "party on the network path, handing an on-path attacker valid logins."),
        rationale=("A missing-TLS observation is only a real credential risk where "
                   "credentials are actually submitted. A login form on that same "
                   "cleartext channel makes interception concrete."),
        mitre=("T1040", "T1557"),
        cwe="CWE-319",
        owasp="A02:2021 Cryptographic Failures",
        phase="Credential Access",
        prerequisites=(
            "Credentials are transmitted without TLS on the login flow ({s1.title}).",
            "The tester holds an authorized on-path position to observe or relay traffic.",
        ),
        playbook=(
            "Confirm the login at {s1.url} submits credentials over cleartext HTTP (capture the request to {s0.url}).",
            "From an authorized on-path position, demonstrate that the submitted credentials are visible in transit.",
            "Record a redacted capture as proof; never store the full plaintext credential.",
        ),
    ),
    AmplificationRule(
        rule_id="enum_nolimit_bruteforce",
        name="Account Enumeration + No Rate Limit/Lockout → Practical Credential Attack",
        components=(
            Component("Account enumeration",
                      ("user_enumeration", "username_enumeration", "account_enumeration",
                       "email_enumeration")),
            Component("No lockout or throttling",
                      ("no_account_lockout", "no_rate_limit", "missing_rate_limit",
                       "weak_lockout", "no_throttle", "brute")),
        ),
        combined_severity="high",
        impact=("Valid accounts can be enumerated and then guessed at speed because the "
                "authentication endpoint neither locks out nor throttles, making "
                "credential stuffing and brute force practical."),
        rationale=("Enumeration alone leaks who exists; a missing lockout alone is a "
                   "hardening gap. Together they remove both the guesswork and the "
                   "brake on an online password attack."),
        mitre=("T1110.001", "T1589.001"),
        cwe="CWE-307",
        owasp="A07:2021 Identification and Authentication Failures",
        phase="Credential Access",
        prerequisites=(
            "Valid usernames/accounts can be enumerated ({s0.title}).",
            "The authentication endpoint applies no lockout or rate limiting ({s1.title}).",
        ),
        playbook=(
            "Enumerate a small set of valid usernames via {s0.url}.",
            "Confirm the login/auth endpoint at {s1.url} does not lock out or throttle repeated attempts.",
            "Demonstrate a bounded credential-guessing run against one enumerated account with a tiny wordlist "
            "(proof of feasibility, not full compromise).",
            "Record attempts made without lockout as evidence.",
        ),
    ),
)


# ── Result type ──────────────────────────────────────────────────────────────


@dataclass
class CombinationFinding:
    """One recommended merge: several findings that together warrant an elevated,
    combined rating, with the target-grounded steps to prove it."""
    id: str
    rule_id: str
    name: str
    combined_severity: str
    representative_cvss: float
    confirmation: str                       # "Confirmed" or "Potential"
    confidence: float
    priority: float = 0.0                   # 0-100 rank: severity, confidence, actionability
    actionability: float = 0.0              # 0-1: how much concrete target evidence we have
    phase: str = ""                         # kill-chain phase the emergent issue lands in
    scope: list[str] = field(default_factory=list)      # host(s) the combo spans
    components: list[dict] = field(default_factory=list)  # constituent findings (compact)
    elevated_from: list[str] = field(default_factory=list)  # constituent severities
    impact: str = ""
    rationale: str = ""
    recommendation: str = ""
    prerequisites: list[str] = field(default_factory=list)  # rendered conditions
    playbook: list[str] = field(default_factory=list)       # rendered proof/exploit steps
    mitre: list[str] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    cross_host: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "combined_severity": self.combined_severity,
            "representative_cvss": self.representative_cvss,
            "confirmation": self.confirmation,
            "confidence": self.confidence,
            "priority": self.priority,
            "actionability": self.actionability,
            "phase": self.phase,
            "scope": self.scope,
            "components": self.components,
            "elevated_from": self.elevated_from,
            "impact": self.impact,
            "rationale": self.rationale,
            "recommendation": self.recommendation,
            "prerequisites": self.prerequisites,
            "playbook": self.playbook,
            "mitre": self.mitre,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cross_host": self.cross_host,
        }


# ── Engine ───────────────────────────────────────────────────────────────────


class CorrelationEngine:
    """Finds combinations of findings that elevate into a more critical issue.

    Stateless across calls: build one and call :meth:`correlate` with any finding
    list (scan output, engagement store rows, or operator-submitted findings).
    """

    def __init__(self, rules: tuple[AmplificationRule, ...] = AMPLIFICATION_RULES):
        self.rules = rules

    # -- internal matching ----------------------------------------------------

    @staticmethod
    def _assign_components(rule: AmplificationRule,
                           findings: list[dict]) -> Optional[list[dict]]:
        """Fill each of the rule's slots with a DISTINCT finding, or return None.

        Most-constrained slot first (fewest candidates), then greedy by highest
        severity then confidence. A single finding can never fill two slots.
        """
        # Candidate findings per slot (as indices into ``findings``).
        cand: list[tuple[int, list[int]]] = []
        for si, comp in enumerate(rule.components):
            idxs = [i for i, f in enumerate(findings) if comp.matches(f)]
            if not idxs:
                return None  # a slot with no candidate can never be satisfied
            cand.append((si, idxs))
        # Assign most-constrained slot first.
        cand.sort(key=lambda c: len(c[1]))
        used: set[int] = set()
        chosen: dict[int, int] = {}
        for si, idxs in cand:
            pool = [i for i in idxs if i not in used]
            if not pool:
                return None
            pick = max(pool, key=lambda i: (
                _sev_rank(findings[i].get("severity")),
                _confidence_of(findings[i]),
            ))
            used.add(pick)
            chosen[si] = pick
        # Return findings in original slot order.
        return [findings[chosen[si]] for si in range(len(rule.components))]

    def _build_combo(self, rule: AmplificationRule,
                     members: list[dict]) -> Optional[CombinationFinding]:
        """Turn a matched member set into a CombinationFinding, or None when the
        emergent severity would not actually elevate the strongest constituent."""
        comp_ranks = [_sev_rank(m.get("severity")) for m in members]
        max_comp = max(comp_ranks)
        rule_rank = _sev_rank(rule.combined_severity)
        # Honesty gate: only report a combination that genuinely raises the bar
        # above the strongest constituent. Otherwise there is nothing to elevate.
        if rule_rank <= max_comp:
            return None

        confs = [_confidence_of(m) for m in members]
        # Weakest link governs, with a small penalty for each extra dependency
        # (every additional required step is another thing that can fail).
        combined_conf = round(min(confs) * (0.95 ** (len(members) - 1)), 2)
        confirmed = all(is_confirmed_finding(m) for m in members)

        # Per-slot evidence (in slot order) drives the templated playbook.
        evidences = [_evidence(m) for m in members]

        hosts: list[str] = []
        for ev in evidences:
            h = ev.get("host") or ""
            if h and h not in hosts:
                hosts.append(h)
        if not hosts:
            # fall back to the raw host key so scope is never empty
            for m in members:
                h = _host_of(m)
                if h and h not in hosts:
                    hosts.append(h)

        components = [{
            "id": str(m.get("id") or ""),
            "title": ev["title"],
            "vuln_type": str(m.get("vuln_type") or m.get("type") or ""),
            "severity": str(m.get("severity") or "info").lower(),
            "target": ev["url"],
            "param": ev["param"],
            "port": ev["port"],
            "cve": ev["cve"],
            "method": ev["method"],
        } for m, ev in zip(members, evidences)]

        # Actionability: how much concrete, target-specific evidence we hold. A
        # combination we can point at a real URL + parameter/port/CVE is one an
        # operator can act on immediately; one with only a bare host is weaker.
        action_scores: list[float] = []
        for ev in evidences:
            s = 0.0
            if ev["url"]:
                s += 0.5
            if ev["param"] or ev["port"] or ev["cve"]:
                s += 0.5
            action_scores.append(s)
        actionability = round(sum(action_scores) / len(action_scores), 3) if action_scores else 0.0

        # Priority (0-100): severity dominates, then confidence, then whether it
        # is confirmed, then how actionable the evidence is.
        priority = round(100.0 * (
            0.45 * (rule_rank / 4.0)
            + 0.25 * combined_conf
            + 0.15 * (1.0 if confirmed else 0.0)
            + 0.15 * actionability
        ), 1)

        prerequisites = [_render(p, evidences) for p in rule.prerequisites]
        playbook = [_render(step, evidences) for step in rule.playbook]

        weakest = min(members, key=lambda m: (_sev_rank(m.get("severity")),
                                              _confidence_of(m)))
        weakest_label = str(weakest.get("title") or weakest.get("vuln_type")
                            or weakest.get("type") or "the weakest link")
        recommendation = (
            f"Break the chain by remediating any single component: fixing "
            f"\"{weakest_label}\" alone neutralises the elevated "
            f"{rule.combined_severity} risk. Ideally remediate every component."
        )

        # Stable id from the rule and the constituent finding identities, so the
        # same combination keeps the same id across re-scans.
        ident = rule.rule_id + "|" + "|".join(sorted(c["id"] or c["title"]
                                                     for c in components))
        cid = "HEAVEN-CHAIN-" + hashlib.sha256(
            ident.encode("utf-8", "replace")).hexdigest()[:8].upper()

        return CombinationFinding(
            id=cid,
            rule_id=rule.rule_id,
            name=rule.name,
            combined_severity=rule.combined_severity,
            representative_cvss=score_from_label(rule.combined_severity),
            confirmation="Confirmed" if confirmed else "Potential",
            confidence=combined_conf,
            priority=priority,
            actionability=actionability,
            phase=rule.phase,
            scope=hosts,
            components=components,
            elevated_from=[c["severity"] for c in components],
            impact=rule.impact,
            rationale=rule.rationale,
            recommendation=recommendation,
            prerequisites=prerequisites,
            playbook=playbook,
            mitre=list(rule.mitre),
            cwe=rule.cwe,
            owasp=rule.owasp,
            cross_host=rule.cross_host,
        )

    # -- public API -----------------------------------------------------------

    def correlate(self, findings: list[dict]) -> list[CombinationFinding]:
        """Return the elevated combinations discoverable from ``findings``.

        Findings that are suppressed or marked false-positive are ignored — a
        combination should never be built from a rejected finding.
        """
        pool = [f for f in (findings or [])
                if isinstance(f, dict)
                and not f.get("suppressed")
                and str(f.get("status") or "").lower() != "false_positive"]
        if len(pool) < 2:
            return []

        # Group by host once, so same-host rules only combine co-located findings.
        by_host: dict[str, list[dict]] = {}
        for f in pool:
            by_host.setdefault(_host_of(f), []).append(f)

        results: list[CombinationFinding] = []
        seen: set[tuple[str, frozenset[str]]] = set()

        for rule in self.rules:
            search_sets = ([pool] if rule.cross_host else list(by_host.values()))
            for subset in search_sets:
                if len(subset) < len(rule.components):
                    continue
                members = self._assign_components(rule, subset)
                if not members:
                    continue
                combo = self._build_combo(rule, members)
                if combo is None:
                    continue
                key = (rule.rule_id, frozenset(c["id"] or c["title"]
                                               for c in combo.components))
                if key in seen:
                    continue
                seen.add(key)
                results.append(combo)

        # Highest emergent severity first, then priority, then confidence, then
        # confirmed-first. Severity leads so a critical always outranks a high.
        results.sort(key=lambda c: (
            _sev_rank(c.combined_severity),
            c.priority,
            c.confidence,
            1 if c.confirmation == "Confirmed" else 0,
        ), reverse=True)
        logger.info("Correlation: %d elevated combination(s) from %d finding(s)",
                    len(results), len(pool))
        return results

    def summary(self, findings: list[dict]) -> dict[str, Any]:
        """Structured summary for the API, report, and UI."""
        combos = self.correlate(findings)
        by_sev: dict[str, int] = {}
        for c in combos:
            by_sev[c.combined_severity] = by_sev.get(c.combined_severity, 0) + 1
        return {
            "total_input_findings": len([f for f in (findings or [])
                                         if isinstance(f, dict)]),
            "total_combinations": len(combos),
            "critical_combinations": sum(1 for c in combos
                                         if c.combined_severity == "critical"),
            "confirmed_combinations": sum(1 for c in combos
                                          if c.confirmation == "Confirmed"),
            "by_severity": by_sev,
            "highest_priority": max((c.priority for c in combos), default=0.0),
            "combinations": [c.to_dict() for c in combos],
        }


def correlate_findings(findings: list[dict]) -> dict[str, Any]:
    """Convenience wrapper: run the default engine and return its summary dict."""
    return CorrelationEngine().summary(findings)
