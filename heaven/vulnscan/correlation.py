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
    filled by a *distinct* real finding. Its combined severity is the higher of
    the rule's declared rating and the strongest constituent, so the number is
    never overstated beyond what the rule warrants nor understated below a real
    part. A chain whose parts are already critical stays critical (nothing is
    higher) but is still reported, because the combination is a materially worse,
    distinct issue than the parts alone and its concrete exploitation path is the
    deliverable. Confidence tracks the weakest link, and a combination is only
    "Confirmed" when every constituent finding is confirmed. The playbook is
    written as benign, bounded, in-scope proof steps, never as a claim that
    exploitation has already happened.

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


def _finding_identity(finding: dict) -> tuple:
    """A stable identity for a finding, used to collapse exact duplicates.

    Prefers the explicit ``id``. When a finding has none (common for report
    JSON), falls back to its type + target + title, so the same finding carried
    in two arrays (or persisted twice) is recognised as one and can never be
    "combined" with a copy of itself.
    """
    fid = str(finding.get("id") or "").strip()
    if fid:
        return ("id", fid)
    vt = str(finding.get("vuln_type") or finding.get("type") or "").strip().lower()
    tgt = str(finding.get("target") or finding.get("url")
              or finding.get("host") or "").strip().lower()
    title = str(finding.get("title") or finding.get("name") or "").strip().lower()
    return ("vtt", vt, tgt, title)


# Separators a human writes but a slug does not (and the reverse). We fold them
# all to single spaces so a rule keyword written as an internal slug
# (``sql_injection``) matches a finding a human worded naturally
# (``SQL Injection in the login form``) and vice versa. The word-start rule in
# ``_kw_matches`` is what keeps this fold from over-matching.
_SEP_RE = re.compile(r"[_\-/:]+")
_WS_RE = re.compile(r"\s+")

# Fields scanned for keyword evidence. ``title``/``name`` carry the human wording;
# ``vuln_type``/``type``/``subtype``/``category`` carry HEAVEN's slugs; ``cwe`` and
# ``cve_id`` carry precise identifiers a slot can match on directly. This is what
# lets the matcher work whether a finding came from a HEAVEN scan or was pasted
# in by an operator using their own wording or an external tool's output.
_MATCH_FIELDS = ("vuln_type", "type", "subtype", "category", "title", "name",
                 "cwe", "cwe_id", "cve_id")


def _normalize(text: Any) -> str:
    """Lowercase, then fold separators and runs of whitespace to single spaces."""
    return _WS_RE.sub(" ", _SEP_RE.sub(" ", str(text or "").lower())).strip()


def _haystack(finding: dict) -> str:
    """Normalised text used for keyword-matching a finding to a component slot."""
    return _normalize(" ".join(str(finding.get(k, "")) for k in _MATCH_FIELDS))


def _kw_matches(hay: str, keyword: str) -> bool:
    """True when ``keyword`` occurs in ``hay`` starting at a word boundary.

    Both are already normalised (separators folded to spaces). Matching at a
    word start lets a stem match its inflections (``clickjack`` → ``clickjacking``)
    while stopping a short token from matching the middle of an unrelated word
    (``iam`` must not match ``reclaim``). A keyword ending in a digit additionally
    requires a non-digit on its right, so ``cwe 89`` does not match ``cwe 890``.
    """
    kw = _normalize(keyword)
    if not kw:
        return False
    tail_digit = kw[-1].isdigit()
    start = 0
    while True:
        idx = hay.find(kw, start)
        if idx == -1:
            return False
        left_ok = idx == 0 or hay[idx - 1] == " "
        after = idx + len(kw)
        right_ok = not (tail_digit and after < len(hay) and hay[after].isdigit())
        if left_ok and right_ok:
            return True
        start = idx + 1


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
        return any(_kw_matches(hay, k) for k in self.any_of)


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
                       "file_inclusion", "cwe-22", "cwe-98", "cwe-73")),
            Component("Unrestricted upload",
                      ("file_upload", "unrestricted_upload", "arbitrary_file_upload",
                       "upload", "cwe-434")),
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
                       "file_inclusion", "cwe-22", "cwe-98", "cwe-73")),
            Component("Log or header injection",
                      ("log_injection", "log_poison", "header_injection",
                       "crlf_injection", "response_splitting",
                       "cwe-117", "cwe-93", "cwe-113")),
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
                      ("ssrf", "server_side_request", "cwe-918")),
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
            Component("SQL injection", ("sqli", "sql_injection", "cwe-89")),
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
                       "missing_auth", "unauthenticated", "no_authentication",
                       "cwe-287", "cwe-306")),
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
                       "weak_cred", "guessable", "reused_password",
                       "cwe-798", "cwe-521", "cwe-1392", "cwe-1391")),
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
                      ("xss", "cross_site_script", "stored_xss", "persistent_xss",
                       "cwe-79")),
            Component("Session/request-forgery weakness",
                      ("csrf", "cross_site_request", "cookie_no_samesite",
                       "samesite", "cookie_no_httponly", "session_fixation",
                       "cwe-352", "cwe-1275", "cwe-1004", "cwe-384")),
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
                      # A leaked secret specifically. Not "cwe-798" (see the
                      # matching note on exposure_secret_credentialed): default/
                      # guessable credentials carry it but are weak-cred issues,
                      # already chained by ``defaultcreds_exposed_service``.
                      ("hardcoded_secret", "exposed_credential", "exposed_secret",
                       "api_key", "private_key", "credential_leak",
                       "cwe-522", "cwe-540")),
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
                       "source_disclosure", ".git",
                       "cwe-538", "cwe-548", "cwe-527")),
            Component("Exposed secret",
                      # A leaked secret specifically (key/password in code, a
                      # dumped credential). Deliberately NOT "cwe-798": that
                      # (Use of Hard-coded Credentials) is also carried by
                      # default/guessable-credential findings, which are weak-cred
                      # issues, not leaked secrets, and are already chained by
                      # ``defaultcreds_exposed_service``.
                      ("hardcoded_secret", "exposed_credential", "exposed_secret",
                       "api_key", "private_key", "credential_leak",
                       "cwe-522", "cwe-540")),
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
                      ("idor", "bola", "broken_object", "insecure_direct_object",
                       "cwe-639", "cwe-566")),
            Component("Enumeration/disclosure primitive",
                      ("user_enumeration", "username_enumeration", "id_enumeration",
                       "information_disclosure", "info_disclosure",
                       "excessive_data_exposure", "cwe-203", "cwe-204")),
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
            Component("Open redirect",
                      ("open_redirect", "unvalidated_redirect", "cwe-601")),
            Component("Token-bearing flow",
                      # Specific token-bearing constructs only. A bare "token"
                      # would wrongly match "CSRF token missing" (the opposite of
                      # a token-bearing auth flow), and a bare "jwt" wrongly
                      # matches a standalone weak-JWT *signing* finding
                      # (jwt_weak_secret / jwt_none), which is not a redirectable
                      # OAuth/SSO flow the open redirect can steal a code from.
                      # Match the real callback-bearing carriers instead.
                      ("oauth", "sso", "saml", "auth_code", "authorization_code",
                       "access_token", "id_token", "refresh_token", "bearer_token",
                       "session_token")),
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
                      ("cors", "cross_origin", "access_control_allow_origin",
                       "cwe-942", "cwe-346")),
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
                      ("subdomain_takeover", "dangling_dns", "dangling_cname",
                       "cwe-350")),
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
                       "ui_redress", "cwe-1021")),
            Component("Unprotected state change",
                      ("csrf", "cross_site_request", "no_csrf_token",
                       "state_changing", "cwe-352")),
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
                       "weak_signing", "jwt_key_confusion", "unsigned_jwt", "cwe-347")),
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
        name="Downgradable/Cleartext Transport + Session or Credential in Transit → Interception",
        # Keywords match HEAVEN's real transport-security findings (missing/short
        # HSTS, cleartext services, no STARTTLS) and its real session/credential
        # findings (a cookie without Secure, basic-auth or weak HTTP-auth
        # credentials, a predictable/weak session id). The two slots are filled
        # by DISTINCT findings, so this fires on the genuine sslstrip-style chain:
        # a session/credential that travels over a channel an on-path attacker
        # can read or downgrade.
        components=(
            Component("Downgradable or cleartext transport",
                      ("no_hsts", "missing_hsts", "hsts_short_maxage",
                       "cleartext_service", "cleartext_transmission",
                       "websocket_cleartext", "smtp_no_starttls",
                       "smtp_starttls_missing", "insecure_transmission",
                       "no_tls", "cwe-319", "cwe-311", "cwe-523")),
            Component("Session or credential material in transit",
                      # Genuine session/credential carriers only. Deliberately NOT
                      # "password_field"/"login_form": those match best-practice
                      # notes like "password field has autocomplete enabled",
                      # which is not a credential-in-transit exposure.
                      ("cookie_no_secure", "cookie_missing_secure", "cookie_insecure",
                       "basic_auth", "weak_http_auth", "weak_login_credentials",
                       "predictable_session_id", "weak_session_id")),
        ),
        combined_severity="high",
        impact=("A session cookie or credential travels over a channel an on-path "
                "attacker can read or force down to cleartext, so the session or "
                "login can be captured and replayed."),
        rationale=("Missing HSTS or a cleartext service is only a hardening gap until "
                   "something sensitive rides that channel. A session cookie without "
                   "the Secure flag, or a credential submitted over it, turns the "
                   "downgrade into a concrete session/credential theft."),
        mitre=("T1040", "T1557"),
        cwe="CWE-319",
        owasp="A02:2021 Cryptographic Failures",
        phase="Credential Access",
        prerequisites=(
            "The session/credential material ({s1.title}) is not bound to TLS "
            "(for example a cookie missing the Secure flag).",
            "The transport can be downgraded or is already cleartext ({s0.title}), "
            "and the tester holds an authorized on-path position.",
        ),
        playbook=(
            "Confirm the transport weakness at {s0.url} (no/again-downgradable HSTS, "
            "or a cleartext service).",
            "Confirm the session/credential material at {s1.url} is not Secure-bound "
            "(for example the session cookie lacks the Secure attribute).",
            "From an authorized on-path position, force a cleartext request and show the "
            "session cookie or credential is visible in transit.",
            "Record a redacted capture as proof; never store the full plaintext value.",
        ),
    ),
    AmplificationRule(
        rule_id="enum_nolimit_bruteforce",
        name="Account Enumeration + No Rate Limit/Lockout → Practical Credential Attack",
        components=(
            Component("Account enumeration",
                      ("user_enumeration", "username_enumeration", "account_enumeration",
                       "email_enumeration", "cwe-203", "cwe-204")),
            Component("No lockout or throttling",
                      ("no_account_lockout", "no_rate_limit", "missing_rate_limit",
                       "weak_lockout", "no_throttle", "brute", "cwe-307", "cwe-799")),
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
    AmplificationRule(
        rule_id="email_spoofing_capable",
        name="Missing/Weak SPF + Missing/Weak DMARC → Practical Email Spoofing",
        # Email authentication is a domain-level property, so this rule spans
        # hosts. Keywords match HEAVEN's real mail-posture findings. Because the
        # engine drops info-severity findings before correlating, a domain whose
        # SPF/DMARC are actually fine (reported at info) never fills a slot here.
        components=(
            Component("Sender-authentication gap (SPF)",
                      ("spf_missing", "spf_analysis", "spf_weak", "spf_soft_fail",
                       "spf_open_relay", "spf_too_many_lookups", "spf_neutral",
                       "no_spf")),
            Component("No delivery-time enforcement (DMARC)",
                      ("dmarc_missing", "dmarc_analysis", "dmarc_policy_none",
                       "dmarc_weak", "dmarc_partial_rollout",
                       "dmarc_policy_weak_subdomain", "no_dmarc")),
        ),
        combined_severity="high",
        impact=("With no enforceable SPF and no DMARC enforcement, mail claiming to be "
                "from the domain is neither authenticated at the edge nor rejected on "
                "delivery, so an attacker can send convincing spoofed email as the "
                "organisation (phishing, business-email-compromise)."),
        rationale=("A weak or missing SPF alone might still be caught by DMARC, and a "
                   "missing DMARC alone might still be limited by a strict SPF. With "
                   "both gaps present the domain is practically spoofable end to end, "
                   "which is materially worse than either gap on its own."),
        mitre=("T1566", "T1656"),
        cwe="CWE-290",
        owasp="",
        cross_host=True,
        phase="Initial Access / Impersonation",
        prerequisites=(
            "The domain publishes no enforcing SPF policy ({s0.title}).",
            "The domain publishes no enforcing DMARC policy ({s1.title}).",
        ),
        playbook=(
            "Confirm the published SPF record for the domain is missing or non-enforcing "
            "({s0.url}).",
            "Confirm the published DMARC record is missing or set to p=none ({s1.url}).",
            "From an authorized position, craft a test message with a forged From header for "
            "the domain and confirm it would pass alignment checks; do not send to third parties.",
            "Record the spoofability as evidence and recommend an enforcing SPF plus DMARC "
            "p=reject.",
        ),
    ),
)


# ── Capability model for multi-step attack paths ─────────────────────────────
# A single ``CombinationFinding`` is one validated step. Real compromise is a
# *walk*: each step hands the attacker a capability that unlocks the next. This
# table encodes, per rule, the capabilities a step GRANTS and the capabilities a
# prior step can supply that make this step a genuine FOLLOW-ON (``needs``).
#
# It is kept separate from the curated rules above (rather than embedded) so the
# detection rules stay focused on matching, and the chaining semantics live in
# one auditable place. The honesty rule for edges: a path edge A → B is drawn
# ONLY when B genuinely consumes a capability A produces (``grants[A] & needs[B]``)
# and B's host is reachable given what A yields. Only the reuse/pivot steps carry
# a non-empty ``needs``; every other step is an independently exploitable entry
# that can start a path but is never fabricated as depending on a predecessor.
# A step is still surfaced as its own combined risk regardless of any path.
#
# Capability vocabulary (small and fixed):
#   foothold       code execution / a shell on a host
#   credentials    reusable credentials, secrets, keys or tokens obtained
#   account        a user/admin account or live session taken over
#   internal_reach ability to reach otherwise-internal / segmented hosts
#   data           bulk read of sensitive application or user data
#   admin          administrative / privileged control of an app or host
_CAP_TOKENS = frozenset({"foothold", "credentials", "account",
                         "internal_reach", "data", "admin"})
# Capabilities that let an attacker move from one host to another. A cross-host
# path edge is only drawn when the predecessor yields one of these (or the step
# itself is inherently cross-host, e.g. credential reuse / domain-level mail).
_MOVEMENT_CAPS = frozenset({"credentials", "internal_reach"})

_RULE_GRANTS: dict[str, frozenset[str]] = {
    "lfi_upload_rce": frozenset({"foothold"}),
    "traversal_logpoison_rce": frozenset({"foothold"}),
    "ssrf_internal_pivot": frozenset({"internal_reach", "credentials"}),
    "sqli_admin_rce": frozenset({"credentials", "admin", "data"}),
    "authbypass_sensitive_action": frozenset({"foothold", "admin"}),
    "defaultcreds_exposed_service": frozenset({"foothold", "admin", "credentials"}),
    "xss_csrf_account_takeover": frozenset({"account"}),
    "secret_reuse_lateral": frozenset({"foothold", "credentials"}),
    "exposure_secret_credentialed": frozenset({"credentials"}),
    "idor_enumeration_massdata": frozenset({"data"}),
    "open_redirect_oauth_ato": frozenset({"account"}),
    "cors_xss_data_theft": frozenset({"data"}),
    "subdomain_takeover_session": frozenset({"account", "credentials"}),
    "clickjacking_csrf_forced_action": frozenset(),
    "jwt_forge_privesc": frozenset({"admin", "account"}),
    "cleartext_creds_mitm": frozenset({"credentials", "account"}),
    "enum_nolimit_bruteforce": frozenset({"credentials", "account"}),
    "email_spoofing_capable": frozenset(),
}
# Only the genuine reuse/pivot steps consume a prior capability. Everything else
# has an empty ``needs`` and is therefore never attached behind another step
# unless it is one of these three — which is exactly what keeps paths honest.
_RULE_NEEDS: dict[str, frozenset[str]] = {
    "secret_reuse_lateral": frozenset({"credentials", "foothold", "internal_reach"}),
    "defaultcreds_exposed_service": frozenset({"credentials", "internal_reach"}),
    "sqli_admin_rce": frozenset({"internal_reach"}),
}


def _grants_of(rule_id: str) -> frozenset[str]:
    return _RULE_GRANTS.get(rule_id, frozenset())


def _needs_of(rule_id: str) -> frozenset[str]:
    return _RULE_NEEDS.get(rule_id, frozenset())


# Human labels for a capability, used in the path narrative.
_CAP_LABEL: dict[str, str] = {
    "foothold": "code execution",
    "credentials": "reusable credentials",
    "account": "a hijacked account or session",
    "internal_reach": "internal network reach",
    "data": "bulk data access",
    "admin": "administrative control",
}

# Best-effort host-role inference, used only to LABEL a path's business impact
# (never to gate an edge, so it can carry no false-positive risk). Ports and
# product names that mark a datastore or a directory/domain-controller class host.
_DB_TOKENS = ("mysql", "mariadb", "postgres", "postgresql", "mssql", "sql server",
              "sqlserver", "mongodb", "mongo", "redis", "elasticsearch", "oracle",
              "db2", "cassandra", "memcached", "couchdb", "database", "datastore")
_DB_PORTS = ("3306", "5432", "1433", "27017", "6379", "9200", "1521", "5984",
             "11211", "9042")
_DC_TOKENS = ("ldap", "kerberos", "active directory", "active_directory",
              "domain controller", "domain_controller", "netbios", "kdc",
              "global catalog")
_DC_PORTS = ("389", "636", "88", "3268", "3269")


def _component_key(comp: dict) -> str:
    """Stable identity for a constituent finding, used for remediation leverage
    and choke-point analysis (which real finding, if fixed, breaks which chains)."""
    cid = str(comp.get("id") or "").strip()
    if cid:
        return "id:" + cid
    return "vtt:%s|%s|%s" % (
        str(comp.get("vuln_type") or "").strip().lower(),
        str(comp.get("target") or "").strip().lower(),
        str(comp.get("title") or "").strip().lower(),
    )


def _host_role(components: list[dict]) -> str:
    """Classify a host from the findings observed on it: a datastore, a
    directory/domain-controller class host, or a generic host. Label-only."""
    parts: list[str] = []
    for comp in components:
        parts.append(str(comp.get("vuln_type") or ""))
        parts.append(str(comp.get("title") or ""))
        parts.append(str(comp.get("target") or ""))
        if comp.get("port"):
            parts.append(":" + str(comp.get("port")))
    hay = _normalize(" ".join(parts))
    ports = {p for p in re.findall(r":(\d{2,5})", hay)}
    if any(_kw_matches(hay, t) for t in _DC_TOKENS) or (ports & set(_DC_PORTS)):
        return "directory / domain controller"
    if any(_kw_matches(hay, t) for t in _DB_TOKENS) or (ports & set(_DB_PORTS)):
        return "database server"
    return "host"


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


@dataclass
class AttackPath:
    """An ordered walk of two or more ``CombinationFinding`` steps where each
    step hands the attacker a capability the next step consumes. This is the
    end-to-end story a human writes in the attack-narrative section of a report:
    "SQL injection dumps credentials on web-01, those credentials open SSH on
    db-02, and from there the exposed database falls." Nothing is invented: every
    step is an independently validated combination, and an edge is drawn only
    where one step genuinely produces what the next requires."""
    id: str
    steps: list[dict] = field(default_factory=list)      # ordered compact step views
    entry: str = ""                                       # first step / entry point
    hosts: list[str] = field(default_factory=list)        # hosts touched, in order
    length: int = 0
    severity: str = "info"                                # max step severity
    representative_cvss: float = 0.0
    confidence: float = 0.0                               # product of step confidences
    confirmation: str = "Potential"                       # Confirmed if every step is
    capabilities: list[str] = field(default_factory=list)  # capabilities gained, in order
    business_impact: str = ""                             # terminal outcome label
    impact_detail: str = ""
    mitre: list[str] = field(default_factory=list)
    phases: list[str] = field(default_factory=list)
    narrative: list[str] = field(default_factory=list)   # one sentence per hop
    component_keys: list[str] = field(default_factory=list)  # constituent finding keys

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "steps": self.steps,
            "entry": self.entry,
            "hosts": self.hosts,
            "length": self.length,
            "severity": self.severity,
            "representative_cvss": self.representative_cvss,
            "confidence": self.confidence,
            "confirmation": self.confirmation,
            "capabilities": self.capabilities,
            "business_impact": self.business_impact,
            "impact_detail": self.impact_detail,
            "mitre": self.mitre,
            "phases": self.phases,
            "narrative": self.narrative,
            "component_keys": self.component_keys,
        }


def _path_business_impact(caps: set[str], roles: set[str]) -> tuple[str, str]:
    """Terminal business impact of a path, from the capabilities reached and the
    role of the hosts touched. Label plus a one-sentence explanation."""
    if "directory / domain controller" in roles:
        crown = "directory / domain controller"
    elif "database server" in roles:
        crown = "database server"
    else:
        crown = "host"
    if caps & {"admin", "foothold"}:
        if crown == "directory / domain controller":
            return ("Domain / directory compromise",
                    "The chain reaches administrative control of a directory or "
                    "domain-controller class host, which typically means control over "
                    "every account and system that trusts it.")
        if crown == "database server":
            return ("Database server compromise",
                    "The chain reaches code execution or administrative control on a "
                    "database-class host, exposing the data it holds and any credentials "
                    "stored on it.")
        return ("Full host compromise",
                "The chain reaches code execution or administrative control on the host, "
                "giving the attacker a durable foothold to operate and pivot from.")
    if "data" in caps:
        return ("Sensitive data exposure",
                "The chain ends in bulk read access to sensitive application or user data.")
    if "account" in caps:
        return ("Account takeover",
                "The chain ends with the attacker able to act as a legitimate "
                "(and possibly privileged) user.")
    if "credentials" in caps:
        return ("Credential compromise",
                "The chain yields reusable credentials or secrets that extend the "
                "attacker's access to other systems.")
    if "internal_reach" in caps:
        return ("Internal network access",
                "The chain gives the attacker a request path into otherwise internal "
                "or segmented systems.")
    return ("Escalated risk",
            "The combination raises the attacker's position beyond any single finding.")


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
        """Turn a matched member set into a CombinationFinding.

        Returns None only on a degenerate (empty) member set. The combined
        severity is the higher of the rule's declared rating and the strongest
        constituent: a chain is never rated below one of its real parts, and
        never above what the rule warrants. When the parts are already critical
        the chain stays critical (there is nothing higher) but is still reported,
        because the combination is a distinct, materially worse issue whose
        concrete exploitation path is the deliverable.
        """
        if not members:
            return None
        comp_ranks = [_sev_rank(m.get("severity")) for m in members]
        max_comp = max(comp_ranks)
        rule_rank = _sev_rank(rule.combined_severity)
        emergent_rank = max(rule_rank, max_comp)
        combined_severity = _RANK_SEV[emergent_rank]

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
            0.45 * (emergent_rank / 4.0)
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
            f"\"{weakest_label}\" alone neutralises the combined "
            f"{combined_severity} risk. Ideally remediate every component."
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
            combined_severity=combined_severity,
            representative_cvss=score_from_label(combined_severity),
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
        """Return the combinations discoverable from ``findings``.

        Excluded before matching: suppressed or false-positive findings (a
        combination must never be built from a rejected finding), and
        info/none-severity findings (an informational observation is not a
        weakness, so it must not become a chain component — this also stops a
        posture check that is actually *fine*, reported at info, from filling a
        slot, e.g. a healthy SPF/DMARC record).
        """
        pool = [f for f in (findings or [])
                if isinstance(f, dict)
                and not f.get("suppressed")
                and str(f.get("status") or "").lower() != "false_positive"
                and _sev_rank(f.get("severity")) >= _SEV_RANK["low"]]
        # Collapse exact-duplicate findings so a finding can never be "combined"
        # with a copy of itself. Reports that carry the same finding in both their
        # ``vulnerabilities`` and ``findings`` arrays would otherwise double every
        # finding and manufacture bogus self-pairings.
        seen_ident: set[tuple] = set()
        deduped: list[dict] = []
        for f in pool:
            ident = _finding_identity(f)
            if ident in seen_ident:
                continue
            seen_ident.add(ident)
            deduped.append(f)
        pool = deduped
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

    # -- attack paths (multi-step chaining) -----------------------------------

    # Bounds so a pathological finding set cannot make path enumeration explode.
    _PATH_MAX_DEPTH = 6      # most steps in a single chain
    _PATH_MAX_RAW = 400      # most raw simple paths explored before we stop
    _PATH_MAX_OUT = 25       # most chains returned to the caller

    def attack_paths(self, combos: list[CombinationFinding]) -> list[AttackPath]:
        """Stitch the individual combinations into end-to-end attack chains.

        Takes the combinations from :meth:`correlate` and links them into ordered
        walks where each step yields a capability the next step consumes
        (``grants`` → ``needs``), and the next step's host is reachable given what
        the previous one produced (same host, a movement capability, or a
        genuinely cross-host technique). Only chains of two or more steps are
        returned; a lone combination is already reported on its own. Deterministic
        and bounded.
        """
        nodes = list(combos)
        n = len(nodes)
        if n < 2:
            return []

        grants = [_grants_of(c.rule_id) for c in nodes]
        needs = [_needs_of(c.rule_id) for c in nodes]
        cross = [bool(c.cross_host) for c in nodes]
        hostsets = [set(c.scope) for c in nodes]

        # Adjacency: an edge a → b exists only when b consumes a capability a
        # yields, and b's host is reachable from a. Built in index order so the
        # whole enumeration is deterministic.
        adj: list[list[int]] = [[] for _ in range(n)]
        for a in range(n):
            if not grants[a]:
                continue
            for b in range(n):
                if a == b or not needs[b]:
                    continue
                if not (grants[a] & needs[b]):
                    continue
                # Reachability: same host, a movement capability was gained, or
                # the step is inherently cross-host (credential reuse, mail).
                same_host = (not hostsets[a] or not hostsets[b]
                             or bool(hostsets[a] & hostsets[b]))
                can_move = bool(grants[a] & _MOVEMENT_CAPS) or cross[b] or cross[a]
                if same_host or can_move:
                    adj[a].append(b)

        raw: list[tuple[int, ...]] = []

        def _dfs(node: int, visited: set[int], acc: list[int]) -> None:
            if len(raw) >= self._PATH_MAX_RAW:
                return
            if len(acc) < self._PATH_MAX_DEPTH:
                for nb in adj[node]:
                    if nb in visited:
                        continue
                    visited.add(nb)
                    acc.append(nb)
                    _dfs(nb, visited, acc)
                    acc.pop()
                    visited.discard(nb)
                    if len(raw) >= self._PATH_MAX_RAW:
                        return
            if len(acc) >= 2:
                raw.append(tuple(acc))

        for start in range(n):
            _dfs(start, {start}, [start])

        # Collapse orderings of the same combo set to one deterministic
        # representative (the first seen), then keep only maximal chains: a
        # chain whose combo set is a strict subset of a longer kept chain is
        # dropped, since the longer chain already tells its story.
        seen_sets: set[frozenset[int]] = set()
        reps: list[tuple[int, ...]] = []
        for p in raw:
            fs = frozenset(p)
            if fs in seen_sets:
                continue
            seen_sets.add(fs)
            reps.append(p)
        reps.sort(key=len, reverse=True)
        kept: list[tuple[int, ...]] = []
        kept_sets: list[set[int]] = []
        for p in reps:
            s = set(p)
            if any(s < ks for ks in kept_sets):
                continue
            kept.append(p)
            kept_sets.append(s)

        paths = [self._build_path(nodes, grants, cross, idxs) for idxs in kept]
        paths.sort(key=lambda p: (
            _sev_rank(p.severity), p.length, p.confidence,
            1 if p.confirmation == "Confirmed" else 0,
        ), reverse=True)
        return paths[:self._PATH_MAX_OUT]

    @staticmethod
    def _build_path(nodes: list[CombinationFinding],
                    grants: list[frozenset[str]], cross: list[bool],
                    idxs: tuple[int, ...]) -> AttackPath:
        """Assemble one AttackPath from an ordered list of combo indices."""
        def _caps_label(caps: set[str]) -> str:
            named = [_CAP_LABEL[c] for c in sorted(caps) if c in _CAP_LABEL]
            return ", ".join(named) if named else "no new capability"

        steps: list[dict] = []
        narrative: list[str] = []
        hosts_ordered: list[str] = []
        caps_ordered: list[str] = []
        comps_by_host: dict[str, list[dict]] = {}
        component_keys: list[str] = []
        mitre_ordered: list[str] = []
        phases: list[str] = []
        confidence = 1.0
        confirmed = True
        max_rank = 0

        for pos, node_i in enumerate(idxs):
            c = nodes[node_i]
            prev_i = idxs[pos - 1] if pos > 0 else None
            cur_hosts = list(c.scope)
            prev_hosts = set(nodes[prev_i].scope) if prev_i is not None else set()
            shared = set(cur_hosts) & prev_hosts
            new_hosts = [h for h in cur_hosts if h not in prev_hosts]
            cur_host = (new_hosts or cur_hosts or ["the next host"])[0]

            if prev_i is None:
                via = ""
            elif shared:
                via = f"On the same host ({sorted(shared)[0]})"
            elif "internal_reach" in grants[prev_i]:
                via = f"Pivoting over the internal network reach just gained, to {cur_host}"
            elif "credentials" in grants[prev_i]:
                via = f"Reusing the captured credentials against {cur_host}"
            elif cross[node_i] or cross[prev_i]:
                via = f"Pivoting to {cur_host}"
            else:
                via = f"Continuing against {cur_host}"

            for h in cur_hosts:
                if h and h not in hosts_ordered:
                    hosts_ordered.append(h)
                comps_by_host.setdefault(h, [])
            for comp in c.components:
                comps_by_host.setdefault(
                    _host_of({"target": comp.get("target")}), []).append(comp)
                k = _component_key(comp)
                if k not in component_keys:
                    component_keys.append(k)
            for cap in sorted(grants[node_i]):
                if cap not in caps_ordered:
                    caps_ordered.append(cap)
            for t in c.mitre:
                if t not in mitre_ordered:
                    mitre_ordered.append(t)
            if c.phase and c.phase not in phases:
                phases.append(c.phase)
            confidence *= float(c.confidence or 0.0)
            confirmed = confirmed and (c.confirmation == "Confirmed")
            max_rank = max(max_rank, _sev_rank(c.combined_severity))

            gained = _caps_label(set(grants[node_i]))
            if pos == 0:
                narrative.append(
                    f"Entry: \"{c.name}\" on {cur_host} yields {gained}.")
            else:
                narrative.append(f"{via}, \"{c.name}\" yields {gained}.")

            steps.append({
                "position": pos + 1,
                "id": c.id,
                "rule_id": c.rule_id,
                "name": c.name,
                "combined_severity": c.combined_severity,
                "confirmation": c.confirmation,
                "hosts": cur_hosts,
                "phase": c.phase,
                "cwe": c.cwe,
                "mitre": list(c.mitre),
                "grants": sorted(grants[node_i]),
                "via": via,
                "components": [{
                    "title": comp.get("title") or comp.get("vuln_type") or "Finding",
                    "severity": comp.get("severity") or "info",
                    "target": comp.get("target") or "",
                    "vuln_type": comp.get("vuln_type") or "",
                } for comp in c.components],
            })

        roles = {_host_role(v) for v in comps_by_host.values() if v}
        impact, impact_detail = _path_business_impact(set(caps_ordered), roles)
        severity = _RANK_SEV[max_rank]
        narrative.append(f"Impact: {impact}.")

        pid = "HEAVEN-PATH-" + hashlib.sha256(
            "|".join(nodes[i].id for i in idxs).encode("utf-8", "replace")
        ).hexdigest()[:8].upper()

        return AttackPath(
            id=pid,
            steps=steps,
            entry=f"{nodes[idxs[0]].name} on {(list(nodes[idxs[0]].scope) or ['host'])[0]}",
            hosts=hosts_ordered,
            length=len(idxs),
            severity=severity,
            representative_cvss=score_from_label(severity),
            confidence=round(confidence, 2),
            confirmation="Confirmed" if confirmed else "Potential",
            capabilities=caps_ordered,
            business_impact=impact,
            impact_detail=impact_detail,
            mitre=mitre_ordered,
            phases=phases,
            narrative=narrative,
            component_keys=component_keys,
        )

    # -- remediation leverage (break the chain) -------------------------------

    def _remediation(self, combos: list[CombinationFinding],
                     paths: list[AttackPath]) -> dict[str, Any]:
        """Which single fixes break the most chains, and the smallest set of
        fixes that severs every multi-step attack path.

        A combined risk needs all of its parts, so fixing any one constituent
        breaks it; a path is broken when any combo along it is broken. This
        turns the graph into a concrete, ranked to-do list: fix these and this
        many chains (and paths to your crown jewels) collapse.
        """
        reg: dict[str, dict] = {}
        for c in combos:
            for comp in c.components:
                k = _component_key(comp)
                r = reg.get(k)
                if r is None:
                    r = reg[k] = {
                        "title": comp.get("title") or comp.get("vuln_type") or "finding",
                        "target": comp.get("target") or "",
                        "severity": str(comp.get("severity") or "info").lower(),
                        "chains": set(), "chain_names": set(), "paths": set(),
                    }
                elif _sev_rank(comp.get("severity")) > _sev_rank(r["severity"]):
                    r["severity"] = str(comp.get("severity") or "info").lower()
                r["chains"].add(c.id)
                r["chain_names"].add(c.name)

        path_members: dict[str, set[str]] = {}
        for p in paths:
            keys = set(p.component_keys)
            path_members[p.id] = keys
            for k in keys:
                if k in reg:
                    reg[k]["paths"].add(p.id)

        ranked = list(reg.values())
        ranked.sort(key=lambda r: r["title"])
        ranked.sort(key=lambda r: (len(r["chains"]), len(r["paths"]),
                                   _sev_rank(r["severity"])), reverse=True)

        def _out(r: dict) -> dict:
            return {
                "title": r["title"],
                "target": r["target"],
                "severity": r["severity"],
                "chains_broken": len(r["chains"]),
                "paths_broken": len(r["paths"]),
                "breaks": sorted(r["chain_names"])[:6],
            }

        by_finding = [_out(r) for r in ranked[:12]]
        top_fix = by_finding[0] if by_finding else None

        # Greedy minimum set that breaks every attack path (deterministic: on a
        # tie the higher-leverage finding, already earlier in ``ranked``, wins).
        cut: list[dict] = []
        if path_members:
            uncovered = set(path_members)
            cands = [r for r in ranked if r["paths"]]
            while uncovered:
                best = None
                best_cov = 0
                for r in cands:
                    cov = len(r["paths"] & uncovered)
                    if cov > best_cov:
                        best_cov = cov
                        best = r
                if best is None or best_cov == 0:
                    break
                cut.append({
                    "title": best["title"], "target": best["target"],
                    "severity": best["severity"], "paths_broken": best_cov,
                })
                uncovered -= best["paths"]

        return {
            "by_finding": by_finding,
            "top_fix": top_fix,
            "path_cut": cut,
            "total_paths": len(paths),
            "paths_cut": len(paths) - len(uncovered) if path_members else 0,
        }

    def summary(self, findings: list[dict]) -> dict[str, Any]:
        """Structured summary for the API, report, and UI."""
        combos = self.correlate(findings)
        paths = self.attack_paths(combos)
        remediation = self._remediation(combos, paths)
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
            "total_attack_paths": len(paths),
            "attack_paths": [p.to_dict() for p in paths],
            "remediation": remediation,
        }


def correlate_findings(findings: list[dict]) -> dict[str, Any]:
    """Convenience wrapper: run the default engine and return its summary dict."""
    return CorrelationEngine().summary(findings)
