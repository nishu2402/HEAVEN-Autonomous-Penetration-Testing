"""
HEAVEN — Vulnerability Knowledge Base

Static, curated reference data keyed by ``vuln_type``. When a finding doesn't
carry its own description / remediation / references (e.g. host-level findings
from recon that never produced an HTTP request/response pair), the evidence
packager and the API enrich it from this table so the UI and reports always
show meaningful, accurate, real-world information instead of blank fields.

Every entry is grounded in real standards (OWASP, CWE, MITRE ATT&CK, CIS).
Nothing here is fabricated per-target — it is generic, factual guidance for the
vulnerability *class*, exactly like a professional pentest report's appendix.

Keys are normalised: lowercased, non-alphanumerics collapsed to ``_``. So
``DOCKER_SOCKET_EXPOSED``, ``docker-socket-exposed`` and
``Docker Socket Exposed`` all resolve to the same entry.
"""

from __future__ import annotations

import re
from typing import Any

# Typical CVSS v3.1 base score for the class (used only as a labelled fallback
# when no per-finding predicted score exists — always shown as "typical").
_KB: dict[str, dict[str, Any]] = {
    "docker_socket_exposed": {
        "title": "Exposed Docker daemon socket",
        "cwe": "CWE-284",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1610 — Deploy Container",
        "typical_cvss": 9.8,
        "description": (
            "The Docker daemon UNIX socket (/var/run/docker.sock) or TCP API is "
            "reachable. Anyone who can talk to it has root-equivalent control of "
            "the host: they can start a privileged container that bind-mounts the "
            "host filesystem and escape to the underlying node."
        ),
        "impact": (
            "Full host compromise / container escape. An attacker can read or "
            "modify any file on the host, pivot to other containers, and harvest "
            "secrets mounted into the daemon."
        ),
        "remediation": (
            "1. Never bind-mount /var/run/docker.sock into untrusted containers.\n"
            "2. Do not expose the Docker API over TCP without mTLS; if you must, "
            "bind to 127.0.0.1 and require client certificates.\n"
            "3. Use a rootless Docker daemon or a brokered API (e.g. Docker "
            "socket-proxy with a least-privilege allowlist).\n"
            "4. Apply firewall rules so ports 2375/2376 are never internet-facing."
        ),
        "references": [
            "https://docs.docker.com/engine/security/protect-access/",
            "https://owasp.org/www-project-docker-top-10/",
        ],
    },
    "sql_injection": {
        "title": "SQL Injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 9.8,
        "description": (
            "User-controllable input is concatenated into a SQL query, allowing an "
            "attacker to alter query logic — reading, modifying or destroying data, "
            "and in some configurations executing OS commands."
        ),
        "impact": "Database compromise, authentication bypass, data exfiltration, possible RCE.",
        "remediation": (
            "1. Use parameterised queries / prepared statements everywhere.\n"
            "2. Use an ORM with bound parameters; never string-format SQL.\n"
            "3. Apply least-privilege DB accounts and input allowlisting.\n"
            "4. Add a WAF rule as defence-in-depth, not the primary control."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    "rce": {
        "title": "Remote Code Execution",
        "cwe": "CWE-94",
        "owasp": "A03:2021 Injection",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 9.9,
        "description": (
            "The application executes attacker-controlled input as code or OS "
            "commands, giving the attacker arbitrary execution on the server."
        ),
        "impact": "Complete server takeover, lateral movement, data theft, persistence.",
        "remediation": (
            "1. Never pass user input to eval/exec/system/deserialisers.\n"
            "2. Use safe APIs and strict allowlists for any dynamic behaviour.\n"
            "3. Run the service as an unprivileged user inside a sandbox.\n"
            "4. Patch the vulnerable component to a fixed version."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Code_Injection",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery",
        "cwe": "CWE-918",
        "owasp": "A10:2021 Server-Side Request Forgery",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 8.6,
        "description": (
            "The server fetches a URL supplied by the user, letting an attacker "
            "reach internal services, cloud metadata endpoints (169.254.169.254), "
            "or otherwise unreachable hosts."
        ),
        "impact": "Cloud credential theft, internal network scanning, firewall bypass.",
        "remediation": (
            "1. Allowlist outbound destinations; deny RFC1918 + link-local by default.\n"
            "2. Disable unused URL schemes (file://, gopher://, dict://).\n"
            "3. Require IMDSv2 on AWS; block metadata IPs at the egress proxy.\n"
            "4. Validate and re-resolve hostnames to prevent DNS rebinding."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "xss_stored": {
        "title": "Stored Cross-Site Scripting",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "mitre": "T1059.007 — JavaScript",
        "typical_cvss": 7.2,
        "description": (
            "Attacker-supplied script is persisted and later rendered to other "
            "users without proper output encoding, executing in their browser."
        ),
        "impact": "Session hijacking, credential theft, account takeover, worming.",
        "remediation": (
            "1. Contextual output encoding on all user data.\n"
            "2. A strict Content-Security-Policy (no unsafe-inline).\n"
            "3. Sanitise rich text with a vetted library (e.g. DOMPurify).\n"
            "4. Set HttpOnly + SameSite on session cookies."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "xss": {
        "title": "Cross-Site Scripting",
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "mitre": "T1059.007 — JavaScript",
        "typical_cvss": 6.1,
        "description": "User input is reflected into a page without encoding, executing script in the victim's browser.",
        "impact": "Session theft, phishing, defacement, CSRF-token exfiltration.",
        "remediation": "Contextual output encoding, a strict CSP, and HttpOnly cookies.",
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "idor": {
        "title": "Insecure Direct Object Reference",
        "cwe": "CWE-639",
        "owasp": "A01:2021 Broken Access Control",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 8.1,
        "description": (
            "An object identifier in the request can be changed to access another "
            "user's data because the server doesn't enforce per-object authorization."
        ),
        "impact": "Horizontal/vertical privilege escalation, mass data disclosure.",
        "remediation": (
            "1. Enforce object-level authorization on every request server-side.\n"
            "2. Use unguessable, non-sequential identifiers as defence-in-depth.\n"
            "3. Add automated access-control tests to CI."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
        ],
    },
    "auth_bypass": {
        "title": "Authentication Bypass",
        "cwe": "CWE-287",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "mitre": "T1078 — Valid Accounts",
        "typical_cvss": 9.1,
        "description": "A flaw in the auth flow lets an attacker access protected functionality without valid credentials.",
        "impact": "Unauthorized access to privileged functions and data.",
        "remediation": (
            "1. Centralise auth checks in middleware; deny by default.\n"
            "2. Use a vetted identity library; never roll your own session logic.\n"
            "3. Enforce MFA for privileged roles."
        ),
        "references": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    },
    "exposed_rdp": {
        "title": "Internet-Exposed RDP",
        "cwe": "CWE-284",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1021.001 — Remote Desktop Protocol",
        "typical_cvss": 8.8,
        "description": "Remote Desktop (TCP 3389) is reachable from untrusted networks, a primary ransomware entry vector.",
        "impact": "Brute-force / credential-stuffing leading to full host access; common ransomware foothold.",
        "remediation": (
            "1. Never expose 3389 to the internet — require a VPN or bastion.\n"
            "2. Enforce Network Level Authentication + MFA.\n"
            "3. Apply account-lockout and rate-limiting; monitor logon failures."
        ),
        "references": ["https://attack.mitre.org/techniques/T1021/001/"],
    },
    "weak_tls": {
        "title": "Weak TLS Configuration",
        "cwe": "CWE-326",
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": "T1040 — Network Sniffing",
        "typical_cvss": 5.9,
        "description": "The endpoint supports deprecated protocols (SSLv3/TLS 1.0/1.1) or weak ciphers vulnerable to interception.",
        "impact": "Man-in-the-middle decryption of traffic, credential capture.",
        "remediation": (
            "1. Disable TLS < 1.2; prefer TLS 1.3.\n"
            "2. Use modern AEAD cipher suites only; enable HSTS.\n"
            "3. Test with the Mozilla SSL Configuration Generator."
        ),
        "references": ["https://wiki.mozilla.org/Security/Server_Side_TLS"],
    },
    "missing_security_headers": {
        "title": "Missing Security Headers",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1185 — Browser Session Hijacking",
        "typical_cvss": 4.3,
        "description": "Response lacks protective headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).",
        "impact": "Increases exploitability of XSS, clickjacking, MIME-sniffing and downgrade attacks.",
        "remediation": (
            "1. Add Content-Security-Policy, Strict-Transport-Security, "
            "X-Content-Type-Options: nosniff, and X-Frame-Options: DENY.\n"
            "2. Verify with securityheaders.com."
        ),
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "open_redirect": {
        "title": "Open Redirect",
        "cwe": "CWE-601",
        "owasp": "A01:2021 Broken Access Control",
        "mitre": "T1566 — Phishing",
        "typical_cvss": 4.7,
        "description": "A redirect target is taken from user input without validation, enabling convincing phishing.",
        "impact": "Phishing, OAuth token theft via redirect_uri abuse.",
        "remediation": "Allowlist redirect targets; never redirect to a raw user-supplied URL.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    },
    "cookie_no_httponly": {
        "title": "Session Cookie Without HttpOnly",
        "cwe": "CWE-1004",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1539 — Steal Web Session Cookie",
        "typical_cvss": 4.0,
        "description": "A session cookie lacks the HttpOnly flag, so client-side script can read it.",
        "impact": "XSS becomes session theft; weakens defence-in-depth.",
        "remediation": "Set HttpOnly, Secure and SameSite on all session cookies.",
        "references": ["https://owasp.org/www-community/HttpOnly"],
    },
    "verbose_errors": {
        "title": "Verbose Error Messages",
        "cwe": "CWE-209",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1592 — Gather Victim Host Information",
        "typical_cvss": 3.7,
        "description": "Stack traces or debug output leak framework versions, file paths or SQL, aiding attackers.",
        "impact": "Information disclosure that accelerates targeted attacks.",
        "remediation": "Return generic error pages in production; log details server-side only.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },
    "info_disclosure": {
        "title": "Information Disclosure",
        "cwe": "CWE-200",
        "owasp": "A01:2021 Broken Access Control",
        "mitre": "T1592 — Gather Victim Host Information",
        "typical_cvss": 5.3,
        "description": "Sensitive technical information (server-status, version banners, internal paths) is exposed.",
        "impact": "Reconnaissance aid; narrows an attacker's path to exploitation.",
        "remediation": "Restrict status/diagnostic endpoints; suppress version banners.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "default_credentials": {
        "title": "Default / Weak Credentials",
        "cwe": "CWE-1392",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "mitre": "T1078.001 — Default Accounts",
        "typical_cvss": 9.8,
        "description": "A service accepts vendor-default or trivially guessable credentials.",
        "impact": "Immediate unauthorized access, often with administrative rights.",
        "remediation": "Force a credential change on first use; enforce a strong password policy + MFA.",
        "references": ["https://attack.mitre.org/techniques/T1078/001/"],
    },
    "command_injection": {
        "title": "OS Command Injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "mitre": "T1059 — Command and Scripting Interpreter",
        "typical_cvss": 9.8,
        "description": (
            "User input reaches a shell command, letting an attacker run arbitrary "
            "OS commands with the privileges of the web process."
        ),
        "impact": "Full server compromise, data theft, lateral movement, persistence.",
        "remediation": (
            "1. Never build shell strings from user input; pass an argument list "
            "with shell=False (e.g. subprocess.run([...], shell=False)).\n"
            "2. Avoid the shell entirely; call the target binary directly.\n"
            "3. Strictly allowlist any values that must reach a command.\n"
            "4. Drop privileges and sandbox the process (seccomp/AppArmor)."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    "file_inclusion": {
        "title": "File Inclusion (LFI/RFI)",
        "cwe": "CWE-98",
        "owasp": "A03:2021 Injection",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 8.1,
        "description": (
            "A file path or include target is taken from user input, letting an "
            "attacker read local files (LFI) or, if remote includes are enabled, "
            "load and execute remote code (RFI)."
        ),
        "impact": "Source/secret disclosure, log-poisoning to RCE, remote code execution.",
        "remediation": (
            "1. Never pass user input to include/require/open; map an allowlist of "
            "identifiers to fixed server-side paths instead.\n"
            "2. Disable remote includes (PHP allow_url_include=Off).\n"
            "3. Canonicalise paths and confine them under a base directory.\n"
            "4. Run with least-privilege filesystem permissions."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.mitre.org/data/definitions/98.html",
        ],
    },
    "path_traversal": {
        "title": "Path Traversal",
        "cwe": "CWE-22",
        "owasp": "A01:2021 Broken Access Control",
        "mitre": "T1006 — Direct Volume Access",
        "typical_cvss": 7.5,
        "description": (
            "A filename parameter containing ../ sequences escapes the intended "
            "directory, exposing arbitrary files on disk."
        ),
        "impact": "Disclosure of source code, credentials, keys and system files.",
        "remediation": (
            "1. Resolve the path and verify it stays within the intended base "
            "directory (os.path.realpath / Path.resolve + prefix check).\n"
            "2. Reject any input containing path separators or ../.\n"
            "3. Prefer opaque identifiers mapped to files server-side."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },
    "ssti": {
        "title": "Server-Side Template Injection",
        "cwe": "CWE-1336",
        "owasp": "A03:2021 Injection",
        "mitre": "T1059 — Command and Scripting Interpreter",
        "typical_cvss": 9.0,
        "description": (
            "User input is evaluated as template code, which in most engines leads "
            "directly to remote code execution."
        ),
        "impact": "Remote code execution, full server takeover.",
        "remediation": (
            "1. Never render user input as a template; pass it as data/variables.\n"
            "2. Use a sandboxed environment (e.g. Jinja2 SandboxedEnvironment).\n"
            "3. Prefer logic-less templates for user-influenced content."
        ),
        "references": [
            "https://portswigger.net/research/server-side-template-injection",
        ],
    },
    "xxe": {
        "title": "XML External Entity (XXE) Injection",
        "cwe": "CWE-611",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 8.2,
        "description": (
            "An XML parser resolves external entities defined by the attacker, "
            "enabling local file disclosure, SSRF, and denial of service."
        ),
        "impact": "Local file read, internal SSRF, credential theft, DoS (billion laughs).",
        "remediation": (
            "1. Disable DTDs and external entity resolution in every XML parser "
            "(e.g. Python: use defusedxml; Java: setFeature disallow-doctype-decl).\n"
            "2. Prefer JSON or a hardened parser where XML isn't required.\n"
            "3. Never let entity URIs reach the network or filesystem."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    },
    "cors_misconfig": {
        "title": "CORS Misconfiguration",
        "cwe": "CWE-942",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 7.5,
        "description": (
            "The server reflects an arbitrary Origin into "
            "Access-Control-Allow-Origin — especially with "
            "Access-Control-Allow-Credentials: true — so a malicious site can read "
            "authenticated cross-origin responses."
        ),
        "impact": "Cross-origin theft of authenticated data and CSRF-token exfiltration.",
        "remediation": (
            "1. Allowlist exact trusted origins; never reflect the request Origin.\n"
            "2. Never combine a wildcard/reflected origin with "
            "Allow-Credentials: true.\n"
            "3. Add 'Vary: Origin' and keep the allowed set minimal."
        ),
        "references": [
            "https://portswigger.net/web-security/cors",
        ],
    },
    "insecure_cookie": {
        "title": "Insecure Session Cookie",
        "cwe": "CWE-1004",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1539 — Steal Web Session Cookie",
        "typical_cvss": 5.0,
        "description": (
            "A session/auth cookie is missing protective attributes (HttpOnly, "
            "Secure, SameSite), exposing it to theft or cross-site sending."
        ),
        "impact": "XSS-driven session theft, cookie capture over plaintext, CSRF.",
        "remediation": (
            "1. Set HttpOnly on all session cookies (blocks script access).\n"
            "2. Set Secure so the cookie is only sent over HTTPS.\n"
            "3. Set SameSite=Lax or Strict to blunt cross-site requests.\n"
            "4. Scope with Path and a short, rotating lifetime."
        ),
        "references": ["https://owasp.org/www-community/HttpOnly"],
    },
    "jwt_weak_secret": {
        "title": "JWT Signed With a Weak Secret",
        "cwe": "CWE-326",
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": "T1552 — Unsecured Credentials",
        "typical_cvss": 9.1,
        "description": (
            "The HMAC key used to sign JSON Web Tokens is guessable, so an attacker "
            "can forge valid tokens with arbitrary claims (e.g. escalate to admin)."
        ),
        "impact": "Authentication bypass and privilege escalation via forged tokens.",
        "remediation": (
            "1. Rotate to a long, random secret (>=256 bits) stored in a secrets "
            "manager, not in code.\n"
            "2. Prefer asymmetric signing (RS256/ES256) so the verifier holds no "
            "signing key.\n"
            "3. Pin the expected algorithm on verification and reject others."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ],
    },
    "jwt_none_algorithm": {
        "title": "JWT Accepts alg:none",
        "cwe": "CWE-347",
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": "T1552 — Unsecured Credentials",
        "typical_cvss": 9.8,
        "description": (
            "The verifier accepts tokens using the 'none' algorithm, which carry no "
            "signature — any client can forge a token with any claims."
        ),
        "impact": "Trivial authentication bypass and privilege escalation.",
        "remediation": (
            "1. Reject alg:none outright; pin an explicit allowed algorithm list.\n"
            "2. Verify the signature before trusting any claim.\n"
            "3. Upgrade the JWT library to a version that blocks alg confusion."
        ),
        "references": [
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
    },
    "crlf_injection": {
        "title": "CRLF / HTTP Response Splitting",
        "cwe": "CWE-113",
        "owasp": "A03:2021 Injection",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 6.1,
        "description": (
            "Unescaped CR/LF in user input is written into HTTP response headers, "
            "letting an attacker inject headers or split the response."
        ),
        "impact": "Header injection, cache poisoning, reflected XSS, session fixation.",
        "remediation": (
            "1. Strip/deny CR and LF in any value placed into a header.\n"
            "2. Use framework APIs that encode header values.\n"
            "3. Avoid reflecting user input into Location/Set-Cookie headers."
        ),
        "references": ["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
    },
    "request_smuggling": {
        "title": "HTTP Request Smuggling",
        "cwe": "CWE-444",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 8.1,
        "description": (
            "A front-end and back-end disagree on request boundaries "
            "(Content-Length vs Transfer-Encoding), letting an attacker smuggle a "
            "second request past the front-end."
        ),
        "impact": "Cache poisoning, request hijacking, security-control bypass.",
        "remediation": (
            "1. Normalise/reject ambiguous Content-Length + Transfer-Encoding.\n"
            "2. Use HTTP/2 end-to-end and a single, consistent proxy stack.\n"
            "3. Drop conflicting or duplicate framing headers at the edge."
        ),
        "references": ["https://portswigger.net/web-security/request-smuggling"],
    },
    "subdomain_takeover": {
        "title": "Subdomain Takeover",
        "cwe": "CWE-350",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1584 — Compromise Infrastructure",
        "typical_cvss": 7.4,
        "description": (
            "A DNS record points at a de-provisioned third-party service, letting "
            "an attacker claim it and serve content from your domain."
        ),
        "impact": "Phishing under your brand, cookie theft, OAuth/callback abuse.",
        "remediation": (
            "1. Remove dangling DNS records for decommissioned services.\n"
            "2. Claim/park the backing resource before releasing it.\n"
            "3. Continuously monitor CNAMEs for unclaimed targets."
        ),
        "references": ["https://owasp.org/www-community/attacks/Subdomain_takeover"],
    },

    # ── HTTP security-header / posture findings ─────────────────────────
    # These are what a live recon scan of a real site actually produces
    # (certifiedhacker.com et al.). Without KB entries the report's
    # CWE / OWASP / MITRE / CVSS-vector columns were left blank.
    "csp_missing": {
        "title": "Content-Security-Policy Not Set",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1185 — Browser Session Hijacking",
        "typical_cvss": 4.6,
        "description": (
            "The response does not send a Content-Security-Policy header, so the "
            "browser applies no restrictions on where scripts, styles and other "
            "resources may load from."
        ),
        "impact": "Removes a key defence-in-depth control against XSS and data injection.",
        "remediation": (
            "1. Add a Content-Security-Policy header, starting in report-only mode.\n"
            "2. Use 'default-src \\'self\\''; avoid 'unsafe-inline'/'unsafe-eval'.\n"
            "3. Verify coverage with securityheaders.com / CSP Evaluator."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            "https://owasp.org/www-project-secure-headers/",
        ],
    },
    "clickjacking": {
        "title": "Clickjacking — X-Frame-Options Not Set",
        "cwe": "CWE-1021",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1185 — Browser Session Hijacking",
        "typical_cvss": 4.6,
        "description": (
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so "
            "the page can be embedded in an attacker-controlled <iframe> and used "
            "for a clickjacking (UI-redress) attack."
        ),
        "impact": "Tricks a logged-in victim into performing unintended actions.",
        "remediation": (
            "1. Set 'X-Frame-Options: DENY' (or SAMEORIGIN where framing is needed).\n"
            "2. Add CSP 'frame-ancestors \\'none\\'' as the modern equivalent.\n"
            "3. Confirm on sensitive/state-changing pages specifically."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
    },
    "hsts_missing": {
        "title": "HTTP Strict Transport Security Not Configured",
        "cwe": "CWE-319",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1557 — Adversary-in-the-Middle",
        "typical_cvss": 4.6,
        "description": (
            "The site does not send a Strict-Transport-Security header, so a browser "
            "will still attempt plaintext HTTP and can be downgraded / SSL-stripped "
            "by a network attacker."
        ),
        "impact": "Man-in-the-middle downgrade, session-cookie capture over HTTP.",
        "remediation": (
            "1. Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.\n"
            "2. Redirect all HTTP to HTTPS first, then enable HSTS.\n"
            "3. Consider preloading once stable (hstspreload.org)."
        ),
        "references": ["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"],
    },
    "x_content_type_missing": {
        "title": "X-Content-Type-Options Not Set",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1185 — Browser Session Hijacking",
        "typical_cvss": 3.5,
        "description": (
            "The response omits 'X-Content-Type-Options: nosniff', so browsers may "
            "MIME-sniff responses and interpret them as a different content type."
        ),
        "impact": "Enables MIME-confusion attacks that can turn uploads into script.",
        "remediation": "Send 'X-Content-Type-Options: nosniff' on every response.",
        "references": ["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
    },
    "referrer_policy_missing": {
        "title": "Referrer-Policy Not Set",
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1592 — Gather Victim Host Information",
        "typical_cvss": 3.5,
        "description": (
            "No Referrer-Policy header is set, so full URLs (which may contain "
            "tokens or identifiers) can leak to third-party sites via the Referer."
        ),
        "impact": "Leakage of sensitive URL parameters to external origins.",
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).",
        "references": ["https://owasp.org/www-project-secure-headers/#referrer-policy"],
    },
    "permissions_policy_missing": {
        "title": "Permissions-Policy Not Set",
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1185 — Browser Session Hijacking",
        "typical_cvss": 3.5,
        "description": (
            "No Permissions-Policy (formerly Feature-Policy) header is set, so "
            "powerful browser features (camera, microphone, geolocation) are not "
            "explicitly restricted."
        ),
        "impact": "Widens the attack surface available to injected/embedded content.",
        "remediation": "Set a Permissions-Policy that disables unused features, e.g. 'camera=(), microphone=(), geolocation=()'.",
        "references": ["https://owasp.org/www-project-secure-headers/#permissions-policy"],
    },
    "dangerous_http_method": {
        "title": "Dangerous HTTP Method Enabled",
        "cwe": "CWE-650",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "typical_cvss": 6.2,
        "description": (
            "The server accepts a state-changing/administrative HTTP method (e.g. "
            "PUT, DELETE, TRACE, CONNECT) that should normally be disabled on a "
            "public web endpoint. PUT in particular can allow arbitrary file upload."
        ),
        "impact": "Arbitrary file upload / content tampering, potentially leading to RCE.",
        "remediation": (
            "1. Restrict the endpoint to the methods it needs (usually GET/POST/HEAD).\n"
            "2. Disable WebDAV / PUT / DELETE / TRACE at the server or proxy.\n"
            "3. Return 405 Method Not Allowed for everything else."
        ),
        "references": ["https://owasp.org/www-community/attacks/Testing_HTTP_Methods_for_Server_Config"],
    },
    "version_disclosure": {
        "title": "Server / Software Version Disclosure",
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1592.002 — Software",
        "typical_cvss": 3.5,
        "description": (
            "A response header (Server, X-Powered-By, etc.) reveals the exact "
            "software and version, letting an attacker match known CVEs precisely."
        ),
        "impact": "Accelerates targeted exploitation of known vulnerabilities.",
        "remediation": "Suppress version banners (e.g. nginx 'server_tokens off;', remove X-Powered-By).",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "no_rate_limit": {
        "title": "No Rate Limiting Detected",
        "cwe": "CWE-770",
        "owasp": "A04:2021 Insecure Design",
        "mitre": "T1110 — Brute Force",
        "typical_cvss": 4.6,
        "description": (
            "An endpoint (often an API or login) accepted many rapid requests "
            "without throttling, indicating missing rate limiting."
        ),
        "impact": "Enables credential brute-forcing, enumeration and resource-exhaustion DoS.",
        "remediation": (
            "1. Apply per-IP/per-account rate limits and exponential backoff.\n"
            "2. Add lockouts and CAPTCHA on authentication endpoints.\n"
            "3. Enforce quotas at the API gateway."
        ),
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
    },
    "no_forward_secrecy": {
        "title": "No Forward Secrecy",
        "cwe": "CWE-310",
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": "T1040 — Network Sniffing",
        "typical_cvss": 4.6,
        "description": (
            "The TLS configuration does not prefer ephemeral (ECDHE/DHE) key "
            "exchange, so a future compromise of the server's private key would "
            "allow decryption of previously captured traffic."
        ),
        "impact": "Retrospective decryption of recorded sessions after a key compromise.",
        "remediation": "Prefer ECDHE cipher suites (and TLS 1.3, which mandates forward secrecy).",
        "references": ["https://wiki.mozilla.org/Security/Server_Side_TLS"],
    },

    # ── DNS / email authentication posture ──────────────────────────────
    "spf_missing": {
        "title": "SPF Record Missing or Weak",
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1566 — Phishing",
        "typical_cvss": 6.2,
        "description": (
            "The domain has no SPF record, or an SPF policy that does not hard-fail "
            "(no '-all'), so senders are not restricted and the domain can be "
            "spoofed in email."
        ),
        "impact": "Email spoofing / phishing that appears to originate from the domain.",
        "remediation": (
            "1. Publish an SPF TXT record listing authorised senders.\n"
            "2. End the record with '-all' (hard fail) once senders are confirmed.\n"
            "3. Pair with DKIM and DMARC for full coverage."
        ),
        "references": ["https://datatracker.ietf.org/doc/html/rfc7208"],
    },
    "dmarc_missing": {
        "title": "DMARC Record Missing or Weak",
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1566 — Phishing",
        "typical_cvss": 6.2,
        "description": (
            "No DMARC record is published (or the policy is 'p=none'), so receiving "
            "mail servers are not told to reject or quarantine spoofed mail even "
            "when SPF/DKIM fail."
        ),
        "impact": "Domain spoofing and brand-impersonation phishing go undetected.",
        "remediation": (
            "1. Publish a DMARC TXT record at _dmarc.<domain>.\n"
            "2. Start at 'p=none' with rua reporting, then move to quarantine/reject.\n"
            "3. Align SPF and DKIM before enforcing."
        ),
        "references": ["https://datatracker.ietf.org/doc/html/rfc7489"],
    },
    "dkim_missing": {
        "title": "DKIM Not Configured",
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1566 — Phishing",
        "typical_cvss": 4.6,
        "description": (
            "No DKIM signing selector was found for the domain, so outbound mail "
            "cannot be cryptographically verified by recipients."
        ),
        "impact": "Weakens anti-spoofing; DMARC cannot rely on DKIM alignment.",
        "remediation": "Enable DKIM signing on the mail platform and publish the selector's public key in DNS.",
        "references": ["https://datatracker.ietf.org/doc/html/rfc6376"],
    },
    "dnssec_missing": {
        "title": "DNSSEC Not Configured",
        "cwe": "CWE-350",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1557 — Adversary-in-the-Middle",
        "typical_cvss": 4.6,
        "description": (
            "The zone is not signed with DNSSEC, so DNS responses are not "
            "authenticated and can be spoofed via cache poisoning."
        ),
        "impact": "DNS cache poisoning / response forgery redirecting users or mail.",
        "remediation": "Sign the zone with DNSSEC and publish DS records at the parent registrar.",
        "references": ["https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
    },
    "dns_info": {
        "title": "DNS / Mail Infrastructure Information",
        "cwe": "",
        "owasp": "",
        "mitre": "T1590 — Gather Victim Network Information",
        "typical_cvss": 1.0,
        "description": (
            "Informational reconnaissance data enumerated from public DNS "
            "(MX records, SOA administrative contact, DKIM selectors). No "
            "vulnerability is implied — this is context for the assessment."
        ),
        "impact": "Provides an attacker with mapping/targeting information.",
        "remediation": "No action required; ensure records expose only intended information.",
        "references": ["https://attack.mitre.org/techniques/T1590/"],
    },
}

# Severity → typical CVSS fallback when the class is unknown.
_SEV_FALLBACK_CVSS = {
    "critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.5, "info": 1.0,
}

# Detectors emit many spellings for the same class. Map each to its canonical KB
# key so a single curated entry serves every alias (normalised on both sides).
_ALIASES: dict[str, str] = {
    "sqli": "sql_injection",
    "sqli_confirmed": "sql_injection",
    "sql": "sql_injection",
    "blind_sqli": "sql_injection",
    "error_sqli": "sql_injection",
    "union_sqli": "sql_injection",
    "boolean_sqli": "sql_injection",
    "time_sqli": "sql_injection",
    "cmdi": "command_injection",
    "os_command_injection": "command_injection",
    "reflected_xss": "xss",
    "dom_xss": "xss",
    "stored_xss": "xss_stored",
    "lfi": "file_inclusion",
    "rfi": "file_inclusion",
    "local_file_inclusion": "file_inclusion",
    "remote_file_inclusion": "file_inclusion",
    "cors": "cors_misconfig",
    "security_headers": "missing_security_headers",
    "jwt_alg_none": "jwt_none_algorithm",
    "jwt_none": "jwt_none_algorithm",
    "jwt": "jwt_weak_secret",
    "cookie_no_httponly": "insecure_cookie",
    "cookie_insecure": "insecure_cookie",
    "bola": "idor",
    "rce": "rce",
    "remote_code_execution": "rce",
    "code_injection": "rce",
    "tls": "weak_tls",
    "ssl": "weak_tls",
    "weak_ssl": "weak_tls",
    "unvalidated_redirect": "open_redirect",
    # HTTP security-header posture (detector spellings → canonical KB key)
    "missing_csp": "csp_missing",
    "no_csp": "csp_missing",
    "clickjacking_no_xfo": "clickjacking",
    "x_frame_options_missing": "clickjacking",
    "missing_x_frame_options": "clickjacking",
    "no_hsts": "hsts_missing",
    "missing_hsts": "hsts_missing",
    "no_x_content_type": "x_content_type_missing",
    "x_content_type_options_missing": "x_content_type_missing",
    "missing_x_content_type": "x_content_type_missing",
    "no_referrer_policy": "referrer_policy_missing",
    "no_permissions_policy": "permissions_policy_missing",
    "feature_policy_missing": "permissions_policy_missing",
    # HTTP methods / smuggling / disclosure
    "http_smuggling_indicator": "request_smuggling",
    "http_smuggling": "request_smuggling",
    "cl_te": "request_smuggling",
    "server_version_disclosure": "version_disclosure",
    "server_banner": "version_disclosure",
    "server_version": "version_disclosure",
    "powered_by_disclosure": "version_disclosure",
    "no_rate_limiting": "no_rate_limit",
    "rate_limit": "no_rate_limit",
    "api_no_rate_limit": "no_rate_limit",
    "xml_accepted": "xxe",
    "xml_input_accepted": "xxe",
    # DNS / email authentication posture
    "spf_analysis": "spf_missing",
    "spf_weak": "spf_missing",
    "dmarc_weak": "dmarc_missing",
    "dkim_weak": "dkim_missing",
    "dnssec_not_enabled": "dnssec_missing",
    "dnssec_disabled": "dnssec_missing",
    # Informational DNS / mail recon
    "mx_enumeration": "dns_info",
    "mx_records": "dns_info",
    "soa_admin_email": "dns_info",
    "dkim_found": "dns_info",
    "dkim_selector_found": "dns_info",
    "dns_enumeration": "dns_info",
}

# Representative CVSS v3.1 base vectors per canonical KB class. Kept as a single
# source of truth so the report's "CVSS vector" column is never blank for a
# known class (previously only ~8 web classes were covered). Illustrative for
# the vulnerability *class* — not a per-target recomputation.
_CVSS_VECTOR_BY_KEY: dict[str, str] = {
    "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "xss_stored": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N",
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "default_credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "file_inclusion": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L",
    "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "cors_misconfig": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "insecure_cookie": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "cookie_no_httponly": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "jwt_weak_secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "jwt_none_algorithm": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "crlf_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "request_smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "subdomain_takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "docker_socket_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "exposed_rdp": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "weak_tls": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "no_forward_secrecy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "missing_security_headers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "csp_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "clickjacking": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "hsts_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "x_content_type_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "referrer_policy_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "permissions_policy_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "dangerous_http_method": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
    "version_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "info_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "verbose_errors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "no_rate_limit": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "spf_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
    "dmarc_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
    "dkim_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "dnssec_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
}


def cvss_vector_for(vuln_type: str) -> str:
    """Representative CVSS v3.1 vector for a vuln class (resolving aliases), or ''."""
    key = normalize_key(vuln_type)
    if key not in _CVSS_VECTOR_BY_KEY:
        key = _ALIASES.get(key, key)
    return _CVSS_VECTOR_BY_KEY.get(key, "")


def normalize_key(vuln_type: str) -> str:
    """Lowercase + collapse non-alphanumerics to `_` (so all spellings match)."""
    return re.sub(r"[^a-z0-9]+", "_", (vuln_type or "").lower()).strip("_")


def lookup(vuln_type: str) -> dict[str, Any]:
    """Return the KB entry for a vuln type (resolving aliases), or {} if unknown."""
    key = normalize_key(vuln_type)
    if key in _KB:
        return _KB[key]
    return _KB.get(_ALIASES.get(key, ""), {})


def remediation_text(finding: dict) -> str:
    """A complete, human-readable remediation write-up for a finding — built
    entirely in-house from the KB, no LLM required.

    This is what HEAVEN returns for "explain the fix" when no LLM key is
    configured: a professional, class-accurate report section (summary, impact,
    numbered fix steps, references) rather than a generic one-liner.
    """
    entry = lookup(finding.get("vuln_type", "") or finding.get("type", ""))
    title = (finding.get("title") or entry.get("title")
             or finding.get("vuln_type") or "Security Finding")
    target = finding.get("target", "")
    lines = [f"# Remediation — {title}"]
    if target:
        lines.append(f"_Affected target: {target}_")
    if not entry:
        # Unknown class: still better than a bare string — give the standard drill.
        sev = (finding.get("severity") or "medium").lower()
        lines += [
            "",
            f"**Severity:** {sev}",
            "",
            "This finding isn't in the built-in knowledge base. Apply the standard "
            "remediation drill:",
            "1. Reproduce and confirm the issue against the affected endpoint.",
            "2. Treat all client input as untrusted — validate, encode, and "
            "parameterise at the sink.",
            "3. Apply least privilege to the affected component and its data access.",
            "4. Patch the underlying framework/library to a fixed release.",
            "5. Add a regression test so the fix can't silently revert.",
        ]
        return "\n".join(lines)

    if entry.get("cwe") or entry.get("owasp"):
        meta = "  ".join(x for x in (entry.get("cwe", ""), entry.get("owasp", "")) if x)
        lines.append(f"_{meta}_")
    if entry.get("description"):
        lines += ["", "## What it is", entry["description"]]
    if entry.get("impact"):
        lines += ["", "## Impact", entry["impact"]]
    if entry.get("remediation"):
        lines += ["", "## How to fix it", entry["remediation"]]
    refs = entry.get("references") or []
    if refs:
        lines += ["", "## References"] + [f"- {r}" for r in refs]
    return "\n".join(lines)


def enrich_finding(finding: dict) -> dict:
    """Return a shallow copy of `finding` with KB defaults filled into any
    missing description / remediation / references / mitre / cwe / owasp /
    typical_cvss fields. Per-finding data always wins over KB defaults.
    """
    out = dict(finding)
    entry = lookup(finding.get("vuln_type", ""))
    ev = dict(out.get("evidence") or {})

    if entry:
        ev.setdefault("description", entry.get("description", ""))
        if entry.get("impact"):
            ev.setdefault("impact", entry["impact"])
        if not ev.get("remediation") and entry.get("remediation"):
            ev["remediation"] = entry["remediation"]
        if not ev.get("references") and entry.get("references"):
            ev["references"] = entry["references"]
        if not ev.get("reasons") and entry.get("description"):
            ev["reasons"] = [
                f"Matches the {entry.get('title', finding.get('vuln_type'))} "
                f"class ({entry.get('cwe', '')})."
            ]
    out["evidence"] = ev

    if not out.get("mitre_technique") and entry.get("mitre"):
        out["mitre_technique"] = entry["mitre"]
    if not out.get("cwe") and entry.get("cwe"):
        out["cwe"] = entry["cwe"]
    if not out.get("owasp") and entry.get("owasp"):
        out["owasp"] = entry["owasp"]

    # A representative CVSS vector for the class so the report's "CVSS vector"
    # column is populated for every known class, not just a handful.
    if not out.get("cvss_vector"):
        vec = cvss_vector_for(finding.get("vuln_type", ""))
        if vec:
            out["cvss_vector"] = vec

    # Mirror the taxonomy into evidence too — the web FindingDetail falls back to
    # evidence.cwe / evidence.owasp / evidence.mitre, so keep both in sync.
    for src, dst in (("cwe", "cwe"), ("owasp", "owasp"), ("mitre_technique", "mitre")):
        if out.get(src) and not ev.get(dst):
            ev[dst] = out[src]
    if out.get("cvss_vector"):
        ev.setdefault("cvss_vector", out["cvss_vector"])
    out["evidence"] = ev

    if not out.get("predicted_cvss_score"):
        out["typical_cvss"] = entry.get("typical_cvss") or _SEV_FALLBACK_CVSS.get(
            (finding.get("severity") or "").lower(), 0.0
        )
    return out
