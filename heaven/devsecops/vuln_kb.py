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
}


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

    if not out.get("predicted_cvss_score"):
        out["typical_cvss"] = entry.get("typical_cvss") or _SEV_FALLBACK_CVSS.get(
            (finding.get("severity") or "").lower(), 0.0
        )
    return out
