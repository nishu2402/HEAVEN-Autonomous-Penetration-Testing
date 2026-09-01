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

import contextlib
import re
from typing import Any

# Typical CVSS v3.1 base score for the class (used only as a labelled fallback
# when no per-finding predicted score exists — always shown as "typical").
_KB: dict[str, dict[str, Any]] = {
    # ── OWASP-WSTG client-side, source-review & auth-channel detectors ────────
    "source_comment_disclosure": {
        "title": "Sensitive Data in Page Source (Comments / Developer Notes)",
        "cwe": "CWE-615",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1592 · Gather Victim Host Information",
        "typical_cvss": 5.3,
        "description": (
            "Reviewing the delivered HTML/JS source (WSTG-INFO-05) exposed sensitive "
            "content in comments or developer notes, credentials, API keys, tokens, "
            "internal IP addresses or backdoor markers."
        ),
        "impact": "Hands an attacker credentials, internal hostnames or hidden endpoints.",
        "remediation": (
            "1. Strip developer comments and debug notes from production builds.\n"
            "2. Never embed secrets in client-delivered source.\n"
            "3. Add a build step that fails on secret patterns in shipped assets."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "dom_xss_sink": {
        "title": "Potential DOM-based XSS (Source → Sink)",
        "cwe": "CWE-79",
        "owasp": "A05:2025 Injection",
        "mitre": "T1059.007 · JavaScript",
        "typical_cvss": 6.1,
        "description": (
            "Client JavaScript passes an attacker-influenceable source "
            "(location/URL/referrer/window.name/postMessage) into a dangerous sink "
            "(innerHTML/document.write/eval/setTimeout-string), the DOM-XSS pattern "
            "(WSTG-CLNT-01/02)."
        ),
        "impact": "Script execution in the victim's browser without a server round-trip.",
        "remediation": (
            "1. Never pass untrusted data to innerHTML/document.write/eval.\n"
            "2. Use textContent / safe DOM APIs and a strict CSP.\n"
            "3. Sanitize with a vetted library (DOMPurify) where HTML is required."
        ),
        "references": ["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
    },
    "insecure_postmessage": {
        "title": "postMessage Handler Without Origin Validation",
        "cwe": "CWE-346",
        "owasp": "A05:2025 Injection",
        "mitre": "T1059.007 · JavaScript",
        "typical_cvss": 6.1,
        "description": (
            "A window 'message' event handler never checks event.origin, so any "
            "site can postMessage into it, a cross-origin data-injection / XSS "
            "vector (WSTG-CLNT-11)."
        ),
        "impact": "Cross-origin script/data injection into the application.",
        "remediation": (
            "1. Validate event.origin against an allow-list in every message handler.\n"
            "2. Validate the message structure before acting on it.\n"
            "3. Specify a target origin (never '*') when calling postMessage."
        ),
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"],
    },
    "sensitive_browser_storage": {
        "title": "Sensitive Data in Browser Storage",
        "cwe": "CWE-922",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1539 · Steal Web Session Cookie",
        "typical_cvss": 5.3,
        "description": (
            "Client JavaScript stores sensitive-looking keys (token/session/secret/"
            "api_key) in localStorage/sessionStorage, which any XSS can read and "
            "which persists on shared machines (WSTG-CLNT-12)."
        ),
        "impact": "Session/secret theft via XSS or shared-device access.",
        "remediation": (
            "1. Store session tokens in Secure, HttpOnly cookies, not web storage.\n"
            "2. Never persist secrets client-side.\n"
            "3. Clear sensitive storage on logout."
        ),
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"],
    },
    "cross_site_script_inclusion": {
        "title": "Cross-Site Script Inclusion (XSSI) Exposure",
        "cwe": "CWE-352",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1119 · Automated Collection",
        "typical_cvss": 5.3,
        "description": (
            "A dynamic data endpoint is loadable as a script. If it returns raw "
            "JSON/JS with sensitive data and no anti-XSSI guard, a third-party page "
            "can include it and read the data (WSTG-CLNT-13)."
        ),
        "impact": "Cross-origin theft of authenticated data.",
        "remediation": (
            "1. Prefix JSON responses with an unexecutable guard ()]}',\\n).\n"
            "2. Require POST / a custom header for sensitive data endpoints.\n"
            "3. Serve data with a non-executable Content-Type and correct CORS."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "css_injection": {
        "title": "CSS Injection",
        "cwe": "CWE-79",
        "owasp": "A05:2025 Injection",
        "mitre": "T1059.007 · JavaScript",
        "typical_cvss": 4.3,
        "description": (
            "User input is reflected into a style context, letting an attacker "
            "inject CSS to exfiltrate data (attribute selectors), overlay content, "
            "or aid UI-redress (WSTG-CLNT-05)."
        ),
        "impact": "Data exfiltration via CSS selectors and UI manipulation.",
        "remediation": (
            "1. Never reflect untrusted input into <style> or style attributes.\n"
            "2. Encode output for the CSS context and apply a strict CSP.\n"
            "3. Avoid user-controlled class/style names."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "client_resource_manipulation": {
        "title": "Client-Side Resource Manipulation",
        "cwe": "CWE-601",
        "owasp": "A05:2025 Injection",
        "mitre": "T1059.007 · JavaScript",
        "typical_cvss": 5.4,
        "description": (
            "Client JavaScript assigns an attacker-influenceable source into a "
            "resource-loading sink (script/img/iframe src, form action, href), so a "
            "crafted URL can point the page at attacker-controlled resources "
            "(WSTG-CLNT-06)."
        ),
        "impact": "Loading of attacker-controlled scripts/resources or redirection.",
        "remediation": (
            "1. Validate/allow-list any URL used to load a resource.\n"
            "2. Do not derive resource URLs from location/referrer/postMessage.\n"
            "3. Apply a CSP restricting script/img/frame sources."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "flash_crossdomain": {
        "title": "Legacy Flash (SWF) Content Referenced",
        "cwe": "CWE-1104",
        "owasp": "A03:2025 Software Supply Chain Failures",
        "mitre": "T1203 · Exploitation for Client Execution",
        "typical_cvss": 4.0,
        "description": (
            "The page references end-of-life Adobe Flash (.swf) content which, with "
            "a permissive crossdomain policy, enables cross-site flashing "
            "(WSTG-CLNT-08)."
        ),
        "impact": "Legacy client-execution and cross-domain data theft surface.",
        "remediation": (
            "1. Remove all Flash content, it is end-of-life and unsupported.\n"
            "2. Migrate functionality to modern HTML5.\n"
            "3. Delete permissive crossdomain.xml / clientaccesspolicy.xml files."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "permissive_crossdomain_policy": {
        "title": "Permissive RIA Cross-Domain Policy",
        "cwe": "CWE-942",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 6.5,
        "description": (
            "A Flash/Silverlight cross-domain policy allows access from any domain "
            "(domain=\"*\"), letting a hostile site make credentialed cross-domain "
            "requests through a victim's browser (WSTG-CONF-08)."
        ),
        "impact": "Cross-domain theft of authenticated data.",
        "remediation": (
            "1. Restrict crossdomain.xml / clientaccesspolicy.xml to trusted domains.\n"
            "2. Remove the policy files entirely if Flash/Silverlight is unused.\n"
            "3. Never use a wildcard domain with credentials."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "password_autocomplete_enabled": {
        "title": "Password Field Allows Browser Autocomplete",
        "cwe": "CWE-522",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1555 · Credentials from Password Stores",
        "typical_cvss": 3.1,
        "description": (
            "A password input does not set autocomplete=\"off\"/\"new-password\", so "
            "browsers may store the credential, a risk on shared/public machines "
            "(WSTG-ATHN-05)."
        ),
        "impact": "Cached credentials recoverable on shared devices.",
        "remediation": (
            "1. Set autocomplete=\"off\" (or \"new-password\") on password inputs.\n"
            "2. Educate users about shared-device risk.\n"
            "3. Combine with short session lifetimes."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "sensitive_cache_control": {
        "title": "Credential/Sensitive Page Is Cacheable",
        "cwe": "CWE-525",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1539 · Steal Web Session Cookie",
        "typical_cvss": 4.0,
        "description": (
            "A page containing a password field (or sensitive content) is served "
            "without Cache-Control: no-store/no-cache, so proxies or the browser may "
            "cache sensitive content (WSTG-ATHN-06)."
        ),
        "impact": "Sensitive content recoverable from browser/proxy caches.",
        "remediation": (
            "1. Send 'Cache-Control: no-store' on authenticated/sensitive responses.\n"
            "2. Add 'Pragma: no-cache' for legacy proxies.\n"
            "3. Never cache pages that render credentials or personal data."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "session_token_in_url": {
        "title": "Session Identifier Exposed in URL",
        "cwe": "CWE-598",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1539 · Steal Web Session Cookie",
        "typical_cvss": 6.5,
        "description": (
            "A session/auth token is passed in the URL query string, where it leaks "
            "via browser history, Referer headers, and proxy/server logs "
            "(WSTG-SESS-04)."
        ),
        "impact": "Session hijacking via logged or referred URLs.",
        "remediation": (
            "1. Carry session state in Secure, HttpOnly cookies, never in the URL.\n"
            "2. Reject session identifiers supplied as query parameters.\n"
            "3. Regenerate the session ID after authentication."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "long_session_timeout": {
        "title": "Persistent Session Cookie (No Idle Timeout)",
        "cwe": "CWE-613",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1539 · Steal Web Session Cookie",
        "typical_cvss": 4.0,
        "description": (
            "A session cookie carries a far-future expiry, indicating no idle "
            "session timeout, a stolen or shared-device session stays valid "
            "indefinitely (WSTG-SESS-07)."
        ),
        "impact": "Extended window for session hijacking / shared-device misuse.",
        "remediation": (
            "1. Use short-lived session cookies with an absolute and idle timeout.\n"
            "2. Re-authenticate for sensitive operations.\n"
            "3. Invalidate sessions server-side on logout and expiry."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "padding_oracle": {
        "title": "Potential CBC Padding Oracle",
        "cwe": "CWE-696",
        "owasp": "A08:2025 Software or Data Integrity Failures",
        "mitre": "T1600 · Weaken Encryption",
        "typical_cvss": 7.4,
        "description": (
            "Corrupting one byte of a ciphertext-looking parameter produced a "
            "distinct decryption/padding error the valid value did not, the classic "
            "padding-oracle signal (WSTG-CRYP-02)."
        ),
        "impact": "Decryption/forgery of encrypted tokens without the key.",
        "remediation": (
            "1. Use authenticated encryption (AES-GCM) instead of unauthenticated CBC.\n"
            "2. Return identical, generic errors for all decrypt failures.\n"
            "3. MAC-then-verify before attempting to decrypt."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "ssi_injection": {
        "title": "Server-Side Includes (SSI) Injection",
        "cwe": "CWE-97",
        "owasp": "A05:2025 Injection",
        "mitre": "T1059 · Command and Scripting Interpreter",
        "typical_cvss": 8.6,
        "description": (
            "An SSI directive injected into a parameter was processed by the server "
            "rather than echoed literally. SSI injection can escalate to command "
            "execution via #exec (WSTG-INPV-08)."
        ),
        "impact": "Server-side file disclosure and potential command execution.",
        "remediation": (
            "1. Disable SSI where not required (Options -Includes).\n"
            "2. Never pass user input into SSI-parsed responses.\n"
            "3. Encode '<', '!', '#', '-' in reflected output."
        ),
        "references": ["https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection"],
    },
    "smtp_header_injection": {
        "title": "Mail (SMTP/IMAP) Header Injection",
        "cwe": "CWE-93",
        "owasp": "A05:2025 Injection",
        "mitre": "T1566 · Phishing",
        "typical_cvss": 7.3,
        "description": (
            "A CRLF-delimited mail header injected into a contact/mail parameter was "
            "reflected unfiltered, indicating the value builds mail headers without "
            "sanitisation, enabling Bcc/recipient injection and mail relay "
            "(WSTG-INPV-10)."
        ),
        "impact": "Unauthorized mail relay, recipient injection, spam/phishing.",
        "remediation": (
            "1. Strip CR/LF from any user input used in mail headers.\n"
            "2. Use a mail library that separates headers from user data.\n"
            "3. Allow-list header values and recipients."
        ),
        "references": ["https://owasp.org/www-community/vulnerabilities/CRLF_Injection"],
    },
    "open_registration": {
        "title": "Open Self-Service Registration / Provisioning",
        "cwe": "CWE-284",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1136 · Create Account",
        "typical_cvss": 3.7,
        "description": (
            "A public self-service registration form is reachable, so accounts can "
            "be provisioned without operator approval (WSTG-IDNT-02/03). Verify the "
            "workflow enforces verification, a strong password policy and "
            "least-privilege roles."
        ),
        "impact": "Unapproved account creation; abuse if provisioning is weak.",
        "remediation": (
            "1. Require email/phone verification before activation.\n"
            "2. Enforce a strong password policy and default least-privilege roles.\n"
            "3. Rate-limit and monitor registration; add CAPTCHA where appropriate."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "security_question_reset": {
        "title": "Password Reset Relies on Security Questions",
        "cwe": "CWE-640",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1098 · Account Manipulation",
        "typical_cvss": 5.3,
        "description": (
            "The account-recovery flow uses knowledge-based security questions, "
            "whose answers are often guessable or discoverable via OSINT "
            "(WSTG-ATHN-08)."
        ),
        "impact": "Account takeover via guessable recovery answers.",
        "remediation": (
            "1. Replace security questions with time-limited emailed reset tokens.\n"
            "2. If retained, require additional factors and rate-limit attempts.\n"
            "3. Never reveal whether an answer/account was correct."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "alt_channel_auth_weakness": {
        "title": "Alternate Authentication Channel Present",
        "cwe": "CWE-287",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1078 · Valid Accounts",
        # Aligned with the class CVSS vector (a network low-confidentiality
        # auth-surface weakness), same band as directory_listing.
        "typical_cvss": 5.3,
        "description": (
            "An alternate (API/mobile) authentication endpoint is reachable and "
            "advertises no rate-limit controls. Alternate channels often skip the "
            "lockout/MFA the web login enforces (WSTG-ATHN-10)."
        ),
        "impact": "Auth controls bypassable via a weaker parallel channel.",
        "remediation": (
            "1. Enforce identical lockout/MFA/rate-limit controls on every auth channel.\n"
            "2. Centralize authentication logic across web/API/mobile.\n"
            "3. Monitor all channels for credential-stuffing."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "docker_socket_exposed": {
        "title": "Exposed Docker daemon socket",
        "cwe": "CWE-284",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1610 · Deploy Container",
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
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 9.8,
        "description": (
            "User-controllable input is concatenated into a SQL query, allowing an "
            "attacker to alter query logic, reading, modifying or destroying data, "
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
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
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
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1190 · Exploit Public-Facing Application",
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
    "ssrf_cloud_metadata": {
        "title": "SSRF to Cloud Instance Metadata (credential theft)",
        "cwe": "CWE-918",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1552.005 · Unsecured Credentials: Cloud Instance Metadata API",
        "typical_cvss": 9.1,
        "description": (
            "A server-side request forgery reaches the link-local cloud metadata "
            "service (169.254.169.254 / metadata.google.internal), which returns "
            "temporary IAM/role credentials for the instance. This upgrades an "
            "SSRF into full cloud-account compromise."
        ),
        "impact": "Theft of temporary cloud credentials → lateral movement and "
                  "data access across the cloud account.",
        "remediation": (
            "1. Enforce IMDSv2 (session-token required) on AWS and set the hop "
            "limit to 1.\n"
            "2. Block 169.254.169.254 and metadata.google.internal at the app's "
            "egress proxy / network policy.\n"
            "3. Fix the underlying SSRF: allowlist outbound hosts, deny RFC1918 + "
            "link-local, disable unused URL schemes.\n"
            "4. Scope instance roles to least privilege so a leak is contained."
        ),
        "references": [
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        ],
    },
    "exposed_storage_bucket": {
        "title": "Publicly Exposed Cloud Storage Bucket",
        "cwe": "CWE-284",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1530 · Data from Cloud Storage Object",
        "typical_cvss": 7.5,
        "description": (
            "An S3 / Google Cloud Storage / Azure Blob bucket belonging to the "
            "target is world-readable and its object listing is publicly "
            "enumerable, exposing whatever it holds (backups, source, secrets)."
        ),
        "impact": "Disclosure of any data stored in the bucket; often includes "
                  "backups, credentials, or customer records.",
        "remediation": (
            "1. Enable 'Block Public Access' (S3) / uniform bucket-level access "
            "(GCS) / disable anonymous blob access (Azure).\n"
            "2. Remove AllUsers/AuthenticatedUsers ACL grants and public bucket "
            "policies.\n"
            "3. Audit object ACLs, a private bucket can still hold public objects.\n"
            "4. Enable access logging and alert on anonymous reads."
        ),
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ],
    },
    "xss_stored": {
        "title": "Stored Cross-Site Scripting",
        "cwe": "CWE-79",
        "owasp": "A05:2025 Injection",
        "mitre": "T1059.007 · JavaScript",
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
        "owasp": "A05:2025 Injection",
        "mitre": "T1059.007 · JavaScript",
        "typical_cvss": 6.1,
        "description": "User input is reflected into a page without encoding, executing script in the victim's browser.",
        "impact": "Session theft, phishing, defacement, CSRF-token exfiltration.",
        "remediation": "Contextual output encoding, a strict CSP, and HttpOnly cookies.",
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "idor": {
        "title": "Insecure Direct Object Reference",
        "cwe": "CWE-639",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1190 · Exploit Public-Facing Application",
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
    "broken_access_control": {
        "title": "Broken Access Control",
        "cwe": "CWE-284",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 8.2,
        "description": (
            "A protected resource or privileged function is reachable by a session "
            "that should not have access, an unauthenticated request, or a lower-"
            "privileged user retrieving another role's content, because the server "
            "does not enforce authorization on the endpoint."
        ),
        "impact": "Unauthorized access to privileged data/functions; privilege escalation.",
        "remediation": (
            "1. Enforce authorization server-side on every request; deny by default.\n"
            "2. Check the authenticated principal's role and object ownership for the "
            "specific action, not merely that a session exists.\n"
            "3. Centralise access control in middleware and add per-role automated "
            "access-control tests to CI so regressions are caught."
        ),
        "references": [
            "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
        ],
    },
    "auth_bypass": {
        "title": "Authentication Bypass",
        "cwe": "CWE-287",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1078 · Valid Accounts",
        "typical_cvss": 9.1,
        "description": "A flaw in the auth flow lets an attacker access protected functionality without valid credentials.",
        "impact": "Unauthorized access to privileged functions and data.",
        "remediation": (
            "1. Centralise auth checks in middleware; deny by default.\n"
            "2. Use a vetted identity library; never roll your own session logic.\n"
            "3. Enforce MFA for privileged roles."
        ),
        "references": ["https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/"],
    },
    "exposed_rdp": {
        "title": "Internet-Exposed RDP",
        "cwe": "CWE-284",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1021.001 · Remote Desktop Protocol",
        "typical_cvss": 8.8,
        "description": "Remote Desktop (TCP 3389) is reachable from untrusted networks, a primary ransomware entry vector.",
        "impact": "Brute-force / credential-stuffing leading to full host access; common ransomware foothold.",
        "remediation": (
            "1. Never expose 3389 to the internet, require a VPN or bastion.\n"
            "2. Enforce Network Level Authentication + MFA.\n"
            "3. Apply account-lockout and rate-limiting; monitor logon failures."
        ),
        "references": ["https://attack.mitre.org/techniques/T1021/001/"],
    },
    "weak_tls": {
        "title": "Weak TLS Configuration",
        "cwe": "CWE-326",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1040 · Network Sniffing",
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
    "certificate_issue": {
        "title": "TLS Certificate Issue",
        "cwe": "CWE-295",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1557 · Adversary-in-the-Middle",
        "typical_cvss": 5.9,
        "description": "The server's X.509 certificate is expired, near expiry, self-signed, or signed with a weak algorithm (e.g. SHA-1), so clients cannot reliably establish trust.",
        "impact": "Enables man-in-the-middle interception, trains users to click through TLS warnings, and can break clients that enforce validation.",
        "remediation": (
            "1. Issue a certificate from a trusted CA (e.g. Let's Encrypt) with SHA-256+.\n"
            "2. Automate renewal so it never expires; monitor expiry.\n"
            "3. Deploy the full chain and enable OCSP stapling."
        ),
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "missing_security_headers": {
        "title": "Missing Security Headers",
        "cwe": "CWE-693",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1185 · Browser Session Hijacking",
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
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1566 · Phishing",
        "typical_cvss": 4.7,
        "description": "A redirect target is taken from user input without validation, enabling convincing phishing.",
        "impact": "Phishing, OAuth token theft via redirect_uri abuse.",
        "remediation": "Allowlist redirect targets; never redirect to a raw user-supplied URL.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    },
    "cookie_no_httponly": {
        "title": "Session Cookie Without HttpOnly",
        "cwe": "CWE-1004",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1539 · Steal Web Session Cookie",
        "typical_cvss": 4.0,
        "description": "A session cookie lacks the HttpOnly flag, so client-side script can read it.",
        "impact": "XSS becomes session theft; weakens defence-in-depth.",
        "remediation": "Set HttpOnly, Secure and SameSite on all session cookies.",
        "references": ["https://owasp.org/www-community/HttpOnly"],
    },
    "verbose_errors": {
        "title": "Verbose Error Messages",
        "cwe": "CWE-209",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1592 · Gather Victim Host Information",
        "typical_cvss": 3.7,
        "description": "Stack traces or debug output leak framework versions, file paths or SQL, aiding attackers.",
        "impact": "Information disclosure that accelerates targeted attacks.",
        "remediation": "Return generic error pages in production; log details server-side only.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
    },
    "info_disclosure": {
        "title": "Information Disclosure",
        "cwe": "CWE-200",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1592 · Gather Victim Host Information",
        "typical_cvss": 5.3,
        "description": "Sensitive technical information (server-status, version banners, internal paths) is exposed.",
        "impact": "Reconnaissance aid; narrows an attacker's path to exploitation.",
        "remediation": "Restrict status/diagnostic endpoints; suppress version banners.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "default_credentials": {
        "title": "Default / Weak Credentials",
        "cwe": "CWE-1392",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1078.001 · Default Accounts",
        "typical_cvss": 9.8,
        "description": "A service accepts vendor-default or trivially guessable credentials.",
        "impact": "Immediate unauthorized access, often with administrative rights.",
        "remediation": "Force a credential change on first use; enforce a strong password policy + MFA.",
        "references": ["https://attack.mitre.org/techniques/T1078/001/"],
    },
    "exposed_database": {
        "title": "Exposed Database Service",
        "cwe": "CWE-668",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1210 · Exploitation of Remote Services",
        "typical_cvss": 8.6,
        "description": (
            "A database service (e.g. MySQL, PostgreSQL, MSSQL, MongoDB, Redis) is "
            "reachable over the network on its well-known port. Data stores should "
            "never be exposed beyond the application tier that needs them."
        ),
        "impact": (
            "Direct access to stored data, credential theft, tampering, and "
            "ransomware when the instance is unauthenticated or weakly authenticated."
        ),
        "remediation": (
            "1. Bind the service to localhost or a private interface, never 0.0.0.0.\n"
            "2. Restrict access with a host firewall / security group to only the app tier.\n"
            "3. Require strong authentication and TLS; disable anonymous access.\n"
            "4. Place the datastore in a private subnet with no public route."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/668.html",
            "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
        ],
    },
    "nuclei": {
        "title": "Nuclei Template Match",
        "owasp": "A03:2025 Software Supply Chain Failures",
        "mitre": "T1595 · Active Scanning",
        "typical_cvss": 5.0,
        "description": (
            "A Nuclei community/template signature matched on the target. The "
            "specific weakness class, CWE, CVE and CVSS are taken from the "
            "matching template's own classification when present."
        ),
        "impact": (
            "Varies by template, ranges from information disclosure to remote "
            "code execution. Review the matched template and evidence for the "
            "concrete risk."
        ),
        "remediation": (
            "1. Open the referenced template to confirm the exact issue and affected component.\n"
            "2. Patch or upgrade the affected component to a fixed version.\n"
            "3. Remove or restrict access to any exposed resource the template flagged.\n"
            "4. Re-run the scan to confirm the signature no longer matches."
        ),
        "references": [
            "https://github.com/projectdiscovery/nuclei-templates",
            "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
        ],
    },
    "command_injection": {
        "title": "OS Command Injection",
        "cwe": "CWE-78",
        "owasp": "A05:2025 Injection",
        "mitre": "T1059 · Command and Scripting Interpreter",
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
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
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
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1006 · Direct Volume Access",
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
    "file_upload": {
        "title": "Unrestricted File Upload",
        "cwe": "CWE-434",
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1608 · Stage Capabilities",
        "typical_cvss": 8.8,
        "description": (
            "An upload form accepted a server-executable file with no content or "
            "extension validation, letting an attacker plant a web shell or other "
            "dangerous file in a web-reachable location."
        ),
        "impact": "Remote code execution, web-shell persistence, full server compromise.",
        "remediation": (
            "1. Validate uploads by content, not just extension, against a strict "
            "allow-list of safe types.\n"
            "2. Store uploads outside the web root or on a separate domain and "
            "serve them non-executable.\n"
            "3. Randomise stored filenames and strip active extensions."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/434.html",
        ],
    },
    "ssti": {
        "title": "Server-Side Template Injection",
        "cwe": "CWE-1336",
        "owasp": "A05:2025 Injection",
        "mitre": "T1059 · Command and Scripting Interpreter",
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
    "nosql_injection": {
        "title": "NoSQL Injection",
        "cwe": "CWE-943",
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 9.1,
        "description": (
            "User input reaches a NoSQL query (MongoDB, Redis, Elasticsearch) as an "
            "operator/object rather than a scalar, so query operators such as $ne, "
            "$gt, $regex or $where alter the query logic."
        ),
        "impact": "Authentication bypass, data exfiltration, and (via $where) code execution.",
        "remediation": (
            "1. Enforce the expected scalar type; reject objects/arrays where a string "
            "is expected.\n"
            "2. Use schema validation (e.g. Mongoose types, JSON-schema) at the boundary.\n"
            "3. Disable server-side JavaScript evaluation ($where, mapReduce)."
        ),
        "references": [
            "https://owasp.org/www-community/Injection_Flaws",
            "https://cwe.mitre.org/data/definitions/943.html",
        ],
    },
    "ldap_injection": {
        "title": "LDAP Injection",
        "cwe": "CWE-90",
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 8.6,
        "description": (
            "User input is concatenated into an LDAP search filter without escaping, "
            "so filter metacharacters ( * ( ) \\ ) change the query, enabling "
            "authentication bypass and directory enumeration."
        ),
        "impact": "Authentication bypass and disclosure of directory objects/attributes.",
        "remediation": (
            "1. Escape LDAP special characters ( * ( ) \\ NUL ) per RFC 4515.\n"
            "2. Use parameterised LDAP APIs / bind with a fixed filter template.\n"
            "3. Validate input against an allowlist before it reaches the filter."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/90.html",
        ],
    },
    "xpath_injection": {
        "title": "XPath Injection",
        "cwe": "CWE-643",
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 8.2,
        "description": (
            "User input is concatenated into an XPath query over an XML document, so "
            "boolean/quote metacharacters (' or 1=1 or ') subvert the query logic, "
            "typically bypassing authentication or extracting the whole document."
        ),
        "impact": "Authentication bypass and blind extraction of the backing XML store.",
        "remediation": (
            "1. Use parameterised XPath (variable binding) instead of string "
            "concatenation.\n"
            "2. Escape or reject XPath metacharacters ( ' \" [ ] ( ) = / ).\n"
            "3. Prefer a typed data store over free-form XML for auth/lookup data."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/XPATH_Injection",
            "https://cwe.mitre.org/data/definitions/643.html",
        ],
    },
    "prototype_pollution": {
        "title": "Prototype Pollution",
        "cwe": "CWE-1321",
        "owasp": "A08:2025 Software or Data Integrity Failures",
        "mitre": "T1059.007 · JavaScript",
        "typical_cvss": 8.1,
        "description": (
            "Attacker-controlled keys such as __proto__ / constructor.prototype are "
            "merged into a JavaScript object, mutating Object.prototype for the whole "
            "process, which can escalate to denial of service, property injection or "
            "remote code execution depending on downstream sinks."
        ),
        "impact": "Application-wide logic tampering, DoS, and potential RCE via gadget chains.",
        "remediation": (
            "1. Reject __proto__, constructor and prototype keys before merging.\n"
            "2. Use Map/Object.create(null) for untrusted key/value data.\n"
            "3. Freeze Object.prototype and use safe merge/clone utilities."
        ),
        "references": [
            "https://portswigger.net/web-security/prototype-pollution",
            "https://cwe.mitre.org/data/definitions/1321.html",
        ],
    },
    "integer_overflow": {
        "title": "Integer Overflow or Wraparound",
        "cwe": "CWE-190",
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 6.5,
        "description": (
            "A numeric parameter at or beyond an integer boundary changes application "
            "behaviour (wraparound), indicating unchecked arithmetic that can corrupt "
            "logic, allocation sizes or access decisions."
        ),
        "impact": "Logic corruption, memory-size miscalculation, and possible availability loss.",
        "remediation": (
            "1. Validate numeric inputs against explicit min/max bounds.\n"
            "2. Use checked/arbitrary-precision arithmetic for size and index math.\n"
            "3. Reject values outside the documented range at the boundary."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/190.html",
        ],
    },
    "format_string": {
        "title": "Externally-Controlled Format String",
        "cwe": "CWE-134",
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 8.6,
        "description": (
            "User input is used as a format string (printf-family / logging format), "
            "so format specifiers are interpreted, leaking memory or, in native "
            "code, corrupting it."
        ),
        "impact": "Memory disclosure and, in native components, memory corruption / RCE.",
        "remediation": (
            "1. Never pass user input as the format argument; use a constant format "
            "with the input as a parameter.\n"
            "2. Enable compiler format-string warnings (-Wformat-security).\n"
            "3. Sanitise input used in logging templates."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/134.html",
        ],
    },
    "buffer_overflow": {
        "title": "Buffer Overflow",
        "cwe": "CWE-120",
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 8.1,
        "description": (
            "Oversized input triggers anomalous behaviour (crash, truncation, timing) "
            "consistent with a copy into an undersized buffer in a native component."
        ),
        "impact": "Denial of service and, when exploitable, remote code execution.",
        "remediation": (
            "1. Bound-check all copies; use length-aware APIs (snprintf, strlcpy).\n"
            "2. Compile native code with stack canaries, ASLR and DEP/NX.\n"
            "3. Fuzz the affected parser and add explicit input-length limits."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/120.html",
        ],
    },
    "resource_exhaustion": {
        "title": "Uncontrolled Resource Consumption",
        "cwe": "CWE-400",
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1499 · Endpoint Denial of Service",
        "typical_cvss": 7.5,
        "description": (
            "A single request drives disproportionate CPU/memory/time (e.g. unbounded "
            "expansion, algorithmic complexity), so a small number of requests can "
            "exhaust server resources."
        ),
        "impact": "Denial of service from low-volume, low-cost requests.",
        "remediation": (
            "1. Impose size, depth, time and rate limits on request processing.\n"
            "2. Replace super-linear algorithms on attacker-influenced input.\n"
            "3. Add per-client quotas and circuit breakers."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/400.html",
        ],
    },
    "version_regression": {
        "title": "Vulnerable Version Regression",
        "cwe": "CWE-1104",
        "owasp": "A03:2025 Software Supply Chain Failures",
        "mitre": "T1195 · Supply Chain Compromise",
        "typical_cvss": 5.9,
        "description": (
            "A deployed component reports an older version than a previously observed "
            "release, re-introducing already-patched vulnerabilities (a downgrade / "
            "rollback regression)."
        ),
        "impact": "Re-exposure to known, already-fixed vulnerabilities in the component.",
        "remediation": (
            "1. Pin and monitor component versions; alert on downgrades.\n"
            "2. Gate deploys on an SBOM/version check in CI.\n"
            "3. Roll forward to the latest patched release."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/1104.html",
        ],
    },
    "ip_restriction_bypass": {
        "title": "IP-Based Access Restriction Bypass",
        "cwe": "CWE-290",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 7.5,
        "description": (
            "An IP allowlist is enforced from a client-controlled header "
            "(X-Forwarded-For / X-Real-IP / X-Client-IP), so spoofing the header "
            "reaches an endpoint that should be network-restricted."
        ),
        "impact": "Access to admin/internal endpoints that rely on IP restriction alone.",
        "remediation": (
            "1. Derive the client IP from the trusted edge only; ignore untrusted "
            "forwarding headers.\n"
            "2. Enforce access control with authentication, not IP allowlists.\n"
            "3. Terminate spoofable headers at the reverse proxy."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/290.html",
        ],
    },
    "websocket_hijacking": {
        "title": "Cross-Site WebSocket Hijacking",
        "cwe": "CWE-1385",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1185 · Browser Session Hijacking",
        "typical_cvss": 7.4,
        "description": (
            "A WebSocket handshake authenticates from ambient cookies without "
            "validating the Origin header, so an attacker page can open an "
            "authenticated socket cross-site and read/drive the victim's session."
        ),
        "impact": "Cross-site read/write access to the victim's authenticated WebSocket channel.",
        "remediation": (
            "1. Validate the Origin header on the WebSocket handshake against an "
            "allowlist.\n"
            "2. Require a CSRF-style token in the handshake, not just cookies.\n"
            "3. Scope session cookies with SameSite and re-authenticate the socket."
        ),
        "references": [
            "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
            "https://cwe.mitre.org/data/definitions/1385.html",
        ],
    },
    "websocket_cleartext": {
        "title": "Cleartext WebSocket (ws://)",
        "cwe": "CWE-319",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1040 · Network Sniffing",
        "typical_cvss": 5.9,
        "description": (
            "A WebSocket endpoint is served over unencrypted ws:// rather than wss://, "
            "so messages (including session tokens) traverse the network in cleartext."
        ),
        "impact": "Interception and tampering of WebSocket traffic on the network path.",
        "remediation": (
            "1. Serve WebSockets over wss:// (TLS) only.\n"
            "2. Redirect/upgrade ws:// to wss:// and set HSTS on the origin.\n"
            "3. Never transmit session tokens over an unencrypted socket."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
    },
    "insecure_deserialization": {
        "title": "Insecure Deserialization",
        "cwe": "CWE-502",
        "owasp": "A08:2025 Software or Data Integrity Failures",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 8.6,
        "description": (
            "The application deserializes attacker-controllable data with an "
            "unsafe deserializer (Java native serialization, PHP object "
            "injection, Python pickle, or an unsigned .NET ViewState). Crafted "
            "serialized objects can tamper with application logic or achieve "
            "remote code execution via gadget chains."
        ),
        "impact": (
            "Object-injection tampering up to remote code execution on the "
            "application server."
        ),
        "remediation": (
            "1. Never deserialize untrusted data with a native/unsafe "
            "deserializer; use a data-only format (JSON) with strict schemas.\n"
            "2. Sign and integrity-check any serialized state that must round-trip "
            "the client (e.g. enable ViewState MAC).\n"
            "3. Apply allow-list type filtering and run deserialization with "
            "least privilege."
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
        ],
    },
    "xml_input_accepted": {
        "title": "XML Input Accepted (XXE Attack Surface)",
        "cwe": "CWE-611",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 3.7,
        "description": (
            "The endpoint parses XML request bodies (an XML/SOAP response or an "
            "XML parser error was observed). This is attack surface, not a "
            "confirmed XXE, the test entity was NOT expanded. It should be "
            "manually tested for external-entity resolution."
        ),
        "impact": (
            "None on its own. Marks where to test for XXE (local file disclosure, "
            "SSRF, DoS) if external entities turn out to be resolved."
        ),
        "remediation": (
            "1. Disable DTDs and external entity resolution in the XML parser "
            "(Python: defusedxml; Java: disallow-doctype-decl).\n"
            "2. Prefer JSON where XML isn't required.\n"
            "3. Manually verify whether external entities resolve before treating "
            "this as a confirmed XXE."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    },
    "xxe": {
        "title": "XML External Entity (XXE) Injection",
        "cwe": "CWE-611",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 7.5,
        "description": (
            "The server reflects an arbitrary Origin into "
            "Access-Control-Allow-Origin, especially with "
            "Access-Control-Allow-Credentials: true, so a malicious site can read "
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1539 · Steal Web Session Cookie",
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
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1552 · Unsecured Credentials",
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
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1552 · Unsecured Credentials",
        "typical_cvss": 9.8,
        "description": (
            "The verifier accepts tokens using the 'none' algorithm, which carry no "
            "signature, any client can forge a token with any claims."
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
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1584 · Compromise Infrastructure",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1185 · Browser Session Hijacking",
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
        "title": "Clickjacking, X-Frame-Options Not Set",
        "cwe": "CWE-1021",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1185 · Browser Session Hijacking",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1557 · Adversary-in-the-Middle",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1185 · Browser Session Hijacking",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1592 · Gather Victim Host Information",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1185 · Browser Session Hijacking",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1592.002 · Software",
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
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1110 · Brute Force",
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
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1040 · Network Sniffing",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1566 · Phishing",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1566 · Phishing",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1566 · Phishing",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1557 · Adversary-in-the-Middle",
        "typical_cvss": 4.6,
        "description": (
            "The zone is not signed with DNSSEC, so DNS responses are not "
            "authenticated and can be spoofed via cache poisoning."
        ),
        "impact": "DNS cache poisoning / response forgery redirecting users or mail.",
        "remediation": "Sign the zone with DNSSEC and publish DS records at the parent registrar.",
        "references": ["https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
    },
    "dmarc_subdomain_policy_weak": {
        "title": "DMARC Subdomain Policy Weaker Than Domain",
        "cwe": "CWE-16",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1566 · Phishing",
        "typical_cvss": 5.3,
        "description": (
            "The DMARC record enforces a strict policy on the apex domain but sets a "
            "weaker subdomain policy (sp=), so mail can still be spoofed from any "
            "subdomain even though the apex is protected."
        ),
        "impact": "Subdomain-based spoofing / phishing that bypasses the apex policy.",
        "remediation": (
            "Set sp= to at least the same enforcement level as p= (quarantine or "
            "reject), or remove sp= so subdomains inherit the domain policy."
        ),
        "references": ["https://datatracker.ietf.org/doc/html/rfc7489#section-6.3"],
    },
    "bimi_missing": {
        "title": "BIMI Not Configured",
        "cwe": "CWE-16",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1566 · Phishing",
        "typical_cvss": 2.6,
        "description": (
            "DMARC is enforced but no BIMI record is published, so supporting mail "
            "clients cannot display a verified brand logo — a missed anti-impersonation "
            "and brand-trust control."
        ),
        "impact": "Recipients have a weaker visual signal to distinguish genuine mail.",
        "remediation": (
            "Publish a BIMI record (default._bimi TXT) that references an SVG Tiny PS "
            "logo, ideally backed by a Verified Mark Certificate (VMC)."
        ),
        "references": ["https://bimigroup.org/"],
    },
    "smtp_user_enumeration": {
        "title": "SMTP User Enumeration (VRFY/EXPN)",
        "cwe": "CWE-203",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1087 · Account Discovery",
        "typical_cvss": 3.7,
        "description": (
            "The mail server responds differently to VRFY/EXPN for existing versus "
            "non-existing mailboxes, so an attacker can enumerate valid usernames "
            "without authenticating."
        ),
        "impact": "Valid accounts are harvested for phishing and password-spray targeting.",
        "remediation": (
            "Disable VRFY and EXPN, or configure them to return a uniform response for "
            "every address regardless of whether the mailbox exists."
        ),
        "references": ["https://datatracker.ietf.org/doc/html/rfc5321#section-3.5"],
    },
    "dns_info": {
        "title": "DNS / Mail Infrastructure Information",
        "cwe": "",
        "owasp": "",
        "mitre": "T1590 · Gather Victim Network Information",
        # Aligned with the class CVSS vector (a network-readable low-confidentiality
        # info disclosure), same band as version_disclosure, so the detail view's
        # base score and vector never contradict each other.
        "typical_cvss": 3.5,
        "description": (
            "Informational reconnaissance data enumerated from public DNS "
            "(MX records, SOA administrative contact, DKIM selectors). No "
            "vulnerability is implied, this is context for the assessment."
        ),
        "impact": "Provides an attacker with mapping/targeting information.",
        "remediation": "No action required; ensure records expose only intended information.",
        "references": ["https://attack.mitre.org/techniques/T1590/"],
    },

    # ── Web-app / API posture (auth, GraphQL, files, objects) ───────────
    "csp_unsafe_inline": {
        "title": "Content-Security-Policy Allows unsafe-inline",
        "cwe": "CWE-693",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1185 · Browser Session Hijacking",
        "typical_cvss": 4.6,
        "description": (
            "A Content-Security-Policy is present but weakened by 'unsafe-inline' "
            "(and/or 'unsafe-eval'), which permits inline scripts/styles and largely "
            "defeats the XSS protection CSP is meant to provide."
        ),
        "impact": "Injected inline script still executes, CSP gives little real protection.",
        "remediation": (
            "1. Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes for any "
            "required inline script.\n"
            "2. Move inline handlers/styles to external files.\n"
            "3. Validate with Google's CSP Evaluator."
        ),
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
    },
    "oauth_pkce_missing": {
        "title": "OAuth Authorization Code Without PKCE",
        "cwe": "CWE-287",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1550.001 · Application Access Token",
        "typical_cvss": 5.4,
        "description": (
            "The OAuth 2.0 authorization-code flow does not enforce PKCE, so an "
            "intercepted authorization code can be exchanged for a token by an "
            "attacker (code-interception attack), especially for public clients."
        ),
        "impact": "Authorization-code interception leading to account/token takeover.",
        "remediation": (
            "1. Require PKCE (S256) for every authorization-code flow.\n"
            "2. Reject authorization requests without a code_challenge.\n"
            "3. Bind codes to the client and use short lifetimes / single use."
        ),
        "references": ["https://datatracker.ietf.org/doc/html/rfc7636"],
    },
    "sensitive_file_exposure": {
        "title": "Sensitive File Exposed",
        "cwe": "CWE-538",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1083 · File and Directory Discovery",
        "typical_cvss": 5.3,
        "description": (
            "A sensitive file is reachable over HTTP (e.g. .env, .git/config, "
            "backup/config/dump files), exposing secrets, source or configuration."
        ),
        "impact": "Disclosure of credentials, keys, source code or internal config.",
        "remediation": (
            "1. Remove sensitive files from the web root; serve nothing you don't "
            "intend to publish.\n"
            "2. Block dotfiles / backup extensions at the web server.\n"
            "3. Rotate any secret that was exposed."
        ),
        "references": ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"],
    },
    "directory_listing": {
        "title": "Directory Listing Enabled",
        "cwe": "CWE-548",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1083 · File and Directory Discovery",
        "typical_cvss": 5.3,
        "description": (
            "The web server returns an auto-generated index of a directory's "
            "contents, revealing files that were not meant to be enumerated."
        ),
        "impact": "Discloses file/dir structure and files that aid further attack.",
        "remediation": "Disable auto-indexing (e.g. nginx 'autoindex off;', Apache 'Options -Indexes').",
        "references": ["https://owasp.org/www-community/vulnerabilities/Directory_Indexing"],
    },
    "mass_assignment": {
        "title": "Mass Assignment / Auto-Binding",
        "cwe": "CWE-915",
        "owasp": "A08:2025 Software or Data Integrity Failures",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 7.1,
        "description": (
            "The API binds client-supplied fields directly to internal objects, so "
            "an attacker can set properties they shouldn't control (e.g. role, "
            "is_admin, account balance)."
        ),
        "impact": "Privilege escalation / integrity violation via unexpected fields.",
        "remediation": (
            "1. Bind only an explicit allowlist of fields (DTOs).\n"
            "2. Never bind privileged attributes from the request body.\n"
            "3. Enforce server-side authorization on sensitive property changes."
        ),
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
    },
    "api_docs_exposed": {
        "title": "Exposed API documentation / specification",
        "cwe": "CWE-200",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1526 · Cloud Service Discovery",
        "typical_cvss": 5.3,
        "description": (
            "An OpenAPI/Swagger specification or interactive API explorer is reachable "
            "without authentication. It enumerates every endpoint, parameter and schema, "
            "mapping the API attack surface (including shadow/zombie routes)."
        ),
        "impact": "Full API surface disclosure accelerates targeted attacks on the API.",
        "remediation": (
            "1. Serve API docs only on internal networks or behind authentication.\n"
            "2. Disable interactive explorers (Swagger UI / GraphQL Playground) in production.\n"
            "3. Ensure the published spec does not leak internal/admin endpoints."
        ),
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
    },
    "api_actuator_exposed": {
        "title": "Exposed framework management endpoint (Actuator)",
        "cwe": "CWE-489",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1526 · Cloud Service Discovery",
        "typical_cvss": 7.5,
        "description": (
            "A Spring Boot Actuator (or similar) management endpoint is reachable without "
            "authentication. Endpoints such as /actuator/env, /heapdump and /mappings "
            "disclose configuration, secrets and internal routes."
        ),
        "impact": "Configuration/secret disclosure; /heapdump can leak credentials from memory.",
        "remediation": (
            "1. Require authentication for all management endpoints.\n"
            "2. Expose only /health and /info; disable env/heapdump/beans in production.\n"
            "3. Bind the management port to an internal interface."
        ),
        "references": ["https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"],
    },
    "api_broken_auth": {
        "title": "Broken / Missing API Authentication",
        "cwe": "CWE-306",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 8.2,
        "description": (
            "A conventionally-authenticated API endpoint returned a record collection or "
            "sensitive object with no credentials supplied, the API does not enforce "
            "authentication on data it should protect."
        ),
        "impact": "Unauthenticated data disclosure / takeover of protected resources.",
        "remediation": (
            "1. Enforce authentication on every non-public endpoint (deny-by-default).\n"
            "2. Add object-level authorization so a caller only sees their own data.\n"
            "3. Add automated tests that hit each endpoint unauthenticated and expect 401/403."
        ),
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
    },
    "wireless_mgmt_exposed": {
        "title": "Wireless management interface exposed on the network",
        "cwe": "CWE-284",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1133 · External Remote Services",
        "typical_cvss": 6.5,
        "description": (
            "The web management interface of wireless infrastructure (access point, "
            "home router or WLAN controller) is reachable over the IP network. Even "
            "with authentication enforced, the wireless control plane should be "
            "isolated, combined with weak/default credentials it is a full "
            "wireless-network-takeover path."
        ),
        "impact": (
            "An attacker who reaches (and authenticates to) the controller can "
            "reconfigure SSIDs, disable encryption, add rogue APs or capture client "
            "traffic across the entire wireless estate."
        ),
        "remediation": (
            "1. Restrict the management interface to a dedicated management VLAN / VPN.\n"
            "2. Change default credentials and enable MFA where supported.\n"
            "3. Never expose the controller/AP admin panel to the WAN."
        ),
        "references": ["https://owasp.org/www-project-internet-of-things/"],
    },
    "wireless_mgmt_unauthenticated": {
        "title": "Unauthenticated wireless management interface",
        "cwe": "CWE-306",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1133 · External Remote Services",
        "typical_cvss": 8.6,
        "description": (
            "The web management interface of wireless infrastructure returned its "
            "admin UI with no authentication challenge. If configuration is reachable "
            "without a login, any attacker on the network controls the wireless "
            "infrastructure outright."
        ),
        "impact": "Immediate, credential-free takeover of the wireless control plane.",
        "remediation": (
            "1. Require authentication on the management interface immediately.\n"
            "2. Restrict it to a management VLAN/VPN and change default credentials.\n"
            "3. Patch the device, an unauthenticated admin UI is often a firmware bug."
        ),
        "references": ["https://owasp.org/www-project-internet-of-things/"],
    },
    "race_condition": {
        "title": "Race Condition (TOCTOU)",
        "cwe": "CWE-362",
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 6.5,
        "description": (
            "Concurrent requests can interleave between a check and its use "
            "(time-of-check/time-of-use), allowing limits to be bypassed, e.g. "
            "double-spend, coupon reuse, or over-withdrawal."
        ),
        "impact": "Business-logic bypass: duplicated actions, limit/quota evasion.",
        "remediation": (
            "1. Use atomic operations / row locks / idempotency keys.\n"
            "2. Enforce server-side single-use tokens on sensitive actions.\n"
            "3. Add unique constraints so duplicates fail at the database."
        ),
        "references": ["https://owasp.org/www-community/vulnerabilities/Race_Conditions"],
    },
    "vulnerable_component": {
        "title": "Known-Vulnerable Component / Version",
        "cwe": "CWE-1104",
        "owasp": "A03:2025 Software Supply Chain Failures",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 7.5,
        "description": (
            "A detected software version matches publicly known CVEs, so an attacker "
            "can apply an off-the-shelf exploit for that release."
        ),
        "impact": "Exploitation via a documented CVE for the identified version.",
        "remediation": (
            "1. Upgrade the component to a patched release.\n"
            "2. Track dependencies with an SBOM and monitor advisories.\n"
            "3. Apply virtual patching/WAF rules as an interim control."
        ),
        "references": ["https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"],
    },
    "graphql_introspection": {
        "title": "GraphQL Introspection Enabled",
        "cwe": "CWE-200",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1592 · Gather Victim Host Information",
        "typical_cvss": 5.3,
        "description": (
            "The GraphQL endpoint answers introspection queries, exposing the full "
            "schema (types, fields, mutations) and easing targeted attacks."
        ),
        "impact": "Full API schema disclosure that accelerates attack discovery.",
        "remediation": "Disable introspection in production; expose it only in non-prod.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    },
    "graphql_dos": {
        "title": "GraphQL Resource Exhaustion",
        "cwe": "CWE-770",
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1499 · Endpoint Denial of Service",
        "typical_cvss": 5.3,
        "description": (
            "The GraphQL endpoint allows unbounded query depth/complexity or "
            "aliasing/batching, so a single request can trigger disproportionate "
            "server work (denial of service)."
        ),
        "impact": "Denial of service / resource exhaustion from a single crafted query.",
        "remediation": (
            "1. Enforce query depth and complexity limits.\n"
            "2. Cap aliases/batched operations and add per-client rate limits.\n"
            "3. Use persisted queries where possible."
        ),
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    },
    "secret_exposure": {
        "title": "Exposed Secret / API Key",
        "cwe": "CWE-312",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1552 · Unsecured Credentials",
        "typical_cvss": 7.5,
        "description": (
            "A credential, API key or token was found exposed (in a response, JS "
            "bundle, config or repository), usable by anyone who retrieves it."
        ),
        "impact": "Unauthorized access to the associated service/account/data.",
        "remediation": (
            "1. Revoke and rotate the exposed secret immediately.\n"
            "2. Move secrets to a secrets manager; never ship them to the client.\n"
            "3. Add secret-scanning to CI to catch regressions."
        ),
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
    },
    "smtp_no_starttls": {
        "title": "SMTP Without STARTTLS",
        "cwe": "CWE-319",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1040 · Network Sniffing",
        "typical_cvss": 5.9,
        "description": (
            "The mail server does not offer/enforce STARTTLS, so mail (and any "
            "SMTP AUTH credentials) can travel in cleartext and be intercepted."
        ),
        "impact": "Interception of mail contents and SMTP credentials in transit.",
        "remediation": "Enable and require STARTTLS (or implicit TLS) with a valid certificate.",
        "references": ["https://datatracker.ietf.org/doc/html/rfc3207"],
    },
    "ssh_hardening": {
        "title": "Weak SSH Configuration",
        "cwe": "CWE-326",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1021.004 · Remote Services: SSH",
        "typical_cvss": 5.3,
        "description": (
            "The SSH service permits weak settings (password auth, root login, or "
            "outdated ciphers/KEX/MACs), widening the attack surface."
        ),
        "impact": "Eases brute-force and man-in-the-middle against SSH access.",
        "remediation": (
            "1. Disable password auth and root login; use keys/certificates.\n"
            "2. Restrict to modern ciphers, KEX and MAC algorithms.\n"
            "3. Rate-limit and monitor authentication attempts."
        ),
        "references": ["https://www.ssh-audit.com/hardening_guides.html"],
    },
    "container_escape_risk": {
        "title": "Container Escape Risk (Privileged / Dangerous Mount)",
        "cwe": "CWE-269",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1611 · Escape to Host",
        "typical_cvss": 8.8,
        "description": (
            "A container runs privileged or mounts sensitive host paths (docker.sock, "
            "/proc, host root), giving a compromised container a direct path to the "
            "host."
        ),
        "impact": "Container breakout to full host compromise.",
        "remediation": (
            "1. Drop --privileged; add only the specific capabilities needed.\n"
            "2. Never bind-mount the Docker socket or host root into workloads.\n"
            "3. Enforce a restricted PodSecurity/seccomp/AppArmor profile."
        ),
        "references": ["https://owasp.org/www-project-kubernetes-top-ten/"],
    },
    "k8s_misconfiguration": {
        "title": "Kubernetes Misconfiguration",
        "cwe": "CWE-284",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1610 · Deploy Container",
        "typical_cvss": 8.2,
        "description": (
            "A Kubernetes control-plane/component is exposed or over-permissive "
            "(anonymous API auth, exposed kubelet/etcd, over-privileged RBAC), "
            "letting an attacker read secrets or schedule workloads."
        ),
        "impact": "Cluster compromise: secret theft, workload injection, lateral movement.",
        "remediation": (
            "1. Disable anonymous auth; lock down the kubelet/etcd to the control plane.\n"
            "2. Apply least-privilege RBAC; audit ClusterRoleBindings.\n"
            "3. Network-policy the control-plane components off the public internet."
        ),
        "references": ["https://owasp.org/www-project-kubernetes-top-ten/"],
    },
    "k8s_secrets_exposed": {
        "title": "Kubernetes Secrets Exposed",
        "cwe": "CWE-522",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1552.007 · Container API",
        "typical_cvss": 8.6,
        "description": (
            "Kubernetes Secrets are readable (over-broad RBAC or an exposed API), "
            "so an attacker can retrieve credentials, tokens and keys."
        ),
        "impact": "Theft of cluster and application credentials.",
        "remediation": (
            "1. Restrict 'get/list secrets' RBAC to the minimum necessary.\n"
            "2. Enable encryption-at-rest for etcd Secrets.\n"
            "3. Prefer an external secrets manager and rotate exposed values."
        ),
        "references": ["https://kubernetes.io/docs/concepts/security/secrets-good-practices/"],
    },
    "privilege_escalation": {
        "title": "Privilege Escalation Vector",
        "cwe": "CWE-269",
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1068 · Exploitation for Privilege Escalation",
        "typical_cvss": 8.4,
        "description": (
            "A local privilege-escalation vector was identified (e.g. writable "
            "service/cron/binary, SUID misconfig, sudo rule), letting a low-priv "
            "user gain root/admin."
        ),
        "impact": "Full host/administrative compromise from a low-privilege foothold.",
        "remediation": (
            "1. Remove writable paths from privileged execution; fix SUID/sudo rules.\n"
            "2. Apply least privilege to services and scheduled tasks.\n"
            "3. Patch the kernel/components and monitor for the vector."
        ),
        "references": ["https://attack.mitre.org/techniques/T1068/"],
    },
    "anomaly_heuristic": {
        "title": "Anomalous Behaviour (Heuristic)",
        "cwe": "",
        "owasp": "",
        "mitre": "T1595 · Active Scanning",
        # Aligned with the class CVSS vector so the base score and vector agree
        # (a low, unconfirmed heuristic lead).
        "typical_cvss": 3.5,
        "description": (
            "A heuristic/ML check flagged behaviour that deviates from the expected "
            "baseline. This is a lead for manual review, not a confirmed "
            "vulnerability, validate before reporting."
        ),
        "impact": "May indicate an undiscovered issue; requires analyst confirmation.",
        "remediation": "Manually investigate the flagged behaviour and confirm or dismiss it.",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },

    # ── Session / CSRF / request-handling posture (real detector output) ──
    "csrf": {
        "title": "Cross-Site Request Forgery (Missing Anti-CSRF Token)",
        "cwe": "CWE-352",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1189 · Drive-by Compromise",
        "typical_cvss": 6.5,
        "description": (
            "A state-changing request is accepted without an unpredictable "
            "anti-CSRF token (or equivalent SameSite/Origin check), so a malicious "
            "site can force a logged-in victim's browser to submit it."
        ),
        "impact": "Attacker-forced actions in the victim's session, settings changes, "
                  "fund transfers, account takeover.",
        "remediation": (
            "1. Require a per-session, per-request anti-CSRF token on every "
            "state-changing endpoint and verify it server-side.\n"
            "2. Set SameSite=Lax/Strict on session cookies as defence-in-depth.\n"
            "3. Validate the Origin/Referer for sensitive POSTs."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "session_fixation": {
        "title": "Session Fixation",
        "cwe": "CWE-384",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1539 · Steal Web Session Cookie",
        "typical_cvss": 6.5,
        "description": (
            "The application keeps the same session identifier before and after "
            "authentication, so an attacker who plants a known session ID can ride "
            "the victim's authenticated session once they log in."
        ),
        "impact": "Session hijacking / account takeover.",
        "remediation": (
            "1. Regenerate the session identifier on every privilege change "
            "(especially at login).\n"
            "2. Never accept a session ID from a URL parameter.\n"
            "3. Set HttpOnly, Secure and SameSite on the session cookie."
        ),
        "references": ["https://owasp.org/www-community/attacks/Session_fixation"],
    },
    "weak_session_management": {
        "title": "Weak Session Identifier",
        "cwe": "CWE-331",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1539 · Steal Web Session Cookie",
        "typical_cvss": 5.9,
        "description": (
            "The session token is short, predictable, or has insufficient entropy, "
            "so it can be guessed or brute-forced to hijack a session."
        ),
        "impact": "Session prediction leading to account takeover.",
        "remediation": (
            "1. Generate session IDs with a CSPRNG and at least 128 bits of entropy.\n"
            "2. Use the framework's vetted session manager; don't roll your own.\n"
            "3. Rotate and expire sessions; bind them to client attributes."
        ),
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
    },
    "host_header_injection": {
        "title": "Host Header Injection",
        "cwe": "CWE-644",
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 6.1,
        "description": (
            "The application trusts the client-supplied Host (or X-Forwarded-Host) "
            "header when building absolute URLs, so an attacker can poison "
            "password-reset links, caches, or route requests to their own host."
        ),
        "impact": "Password-reset poisoning, web-cache poisoning, and routing-based SSRF.",
        "remediation": (
            "1. Validate Host against an allowlist of expected virtual hosts; reject "
            "anything else.\n"
            "2. Build absolute URLs from a server-side configured base, never from "
            "the request Host.\n"
            "3. Ignore X-Forwarded-Host unless it comes from a trusted proxy."
        ),
        "references": ["https://portswigger.net/web-security/host-header"],
    },
    "http_parameter_pollution": {
        "title": "HTTP Parameter Pollution",
        "cwe": "CWE-235",
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 5.3,
        "description": (
            "Supplying a parameter multiple times produces inconsistent handling "
            "between tiers (app vs proxy/WAF), which can bypass input validation or "
            "access controls."
        ),
        "impact": "Validation/WAF bypass, logic manipulation, filter evasion.",
        "remediation": (
            "1. Canonicalise duplicated parameters consistently across every tier.\n"
            "2. Reject unexpected duplicate parameters where feasible.\n"
            "3. Validate on the exact value the application logic uses."
        ),
        "references": ["https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution"],
    },
    "web_cache_poisoning": {
        "title": "Web Cache Poisoning (Unkeyed Input)",
        "cwe": "CWE-444",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 7.4,
        "description": (
            "An unkeyed request input (e.g. an untrusted header) influences the "
            "cached response, so an attacker can store a malicious response that is "
            "then served to other users."
        ),
        "impact": "Mass delivery of attacker-controlled content (stored XSS, redirects) "
                  "to every cache consumer.",
        "remediation": (
            "1. Include every request input that affects the response in the cache "
            "key, or strip untrusted headers before caching.\n"
            "2. Do not reflect untrusted headers into cacheable responses.\n"
            "3. Set correct Cache-Control/Vary headers."
        ),
        "references": ["https://portswigger.net/web-security/web-cache-poisoning"],
    },
    "web_cache_deception": {
        "title": "Web Cache Deception",
        "cwe": "CWE-525",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 6.5,
        "description": (
            "A crafted path with a static-looking suffix tricks the cache into "
            "storing an authenticated, sensitive response, which the attacker then "
            "retrieves."
        ),
        "impact": "Disclosure of another user's authenticated content from the cache.",
        "remediation": (
            "1. Cache by content type / Cache-Control, not by URL suffix.\n"
            "2. Never cache responses to authenticated requests.\n"
            "3. Normalise paths and reject deceptive extensions at the edge."
        ),
        "references": ["https://owasp.org/www-community/attacks/Web_Cache_Deception"],
    },
    "open_mail_relay": {
        "title": "Open SMTP Mail Relay",
        "cwe": "CWE-269",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1566 · Phishing",
        "typical_cvss": 7.5,
        "description": (
            "The SMTP server relays mail from an unauthenticated external sender to "
            "an external recipient, so anyone can send mail through it, spoofing "
            "the domain and abusing its reputation for spam/phishing."
        ),
        "impact": "Domain-spoofed phishing/spam, blocklisting of the server's IP.",
        "remediation": (
            "1. Require authentication for submission; relay only for trusted "
            "networks/authenticated users.\n"
            "2. Disable open relaying; restrict RCPT to local domains for "
            "unauthenticated senders.\n"
            "3. Enforce SPF/DKIM/DMARC and monitor relay logs."
        ),
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/"],
    },
    "mta_sts_missing": {
        "title": "MTA-STS Not Configured",
        "cwe": "CWE-319",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1557 · Adversary-in-the-Middle",
        "typical_cvss": 4.6,
        "description": (
            "No MTA-STS policy is published, so a network attacker can strip "
            "STARTTLS and force inbound mail to be delivered in cleartext "
            "(downgrade attack)."
        ),
        "impact": "TLS-downgrade interception of inbound email.",
        "remediation": (
            "1. Publish an MTA-STS policy (_mta-sts TXT + policy file at "
            "mta-sts.<domain>) in enforce mode.\n"
            "2. Publish a TLS-RPT record to receive reporting.\n"
            "3. Ensure all MX hosts present valid certificates."
        ),
        "references": ["https://datatracker.ietf.org/doc/html/rfc8461"],
    },
    "weak_password_policy": {
        "title": "Weak Password Policy",
        "cwe": "CWE-521",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1110 · Brute Force",
        "typical_cvss": 5.3,
        "description": (
            "The application accepts weak passwords (too short, no complexity, or "
            "common/breached values), easing credential guessing and stuffing."
        ),
        "impact": "Account takeover via brute-force / credential stuffing.",
        "remediation": (
            "1. Enforce a modern policy: length ≥ 12, block breached passwords, no "
            "composition gimmicks (per NIST 800-63B).\n"
            "2. Add MFA and rate-limiting on authentication.\n"
            "3. Detect and block credential-stuffing patterns."
        ),
        "references": ["https://pages.nist.gov/800-63-3/sp800-63b.html"],
    },
    "missing_account_lockout": {
        "title": "No Account Lockout / Anti-Automation on Login",
        "cwe": "CWE-307",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1110 · Brute Force",
        "typical_cvss": 5.3,
        "description": (
            "The login endpoint accepts unlimited failed attempts without lockout, "
            "throttling or CAPTCHA, so passwords can be brute-forced or sprayed."
        ),
        "impact": "Credential brute-force / password spraying → account takeover.",
        "remediation": (
            "1. Add per-account and per-IP rate limiting with exponential backoff.\n"
            "2. Lock or step-up (CAPTCHA/MFA) after repeated failures.\n"
            "3. Alert on spray patterns (many accounts, few attempts each)."
        ),
        "references": ["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
    },
    "dns_zone_transfer": {
        "title": "DNS Zone Transfer (AXFR) Allowed",
        "cwe": "CWE-200",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1590.002 · Gather Victim Network Information: DNS",
        "typical_cvss": 5.3,
        "description": (
            "A name server answers AXFR requests from an unauthorised client, "
            "dumping the entire zone, every host, subdomain and record, which "
            "hands an attacker a complete map of the network."
        ),
        "impact": "Full internal/external host enumeration that accelerates targeting.",
        "remediation": (
            "1. Restrict zone transfers to authorised secondary name servers only "
            "(allow-transfer / TSIG).\n"
            "2. Deny AXFR from the public internet at the DNS server and firewall.\n"
            "3. Audit which hosts are exposed in public zones."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    # ── Network-device / host exposure (routers, switches, appliances) ──
    "cleartext_service": {
        "title": "Cleartext / Legacy Network Service Exposed",
        "cwe": "CWE-319",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1040 · Network Sniffing",
        "typical_cvss": 7.5,
        "description": (
            "A service that transmits credentials and data without encryption "
            "(Telnet, FTP, the r-services, TFTP, Finger) is reachable. Anyone on "
            "the network path can capture logins and session data, and several of "
            "these protocols also allow trivial spoofing."
        ),
        "impact": "Credential capture and session interception on the local/adjacent "
                  "network; a classic foothold on routers, switches and appliances.",
        "remediation": (
            "1. Disable the cleartext service and use an encrypted equivalent "
            "(SSH instead of Telnet/rsh, SFTP/FTPS instead of FTP, HTTPS instead "
            "of HTTP admin).\n"
            "2. If the protocol is unavoidable, restrict it to an isolated "
            "management VLAN reachable only over a VPN/bastion.\n"
            "3. Rotate any credentials that may have traversed it."
        ),
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    },
    "perimeter_defense": {
        "title": "Perimeter Defense Detected (Firewall / IDS-IPS)",
        # Not a weakness — a firewall/IPS is good posture. This is an
        # informational assessment observation, so it carries no CWE/OWASP
        # bucket; it explains why results on the affected host may be limited and
        # records the evasion HEAVEN used to still enumerate through it.
        "cwe": "",
        "owasp": "",
        "mitre": "T1046 · Network Service Discovery (perimeter-impeded)",
        "typical_cvss": 0.0,
        "description": (
            "A packet-filtering firewall, an active IDS/IPS, or a tarpit was "
            "detected in front of this host: probes to most ports were silently "
            "dropped (filtered) rather than refused, or connections were rate-"
            "blocked mid-scan. This is expected on hardened / internal targets and "
            "is not itself a vulnerability."
        ),
        "impact": "Scan visibility on this host is reduced, services hidden behind "
                  "the filter may not appear in a naive scan, which is how a "
                  "genuinely-vulnerable host can look empty.",
        "remediation": (
            "For the assessment (not a defect to fix on the target):\n"
            "1. Re-run with evasion, `heaven scan --evade` (or `--stealth stealth "
            "/ paranoid`) fragments and pads probes and sources them from a trusted "
            "port. HEAVEN already auto-runs a bounded evasion re-probe of the "
            "high-value ports on a filtered host.\n"
            "2. Scan from an in-scope network segment closer to the target, inside "
            "the firewall boundary where possible.\n"
            "3. Coordinate a tester-IP allowlist with the firewall/IPS owner so the "
            "assessment sees the true service exposure.\n"
            "4. Confirm the intended allowed ports against the firewall policy, an "
            "unexpectedly-open port through the filter is itself worth reporting."
        ),
        "references": [
            "https://nmap.org/book/man-bypass-firewalls-ids.html",
            "https://attack.mitre.org/techniques/T1046/",
        ],
    },
    "snmp_exposed": {
        "title": "SNMP Service Exposed",
        "cwe": "CWE-200",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1046 · Network Service Discovery",
        "typical_cvss": 5.3,
        "description": (
            "An SNMP service is reachable from the scanning position. Exposed SNMP "
            "is a reconnaissance and brute-force target and frequently leaks device "
            "information even before a community string is guessed."
        ),
        "impact": "Device-information disclosure and a brute-force target for "
                  "community strings.",
        "remediation": (
            "1. Restrict SNMP (UDP 161) to a management network with ACLs/firewall.\n"
            "2. Move to SNMPv3 with authPriv (authentication + encryption).\n"
            "3. Remove default/guessable community strings."
        ),
        "references": ["https://attack.mitre.org/techniques/T1046/"],
    },
    "snmp_default_community": {
        "title": "SNMP Default/Guessable Community String Accepted",
        "cwe": "CWE-1188",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1602.001 · Data from Configuration Repository: SNMP (MIB Dump)",
        "typical_cvss": 8.6,
        "description": (
            "The device answered SNMP queries authenticated with a vendor-default "
            "community string (e.g. 'public'/'private'). SNMP read access exposes "
            "the full device configuration, interfaces, ARP/routing tables and "
            "software versions; write access permits reconfiguration."
        ),
        "impact": "Full device-configuration disclosure and, with RW access, remote "
                  "reconfiguration of the network device.",
        "remediation": (
            "1. Remove default community strings; set a strong, unique value.\n"
            "2. Migrate to SNMPv3 with authPriv and disable v1/v2c.\n"
            "3. Restrict SNMP to a management VLAN and set read-only where possible."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1602/001/",
            "https://cwe.mitre.org/data/definitions/1188.html",
        ],
    },
    "dos_amplification": {
        "title": "DDoS Amplification / Reflection Reflector Exposed",
        "cwe": "CWE-406",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1498.002 · Network Denial of Service: Reflection Amplification",
        "typical_cvss": 7.5,
        "description": (
            "A UDP service on this host (e.g. NTP monlist, an open DNS resolver, "
            "SSDP/UPnP, memcached, CLDAP, chargen, QOTD or RIPv1) reflects a reply "
            "many times larger than the request that triggered it. Because UDP is "
            "connectionless, an attacker can spoof a victim's source address and use "
            "this host to reflect and amplify traffic in a distributed "
            "denial-of-service attack against that third party. The measured "
            "bandwidth amplification factor (BAF) is recorded in the evidence."
        ),
        "impact": "The host can be conscripted into a spoofed-source reflection DDoS, "
                  "amplifying an attacker's traffic against a victim and consuming this "
                  "host's own bandwidth. It also frequently discloses configuration.",
        "remediation": (
            "1. If the service is not needed, disable it or firewall the UDP port from "
            "untrusted networks.\n"
            "2. NTP: disable monlist (`disable monitor` / upgrade ntpd ≥4.2.7p26).\n"
            "3. DNS: disable open recursion or restrict it to trusted clients; enable "
            "response-rate limiting (RRL).\n"
            "4. memcached: bind to localhost and disable the UDP listener (`-U 0`).\n"
            "5. SSDP/CLDAP/chargen/QOTD/RIPv1: block the UDP port at the perimeter and "
            "disable the legacy service.\n"
            "6. Deploy anti-spoofing (BCP 38 / uRPF) at the network edge."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1498/002/",
            "https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks",
            "https://cwe.mitre.org/data/definitions/406.html",
        ],
    },
    "slow_http_dos": {
        "title": "Slow-HTTP (Slowloris) Denial-of-Service Susceptibility",
        "cwe": "CWE-400",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1499.001 · Endpoint Denial of Service: OS Exhaustion Flood",
        "typical_cvss": 5.3,
        "description": (
            "The web server tolerated an incomplete request header held open for an "
            "extended period without enforcing a header-read timeout. A Slowloris / "
            "slow-read attacker can hold many connections open with trickled partial "
            "requests, exhausting the server's connection pool and denying service to "
            "legitimate users from a single low-bandwidth host."
        ),
        "impact": "A single attacker can exhaust the server's worker/connection pool "
                  "and take the site offline without high bandwidth.",
        "remediation": (
            "1. Apache: enable and tune mod_reqtimeout (RequestReadTimeout) and "
            "mod_qos; prefer the event MPM.\n"
            "2. nginx: set client_header_timeout, client_body_timeout and "
            "limit_conn per client IP.\n"
            "3. Terminate connections at a reverse proxy / CDN / load balancer that "
            "buffers full requests before forwarding.\n"
            "4. Cap concurrent connections per source IP at the firewall."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1499/001/",
            "https://owasp.org/www-community/attacks/Denial_of_Service",
        ],
    },
    "adcs_esc1": {
        "title": "AD CS ESC1 · Enrollee-Supplies-Subject Certificate Template",
        "cwe": "CWE-269",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1649 · Steal or Forge Authentication Certificates",
        "typical_cvss": 9.8,
        "description": (
            "An Active Directory Certificate Services template permits the enrollee "
            "to supply an arbitrary subject / subjectAltName, publishes a "
            "client-authentication EKU, requires neither manager approval nor an "
            "enrolment-agent signature, and is enrollable by low-privileged "
            "principals. Any domain user can request a certificate for a Domain "
            "Admin and then authenticate as that account (PKINIT / Schannel)."
        ),
        "impact": "Immediate domain-wide privilege escalation to Domain Admin.",
        "remediation": (
            "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, require manager approval or an "
            "enrolment-agent signature, and restrict the template's enrolment ACL to "
            "only the principals that need it. Audit all published templates with a "
            "tool such as Certipy or the ADCS toolkit."
        ),
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            "https://attack.mitre.org/techniques/T1649/",
        ],
    },
    "adcs_esc8": {
        "title": "AD CS ESC8 · NTLM Relay to Certificate Web Enrolment",
        "cwe": "CWE-269",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1649 · Steal or Forge Authentication Certificates",
        "typical_cvss": 8.8,
        "description": (
            "A Certificate Authority exposes an HTTP(S) web-enrolment endpoint "
            "(/certsrv) that accepts NTLM authentication. Combined with an "
            "authentication-coercion vector (PetitPotam / PrinterBug), an attacker "
            "relays a Domain Controller's machine authentication to the endpoint and "
            "obtains a certificate that authenticates as the DC."
        ),
        "impact": "Relay-to-domain-takeover: full Active Directory compromise.",
        "remediation": (
            "Disable HTTP web enrolment or enforce Extended Protection for "
            "Authentication (EPA) with HTTPS + channel binding, disable NTLM on the "
            "CA, and remove the coercion surface."
        ),
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            "https://attack.mitre.org/techniques/T1649/",
        ],
    },
    "ntlm_coercion": {
        "title": "NTLM Authentication Coercion Surface Exposed",
        "cwe": "CWE-306",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1187 · Forced Authentication",
        "typical_cvss": 8.1,
        "description": (
            "The host exposes an RPC interface that can be abused to coerce it into "
            "authenticating to an attacker-controlled machine: MS-RPRN "
            "(PrinterBug), MS-EFSR (PetitPotam) or MS-DFSNM (DFSCoerce). When SMB or "
            "LDAP signing is not enforced, the coerced authentication can be relayed "
            "to LDAP or to an AD CS web-enrolment endpoint (ESC8) for privilege "
            "escalation. HEAVEN confirmed the interface is reachable by binding to "
            "it; it never issued the coercion call."
        ),
        "impact": "Enables NTLM relay chains leading up to full domain compromise.",
        "remediation": (
            "Enforce SMB and LDAP signing + channel binding, disable the Print "
            "Spooler on servers that do not need it, apply the PetitPotam / "
            "DFSCoerce patches, and restrict RPC with an RPC filter / firewall."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1187/",
            "https://learn.microsoft.com/security-updates/",
        ],
    },
    "saml_unsigned_assertions": {
        "title": "SAML Service Provider Does Not Require Signed Assertions",
        "cwe": "CWE-347",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1606.002 · Forge Web Credentials: SAML Tokens",
        "typical_cvss": 8.2,
        "description": (
            "The SAML service provider's published metadata advertises "
            "WantAssertionsSigned=\"false\". An attacker who can inject or wrap an "
            "assertion (XML signature wrapping, or a forged assertion) may "
            "authenticate as an arbitrary user because the SP accepts an unsigned "
            "assertion."
        ),
        "impact": "Authentication bypass / impersonation of any federated user.",
        "remediation": (
            "Require signed assertions (WantAssertionsSigned=\"true\"), validate the "
            "signature against a pinned IdP certificate, and reject assertions that "
            "are unsigned or wrapped."
        ),
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://attack.mitre.org/techniques/T1606/002/",
        ],
    },
    "edge_appliance_kev": {
        "title": "Internet-Facing Edge / VPN Appliance with Known-Exploited CVEs",
        "cwe": "CWE-1104",
        "owasp": "A03:2025 Software Supply Chain Failures",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 9.8,
        "description": (
            "An internet-facing remote-access / edge appliance (Citrix NetScaler, "
            "Ivanti Connect Secure, FortiOS SSL-VPN, Palo Alto GlobalProtect, "
            "Microsoft Exchange, F5 BIG-IP) was fingerprinted at the perimeter. Each "
            "of these families has vulnerabilities on CISA's Known-Exploited-"
            "Vulnerabilities catalog and is a leading initial-access vector; an "
            "unpatched instance is a likely breach path."
        ),
        "impact": "Unauthenticated remote code execution / initial access into the "
                  "internal network if unpatched.",
        "remediation": (
            "Confirm the appliance's patch level against the vendor's advisories, "
            "upgrade to a fixed release, rotate credentials and sessions where the "
            "relevant CVE leaks them, and restrict management interfaces from the "
            "internet."
        ),
        "references": [
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://attack.mitre.org/techniques/T1190/",
        ],
    },
    "nbtns_poisoning": {
        "title": "NBT-NS Name Poisoning Susceptibility",
        "cwe": "CWE-290",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1557.001 · Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
        "typical_cvss": 8.1,
        "description": (
            "The host participates in NetBIOS Name Service (UDP 137) broadcast name "
            "resolution. When a name fails to resolve, hosts broadcast an NBT-NS "
            "request that any machine on the segment can answer. An attacker running "
            "Responder/Inveigh spoofs the answer, coercing the victim to authenticate "
            "and capturing its NetNTLM hash for offline cracking or SMB relay."
        ),
        "impact": "NetNTLM hash capture and SMB/LDAP relay leading to credential "
                  "compromise and lateral movement across the internal network.",
        "remediation": (
            "1. Disable NetBIOS over TCP/IP on all interfaces (DHCP option 001 / "
            "adapter settings), preferring DNS-only resolution.\n"
            "2. Enforce SMB signing on every host to break the relay path.\n"
            "3. Segment and monitor for NBT-NS/LLMNR spoofing.\n"
            "4. Use the Local Administrator Password Solution (LAPS) so a captured "
            "hash cannot be reused elsewhere."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1557/001/",
            "https://cwe.mitre.org/data/definitions/290.html",
        ],
    },
    "llmnr_poisoning": {
        "title": "LLMNR Name Poisoning Susceptibility",
        "cwe": "CWE-290",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1557.001 · Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
        "typical_cvss": 8.1,
        "description": (
            "Link-Local Multicast Name Resolution (UDP 5355) is enabled on the host. "
            "When DNS resolution fails, hosts multicast an LLMNR query that any "
            "machine on the segment can answer. An attacker race-answers with "
            "Responder/Inveigh to capture NetNTLM credentials or relay them to "
            "another host."
        ),
        "impact": "NetNTLM credential capture and relay, a very common initial "
                  "foothold on internal Windows networks.",
        "remediation": (
            "1. Disable LLMNR via Group Policy: Computer Configuration → "
            "Administrative Templates → Network → DNS Client → "
            "'Turn off multicast name resolution' = Enabled.\n"
            "2. Disable NetBIOS over TCP/IP as well (they are usually abused "
            "together).\n"
            "3. Enforce SMB signing to break the relay path.\n"
            "4. Deploy LAPS so captured credentials are not reusable."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1557/001/",
            "https://cwe.mitre.org/data/definitions/290.html",
        ],
    },
    "mdns_exposure": {
        "title": "mDNS / Bonjour Exposure & Spoofing Susceptibility",
        "cwe": "CWE-290",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1557 · Adversary-in-the-Middle",
        "typical_cvss": 5.3,
        "description": (
            "The host answers multicast-DNS (UDP 5353) queries, disclosing "
            "advertised services and host details. An on-segment attacker can spoof "
            "mDNS responses to redirect '.local' name resolution and stage a "
            "man-in-the-middle."
        ),
        "impact": "Service/host disclosure and '.local' name-resolution hijacking on "
                  "the local segment.",
        "remediation": (
            "1. Disable mDNS/Bonjour/Avahi where it is not required, or restrict it "
            "to trusted segments.\n"
            "2. Block UDP 5353 across VLAN/segment boundaries.\n"
            "3. Prefer authenticated service discovery."
        ),
        "references": ["https://attack.mitre.org/techniques/T1557/"],
    },
    "ipv6_mitm6": {
        "title": "IPv6 mitm6 Susceptibility (Dual-Stack)",
        "cwe": "CWE-300",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1557 · Adversary-in-the-Middle",
        "typical_cvss": 6.5,
        "description": (
            "The host is dual-stack (reachable/advertised over IPv6) in an "
            "environment administered over IPv4. Windows prefers IPv6 and requests a "
            "DHCPv6 lease, so an attacker running mitm6 can answer as a rogue DHCPv6 "
            "server, install itself as the host's IPv6 DNS, and man-in-the-middle "
            "traffic (commonly relayed to LDAP/SMB with ntlmrelayx)."
        ),
        "impact": "IPv6 DNS takeover and credential relay, a widely-used internal "
                  "attack path against Active Directory environments.",
        "remediation": (
            "1. If IPv6 is unused, disable it on hosts and block it at the switch.\n"
            "2. If IPv6 is used, enforce RA-Guard and DHCPv6-Guard on the switch "
            "fabric to reject rogue router advertisements and DHCPv6 servers.\n"
            "3. Enforce LDAP channel binding + signing and SMB signing to defeat the "
            "relay that mitm6 chains into."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1557/",
            "https://cwe.mitre.org/data/definitions/300.html",
        ],
    },
    "backdoor_service": {
        "title": "Backdoor / Trojaned Service Detected",
        "cwe": "CWE-506",
        "owasp": "A08:2025 Software or Data Integrity Failures",
        "mitre": "T1505.003 · Server Software Component: Web Shell / T1205 · Traffic Signaling",
        "typical_cvss": 9.8,
        "description": (
            "A backdoor indicator was found on the host: either a listener bound to "
            "a well-known backdoor/RAT port (e.g. Ingreslock, NetBus, Back Orifice, "
            "SubSeven), an unauthenticated interactive shell answering on a port, or "
            "a service whose version shipped a supply-chain backdoor (vsftpd 2.3.4, "
            "UnrealIRCd 3.2.8.1, ProFTPD 1.3.3c). Each grants remote control of the "
            "host with no legitimate authentication."
        ),
        "impact": "Immediate, unauthenticated remote control of the host; strong "
                  "evidence the system is already compromised.",
        "remediation": (
            "1. Treat the host as compromised: isolate it from the network and begin "
            "incident response / forensic imaging before remediating in place.\n"
            "2. Identify and remove the backdoor listener; reinstall any trojaned "
            "package (vsftpd/UnrealIRCd/ProFTPD) from a verified trusted source.\n"
            "3. Rotate every credential and key that was exposed on the host.\n"
            "4. Rebuild from known-good media if integrity cannot be assured.\n"
            "5. Hunt for persistence (cron, systemd units, startup scripts, SSH keys) "
            "and lateral movement from this host."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1505/003/",
            "https://cwe.mitre.org/data/definitions/506.html",
        ],
    },
    "webshell_detected": {
        "title": "Live Webshell Detected",
        "cwe": "CWE-506",
        "owasp": "A08:2025 Software or Data Integrity Failures",
        "mitre": "T1505.003 · Server Software Component: Web Shell",
        "typical_cvss": 9.8,
        "description": (
            "A response matching a known webshell fingerprint (c99/r57/b374k/WSO/"
            "'FilesMan') was served by the web server. A webshell is an attacker's "
            "remote-control interface for running commands and managing files, and "
            "is direct evidence the web application is already compromised."
        ),
        "impact": "Full remote command execution and file access through the web "
                  "server; the application is compromised.",
        "remediation": (
            "1. Treat the web server as compromised and begin incident response.\n"
            "2. Remove the webshell file and audit the webroot for other planted "
            "files (compare against a known-good deployment).\n"
            "3. Find and fix the upload/RCE flaw that allowed the webshell to be "
            "planted.\n"
            "4. Rotate application, database and system credentials reachable from "
            "the server.\n"
            "5. Review web/access logs for the attacker's activity and rebuild from "
            "trusted media if integrity is uncertain."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1505/003/",
            "https://owasp.org/www-community/attacks/Web_Shell",
        ],
    },
    "cisco_smart_install": {
        "title": "Cisco Smart Install (SMI) Exposed",
        "cwe": "CWE-284",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1210 · Exploitation of Remote Services",
        "typical_cvss": 9.8,
        "description": (
            "The Cisco Smart Install client (TCP 4786) is reachable. SMI requires "
            "no authentication and is widely abused to read or overwrite the device "
            "configuration and to achieve remote code execution on Cisco IOS "
            "switches (CVE-2018-0171; the SIET tooling)."
        ),
        "impact": "Remote configuration theft/overwrite and code execution on the "
                  "switch, full device compromise.",
        "remediation": (
            "1. Disable Smart Install: 'no vstack' in global config.\n"
            "2. If SMI is required, restrict TCP 4786 with an interface ACL.\n"
            "3. Upgrade IOS to a release that addresses CVE-2018-0171."
        ),
        "references": ["https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2"],
    },
    "ipmi_exposed": {
        "title": "IPMI / BMC Management Interface Exposed",
        "cwe": "CWE-284",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1210 · Exploitation of Remote Services",
        "typical_cvss": 7.5,
        "description": (
            "An IPMI/BMC out-of-band management interface is reachable. IPMI is "
            "affected by the cipher-zero authentication bypass and RAKP "
            "password-hash retrieval, granting out-of-band control of the host."
        ),
        "impact": "Out-of-band takeover of the server (power, console, virtual media) "
                  "independent of the OS.",
        "remediation": (
            "1. Place BMC/IPMI on a dedicated, isolated management network.\n"
            "2. Disable cipher suite 0; enforce strong, unique BMC credentials.\n"
            "3. Patch BMC firmware and disable unused management protocols."
        ),
        "references": ["https://www.us-cert.gov/ncas/alerts/TA13-207A"],
    },
    "backdoor_shell": {
        "title": "Unauthenticated Backdoor Shell",
        "cwe": "CWE-506",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1505.003 · Server Software Component",
        "typical_cvss": 10.0,
        "description": (
            "A network port answers with an interactive command shell that "
            "requires no authentication. Any client that can reach the port gets "
            "direct command execution on the host, typically as root, the "
            "hallmark of a bind-shell backdoor (e.g. Metasploitable's TCP 1524 "
            "'root shell')."
        ),
        "impact": "Immediate, unauthenticated command execution and full host "
                  "compromise.",
        "remediation": (
            "1. Treat the host as fully compromised and isolate it from the network.\n"
            "2. Identify and remove the listener / backdoor process.\n"
            "3. Rebuild from a known-good image and rotate every credential the host "
            "could reach."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/506.html"],
    },
    "dangerous_service_exposed": {
        "title": "Dangerous Service Exposed (remote code execution by design)",
        "cwe": "CWE-306",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1210 · Exploitation of Remote Services",
        "typical_cvss": 9.0,
        "description": (
            "A service that runs attacker-supplied code or commands by design is "
            "reachable with no authentication, for example distributed Ruby "
            "(dRuby), a Java RMI registry (remote class loading / deserialization) "
            "or a distcc daemon. Their mere exposure to an untrusted network is the "
            "vulnerability."
        ),
        "impact": "Unauthenticated remote code execution on the host running the "
                  "service.",
        "remediation": (
            "1. Bind the service to localhost or an isolated management network.\n"
            "2. Require an authenticated, encrypted transport.\n"
            "3. Firewall the port to known, trusted clients only."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/306.html"],
    },
    "nfs_export_exposed": {
        "title": "NFS Share Exported to the World",
        "cwe": "CWE-552",
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1005 · Data from Local System",
        "typical_cvss": 9.1,
        "description": (
            "An NFS server exports a filesystem to any host (share list '*'). Any "
            "unauthenticated client on the network can mount it and read its "
            "contents; where the export is read-write, they can modify them too. When the "
            "exported path is the root, home or system filesystem this is a direct "
            "path to credential theft and full host compromise."
        ),
        "impact": (
            "Unauthenticated read/write of exported files: theft of SSH keys and "
            "/etc/shadow, and (via a planted authorized_keys) interactive host access."
        ),
        "remediation": (
            "1. Export only to specific hosts/subnets, never '*'.\n"
            "2. Enable root_squash (the default) and export read-only where possible.\n"
            "3. Require Kerberos (sec=krb5p) and firewall NFS/rpcbind to trusted hosts."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/552.html"],
    },
    "tomcat_manager_default_creds": {
        "title": "Apache Tomcat Manager Default Credentials",
        "cwe": "CWE-1392",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1078.001 · Default Accounts",
        "typical_cvss": 9.8,
        "description": (
            "The Tomcat Manager application accepts a vendor-default credential. The "
            "Manager can deploy arbitrary web applications, so access to it is "
            "equivalent to remote code execution on the server."
        ),
        "impact": "Remote code execution via WAR/JSP webshell deployment; full server "
                  "compromise.",
        "remediation": (
            "1. Change or remove the default users in tomcat-users.xml.\n"
            "2. Restrict /manager and /host-manager to trusted hosts (RemoteAddrValve).\n"
            "3. Never expose the Manager application to untrusted networks."
        ),
        "references": ["https://attack.mitre.org/techniques/T1078/001/"],
    },
    "weak_db_credentials": {
        "title": "Database Default / Weak Credentials",
        "cwe": "CWE-1392",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1078.001 · Default Accounts",
        "typical_cvss": 9.8,
        "description": (
            "A database service (e.g. PostgreSQL) accepts a vendor-default or "
            "trivially-guessable credential. A privileged/superuser login grants "
            "full data access and, on many engines, a path to command execution on "
            "the host."
        ),
        "impact": "Full read/write of all stored data and frequently code execution "
                  "on the database host.",
        "remediation": (
            "1. Set a strong, unique password for every database role.\n"
            "2. Remove or disable default accounts; restrict superuser logins.\n"
            "3. Firewall the port to the application tier and require TLS."
        ),
        "references": ["https://attack.mitre.org/techniques/T1078/001/"],
    },
    "vnc_no_auth": {
        "title": "VNC Server Requires No Authentication",
        "cwe": "CWE-306",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1021.005 · Remote Services: VNC",
        "typical_cvss": 9.8,
        "description": (
            "A VNC/RFB server offers the 'None' security type and accepts "
            "connections with no authentication. Any client that can reach the port "
            "gets full interactive control of the console desktop."
        ),
        "impact": "Unauthenticated, full interactive takeover of the graphical console "
                  "session.",
        "remediation": (
            "1. Require authentication; never enable the 'None' security type.\n"
            "2. Tunnel VNC over SSH/VPN and bind it to localhost.\n"
            "3. Restrict the port to a management network."
        ),
        "references": ["https://attack.mitre.org/techniques/T1021/005/"],
    },
    "vnc_weak_credentials": {
        "title": "VNC Server Accepts a Default Password",
        "cwe": "CWE-1392",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1021.005 · Remote Services: VNC",
        "typical_cvss": 9.8,
        "description": (
            "A VNC/RFB server accepts a well-known default password, granting full "
            "interactive control of the console desktop to anyone who can reach the "
            "port."
        ),
        "impact": "Full interactive takeover of the graphical console session with a "
                  "guessable password.",
        "remediation": (
            "1. Set a strong, unique VNC password (VNC's own auth is 8 chars max; "
            "prefer an SSH/VPN tunnel instead).\n"
            "2. Bind VNC to localhost and tunnel it; restrict to a management network."
        ),
        "references": ["https://attack.mitre.org/techniques/T1021/005/"],
    },
    # Positive posture confirmations (a control is correctly configured). Not a
    # weakness — no CWE/OWASP — but recorded as informational context so the
    # report shows what's *right*, not just what's wrong.
    "posture_ok": {
        "title": "Security Control Correctly Configured",
        "cwe": "",
        "owasp": "",
        "mitre": "",
        "typical_cvss": 0.0,
        "description": (
            "A security control was verified present and correctly configured. "
            "This is a positive finding, recorded for assurance/coverage, not a "
            "vulnerability."
        ),
        "impact": "None, this is a confirmation that a protective control is in place.",
        "remediation": "No action required; maintain the configuration and monitor for drift.",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    # ── CMS / WordPress hardening ────────────────────────────────────────────
    "admin_panel_exposed": {
        "title": "Administrative Panel Exposed to the Internet",
        "cwe": "CWE-307",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1110 · Brute Force",
        "typical_cvss": 7.3,
        "description": (
            "An administrative login panel (e.g. WordPress /wp-login.php, /wp-admin) "
            "is reachable from any network location with no IP/VPN restriction. An "
            "exposed admin interface is a direct target for brute-force and "
            "credential-stuffing attacks against privileged accounts."
        ),
        "impact": "Unauthorised administrative access via password guessing/stuffing, "
                  "leading to full application compromise.",
        "remediation": (
            "1. Restrict the admin panel to trusted IP ranges or a VPN.\n"
            "2. Enforce MFA and strong, rate-limited authentication.\n"
            "3. Consider a WAF / reverse-proxy access rule (e.g. Cloudflare)."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/307.html"],
    },
    "xmlrpc_enabled": {
        "title": "WordPress XML-RPC Interface Enabled",
        "cwe": "CWE-918",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 7.3,
        "description": (
            "The WordPress XML-RPC endpoint (/xmlrpc.php) is enabled and answering "
            "remote procedure calls. Its pingback.ping method is abused for SSRF and "
            "internal port scanning, and system.multicall amplifies brute-force "
            "attempts; the interface is also a reflective DoS vector."
        ),
        "impact": "SSRF/internal scanning, brute-force amplification and denial of "
                  "service against the site.",
        "remediation": (
            "1. Disable XML-RPC entirely if unused (block /xmlrpc.php).\n"
            "2. If required, disable the pingback methods specifically.\n"
            "3. Rate-limit and monitor XML-RPC requests."
        ),
        "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    },
    "wordpress_user_enumeration": {
        "title": "WordPress Username Enumeration",
        "cwe": "CWE-200",
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1589.001 · Gather Victim Identity Information: Credentials",
        "typical_cvss": 5.3,
        "description": (
            "Valid WordPress login names are disclosed via the REST users route "
            "(/wp-json/wp/v2/users) or the ?author= redirect. Knowing real usernames "
            "reduces a login attack from guessing user+password to password-only."
        ),
        "impact": "Enables targeted password-guessing/spraying against confirmed "
                  "accounts, especially paired with an exposed admin panel.",
        "remediation": (
            "1. Restrict or disable the REST users endpoint for anonymous callers.\n"
            "2. Block ?author= enumeration at the web server / plugin level.\n"
            "3. Avoid login names that match the public display name."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    # ── Unsupported / end-of-life software ───────────────────────────────────
    "unsupported_software": {
        "title": "Unsupported / End-of-Life Software",
        "cwe": "CWE-1104",
        "owasp": "A03:2025 Software Supply Chain Failures",
        "mitre": "T1190 · Exploit Public-Facing Application",
        "typical_cvss": 7.4,
        "description": (
            "Software (an operating system or component) that has passed its vendor "
            "end-of-life date is in use. End-of-life software receives no further "
            "security patches, so any vulnerability disclosed after that date stays "
            "permanently exploitable."
        ),
        "impact": "Permanent exposure to newly disclosed vulnerabilities with no "
                  "vendor fix available.",
        "remediation": (
            "1. Decommission or upgrade the affected systems to a supported version.\n"
            "2. Where unavoidable, purchase extended support (ESU) and isolate the "
            "host on a segmented network.\n"
            "3. Run a vulnerability-management process to catch recurrences."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/1104.html"],
    },
    # ── Infrastructure exposure (IPMI / SNMP / FTP / RDP) ────────────────────
    "ipmi_hash_disclosure": {
        "title": "Unauthenticated IPMI RAKP Password-Hash Disclosure",
        "cwe": "CWE-522",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1552 · Unsecured Credentials",
        "typical_cvss": 7.5,
        "description": (
            "The BMC completes the IPMI 2.0 RMCP+/RAKP exchange and returns a salted "
            "hash of a user's password to any unauthenticated party (CVE-2013-4786). "
            "This is a design flaw in the IPMI specification: the hash can be cracked "
            "offline to gain out-of-band control of the host."
        ),
        "impact": "Offline password cracking and out-of-band (BMC) takeover of the "
                  "underlying server.",
        "remediation": (
            "1. Isolate all BMC/IPMI interfaces on a dedicated management network.\n"
            "2. Disable IPMI-over-LAN where not required.\n"
            "3. Set long, random BMC passwords to resist offline cracking."
        ),
        "references": ["https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi-and-bmcs/"],
    },
    "snmp_amplification": {
        "title": "SNMP GETBULK Amplification (Reflected DDoS Source)",
        "cwe": "CWE-406",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1498.002 · Network Denial of Service: Reflection Amplification",
        "typical_cvss": 5.3,
        "description": (
            "The SNMP agent answers a small GETBULK request with a much larger "
            "response. Because SNMP is UDP and source addresses can be spoofed, the "
            "host can be abused as a reflector to amplify a denial-of-service attack "
            "against a third party."
        ),
        "impact": "The host can be weaponised as a DDoS amplifier against arbitrary "
                  "victims.",
        "remediation": (
            "1. Restrict SNMP to a management network with ACLs.\n"
            "2. Disable SNMP v1/v2c; require SNMPv3 authPriv.\n"
            "3. Rate-limit UDP/161 at the network edge."
        ),
        "references": ["https://www.cisa.gov/news-events/alerts/2014/01/14/ntp-amplification-attacks-using-cve-2013-5211"],
    },
    "ftp_anonymous": {
        "title": "Anonymous FTP Login Allowed",
        "cwe": "CWE-1188",
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1078.001 · Valid Accounts: Default Accounts",
        "typical_cvss": 5.8,
        "description": (
            "The FTP service accepted an anonymous login. Anonymous access exposes "
            "whatever the FTP root serves to any unauthenticated user and, where the "
            "share is writable, offers a foothold to stage files."
        ),
        "impact": "Unauthenticated disclosure of served files and, if writable, a "
                  "staging point for further attack.",
        "remediation": (
            "1. Disable anonymous FTP unless it is a deliberate public-download "
            "service.\n"
            "2. Never expose anonymous FTP with write access.\n"
            "3. Prefer SFTP/FTPS with authenticated accounts."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/1188.html"],
    },
    "rdp_nla_disabled": {
        "title": "RDP Network Level Authentication (NLA) Not Required",
        "cwe": "CWE-300",
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1557 · Adversary-in-the-Middle",
        "typical_cvss": 5.4,
        "description": (
            "The Remote Desktop service accepts standard RDP security without "
            "requiring Network Level Authentication. Without NLA, authentication "
            "occurs after a full session is established, exposing the host to "
            "pre-authentication man-in-the-middle attacks and lowering brute-force "
            "cost."
        ),
        "impact": "Pre-auth MiTM/credential interception and cheaper brute-forcing of "
                  "RDP logins.",
        "remediation": (
            "1. Require NLA (CredSSP) via Group Policy / System Properties.\n"
            "2. Restrict RDP to a VPN / jump host and enforce MFA.\n"
            "3. Ensure a valid TLS certificate is presented for RDP."
        ),
        "references": ["https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"],
    },
    "denial_of_service": {
        "title": "Denial of Service",
        "cwe": "CWE-400",
        "owasp": "A06:2025 Insecure Design",
        "mitre": "T1499 · Endpoint Denial of Service",
        "typical_cvss": 7.5,
        "description": (
            "The service can be driven into resource exhaustion or a crash by a "
            "crafted request or traffic pattern, making it unavailable to legitimate "
            "users. A denial of service affects AVAILABILITY only; on its own it "
            "does not disclose or modify data."
        ),
        "impact": "Loss of availability for the affected service or host.",
        "remediation": (
            "1. Enforce rate limiting and request size/complexity caps.\n"
            "2. Add timeouts, connection limits and per-client resource quotas.\n"
            "3. Front the service with a DoS-aware proxy/CDN and autoscaling."
        ),
        "references": ["https://cwe.mitre.org/data/definitions/400.html"],
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
    "enumerable_reference": "idor",  # informational IDOR-adjacent (unproven authz)
    "bac": "broken_access_control",
    "access_control": "broken_access_control",
    "missing_function_level_access_control": "broken_access_control",
    "forced_browsing": "broken_access_control",
    "missing_authentication": "broken_access_control",
    "unauthenticated_access": "broken_access_control",
    "privilege_escalation": "broken_access_control",
    "rce": "rce",
    "remote_code_execution": "rce",
    "code_injection": "rce",
    "tls": "weak_tls",
    "ssl": "weak_tls",
    "weak_ssl": "weak_tls",
    # SSL/TLS scanner findings — protocol/cipher weaknesses collapse to weak_tls,
    # certificate problems to certificate_issue, so the SSL scan's whole output
    # carries CWE/OWASP/CVSS taxonomy instead of going blank in the report.
    "weak_cipher": "weak_tls",
    "beast": "weak_tls",
    "poodle": "weak_tls",
    "freak": "weak_tls",
    "logjam": "weak_tls",
    "drown": "weak_tls",
    "heartbleed": "weak_tls",
    "tls10_only": "weak_tls",
    "tls11_deprecated": "weak_tls",
    "sslv3_enabled": "weak_tls",
    "hsts_short_maxage": "hsts_missing",
    "cert_expired": "certificate_issue",
    "cert_expiring_soon": "certificate_issue",
    "self_signed_cert": "certificate_issue",
    "sha1_signature": "certificate_issue",
    "ssl_expired": "certificate_issue",
    "ssl_self_signed": "certificate_issue",
    "unvalidated_redirect": "open_redirect",
    # Live-CVE-feed / version-CVE findings → the outdated-component KB entry.
    # (known_vulnerable_version / outdated_component already aliased below.)
    "vulnerable_service": "vulnerable_component",
    # Cloud-misconfiguration finding spellings → canonical KB keys.
    "cloud_metadata_ssrf": "ssrf_cloud_metadata",
    "imds_ssrf": "ssrf_cloud_metadata",
    "public_bucket": "exposed_storage_bucket",
    "open_s3_bucket": "exposed_storage_bucket",
    "public_s3": "exposed_storage_bucket",
    "cloud_asset_discovery": "exposed_storage_bucket",
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
    "wordpress_version_disclosure": "version_disclosure",
    "cms_version_disclosure": "version_disclosure",
    # CMS / WordPress hardening
    "wordpress_admin_exposed": "admin_panel_exposed",
    "wp_admin_exposed": "admin_panel_exposed",
    "admin_exposed": "admin_panel_exposed",
    "exposed_admin_panel": "admin_panel_exposed",
    "wordpress_xmlrpc": "xmlrpc_enabled",
    "wp_xmlrpc": "xmlrpc_enabled",
    "xml_rpc_enabled": "xmlrpc_enabled",
    "xmlrpc_pingback": "xmlrpc_enabled",
    "wp_user_enumeration": "wordpress_user_enumeration",
    "user_enumeration": "wordpress_user_enumeration",
    "username_enumeration": "wordpress_user_enumeration",
    # Unsupported / end-of-life software
    "eol_software": "unsupported_software",
    "end_of_life": "unsupported_software",
    "end_of_life_software": "unsupported_software",
    "unsupported_os": "unsupported_software",
    "outdated_os": "unsupported_software",
    "unmaintained_component": "unsupported_software",
    # Infrastructure exposure
    "ipmi_rakp": "ipmi_hash_disclosure",
    "ipmi_hashdump": "ipmi_hash_disclosure",
    "snmp_getbulk_amplification": "snmp_amplification",
    "anonymous_ftp": "ftp_anonymous",
    "ftp_anonymous_login": "ftp_anonymous",
    "rdp_no_nla": "rdp_nla_disabled",
    "terminal_services_nla": "rdp_nla_disabled",
    "nla_not_required": "rdp_nla_disabled",
    "no_rate_limiting": "no_rate_limit",
    "rate_limit": "no_rate_limit",
    "api_no_rate_limit": "no_rate_limit",
    # Merely accepting/parsing XML is an XXE *surface indicator*, NOT a confirmed
    # XXE — it must keep its own low-severity class so reconcile_severity can't
    # inflate a "low" surface note into the High XXE class. Only the *confirmed*
    # entity-expansion spellings map to the real xxe class (below).
    "xml_accepted": "xml_input_accepted",
    # DNS / email authentication posture
    "spf_analysis": "spf_missing",
    "spf_weak": "spf_missing",
    "dmarc_weak": "dmarc_missing",
    "dkim_weak": "dkim_missing",
    "dnssec_not_enabled": "dnssec_missing",
    "dnssec_disabled": "dnssec_missing",
    "dmarc_analysis": "dmarc_missing",
    "dmarc_policy_weak_subdomain": "dmarc_subdomain_policy_weak",
    "dkim_not_found": "dkim_missing",
    "dkim_weak_key": "dkim_missing",
    "dkim_legacy_key": "dkim_missing",
    "smtp_starttls_missing": "smtp_no_starttls",
    "smtp_vrfy_enabled": "smtp_user_enumeration",
    "smtp_expn_enabled": "smtp_user_enumeration",
    # Informational DNS / mail recon
    "mx_enumeration": "dns_info",
    "mx_records": "dns_info",
    "soa_admin_email": "dns_info",
    "dkim_found": "dns_info",
    "dkim_selector_found": "dns_info",
    "dns_enumeration": "dns_info",
    # Web-app / API posture
    "oauth_pkce_not_enforced": "oauth_pkce_missing",
    "pkce_not_enforced": "oauth_pkce_missing",
    "sensitive_file": "sensitive_file_exposure",
    "exposed_sensitive_file": "sensitive_file_exposure",
    "dir_listing": "directory_listing",
    "auto_index": "directory_listing",
    "exposed_db": "exposed_database",
    "database_exposed": "exposed_database",
    "exposed_service": "exposed_database",
    "auto_binding": "mass_assignment",
    "toctou": "race_condition",
    "known_vulnerable_version": "vulnerable_component",
    "outdated_component": "vulnerable_component",
    "vulnerable_dependency": "vulnerable_component",
    # Version-undetermined service: the banner named a product but not its exact
    # version, so CVE applicability is UNVERIFIED. Same weakness class as a
    # confirmed vulnerable component for taxonomy, but the finding itself carries
    # low severity + "potential" naming so reconcile_severity keeps it in the low
    # band and it never inflates the confirmed Critical/High count.
    "potential_vulnerable_service": "vulnerable_component",
    "graphql_batching": "graphql_dos",
    "graphql_complexity": "graphql_dos",
    "graphql_alias_overloading": "graphql_dos",
    # Generic denial of service (specific DoS classes above keep their own entry).
    "dos": "denial_of_service",
    "ddos": "denial_of_service",
    "resource_exhaustion": "denial_of_service",
    "availability_impact": "denial_of_service",
    "api_key_leakage": "secret_exposure",
    "exposed_secret": "secret_exposure",  # nosec B105 -- taxonomy string, not a secret
    "hardcoded_secret": "secret_exposure",  # nosec B105 -- taxonomy string, not a secret
    "credential_leak": "secret_exposure",
    # Containers / Kubernetes / infra
    "docker_api_exposed": "docker_socket_exposed",
    "docker_socket": "docker_socket_exposed",
    "privileged_container": "container_escape_risk",
    "dangerous_mount": "container_escape_risk",
    "host_mount": "container_escape_risk",
    "k8s_anon_auth": "k8s_misconfiguration",
    "k8s_rbac_overprivileged": "k8s_misconfiguration",
    "kubelet_exposed": "k8s_misconfiguration",
    "etcd_exposed": "k8s_misconfiguration",
    "k8s_insecure_port": "k8s_misconfiguration",
    "cadvisor_exposed": "k8s_misconfiguration",
    "registry_exposed": "k8s_misconfiguration",
    "privesc": "privilege_escalation",
    "privilege_esc": "privilege_escalation",
    # Anomaly / heuristic
    "anomalous_behavior": "anomaly_heuristic",
    "zero_day_heuristic": "anomaly_heuristic",
    "anomaly": "anomaly_heuristic",
    # HTTP methods (web_fuzzer spellings) → dangerous-method KB entry
    "dangerous_methods_allowed": "dangerous_http_method",
    "method_override_accepted": "dangerous_http_method",
    "xst_trace_enabled": "dangerous_http_method",
    # Cookie flag spellings (auth_scanner) → insecure-cookie KB entry
    "cookie_no_secure": "insecure_cookie",
    "cookie_no_samesite": "insecure_cookie",
    "cookie_missing_secure": "insecure_cookie",
    "cookie_missing_samesite": "insecure_cookie",
    # CSP weakening
    "csp_unsafe_eval": "csp_unsafe_inline",
    # XXE spellings
    "xxe_entity_expansion": "xxe",
    "xml_entity_expansion": "xxe",
    # Weak/guessable login credentials → default-credentials KB entry
    "weak_login_credentials": "default_credentials",
    "weak_http_auth_credentials": "default_credentials",
    "guessable_credentials": "default_credentials",
    # Version / technology disclosure spellings
    "technology_disclosure": "version_disclosure",
    "dns_version_disclosure": "version_disclosure",
    # Smuggling spellings
    "http_smuggling_te_obfuscation": "request_smuggling",
    # Request-handling / caching / CSRF / session (→ new KB entries above)
    "csrf_missing_token": "csrf",
    "csrf_token_missing": "csrf",
    "oauth_state_reflected": "csrf",
    "oauth_open_redirect": "open_redirect",
    "session_fixation": "session_fixation",
    "weak_session_id": "weak_session_management",
    "predictable_session_id": "weak_session_management",
    "host_header_injection": "host_header_injection",
    "http_parameter_pollution": "http_parameter_pollution",
    "cache_poisoning_unkeyed_header": "web_cache_poisoning",
    "web_cache_poisoning": "web_cache_poisoning",
    "web_cache_deception": "web_cache_deception",
    "content_type_confusion": "x_content_type_missing",
    "hidden_parameter_discovered": "info_disclosure",
    # Auth anti-automation / password policy
    "no_account_lockout": "missing_account_lockout",
    "account_lockout_missing": "missing_account_lockout",
    "weak_password_policy": "weak_password_policy",
    # Email / SMTP posture (email_scanner + dns_recon spellings)
    "smtp_open_relay": "open_mail_relay",
    "spf_open_relay": "spf_missing",
    "spf_soft_fail": "spf_missing",
    "spf_too_many_lookups": "spf_missing",
    "dmarc_policy_none": "dmarc_missing",
    "dmarc_partial_rollout": "dmarc_missing",
    "mta_sts_missing": "mta_sts_missing",
    "no_mta_sts": "mta_sts_missing",
    # DNS recon posture
    "zone_transfer": "dns_zone_transfer",
    "axfr_allowed": "dns_zone_transfer",
    "dnssec_zone_walking": "dns_info",
    "dns_wildcard": "dns_info",
    "ptr_records_discovered": "dns_info",
    "mx_dangling": "subdomain_takeover",
    # Positive posture confirmations → informational "posture_ok" entry
    "dnssec_enabled": "posture_ok",
    "mta_sts_enabled": "posture_ok",
    "bimi_configured": "posture_ok",
    "tls_rpt_enabled": "posture_ok",
    "account_lockout_detected": "posture_ok",
    "lockout_inconclusive": "posture_ok",
}

# Representative CVSS v3.1 base vectors per canonical KB class. Kept as a single
# source of truth so the report's "CVSS vector" column is never blank for a
# known class (previously only ~8 web classes were covered). Illustrative for
# the vulnerability *class* — not a per-target recomputation.
_CVSS_VECTOR_BY_KEY: dict[str, str] = {
    "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "ssti": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "ssrf_cloud_metadata": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "exposed_storage_bucket": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "xss_stored": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N",
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "broken_access_control": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "default_credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "exposed_database": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    "file_inclusion": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "file_upload": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "nosql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "ldap_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "xpath_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "prototype_pollution": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "integer_overflow": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H",
    "format_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "buffer_overflow": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "resource_exhaustion": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "version_regression": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "ip_restriction_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "websocket_hijacking": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "websocket_cleartext": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "insecure_deserialization": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
    # Surface indicator only — low band, so it never renders as a High XXE.
    "xml_input_accepted": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "cors_misconfig": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "insecure_cookie": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "cookie_no_httponly": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "jwt_weak_secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # nosec B105
    "jwt_none_algorithm": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "crlf_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "request_smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "subdomain_takeover": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "docker_socket_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "exposed_rdp": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
    "weak_tls": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "certificate_issue": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "no_forward_secrecy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
    "missing_security_headers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "csp_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "clickjacking": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "hsts_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "x_content_type_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "referrer_policy_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "permissions_policy_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "dangerous_http_method": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
    "version_disclosure": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "info_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "verbose_errors": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "no_rate_limit": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "spf_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N",
    "dmarc_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N",
    "dkim_missing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "dnssec_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "csp_unsafe_inline": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "oauth_pkce_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "sensitive_file_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "directory_listing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "mass_assignment": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
    "race_condition": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "vulnerable_component": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "graphql_introspection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "graphql_dos": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "denial_of_service": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "secret_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # nosec B105
    "smtp_no_starttls": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssh_hardening": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "container_escape_risk": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:H",
    "k8s_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
    "k8s_secrets_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    "privilege_escalation": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
    "session_fixation": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "weak_session_management": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "host_header_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "http_parameter_pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "web_cache_poisoning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N",
    "web_cache_deception": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "open_mail_relay": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "mta_sts_missing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "weak_password_policy": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "missing_account_lockout": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "dns_zone_transfer": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cleartext_service": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "snmp_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "snmp_default_community": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "cisco_smart_install": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ipmi_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "backdoor_shell": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "dangerous_service_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "nfs_export_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "tomcat_manager_default_creds": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "weak_db_credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "vnc_no_auth": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "vnc_weak_credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ipmi_hash_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "snmp_amplification": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L",
    "ftp_anonymous": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "rdp_nla_disabled": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "admin_panel_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "xmlrpc_enabled": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "wordpress_user_enumeration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "unsupported_software": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "api_docs_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "api_actuator_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "api_broken_auth": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "wireless_mgmt_exposed": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "wireless_mgmt_unauthenticated": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
    "anonymous_ldap_enumeration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "azure_ad_tenant_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "adfs_idp_signon_enabled": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "federation_sts_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    # Authenticated AWS IAM audit (cloud_iam.py) — privilege + hygiene posture.
    "cloud_iam_overprivileged": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    "cloud_iam_privilege_escalation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "api_bfla": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cloud_iam_root_access_keys": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    "cloud_iam_no_mfa": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "cloud_iam_stale_access_key": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cloud_iam_weak_password_policy": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "cloud_iam_public_access": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "cloud_iam_authenticated": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    # Web-tier / client-side / session / mail classes (WSTG). Each vector is
    # faithful to the weakness and calibrated so its base score sits in the same
    # band as the class's typical_cvss — so no real finding ever shows a blank
    # CVSS v3.1 vector alongside its v4.0 companion.
    "alt_channel_auth_weakness": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "anomaly_heuristic": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "client_resource_manipulation": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "cross_site_script_inclusion": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "css_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "dns_info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "dom_xss_sink": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "flash_crossdomain": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "insecure_postmessage": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "long_session_timeout": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "nuclei": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "open_registration": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "padding_oracle": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "password_autocomplete_enabled": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "perimeter_defense": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "permissive_crossdomain_policy": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "security_question_reset": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sensitive_browser_storage": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "sensitive_cache_control": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "session_token_in_url": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "smtp_header_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "source_comment_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "ssi_injection": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
    "posture_ok": "",
}

# Representative CVSS v4.0 base vectors per canonical KB class, the current
# standard shown as the primary number alongside the v3.1 vector above. Each is a
# faithful translation of the class's v3.1 vector into v4.0's metric set (AV/AC/PR
# carry over; Attack Requirements marks the classes needing an on-path / race /
# cacheable condition; a v3.1 required interaction becomes UI:Active; C/I/A become
# the Vulnerable-System VC/VI/VA, and a v3.1 scope change extends the impact to the
# Subsequent System SC/SI/SA). Illustrative for the class, not a per-target recompute.
# v4.0 scores the same weakness differently from v3.1 by design, so these are kept
# independent and never forced to match the v3.1 band; HEAVEN's severity badge still
# follows the calibrated v3.1 score, with the v4.0 number shown next to it.
_CVSS4_VECTOR_BY_KEY: dict[str, str] = {
    "sql_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "rce": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "command_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "ssti": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "ssrf": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
    "ssrf_cloud_metadata": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
    "exposed_storage_bucket": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "xss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "xss_stored": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
    "idor": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "broken_access_control": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "auth_bypass": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "default_credentials": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "exposed_database": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
    "file_inclusion": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "path_traversal": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "file_upload": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "nosql_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "ldap_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "xpath_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "prototype_pollution": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "integer_overflow": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N",
    "format_string": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "buffer_overflow": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "resource_exhaustion": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
    "version_regression": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "ip_restriction_bypass": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "websocket_hijacking": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
    "websocket_cleartext": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "insecure_deserialization": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "xxe": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L",
    "xml_input_accepted": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "open_redirect": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "cors_misconfig": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
    "insecure_cookie": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "cookie_no_httponly": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "jwt_weak_secret": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",  # nosec B105
    "jwt_none_algorithm": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "crlf_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "request_smuggling": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
    "subdomain_takeover": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
    "docker_socket_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "exposed_rdp": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N",
    "weak_tls": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "certificate_issue": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "no_forward_secrecy": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N",
    "missing_security_headers": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "csp_missing": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "clickjacking": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "hsts_missing": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "x_content_type_missing": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "referrer_policy_missing": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "permissions_policy_missing": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "dangerous_http_method": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:N/SI:N/SA:N",
    "version_disclosure": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "info_disclosure": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "verbose_errors": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "no_rate_limit": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
    "spf_missing": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N",
    "dmarc_missing": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N",
    "dkim_missing": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "dnssec_missing": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "csp_unsafe_inline": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "oauth_pkce_missing": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "sensitive_file_exposure": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "directory_listing": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "mass_assignment": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
    "race_condition": "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "vulnerable_component": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "graphql_introspection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "graphql_dos": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
    "denial_of_service": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
    "secret_exposure": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",  # nosec B105
    "smtp_no_starttls": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "ssh_hardening": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "container_escape_risk": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:L/SA:H",
    "k8s_misconfiguration": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L",
    "k8s_secrets_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N",
    "privilege_escalation": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "csrf": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
    "session_fixation": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "weak_session_management": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "host_header_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "http_parameter_pollution": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "web_cache_poisoning": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:N/SC:L/SI:H/SA:N",
    "web_cache_deception": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
    "open_mail_relay": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "mta_sts_missing": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "weak_password_policy": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "missing_account_lockout": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "dns_zone_transfer": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "cleartext_service": "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "snmp_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "snmp_default_community": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "cisco_smart_install": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "ipmi_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "backdoor_shell": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "dangerous_service_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "nfs_export_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "tomcat_manager_default_creds": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "weak_db_credentials": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "vnc_no_auth": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "vnc_weak_credentials": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "ipmi_hash_disclosure": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "snmp_amplification": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L",
    "ftp_anonymous": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "rdp_nla_disabled": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "admin_panel_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "xmlrpc_enabled": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    "wordpress_user_enumeration": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "unsupported_software": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N",
    "api_docs_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "api_actuator_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "api_broken_auth": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "wireless_mgmt_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "wireless_mgmt_unauthenticated": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H",
    "anonymous_ldap_enumeration": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "azure_ad_tenant_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "adfs_idp_signon_enabled": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "federation_sts_exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "cloud_iam_overprivileged": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "cloud_iam_privilege_escalation": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "api_bfla": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "cloud_iam_root_access_keys": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "cloud_iam_no_mfa": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "cloud_iam_stale_access_key": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "cloud_iam_weak_password_policy": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "cloud_iam_public_access": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
    "cloud_iam_authenticated": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    # CVSS v4.0 companions for the web-tier / client-side / session / mail classes
    # above. Keyed identically to the v3.1 table so every KB class carries both a
    # v3.1 and a v4.0 vector — no finding is ever left with a blank v4.0 cell.
    "alt_channel_auth_weakness": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "anomaly_heuristic": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "client_resource_manipulation": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "cross_site_script_inclusion": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "css_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "dns_info": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "dom_xss_sink": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "flash_crossdomain": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "insecure_postmessage": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
    "long_session_timeout": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "nuclei": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "open_registration": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    "padding_oracle": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "password_autocomplete_enabled": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "perimeter_defense": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    "permissive_crossdomain_policy": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "security_question_reset": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "sensitive_browser_storage": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "sensitive_cache_control": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "session_token_in_url": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "smtp_header_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "source_comment_disclosure": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "ssi_injection": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    "posture_ok": "",
}


def cvss_vector_for(vuln_type: str, version: str = "3.1") -> str:
    """Representative CVSS vector for a vuln class (resolving aliases), or ''.

    Defaults to the v3.1 vector, which drives HEAVEN's calibrated severity badge.
    Pass ``version="4.0"`` for the CVSS v4.0 representation shown alongside it.
    """
    table = _CVSS4_VECTOR_BY_KEY if str(version).startswith("4") else _CVSS_VECTOR_BY_KEY
    key = normalize_key(vuln_type)
    if key not in table:
        key = _ALIASES.get(key, key)
    return table.get(key, "")


def cvss4_vector_for(vuln_type: str) -> str:
    """Representative CVSS v4.0 vector for a vuln class (resolving aliases), or ''."""
    return cvss_vector_for(vuln_type, version="4.0")


def normalize_key(vuln_type: str) -> str:
    """Lowercase + collapse non-alphanumerics to `_` (so all spellings match)."""
    return re.sub(r"[^a-z0-9]+", "_", (vuln_type or "").lower()).strip("_")


def lookup(vuln_type: str) -> dict[str, Any]:
    """Return the KB entry for a vuln type (resolving aliases), or {} if unknown."""
    key = normalize_key(vuln_type)
    if key in _KB:
        return _KB[key]
    return _KB.get(_ALIASES.get(key, ""), {})


# ── Dynamic taxonomy fallback ───────────────────────────────────────────────
#
# Curated KB entries + aliases cover every class a HEAVEN detector currently
# emits. But a report must never show blank CWE/OWASP/MITRE/CVSS-vector for a
# *real* finding just because a class isn't individually curated (a new detector,
# an imported third-party finding, an LLM-named type). This fallback derives the
# standard taxonomy deterministically from keyword signals in the finding's
# type/title — exactly the tagging a human analyst does when writing up a row.
# It never invents a *finding*; it only labels one already detected. When no
# keyword matches, CWE/OWASP are left blank (not guessed) and only a
# severity-based CVSS vector is supplied.

# Generic CVSS v3.1 vectors by severity band — the last-resort so the "CVSS
# vector" column is populated even for an otherwise-unclassified finding. Each
# vector is authored to compute a base score *inside* its own band (verified in
# tests) so a generic fallback never contradicts the finding's severity label
# (e.g. relabelling a "high" finding "critical" when its score is reconciled).
_GENERIC_CVSS_BY_SEVERITY: dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "high":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  # 8.1
    "medium":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 6.5
    "low":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  # 3.1
    "info":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # 0.0
}

# The same last-resort by-band vectors expressed in CVSS v4.0, so the v4.0 column
# is populated for an unclassified finding too — each also scored inside its band.
_GENERIC_CVSS4_BY_SEVERITY: dict[str, str] = {
    "critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",  # 10.0
    "high":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",  # 7.1
    "medium":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",  # 6.9
    "low":      "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",  # 2.1
    "info":     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",  # 0.0
}

# Keyword → (CWE, OWASP, MITRE). First match wins, so ordered specific → generic.
_KEYWORD_TAXONOMY: list[tuple[tuple[str, ...], tuple[str, str, str]]] = [
    # Active Directory attack classes (attack_type mirrored into vuln_type).
    (("kerberoast", "asrep", "as_rep", "dcsync", "kerberos", "golden_ticket",
      "silver_ticket", "pass_the_hash"),
     ("CWE-522", "A07:2025 Authentication Failures",
      "T1558, Steal or Forge Kerberos Tickets")),
    (("smb_signing", "ntlm_relay", "smbv1", "null_session"),
     ("CWE-522", "A02:2025 Security Misconfiguration",
      "T1557, Adversary-in-the-Middle")),
    (("delegation", "rbcd", "machine_account", "adminsd", "acl_abuse"),
     ("CWE-284", "A01:2025 Broken Access Control", "T1078, Valid Accounts")),
    (("anonymous_ldap", "domain_information"),
     ("CWE-200", "A02:2025 Security Misconfiguration", "T1087, Account Discovery")),
    # AD Certificate Services (ESC1-8) — vulnerable certificate templates / CA that
    # let a low-privileged principal enrol a certificate authenticating as anyone.
    (("adcs_esc", "adcs_ca", "certificate_template", "esc1", "esc2", "esc3",
      "esc4", "esc8", "adcs"),
     ("CWE-269", "A07:2025 Authentication Failures",
      "T1649, Steal or Forge Authentication Certificates")),
    # NTLM authentication coercion surface (PetitPotam / PrinterBug / DFSCoerce).
    (("ntlm_coercion", "coercion", "petitpotam", "printerbug", "dfscoerce"),
     ("CWE-306", "A07:2025 Authentication Failures", "T1187, Forced Authentication")),
    # Kerberos pre-auth username enumeration.
    (("kerberos_user_enum", "kerberos_enum"),
     ("CWE-204", "A02:2025 Security Misconfiguration", "T1087.002, Account Discovery")),
    # SAML SSO misconfiguration (unsigned assertions, RelayState open redirect).
    (("saml_unsigned", "saml_relaystate", "saml_endpoint", "saml_signature",
      "saml_"),
     ("CWE-347", "A07:2025 Authentication Failures",
      "T1606.002, Forge Web Credentials: SAML Tokens")),
    # Internet-facing edge/VPN appliance with actively-exploited (CISA KEV) CVEs.
    (("edge_citrix", "edge_ivanti", "edge_fortinet", "edge_paloalto",
      "edge_microsoft_exchange", "edge_f5", "edge_appliance", "kev_appliance"),
     ("CWE-1104", "A03:2025 Software Supply Chain Failures",
      "T1190, Exploit Public-Facing Application")),
    (("azure_ad_tenant", "cloud_tenant", "tenant_disclosure", "federation_realm",
      "m365_tenant"),
     ("CWE-200", "A02:2025 Security Misconfiguration",
      "T1590, Gather Victim Network Information")),
    # ADFS IdP-initiated sign-on enabled — an internet-facing spray/enumeration
    # surface (kept ahead of the generic exposure/auth groups so it wins).
    (("idp_signon", "idpinitiated", "idp_initiated", "idpinit"),
     ("CWE-284", "A02:2025 Security Misconfiguration", "T1110, Brute Force")),
    # Federation STS metadata disclosure — recon-grade identity-surface mapping.
    (("federation_sts", "federation_metadata", "federation_endpoint",
      "sts_exposed", "sts_disclos"),
     ("CWE-200", "A02:2025 Security Misconfiguration",
      "T1590, Gather Victim Network Information")),
    # Authenticated AWS IAM audit (cloud_iam.py). Specific privilege / hygiene
    # classes first; a catch-all cloud_iam group (recon-info) trails so nothing
    # is left blank. Kept ahead of the generic exposure / misconfig buckets.
    (("cloud_iam_overprivileged", "iam_overprivileged", "admin_equivalent",
      "cloud_iam_root_access_key", "root_access_key"),
     ("CWE-269", "A01:2025 Broken Access Control", "T1078, Valid Accounts")),
    (("cloud_iam_privilege_escalation", "iam_privilege_escalation", "iam_privesc",
      "privesc_technique"),
     ("CWE-269", "A01:2025 Broken Access Control", "T1548, Abuse Elevation Control Mechanism")),
    (("cloud_iam_public_access", "iam_public", "allusers", "public_binding"),
     ("CWE-732", "A01:2025 Broken Access Control", "T1078, Valid Accounts")),
    (("cloud_iam_no_mfa", "without_mfa", "no_mfa"),
     ("CWE-308", "A07:2025 Authentication Failures", "T1078, Valid Accounts")),
    (("cloud_iam_stale_access_key", "stale_access_key", "unrotated_key"),
     ("CWE-324", "A07:2025 Authentication Failures",
      "T1552.001, Unsecured Credentials: Credentials In Files")),
    (("cloud_iam_weak_password_policy", "weak_password_policy"),
     ("CWE-521", "A07:2025 Authentication Failures", "T1110, Brute Force")),
    (("cloud_iam", "iam_audit", "caller_identity"),
     ("CWE-16", "A02:2025 Security Misconfiguration", "T1087, Account Discovery")),
    (("sql", "sqli"),
     ("CWE-89", "A05:2025 Injection", "T1190, Exploit Public-Facing Application")),
    (("command_inj", "cmd_inj", "os_command", "rce", "remote_code", "code_exec", "code_inj"),
     ("CWE-78", "A05:2025 Injection", "T1059, Command and Scripting Interpreter")),
    (("ssti", "template_inj"),
     ("CWE-1336", "A05:2025 Injection", "T1059, Command and Scripting Interpreter")),
    (("xxe", "xml_ext", "xml_entity"),
     ("CWE-611", "A02:2025 Security Misconfiguration", "T1190, Exploit Public-Facing Application")),
    (("xss", "cross_site_script"),
     ("CWE-79", "A05:2025 Injection", "T1059.007, JavaScript")),
    (("ssrf",),
     ("CWE-918", "A01:2025 Broken Access Control", "T1190, Exploit Public-Facing Application")),
    (("csrf", "cross_site_request"),
     ("CWE-352", "A01:2025 Broken Access Control", "T1189, Drive-by Compromise")),
    (("idor", "insecure_direct", "bola", "object_reference"),
     ("CWE-639", "A01:2025 Broken Access Control", "T1190, Exploit Public-Facing Application")),
    (("api_bfla", "bfla", "broken_function_level", "function_level_authorization"),
     ("CWE-285", "A01:2025 Broken Access Control", "T1190, Exploit Public-Facing Application")),
    (("access_control", "authz", "authorization", "forced_brows", "priv_esc",
      "privilege_esc", "unauthenticated", "missing_auth"),
     ("CWE-284", "A01:2025 Broken Access Control", "T1190, Exploit Public-Facing Application")),
    (("path_travers", "directory_travers", "lfi", "rfi", "file_inclusion"),
     ("CWE-22", "A01:2025 Broken Access Control", "T1083, File and Directory Discovery")),
    (("open_redirect", "unvalidated_redirect"),
     ("CWE-601", "A01:2025 Broken Access Control", "T1566, Phishing")),
    (("jwt", "token_forge", "alg_none", "alg_confusion"),
     ("CWE-347", "A04:2025 Cryptographic Failures", "T1552, Unsecured Credentials")),
    (("session",),
     ("CWE-384", "A07:2025 Authentication Failures", "T1539, Steal Web Session Cookie")),
    (("cookie",),
     ("CWE-1004", "A02:2025 Security Misconfiguration", "T1539, Steal Web Session Cookie")),
    (("cache_poison", "cache_decept", "smuggl"),
     ("CWE-444", "A02:2025 Security Misconfiguration", "T1190, Exploit Public-Facing Application")),
    (("host_header", "parameter_pollution", "hpp", "header_inj", "crlf", "response_split"),
     ("CWE-113", "A05:2025 Injection", "T1190, Exploit Public-Facing Application")),
    (("cors",),
     ("CWE-942", "A02:2025 Security Misconfiguration", "T1190, Exploit Public-Facing Application")),
    (("csp", "clickjack", "x_frame", "security_header", "hsts", "content_type",
      "referrer_policy", "permissions_policy", "dangerous_method", "method_override",
      "trace", "options"),
     ("CWE-693", "A02:2025 Security Misconfiguration", "T1185, Browser Session Hijacking")),
    (("default_cred", "weak_cred", "default_password", "guessable"),
     ("CWE-1392", "A07:2025 Authentication Failures", "T1078.001, Default Accounts")),
    (("password", "credential", "login", "brute", "lockout", "spray", "auth_bypass"),
     ("CWE-307", "A07:2025 Authentication Failures", "T1110, Brute Force")),
    (("tls", "ssl", "cipher", "certificate", "cert_", "forward_secrecy", "starttls"),
     ("CWE-326", "A04:2025 Cryptographic Failures", "T1040, Network Sniffing")),
    (("spf", "dmarc", "dkim", "mail_relay", "open_relay", "mta_sts", "spoof"),
     ("CWE-16", "A02:2025 Security Misconfiguration", "T1566, Phishing")),
    (("dnssec", "zone_transfer", "axfr", "dns_"),
     ("CWE-350", "A02:2025 Security Misconfiguration", "T1590, Gather Victim Network Information")),
    (("snmp", "community"),
     ("CWE-1188", "A02:2025 Security Misconfiguration", "T1602, Data from Configuration Repository")),
    (("telnet", "cleartext", "plaintext", "unencrypted", "ftp", "rlogin", "rsh"),
     ("CWE-319", "A04:2025 Cryptographic Failures", "T1040, Network Sniffing")),
    (("rate_limit", "resource_exhaust", "flood", "dos"),
     ("CWE-770", "A06:2025 Insecure Design", "T1499, Endpoint Denial of Service")),
    (("mass_assign", "auto_bind"),
     ("CWE-915", "A08:2025 Software or Data Integrity Failures", "T1190, Exploit Public-Facing Application")),
    (("deserial",),
     ("CWE-502", "A08:2025 Software or Data Integrity Failures", "T1190, Exploit Public-Facing Application")),
    (("outdated", "vulnerable_comp", "known_vuln", "eol", "end_of_life", "cve"),
     ("CWE-1104", "A03:2025 Software Supply Chain Failures", "T1190, Exploit Public-Facing Application")),
    (("docker", "container", "kubernetes", "k8s", "kubelet", "etcd"),
     ("CWE-284", "A02:2025 Security Misconfiguration", "T1610, Deploy Container")),
    # A10:2025 Mishandling of Exceptional Conditions (new in 2025) — verbose
    # errors, stack traces and unhandled / fail-open exception paths
    # (CWE-209/703/755/248). Kept ahead of the generic disclosure and
    # misconfiguration buckets so an error-message leak scores against the right
    # 2025 category instead of falling through to Security Misconfiguration.
    (("verbose_error", "stack_trace", "stacktrace", "error_message",
      "error_disclos", "exception_disclos", "unhandled_exception",
      "improper_error", "error_handling", "fail_open", "detailed_error"),
     ("CWE-209", "A10:2025 Mishandling of Exceptional Conditions",
      "T1592, Gather Victim Host Information")),
    (("exposed", "public", "listing", "backup", "sensitive_file", "disclosure",
      "version", "banner", "leak", "secret", "info"),
     ("CWE-200", "A02:2025 Security Misconfiguration", "T1592, Gather Victim Host Information")),
    (("misconfig", "insecure_config", "debug", "verbose"),
     ("CWE-16", "A02:2025 Security Misconfiguration", "T1592, Gather Victim Host Information")),
]


def _dynamic_taxonomy(finding: dict) -> dict:
    """Best-effort CWE/OWASP/MITRE for a finding whose exact class isn't curated,
    derived from keyword signals in its type/title. ``{}`` when nothing matches
    (so CWE/OWASP are left blank rather than guessed)."""
    hay = normalize_key(
        f"{finding.get('vuln_type', '') or finding.get('type', '')}_"
        f"{finding.get('title', '')}"
    )
    if not hay:
        return {}
    for keywords, (cwe, owasp, mitre) in _KEYWORD_TAXONOMY:
        if any(k in hay for k in keywords):
            return {"cwe": cwe, "owasp": owasp, "mitre": mitre}
    return {}


def _generic_cvss_for_severity(severity: str, version: str = "3.1") -> str:
    """A conservative CVSS vector for a severity band, last-resort so the vector
    column is never blank for an unclassified finding. Defaults to v3.1; pass
    ``version="4.0"`` for the CVSS v4.0 form."""
    table = (_GENERIC_CVSS4_BY_SEVERITY if str(version).startswith("4")
             else _GENERIC_CVSS_BY_SEVERITY)
    return table.get((severity or "").strip().lower(), "")


def _resolve_severity_band(out: dict, ev: dict | None = None) -> str:
    """Resolve a finding to one of the five CVSS severity bands
    (``critical``/``high``/``medium``/``low``/``info``) — never blank.

    Prefers the finding's own qualitative severity; when that is missing or
    non-standard it is derived from the best available numeric score (published
    CVE base, ML-predicted, class typical, engine risk). Guarantees every finding
    resolves to a band that ``_generic_cvss_for_severity`` can turn into a vector,
    so no finding is ever left with a blank CVSS cell. Falls back to ``info``
    (a zero-impact, honest score) only when there is no severity and no score at
    all — never an invented non-zero score."""
    from heaven.utils.cvss import severity_from_score
    sev = (out.get("severity") or "").strip().lower()
    if sev in _GENERIC_CVSS_BY_SEVERITY:
        return sev
    ev = ev if isinstance(ev, dict) else {}
    for key in ("predicted_cvss_score", "cvss_base", "typical_cvss",
                "cvss4_base", "risk_score"):
        for src in (out, ev):
            try:
                val = float(src.get(key))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if val > 0.0:
                return severity_from_score(val)
    return "info"


# ── Dynamic, per-CVE remediation for known-vulnerable-component findings ──
#
# Every CVE finding (inline DB / live feed / NVD) is typed ``vulnerable_service``
# and aliases to the single ``vulnerable_component`` KB entry — so *without* this
# generator they would all show the same generic three-line fix. That reads as
# "fake" because OpenSSH regreSSHion and an Apache SSRF get identical advice.
# ``component_remediation`` builds a remediation that names the actual product,
# version and CVE, and picks an interim mitigation that fits the *weakness class*
# (CWE) — so a path-traversal RCE, an SSRF and a deserialization bug each get the
# control that actually blunts them. Nothing is fabricated: the upgrade target is
# stated as "the vendor's fixed release" (we don't invent a precise version), and
# the interim control is standard, class-accurate guidance.

# The vuln_types that mean "a specific product version is known-vulnerable".
_COMPONENT_KEYS = frozenset({
    "vulnerable_component", "vulnerable_service", "known_vulnerable_version",
    "outdated_component", "vulnerable_dependency",
})

# Human-readable product names for the CPE product keys used by the CVE mapper.
_PRODUCT_DISPLAY: dict[str, str] = {
    "openssh": "OpenSSH", "apache_http_server": "Apache HTTP Server",
    "nginx": "nginx", "microsoft_iis": "Microsoft IIS", "tomcat": "Apache Tomcat",
    "mysql": "MySQL", "mariadb_server": "MariaDB", "postgresql": "PostgreSQL",
    "redis": "Redis", "mongodb": "MongoDB", "elasticsearch": "Elasticsearch",
    "jenkins": "Jenkins", "gitlab": "GitLab", "confluence": "Atlassian Confluence",
    "weblogic_server": "Oracle WebLogic", "apache_struts": "Apache Struts",
    "log4j": "Apache Log4j", "spring_framework": "Spring Framework",
    "apache_shiro": "Apache Shiro", "phpmyadmin": "phpMyAdmin",
    "wordpress": "WordPress", "drupal": "Drupal", "openssl": "OpenSSL",
    "exim": "Exim", "samba": "Samba", "dovecot": "Dovecot", "nodejs": "Node.js",
    "php": "PHP", "kubernetes": "Kubernetes", "docker": "Docker",
    "vsftpd": "vsftpd", "proftpd": "ProFTPD", "rabbitmq": "RabbitMQ",
}

# Interim mitigation keyed by CWE — the control that genuinely reduces exposure
# for that weakness class while the upgrade is scheduled. Grouped so several
# related CWEs share one accurate control.
_CWE_INTERIM: dict[str, str] = {
    # SSRF
    "CWE-918": "block the affected component's outbound network egress and deny "
               "access to internal and cloud-metadata endpoints (e.g. "
               "169.254.169.254) at the firewall",
    # Path / directory traversal & file handling
    "CWE-22": "add a WAF or reverse-proxy rule that rejects `../` and encoded "
              "traversal sequences, and canonicalise paths before any file access",
    "CWE-23": "add a WAF or reverse-proxy rule that rejects `../` and encoded "
              "traversal sequences, and canonicalise paths before any file access",
    "CWE-36": "add a WAF or reverse-proxy rule that rejects `../` and encoded "
              "traversal sequences, and canonicalise paths before any file access",
    "CWE-61": "restrict symlink following and canonicalise paths before file "
              "access; deny the affected path prefixes at the proxy",
    "CWE-434": "block uploads of executable/script extensions at the proxy and "
               "store uploads outside the web root",
    # Deserialization
    "CWE-502": "disable or firewall the affected listener, reject untrusted "
               "serialized input, and expose the service only to trusted networks",
    # Command / argument injection
    "CWE-78": "disable the affected module if unused (e.g. mod_cgi) and restrict "
              "the interface to trusted hosts; allowlist any command arguments",
    "CWE-88": "disable the affected module if unused and restrict the interface "
              "to trusted hosts; allowlist any command arguments",
    # SQL injection
    "CWE-89": "deploy a WAF signature for the injection pattern and route all "
              "database access through parameterised queries",
    # Expression / template / JNDI injection (Log4Shell, Spring4Shell, OGNL)
    "CWE-917": "apply the vendor mitigation (disable message lookups / remove the "
               "affected JAR) and add a WAF signature for the exploit string",
    "CWE-94": "apply the vendor mitigation (disable the vulnerable evaluation "
              "feature) and add a WAF signature for the exploit pattern",
    "CWE-74": "apply the vendor mitigation (disable the vulnerable evaluation "
              "feature) and add a WAF signature for the exploit pattern",
    # XXE
    "CWE-611": "disable external-entity and DTD resolution in the affected parser "
               "and strip DTDs at the gateway",
    # Auth bypass / access control / privilege
    "CWE-287": "place the service behind an authenticated reverse proxy and "
               "disable remote or anonymous access until the fix is deployed",
    "CWE-290": "place the service behind an authenticated reverse proxy and "
               "disable remote or anonymous access until the fix is deployed",
    "CWE-306": "place the service behind an authenticated reverse proxy and "
               "disable remote or anonymous access until the fix is deployed",
    "CWE-640": "restrict the password-reset / account endpoints to trusted "
               "networks and monitor for abuse until patched",
    "CWE-284": "tighten access control at the proxy and restrict the endpoint to "
               "authenticated, trusted callers",
    "CWE-285": "tighten authorisation at the proxy and restrict the endpoint to "
               "authenticated, trusted callers",
    "CWE-269": "restrict the interface to trusted administrators and remove any "
               "unneeded privileged access paths",
    "CWE-862": "enforce authorisation at the proxy and restrict the endpoint to "
               "authenticated callers",
    "CWE-863": "enforce authorisation at the proxy and restrict the endpoint to "
               "authenticated callers",
    # XSS
    "CWE-79": "enable a WAF XSS ruleset and enforce output encoding and a strict "
              "Content-Security-Policy on the affected pages",
    # HTTP request smuggling
    "CWE-444": "normalise HTTP framing at the front-end proxy and reject requests "
               "with conflicting Content-Length / Transfer-Encoding headers",
    # Resource exhaustion / DoS
    "CWE-400": "add rate limits and request/resource caps at the proxy to blunt "
               "resource-exhaustion attempts",
    "CWE-770": "add rate limits and request/resource caps at the proxy to blunt "
               "resource-exhaustion attempts",
    "CWE-835": "add rate limits and request timeouts at the proxy to blunt "
               "resource-exhaustion attempts",
    # Open redirect
    "CWE-601": "allowlist redirect destinations at the proxy and reject "
               "off-site redirect targets",
    # Weak crypto / transport
    "CWE-310": "restrict the service to trusted networks and enforce strong "
               "transport crypto until patched",
    "CWE-924": "restrict the service to trusted networks and enforce strong "
               "transport crypto until patched",
    "CWE-330": "restrict the service to trusted networks and rotate any "
               "predictable secrets until patched",
}

# Memory-safety CWEs: no reliable virtual patch exists, so the honest interim
# control is exposure reduction, not a WAF rule.
_MEMORY_CWES = frozenset({
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126", "CWE-127",
    "CWE-787", "CWE-416", "CWE-415", "CWE-190", "CWE-191", "CWE-193", "CWE-476",
    "CWE-617", "CWE-134", "CWE-364", "CWE-749", "CWE-668",
})


def _product_display(product_key: str) -> str:
    key = (product_key or "").strip().lower()
    if key in _PRODUCT_DISPLAY:
        return _PRODUCT_DISPLAY[key]
    return key.replace("_", " ").title() if key else "the affected component"


def _cwe_interim(cwe: str) -> str:
    cwe = (cwe or "").upper().strip()
    if cwe in _CWE_INTERIM:
        return _CWE_INTERIM[cwe]
    if cwe in _MEMORY_CWES:
        return ("reduce network exposure (firewall / allowlist), no reliable "
                "virtual patch exists for this memory-safety flaw, so prioritise "
                "the upgrade")
    return ("apply a virtual patch / WAF rule targeting the exploit pattern for "
            "this CVE as an interim control")


def _is_real_cve(cve: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{3,}$", (cve or "").strip(), re.IGNORECASE))


def component_remediation(finding: dict) -> str:
    """Tailored remediation for a known-vulnerable-component finding, or "" if the
    finding isn't one (so callers fall back to the generic KB entry).

    Reads product / version / CVE / CWE from either the top level or ``evidence``
    (fields survive the DB round-trip that way), and produces numbered steps that
    name the real component and CVE and choose a class-appropriate interim
    control. Never fabricates a precise fixed version.
    """
    ev = finding.get("evidence") or {}
    vt = normalize_key(finding.get("vuln_type", "") or finding.get("type", ""))
    cve = (finding.get("cve") or finding.get("cve_id")
           or ev.get("cve") or ev.get("cve_id") or "").strip()
    is_component = vt in _COMPONENT_KEYS or _ALIASES.get(vt) == "vulnerable_component"

    # Only specialise when this is a component finding tied to a real CVE — that's
    # exactly the case that otherwise collapses to the generic three-liner.
    if not (is_component and _is_real_cve(cve)):
        return ""

    product = (finding.get("product") or ev.get("product") or "").strip()
    version = (finding.get("version") or ev.get("version") or "").strip()
    cwe = (finding.get("cwe") or ev.get("cwe") or "").strip()
    title = (finding.get("title") or "").strip()
    exploit = bool(finding.get("exploit_available") or ev.get("exploit_available")
                   or finding.get("in_kev") or ev.get("in_kev"))

    prod = _product_display(product)
    # Step 1 — the specific upgrade action, leading with product + version + CVE
    # so it stays informative even when a UI clamps it to a line or two.
    running = f" {version}" if version and version.lower() not in ("unknown", "") else ""
    fix = (f"Upgrade {prod}{running} to the vendor's latest patched release that "
           f"resolves {cve.upper()}")
    if title and title.lower() not in prod.lower():
        fix += f" ({title})"
    fix += "."
    steps = [f"1. {fix}"]

    # Step 2 — interim mitigation matched to the weakness class.
    steps.append(f"2. Interim control: {_cwe_interim(cwe)}.")

    # Step 3 — durable hygiene (SBOM + advisory monitoring), still relevant.
    steps.append("3. Track this component in an SBOM and subscribe to the vendor's "
                 "security advisories so future CVEs are caught early.")

    if exploit:
        steps.append("⚠ A public exploit is available for this CVE, treat it as "
                     "actively exploitable and patch on an emergency timeline.")
    steps.append(f"Verify: confirm the running version is outside the range "
                 f"affected by {cve.upper()} and re-scan to close this finding.")
    steps.append(f"Reference: https://nvd.nist.gov/vuln/detail/{cve.upper()}")
    return "\n".join(steps)


def remediation_text(finding: dict) -> str:
    """A complete, human-readable remediation write-up for a finding, built
    entirely in-house from the KB, no LLM required.

    This is what HEAVEN returns for "explain the fix" when no LLM key is
    configured: a professional, class-accurate report section (summary, impact,
    numbered fix steps, references) rather than a generic one-liner.
    """
    entry = lookup(finding.get("vuln_type", "") or finding.get("type", ""))
    title = (finding.get("title") or entry.get("title")
             or finding.get("vuln_type") or "Security Finding")
    target = finding.get("target", "")
    lines = [f"# Remediation, {title}"]
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
            "2. Treat all client input as untrusted, validate, encode, and "
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
    # A known-vulnerable-component finding gets a remediation tailored to its
    # actual product + CVE + weakness class, not the generic component boilerplate.
    dynamic = component_remediation(finding)
    if dynamic:
        lines += ["", "## How to fix it", dynamic]
    elif entry.get("remediation"):
        lines += ["", "## How to fix it", entry["remediation"]]
    refs = entry.get("references") or []
    if refs:
        lines += ["", "## References"] + [f"- {r}" for r in refs]
    return "\n".join(lines)


def _backfill_published_cvss(out: dict, ev: dict) -> None:
    """Backfill a CVE finding's real published CVSS base from the bundled inline
    DB when it lost its numeric score (e.g. data persisted before per-finding
    CVSS wiring), so the reconciler aligns the label to the true per-CVE number
    rather than a generic class fallback. Offline, so a stale Critical CVE is
    never demoted to its class base. Mutates ``out`` / ``ev`` in place."""
    from heaven.utils.cvss import _finding_float
    if _finding_float(out, ("cvss_base", "cvss_base_score", "cvss_score", "cvss")) is not None:
        return
    cve = out.get("cve") or out.get("cve_id") or ev.get("cve")
    if not cve:
        return
    with contextlib.suppress(Exception):  # inline DB optional
        from heaven.vulnscan.cve_mapper import published_cvss_for
        pub = published_cvss_for(cve)
        if pub:
            out["cvss_base"] = pub
            ev["cvss_base"] = pub
            out["evidence"] = ev


def canonical_severity(finding: dict) -> str:
    """The one authoritative severity band for a finding, shared by every surface
    (findings list, detail, dashboard tally, report) so they can never disagree —
    the drift that let the list show "Critical" while the detail page showed
    "High" for the same CVSS 8.1 finding.

    It is the detector's qualitative band reconciled against the finding's real
    resolved CVSS base: a published CVE score drives the label up or down, an
    unconfirmed / low-confidence indicator is capped to its low band, and a
    finding with no resolvable score keeps its label untouched. Pure — it copies
    the finding and never mutates the caller's dict. Returns "" only when the
    finding carries no severity at all.
    """
    from heaven.utils.cvss import reconcile_severity
    out = dict(finding)
    ev = dict(out.get("evidence") or {})
    out["evidence"] = ev
    _backfill_published_cvss(out, ev)
    reconcile_severity(out)
    return str(out.get("severity") or "").strip().lower()


def enrich_finding(finding: dict) -> dict:
    """Return a shallow copy of `finding` with KB defaults filled into any
    missing description / remediation / references / mitre / cwe / owasp /
    typical_cvss fields. Per-finding data always wins over KB defaults.
    """
    out = dict(finding)
    entry = lookup(finding.get("vuln_type", ""))
    ev = dict(out.get("evidence") or {})

    # A component/CVE finding gets a remediation tailored to its real product +
    # CVE + weakness class (so two different CVEs never share one generic fix).
    # This wins over the KB's generic component remediation.
    dynamic_rem = component_remediation(out)

    if entry:
        ev.setdefault("description", entry.get("description", ""))
        if entry.get("impact"):
            ev.setdefault("impact", entry["impact"])
        if dynamic_rem:
            ev["remediation"] = dynamic_rem
        elif not ev.get("remediation") and entry.get("remediation"):
            ev["remediation"] = entry["remediation"]
        if not ev.get("references") and entry.get("references"):
            ev["references"] = entry["references"]
        if not ev.get("reasons") and entry.get("description"):
            ev["reasons"] = [
                f"Matches the {entry.get('title', finding.get('vuln_type'))} "
                f"class ({entry.get('cwe', '')})."
            ]
    # Belt-and-suspenders: apply the per-CVE remediation even for a component
    # finding whose vuln_type isn't in the KB (so it still beats a blank fix).
    if dynamic_rem:
        ev["remediation"] = dynamic_rem
    out["evidence"] = ev

    if not out.get("mitre_technique") and entry.get("mitre"):
        out["mitre_technique"] = entry["mitre"]
    if not out.get("cwe") and entry.get("cwe"):
        out["cwe"] = entry["cwe"]
    if not out.get("owasp") and entry.get("owasp"):
        out["owasp"] = entry["owasp"]

    # Dynamic fallback: a real finding whose exact class isn't curated still gets
    # the standard taxonomy for its class, derived from its type/title keywords —
    # so the report is never blank. Only applied when the KB had NO entry at all;
    # a curated entry with an intentionally-blank field (informational / positive
    # posture) is left exactly as authored. Skipped for IoT/OT findings: those
    # carry their own framework tag (OWASP IoT Top 10 / IEC 62443) and must never
    # be forced into a web OWASP-2021 category by a keyword match on their title.
    if not entry and not (out.get("owasp_iot") or out.get("iec62443")):
        dyn = _dynamic_taxonomy(out)
        if dyn:
            if not out.get("cwe"):
                out["cwe"] = dyn["cwe"]
            if not out.get("owasp"):
                out["owasp"] = dyn["owasp"]
            if not out.get("mitre_technique"):
                out["mitre_technique"] = dyn["mitre"]

    # A representative CVSS vector for the class so the report's "CVSS vector"
    # column is populated for every known class — and, for an uncurated class, a
    # conservative severity-based vector rather than a blank cell.
    if not out.get("cvss_vector"):
        vec = cvss_vector_for(finding.get("vuln_type", ""))
        if not vec:
            # No curated class vector (an uncurated class, or a curated entry that
            # intentionally carries none) — fall back to a severity-band generic
            # so the v3.1 vector cell is never blank for any finding.
            vec = _generic_cvss_for_severity(_resolve_severity_band(out, ev))
        if vec:
            out["cvss_vector"] = vec

    # Mirror the taxonomy into evidence too — the web FindingDetail falls back to
    # evidence.cwe / evidence.owasp / evidence.mitre, so keep both in sync.
    for src, dst in (("cwe", "cwe"), ("owasp", "owasp"), ("mitre_technique", "mitre")):
        if out.get(src) and not ev.get(dst):
            ev[dst] = out[src]
    if out.get("cvss_vector"):
        ev.setdefault("cvss_vector", out["cvss_vector"])

    # CVSS v4.0 companion — the current standard, shown next to the v3.1 score.
    # For an external CVE already carrying a published v4.0 vector that IS the
    # primary; otherwise use the class's v4.0 vector (or a severity-band generic
    # for an uncurated class). ``cvss_version`` records which standard the
    # authoritative score / severity badge is derived from.
    from heaven.utils.cvss import base_score_from_vector, cvss_version_of
    primary_ver = cvss_version_of(out.get("cvss_vector") or "")
    out["cvss_version"] = out.get("cvss_version") or primary_ver or "3.1"
    if not out.get("cvss4_vector"):
        if primary_ver == "4.0":
            v4vec = out.get("cvss_vector") or ""
        else:
            v4vec = cvss4_vector_for(finding.get("vuln_type", ""))
            if not v4vec:
                # Same guarantee as the v3.1 side: a severity-band generic so the
                # v4.0 cell is never blank for any finding (uncurated class or an
                # intentionally vector-less curated entry).
                v4vec = _generic_cvss_for_severity(
                    _resolve_severity_band(out, ev), version="4.0")
        if v4vec:
            out["cvss4_vector"] = v4vec
    if out.get("cvss4_vector") and out.get("cvss4_base") is None:
        # Compute the base from the vector via the reference scorer. Stored even
        # when 0.0 (a genuinely zero-impact / positive-posture finding) so the
        # field is always present and the UI/report renders a number, not a blank.
        out["cvss4_base"] = round(base_score_from_vector(out["cvss4_vector"]), 1)
    if out.get("cvss4_vector"):
        ev.setdefault("cvss4_vector", out["cvss4_vector"])
    if out.get("cvss4_base") is not None:
        ev.setdefault("cvss4_base", out["cvss4_base"])
    ev.setdefault("cvss_version", out["cvss_version"])
    out["evidence"] = ev

    if not out.get("predicted_cvss_score"):
        typical = entry.get("typical_cvss")
        if not typical:
            # Prefer the real base score computed from the class's curated vector
            # (genuinely per-class) over the flat per-severity constant.
            from heaven.utils.cvss import base_score_from_vector
            score = base_score_from_vector(out.get("cvss_vector") or "")
            typical = score if score > 0 else _SEV_FALLBACK_CVSS.get(
                (finding.get("severity") or "").lower(), 0.0
            )
        out["typical_cvss"] = typical

    # Keep the finding's qualitative severity and its resolved CVSS base score in
    # the same band, so no surface ever shows a contradiction like "CVSS 8.1 /
    # Low": backfill a CVE's real published base from the bundled inline DB, then
    # reconcile the label to it (an unconfirmed 'indicator' is capped to its low
    # band instead). This is the SAME resolver the store applies at write time and
    # the one-time legacy backfill applies, so the findings list, dashboard,
    # detail and report can never disagree on a finding's severity.
    from heaven.utils.cvss import reconcile_severity
    _backfill_published_cvss(out, ev)
    reconcile_severity(out)
    # The ML predictor's raw risk_band reflects its *predicted* CVSS, which can
    # outrank the reconciled, confirmation-aware severity (e.g. a banner-inferred
    # "Potential" finding whose published base is lower). Pin it to the
    # authoritative severity on read so no surface shows "risk_band: high" beside
    # a Medium badge. Resolved on read, exactly like confirmation status.
    final_sev = str(out.get("severity") or "").strip().lower()
    if final_sev:
        if out.get("risk_band"):
            out["risk_band"] = final_sev
        ev_out = out.get("evidence")
        if isinstance(ev_out, dict) and ev_out.get("risk_band"):
            ev_out["risk_band"] = final_sev
    return out
