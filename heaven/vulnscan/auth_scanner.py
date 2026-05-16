"""
HEAVEN — Authentication & Session Security Scanner
Tests: cookie security flags, CSRF protection, session fixation, HTTP auth brute force,
form-based login brute force, account lockout, password policy, OAuth 2.0 misconfigs.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import urllib.parse
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

from heaven.utils.logger import get_logger

logger = get_logger("auth_scanner")


def _dedup(findings: list[dict]) -> list[dict]:
    """Deduplicate by (target, vuln_type) — one finding per unique combination."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for f in findings:
        key = (str(f.get("target", "")), str(f.get("vuln_type", "")))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

# ── Common credential lists ────────────────────────────────────────────────────
_COMMON_PASSWORDS = [
    "password", "Password1", "admin", "Admin1", "123456", "12345678",
    "qwerty", "letmein", "welcome", "monkey", "dragon", "master",
    "abc123", "pass123", "admin123", "root", "toor", "changeme",
    "password1", "Password123", "P@ssw0rd", "P@ssword1", "Passw0rd!",
    "Summer2024", "Winter2024", "Spring2024", "Company123!", "Test1234!",
    "Welcome1", "Welcome123", "Login123", "Access123", "Secret123",
    "1q2w3e4r", "Qwerty123", "qwerty123", "pass@123", "admin@123",
]

_COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest",
    "operator", "manager", "support", "demo", "info", "service",
    "webmaster", "sysadmin", "superuser", "sa", "dba", "api",
]

# ── Login form field name heuristics ──────────────────────────────────────────
_USER_FIELDS  = re.compile(r"user(name)?|email|login|uid|account", re.IGNORECASE)
_PASS_FIELDS  = re.compile(r"pass(word)?|pwd|secret|credential", re.IGNORECASE)
_CSRF_FIELDS  = re.compile(r"csrf|_token|authenticity_token|__RequestVerificationToken|nonce",
                            re.IGNORECASE)
_CSRF_HEADERS = re.compile(r"x-csrf|x-xsrf|x-anti-forgery", re.IGNORECASE)

# ── OAuth / OpenID endpoints ───────────────────────────────────────────────────
_OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
    "/connect/authorize", "/api/oauth/authorize",
    "/.well-known/openid-configuration",
]

# ── Session cookie names ───────────────────────────────────────────────────────
_SESSION_COOKIE_NAMES = re.compile(
    r"sess(ion)?id|auth|token|jwt|bearer|sid|JSESSIONID|PHPSESSID|ASP\.NET_SessionId",
    re.IGNORECASE,
)


def _make_finding(target: str, vuln_type: str, severity: str,
                  title: str, description: str,
                  confidence: float = 0.85,
                  evidence: Optional[dict] = None,
                  cve: str = "") -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "cve_id": cve,
        "evidence": evidence or {},
        "source": "auth_scanner",
    }


# ── Cookie analysis ─────────────────────────────────────────────────────────────

async def _audit_cookies(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    """Analyse Set-Cookie headers for missing security flags."""
    findings: list[dict] = []
    try:
        async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            raw_hdrs = resp.headers.getall("Set-Cookie", [])

            for raw in raw_hdrs:
                raw_lower = raw.lower()
                # Extract cookie name
                name_match = re.match(r"([^=]+)=", raw)
                name = name_match.group(1).strip() if name_match else "unknown"

                is_session = bool(_SESSION_COOKIE_NAMES.search(name))
                severity   = "high" if is_session else "medium"

                if "secure" not in raw_lower:
                    findings.append(_make_finding(
                        url, "cookie_no_secure", severity,
                        f"Cookie '{name}' Missing Secure Flag",
                        "Cookie transmitted over HTTP. An attacker on the network can steal "
                        "it via passive sniffing. Add the Secure attribute.",
                        confidence=0.97,
                        evidence={"cookie_name": name, "raw": raw[:200]},
                    ))
                if "httponly" not in raw_lower:
                    findings.append(_make_finding(
                        url, "cookie_no_httponly", severity,
                        f"Cookie '{name}' Missing HttpOnly Flag",
                        "Cookie accessible via JavaScript (document.cookie). Enables XSS-based "
                        "session hijacking. Add HttpOnly attribute.",
                        confidence=0.97,
                        evidence={"cookie_name": name, "raw": raw[:200]},
                    ))
                if "samesite" not in raw_lower:
                    findings.append(_make_finding(
                        url, "cookie_no_samesite", "medium",
                        f"Cookie '{name}' Missing SameSite Attribute",
                        "No SameSite attribute — cookie is sent on cross-site requests, "
                        "enabling CSRF attacks. Set SameSite=Strict or Lax.",
                        confidence=0.92,
                        evidence={"cookie_name": name},
                    ))
                # Check for short session IDs (<128 bits of entropy)
                val_match = re.match(r"[^=]+=([^;]+)", raw)
                val = val_match.group(1).strip() if val_match else ""
                if is_session and val and len(val) < 16:
                    findings.append(_make_finding(
                        url, "weak_session_id", "high",
                        f"Short Session ID for Cookie '{name}'",
                        f"Session ID '{val[:8]}…' is only {len(val)} chars — may be brute-forceable.",
                        confidence=0.80,
                        evidence={"cookie_name": name, "id_length": len(val)},
                    ))
    except Exception as e:
        logger.debug(f"cookie audit error for {url}: {e}")
    return findings


# ── CSRF detection ──────────────────────────────────────────────────────────────

async def _audit_csrf(session: "aiohttp.ClientSession", url: str,
                      forms: list[dict]) -> list[dict]:
    """
    Check for CSRF protection in forms that perform state-changing operations.
    """
    findings: list[dict] = []
    state_changing_methods = {"post", "put", "delete", "patch"}

    for form in forms:
        method = (form.get("method") or "get").lower()
        action = form.get("action") or url
        fields = form.get("fields", [])

        if method not in state_changing_methods:
            continue

        # Check if the form contains a CSRF token field
        has_token = any(_CSRF_FIELDS.search(f.get("name", "")) for f in fields)
        if not has_token:
            # Also check for meta CSRF tag on the page
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()
                    has_meta_token = bool(re.search(
                        r'<meta[^>]+csrf', body, re.IGNORECASE))
                    has_header_token = any(
                        _CSRF_HEADERS.search(h) for h in resp.headers
                    )
                    if has_meta_token or has_header_token:
                        continue
            except Exception:
                pass

            findings.append(_make_finding(
                action, "csrf_missing_token", "high",
                f"CSRF Token Missing in {method.upper()} Form",
                f"Form at '{action}' ({method.upper()}) submits without a CSRF token. "
                f"Attackers can forge cross-site requests on behalf of authenticated users.",
                confidence=0.82,
                evidence={"form_action": action, "method": method, "fields": [f.get("name") for f in fields]},
            ))

    return findings


# ── Session fixation ────────────────────────────────────────────────────────────

async def _audit_session_fixation(session: "aiohttp.ClientSession",
                                   url: str, forms: list[dict]) -> list[dict]:
    """
    Detect session fixation: if the server accepts a session ID we supply in the
    request and does NOT issue a new one after login, it's vulnerable.
    """
    findings: list[dict] = []
    try:
        fake_sid = "HEAVEN_PROBE_" + hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:16]

        # Find likely login URL
        login_form = next(
            (f for f in forms if any(_PASS_FIELDS.search(fld.get("name", ""))
                                     for fld in f.get("fields", []))),
            None,
        )
        if not login_form:
            return findings

        action = login_form.get("action") or url
        method = (login_form.get("method") or "post").lower()

        # Send request with a forged session cookie
        req_cookies = {"PHPSESSID": fake_sid, "JSESSIONID": fake_sid,
                       "session": fake_sid, "sessionid": fake_sid}
        fn = session.post if method == "post" else session.get
        async with fn(
            action,
            data={},
            cookies=req_cookies,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            new_cookies = {c.key: c.value for c in resp.cookies.values()}
            # If the server echoed back our fixed session ID — fixation is possible
            for name, val in new_cookies.items():
                if val == fake_sid:
                    findings.append(_make_finding(
                        action, "session_fixation", "high",
                        "Session Fixation Vulnerability",
                        f"Server accepted and re-used a client-supplied session ID "
                        f"(cookie '{name}'). An attacker can fix a known session ID then "
                        f"wait for the victim to authenticate.",
                        confidence=0.80,
                        evidence={"cookie_name": name, "fixed_id": fake_sid},
                    ))
    except Exception as e:
        logger.debug(f"session fixation check error: {e}")
    return findings


# ── HTTP Basic auth brute force ─────────────────────────────────────────────────

async def _brute_http_basic(session: "aiohttp.ClientSession",
                             url: str) -> list[dict]:
    """
    Detect HTTP Basic/Digest auth prompt, then try common credentials.
    """
    findings: list[dict] = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status != 401:
                return findings
            www_auth = resp.headers.get("WWW-Authenticate", "")
            auth_type = "Basic" if "basic" in www_auth.lower() else "Digest"
    except Exception:
        return findings

    sem = asyncio.Semaphore(5)
    found: list[tuple[str, str]] = []

    async def _try(user: str, passwd: str) -> None:
        async with sem:
            if found:
                return
            try:
                auth = aiohttp.BasicAuth(user, passwd)
                async with session.get(url, auth=auth,
                                       timeout=aiohttp.ClientTimeout(total=6)) as r:
                    # Require 200 only — redirects (3xx) are not confirmed logins
                    if r.status == 200:
                        found.append((user, passwd))
            except Exception:
                pass

    pairs = [(u, p) for u in _COMMON_USERNAMES[:8] for p in _COMMON_PASSWORDS[:12]]
    await asyncio.gather(*[_try(u, p) for u, p in pairs])

    for user, passwd in found:
        findings.append(_make_finding(
            url, "weak_http_auth_credentials", "critical",
            f"Weak HTTP {auth_type} Credentials ({user}:{passwd})",
            "Successfully authenticated with default credentials. "
            "An unauthenticated attacker can gain access.",
            confidence=0.99,
            evidence={"username": user, "password": passwd, "auth_type": auth_type},
        ))

    if not found:
        # Lockout detection — did we get locked out after attempts?
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=6)) as r:
                if r.status == 429 or "locked" in (await r.text()).lower():
                    findings.append(_make_finding(
                        url, "account_lockout_detected", "info",
                        "Account Lockout Policy Detected",
                        "Server responded with lockout indicator after repeated failed logins. "
                        "This is a positive security control.",
                        confidence=0.75,
                    ))
        except Exception:
            pass

    return findings


# ── Form-based login brute force ────────────────────────────────────────────────

async def _brute_login_form(session: "aiohttp.ClientSession",
                             url: str, forms: list[dict]) -> list[dict]:
    """Attempt common credentials against detected HTML login forms."""
    findings: list[dict] = []
    login_form = next(
        (f for f in forms if any(_PASS_FIELDS.search(fld.get("name", ""))
                                 for fld in f.get("fields", []))),
        None,
    )
    if not login_form:
        return findings

    action = login_form.get("action") or url
    fields = login_form.get("fields", [])
    user_field = next((f["name"] for f in fields if _USER_FIELDS.search(f.get("name", ""))), None)
    pass_field = next((f["name"] for f in fields if _PASS_FIELDS.search(f.get("name", ""))), None)
    csrf_field = next((f["name"] for f in fields if _CSRF_FIELDS.search(f.get("name", ""))), None)

    if not user_field or not pass_field:
        return findings

    # Capture baseline CSRF token if present
    csrf_value = ""
    if csrf_field:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text()
                m = re.search(
                    rf'name=["\']?{re.escape(csrf_field)}["\']?\s+value=["\']([^"\']+)',
                    body, re.IGNORECASE,
                )
                if m:
                    csrf_value = m.group(1)
        except Exception:
            pass

    sem = asyncio.Semaphore(3)
    found: list[tuple[str, str]] = []
    lockout_detected = False
    errored_attempts = 0  # timeouts / connection drops — often an IP-level block

    # Measure baseline response for failed login (length / status)
    try:
        data = {user_field: "nosuchu$er_h3av3n", pass_field: "wr0ngp@ss_h3aven"}
        if csrf_field and csrf_value:
            data[csrf_field] = csrf_value
        async with session.post(action, data=data,
                                timeout=aiohttp.ClientTimeout(total=10)) as r:
            fail_status = r.status
            fail_body   = await r.text()
            fail_len    = len(fail_body)
    except Exception:
        return findings

    async def _try(user: str, passwd: str) -> None:
        nonlocal lockout_detected, errored_attempts
        async with sem:
            if found or lockout_detected:
                return
            try:
                payload = {user_field: user, pass_field: passwd}
                if csrf_field and csrf_value:
                    payload[csrf_field] = csrf_value
                async with session.post(action, data=payload,
                                        timeout=aiohttp.ClientTimeout(total=10)) as r:
                    body = await r.text()
                    # Broad lockout / anti-automation signals — not just HTTP 429.
                    # A site that blocks via 403/423, CAPTCHA, or a lock message
                    # DOES throttle; the old check missed all of these and then
                    # falsely reported "no account lockout".
                    blow = body.lower()
                    if (r.status in (429, 423) or
                            any(s in blow for s in
                                ("too many", "rate limit", "rate-limit", "captcha",
                                 "try again later", "temporarily locked", "account locked",
                                 "account is locked", "has been locked", "blocked"))):
                        lockout_detected = True
                        return
                    # Heuristic: post-login keywords present AND response meaningfully differs
                    body_len = len(body)
                    success_kw = any(kw in body.lower() for kw in
                                     ("logout", "dashboard", "welcome", "account",
                                      "profile", "signout", "sign out", "my account"))
                    response_differs = (r.status != fail_status
                                        or abs(body_len - fail_len) > 300)
                    if success_kw and response_differs:
                        found.append((user, passwd))
            except Exception:
                errored_attempts += 1

    pairs = [(u, p) for u in _COMMON_USERNAMES[:6] for p in _COMMON_PASSWORDS[:8]]
    await asyncio.gather(*[_try(u, p) for u, p in pairs])

    for user, passwd in found:
        findings.append(_make_finding(
            action, "weak_login_credentials", "critical",
            f"Default/Weak Login Credentials Found ({user})",
            f"Login successful with credentials {user}:{passwd}. "
            f"Immediately rotate credentials and enforce strong password policy.",
            confidence=0.92,
            evidence={"username": user, "password": passwd, "form_action": action},
        ))

    if not found and lockout_detected:
        findings.append(_make_finding(
            action, "account_lockout_detected", "info",
            "Account Lockout Policy Active",
            "Server throttles repeated login attempts. Good security control.",
            confidence=0.80,
        ))
    elif not found and not lockout_detected:
        # Only claim "no lockout" if the endpoint kept answering normally for
        # ALL attempts. Many errored requests = the endpoint likely blocked us
        # (IP ban / connection drop) — reporting "no lockout" then is a false
        # positive, so the result is inconclusive instead.
        if errored_attempts > len(pairs) // 3:
            findings.append(_make_finding(
                action, "lockout_inconclusive", "info",
                "Account Lockout — Inconclusive",
                f"{errored_attempts}/{len(pairs)} brute-force attempts failed to "
                f"complete (timeouts/drops). The endpoint may be blocking "
                f"automated logins. Verify the lockout policy manually.",
                confidence=0.50,
            ))
        else:
            findings.append(_make_finding(
                action, "no_account_lockout", "medium",
                "No Account Lockout / Rate Limiting on Login",
                "Login endpoint accepted repeated failed attempts without "
                "throttling, lockout, or CAPTCHA. Vulnerable to online "
                "password brute-force attacks.",
                confidence=0.72,
            ))

    return findings


# ── Password policy fingerprinting ─────────────────────────────────────────────

async def _audit_password_policy(session: "aiohttp.ClientSession",
                                  url: str) -> list[dict]:
    """Try to register/change password with very short inputs to detect weak policy."""
    findings: list[dict] = []
    register_paths = ["/register", "/signup", "/user/new", "/account/create",
                      "/auth/register", "/api/register", "/api/signup"]
    for path in register_paths:
        test_url = urllib.parse.urljoin(url, path)
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=6)) as r:
                if r.status != 200:
                    continue
                body = await r.text()
                # Check password field exists
                if not re.search(r'type=["\']password["\']', body, re.IGNORECASE):
                    continue
                # Check for password strength requirements
                has_minlength = bool(re.search(r'minlength|min.length|minimum.length', body, re.IGNORECASE))
                has_pattern   = bool(re.search(r'pattern=|passwordrule|strength', body, re.IGNORECASE))
                if not has_minlength and not has_pattern:
                    findings.append(_make_finding(
                        test_url, "weak_password_policy", "medium",
                        "No Client-Side Password Policy Enforcement",
                        "Registration form has no visible minimum length or complexity requirements. "
                        "Server may accept very short passwords.",
                        confidence=0.65,
                        evidence={"path": path},
                    ))
                break
        except Exception:
            continue
    return findings


# ── OAuth 2.0 misconfiguration ──────────────────────────────────────────────────

async def _audit_oauth(session: "aiohttp.ClientSession", url: str) -> list[dict]:
    """Test OAuth 2.0 endpoints for open redirect in redirect_uri and state fixation."""
    findings: list[dict] = []
    base = urllib.parse.urlparse(url)
    base_url = f"{base.scheme}://{base.netloc}"

    for path in _OAUTH_PATHS:
        auth_url = base_url + path
        # Test with attacker-controlled redirect_uri
        evil_redirect = "https://evil.attacker.example.com/callback"
        test_url = (f"{auth_url}?response_type=code&client_id=test"
                    f"&redirect_uri={urllib.parse.quote(evil_redirect)}"
                    f"&scope=openid&state=heaven_probe")
        try:
            async with session.get(test_url, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=8)) as resp:
                location = resp.headers.get("Location", "")
                if resp.status in (301, 302, 303, 307, 308):
                    if "evil.attacker" in location:
                        findings.append(_make_finding(
                            auth_url, "oauth_open_redirect", "high",
                            "OAuth 2.0 Open Redirect in redirect_uri",
                            f"Server redirected to attacker-controlled URI: {location}. "
                            f"Authorization codes can be stolen.",
                            confidence=0.90,
                            evidence={"location": location, "evil_uri": evil_redirect},
                        ))
                    # Check for state parameter reflection without validation
                    if "heaven_probe" in location and "evil.attacker" not in location:
                        findings.append(_make_finding(
                            auth_url, "oauth_state_reflected", "medium",
                            "OAuth State Parameter Reflected Without Validation",
                            "The 'state' parameter is reflected but may not be validated, "
                            "enabling CSRF against the OAuth flow.",
                            confidence=0.65,
                        ))
        except Exception:
            continue

        # Check for PKCE enforcement (missing = auth code interception)
        if "openid" in path or "authorize" in path:
            try:
                test_no_pkce = (f"{auth_url}?response_type=code&client_id=test"
                                f"&redirect_uri={urllib.parse.quote(base_url + '/callback')}"
                                f"&scope=openid")
                async with session.get(test_no_pkce, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status in (200, 301, 302):
                        findings.append(_make_finding(
                            auth_url, "oauth_pkce_not_enforced", "medium",
                            "OAuth 2.0 PKCE Not Enforced",
                            "Authorization endpoint accepts requests without code_challenge. "
                            "Public clients are vulnerable to authorization code interception.",
                            confidence=0.65,
                            evidence={"path": path},
                        ))
            except Exception:
                pass

    return findings


# ── Security headers audit ──────────────────────────────────────────────────────

async def _audit_security_headers(session: "aiohttp.ClientSession",
                                   url: str) -> list[dict]:
    """Check for missing/misconfigured security response headers."""
    findings: list[dict] = []
    required = {
        "Content-Security-Policy":           ("csp_missing", "medium",
            "Content-Security-Policy (CSP) Missing",
            "Without CSP, XSS attacks cannot be mitigated by the browser. "
            "Implement a strict CSP with nonce or hash-based script whitelisting."),
        "X-Frame-Options":                   ("clickjacking_no_xfo", "medium",
            "X-Frame-Options Missing — Clickjacking Risk",
            "Page can be embedded in an iframe on an attacker-controlled site, "
            "enabling clickjacking attacks. Add X-Frame-Options: DENY or SAMEORIGIN."),
        "X-Content-Type-Options":            ("no_x_content_type", "low",
            "X-Content-Type-Options Missing",
            "Without nosniff, browsers may MIME-sniff responses, enabling content injection."),
        "Referrer-Policy":                   ("no_referrer_policy", "low",
            "Referrer-Policy Not Set",
            "Sensitive URL paths may be leaked to third parties via the Referer header."),
        "Permissions-Policy":                ("no_permissions_policy", "low",
            "Permissions-Policy / Feature-Policy Not Set",
            "Browser features (camera, geolocation, etc.) are not explicitly restricted."),
    }

    try:
        async with session.get(url, allow_redirects=True,
                               timeout=aiohttp.ClientTimeout(total=10)) as resp:
            hdrs = resp.headers
            for header, (vuln_type, severity, title, desc) in required.items():
                if header not in hdrs:
                    findings.append(_make_finding(
                        url, vuln_type, severity, title, desc,
                        confidence=0.98,
                        evidence={"missing_header": header},
                    ))

            # CSP analysis — check for unsafe-inline / unsafe-eval
            csp = hdrs.get("Content-Security-Policy", "")
            if csp:
                if "'unsafe-inline'" in csp:
                    findings.append(_make_finding(
                        url, "csp_unsafe_inline", "high",
                        "CSP Contains 'unsafe-inline' — XSS Mitigation Bypassed",
                        "CSP with 'unsafe-inline' does not prevent XSS. "
                        "Use nonces or hashes instead.",
                        confidence=0.97,
                        evidence={"csp": csp[:300]},
                    ))
                if "'unsafe-eval'" in csp:
                    findings.append(_make_finding(
                        url, "csp_unsafe_eval", "medium",
                        "CSP Contains 'unsafe-eval'",
                        "CSP with 'unsafe-eval' allows dynamic code execution (eval, Function). "
                        "Remove this directive.",
                        confidence=0.97,
                        evidence={"csp": csp[:300]},
                    ))

            # Check for information disclosure headers
            server_hdr = hdrs.get("Server", "")
            x_powered  = hdrs.get("X-Powered-By", "")
            if re.search(r"\d+\.\d+", server_hdr):
                findings.append(_make_finding(
                    url, "server_version_disclosure", "low",
                    f"Server Version Disclosed: {server_hdr}",
                    "Server header reveals version information, aiding attackers in targeting "
                    "known vulnerabilities.",
                    confidence=0.98,
                    evidence={"server": server_hdr},
                ))
            if x_powered:
                findings.append(_make_finding(
                    url, "technology_disclosure", "low",
                    f"Technology Stack Disclosed: X-Powered-By: {x_powered}",
                    "X-Powered-By reveals framework/language version.",
                    confidence=0.97,
                    evidence={"x_powered_by": x_powered},
                ))
    except Exception as e:
        logger.debug(f"security headers audit error: {e}")

    return findings


# ── Main scanner entry point ────────────────────────────────────────────────────

async def scan_auth(url: str, forms: Optional[list[dict]] = None,
                    brute_force: bool = True) -> dict:
    """
    Full authentication/session security scan for a target URL.

    Args:
        url:         Target URL (with scheme).
        forms:       Pre-extracted form list from web crawler (optional).
        brute_force: Whether to attempt credential brute-forcing.
    Returns:
        Standardized result dict with 'findings' and 'vulnerabilities' keys.
    """
    if not HAS_AIOHTTP:
        return {"findings": [], "error": "aiohttp not installed"}

    forms = forms or []
    all_findings: list[dict] = []

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; HEAVEN-AuthScanner/2.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    timeout   = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(headers=headers,
                                     connector=connector,
                                     timeout=timeout) as session:
        # Run all checks concurrently
        results = await asyncio.gather(
            _audit_cookies(session, url),
            _audit_csrf(session, url, forms),
            _audit_session_fixation(session, url, forms),
            _audit_security_headers(session, url),
            _audit_oauth(session, url),
            _audit_password_policy(session, url),
            *(
                [_brute_http_basic(session, url),
                 _brute_login_form(session, url, forms)]
                if brute_force else []
            ),
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
            elif isinstance(r, Exception):
                logger.debug(f"auth scan subtask error: {r}")

    all_findings = _dedup(all_findings)
    crit = sum(1 for f in all_findings if f.get("severity") == "critical")
    high = sum(1 for f in all_findings if f.get("severity") == "high")
    logger.info(
        f"Auth scan {url} → {len(all_findings)} issues "
        f"({crit} critical, {high} high)"
    )

    return {
        "target": url,
        "total": len(all_findings),
        "critical": crit,
        "high": high,
        "findings": all_findings,
        "vulnerabilities": all_findings,
    }


async def scan_auth_targets(urls: list[str], crawl_data: Optional[dict] = None) -> dict:
    """
    Scan multiple URLs concurrently.
    crawl_data: optional dict keyed by URL containing 'forms' lists from crawler.
    """
    crawl_data = crawl_data or {}
    all_findings: list[dict] = []
    sem = asyncio.Semaphore(5)

    async def _one(url: str) -> None:
        async with sem:
            forms = crawl_data.get(url, {}).get("forms", [])
            res = await scan_auth(url, forms=forms)
            all_findings.extend(res.get("findings", []))

    await asyncio.gather(*[_one(u) for u in urls], return_exceptions=True)

    return {
        "total": len(all_findings),
        "findings": all_findings,
        "vulnerabilities": all_findings,
    }
