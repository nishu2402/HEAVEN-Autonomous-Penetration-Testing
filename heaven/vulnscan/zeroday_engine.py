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
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

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
        for payload in mutation.format_string_payloads()[:5]:
            result = await self._send_tcp_probe(host, port, payload.encode())
            if result:
                anomaly = self._analyze_format_string_response(result, payload)
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

    async def scan_endpoint(self, session: aiohttp.ClientSession, url: str,
                            params: list[str], method: str = "GET") -> list[ZeroDayCandidate]:
        """Scan a web endpoint for zero-day vulnerabilities."""
        candidates = []

        for param in params:
            # 1. Command injection
            cmdi = await self._test_command_injection(session, url, param, method)
            if cmdi:
                candidates.append(cmdi)

            # 2. SSTI (Server-Side Template Injection)
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

            # 5. Header injection
            header_vulns = await self._test_header_injection(session, url)
            candidates.extend(header_vulns)

        return candidates

    async def _test_command_injection(self, session: aiohttp.ClientSession, url: str,
                                       param: str, method: str) -> Optional[ZeroDayCandidate]:
        """Detect command injection via time-based differential analysis."""
        try:
            # Baseline request
            t0 = time.time()
            async with session.request(method, url, params={param: "normalvalue"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                baseline_time = (time.time() - t0) * 1000
                await resp.text()

            # Time-based probe: inject sleep command
            sleep_payload = "; sleep 5" if not sys.platform.startswith("win") else "& timeout 5"
            t1 = time.time()
            async with session.request(method, url, params={param: f"test{sleep_payload}"},
                                        timeout=aiohttp.ClientTimeout(total=15)) as resp:
                probe_time = (time.time() - t1) * 1000
                await resp.text()

            # If response took significantly longer → command injection likely
            if probe_time > baseline_time + 4000:
                return ZeroDayCandidate(
                    target=url, category="command_injection",
                    confidence=0.85, severity="critical",
                    description=f"Time-based command injection on param '{param}' (delta={probe_time - baseline_time:.0f}ms)",
                    evidence={"param": param, "baseline_ms": baseline_time, "probe_ms": probe_time,
                              "technique": "time_based"},
                    remediation="Sanitise all user inputs. Use parameterised system calls. Avoid shell=True.",
                    cwe_id="CWE-78", technique="time_based_cmdi",
                )
        except Exception:
            pass
        return None

    async def _test_ssti(self, session: aiohttp.ClientSession, url: str,
                          param: str, method: str) -> Optional[ZeroDayCandidate]:
        """Detect Server-Side Template Injection."""
        # Use mathematical expressions that template engines evaluate
        probes = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%=7*7%>", "49"),
            ("#{7*7}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime"),  # Spring detection
        ]

        try:
            for payload, expected in probes:
                async with session.request(method, url, params={param: payload},
                                            timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text()
                    if expected in body and payload not in body:
                        return ZeroDayCandidate(
                            target=url, category="ssti",
                            confidence=0.9, severity="critical",
                            description=f"Server-Side Template Injection on param '{param}' (engine evaluated '{payload}' → '{expected}')",
                            evidence={"param": param, "payload": payload, "expected": expected,
                                      "found_in_response": True},
                            remediation="Use template sandboxing. Never pass user input directly to template engines.",
                            cwe_id="CWE-1336", technique="ssti_detection",
                        )
        except Exception:
            pass
        return None

    async def _test_path_traversal(self, session: aiohttp.ClientSession, url: str,
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

    async def _test_integer_overflow(self, session: aiohttp.ClientSession, url: str,
                                      param: str, method: str) -> Optional[ZeroDayCandidate]:
        """Detect integer overflow/underflow vulnerabilities."""
        payloads = MutationEngine.integer_overflow_payloads()

        try:
            # Baseline
            async with session.request(method, url, params={param: "1"},
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                baseline_status = resp.status
                baseline_len = len(await resp.text())

            for payload in payloads:
                async with session.request(method, url, params={param: payload},
                                            timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    body = await resp.text()
                    status = resp.status

                    # Server error with overflow value → potential integer overflow
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
                    elif status == baseline_status and abs(len(body) - baseline_len) > 100:
                        return ZeroDayCandidate(
                            target=url, category="integer_overflow",
                            confidence=0.4, severity="medium",
                            description=f"Significant response size anomaly with integer boundary value '{payload}' on param '{param}'",
                            evidence={"param": param, "payload": payload, "baseline_len": baseline_len, "body_len": len(body)},
                            remediation="Validate numeric inputs. Use appropriate data types with bounds checking.",
                            cwe_id="CWE-190", technique="integer_boundary_testing",
                        )
        except Exception:
            pass
        return None

    async def _test_header_injection(self, session: aiohttp.ClientSession,
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


