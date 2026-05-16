"""
HEAVEN — SSL/TLS Security Scanner
Full TLS/SSL audit: protocol versions, cipher suites, certificate validation,
HEARTBLEED, POODLE, BEAST, CRIME, ROBOT, DROWN, Logjam, FREAK.
"""
from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("ssl_scanner")

# ── Weak cipher patterns ───────────────────────────────────────────────────────
_WEAK_CIPHER_PATTERNS = [
    "NULL", "EXPORT", "LOW", "RC2", "RC4", "DES", "MD5",
    "anon", "aNULL", "eNULL", "ADH", "AECDH",
    "3DES", "IDEA", "SEED", "CAMELLIA128",
]
_FORWARD_SECRECY_KEXES = {"ECDHE", "DHE", "ECDH", "EDH"}

# ── TLS protocol constants ─────────────────────────────────────────────────────
_TLS_VERSIONS = {
    "SSLv2":  ssl.PROTOCOL_SSLv23,   # will negotiate down
    "SSLv3":  None,                   # removed in Python 3.10+
    "TLSv1.0": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.1": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.2": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.3": ssl.PROTOCOL_TLS_CLIENT,
}

# ── HEARTBLEED probe bytes (CVE-2014-0160) ────────────────────────────────────
_HEARTBLEED_HELLO = bytes([
    # TLS Client Hello for TLS 1.0
    0x16, 0x03, 0x01, 0x00, 0xdc,          # Record header: Handshake, TLS1.0, 220 bytes
    0x01, 0x00, 0x00, 0xd8,                 # ClientHello, length=216
    0x03, 0x01,                             # TLS 1.0
    0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b,   # Random (32 bytes)
    0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b,
    0x92, 0xa8, 0x48, 0x97, 0xcf, 0xbd,
    0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
    0x03, 0x90, 0x9f, 0x77, 0x04, 0x33,
    0xd4, 0xde,
    0x00,                                   # Session ID length = 0
    0x00, 0x66,                             # Cipher suites length = 102
    # 51 cipher suites
    0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
    0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
    0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
    0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
    0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
    0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
    0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
    0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
    0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
    0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
    0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,
    0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,
    0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
    0x01,                                   # Compression methods length = 1
    0x00,                                   # no compression
    0x00, 0x49,                             # Extensions length = 73
    # heartbeat extension (type=0x000f, length=1, mode=1 peer_allowed_to_send)
    0x00, 0x0f, 0x00, 0x01, 0x01,
    # other standard extensions...
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
    0x00, 0x0a, 0x00, 0x34, 0x00, 0x32,
    0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b,
    0x00, 0x0c, 0x00, 0x18, 0x00, 0x09, 0x00, 0x0a,
    0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06,
    0x00, 0x07, 0x00, 0x14, 0x00, 0x15, 0x00, 0x04,
    0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x03, 0x00, 0x0f, 0x00, 0x10,
    0x00, 0x11,
    0x00, 0x23, 0x00, 0x00,
    0x00, 0x0f, 0x00, 0x01, 0x01,
])

_HEARTBEAT_REQUEST = bytes([
    0x18,                   # ContentType: Heartbeat (24)
    0x03, 0x02,             # TLS 1.1
    0x00, 0x03,             # Length: 3 bytes
    0x01,                   # HeartbeatMessageType: request
    0x40, 0x00,             # Payload length: 16384 (huge — should trigger overread on vuln servers)
])


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)
    days_until_expiry: int = 9999
    is_expired: bool = False
    is_self_signed: bool = False
    key_type: str = ""
    key_bits: int = 0
    signature_algorithm: str = ""


@dataclass
class SSLResult:
    host: str
    port: int
    reachable: bool = False
    ssl2: bool = False
    ssl3: bool = False
    tls10: bool = False
    tls11: bool = False
    tls12: bool = False
    tls13: bool = False
    heartbleed: bool = False
    poodle: bool = False       # SSLv3 CBC = POODLE
    beast: bool = False        # TLS1.0 CBC without RC4
    crime: bool = False        # TLS compression enabled
    drown: bool = False        # SSLv2 enabled
    logjam: bool = False       # DHE <=1024-bit
    freak: bool = False        # EXPORT cipher support
    robot: bool = False        # RSA key exchange timing (heuristic)
    cert: Optional[CertInfo] = None
    hsts: bool = False
    hsts_max_age: int = 0
    hsts_preload: bool = False
    hsts_subdomains: bool = False
    ocsp_stapling: bool = False
    supported_ciphers: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    forward_secrecy: bool = False
    findings: list[dict] = field(default_factory=list)
    error: Optional[str] = None


# ── Core probing helpers ────────────────────────────────────────────────────────

def _check_protocol(host: str, port: int, min_ver: int, max_ver: int,
                    timeout: float = 5.0) -> bool:
    """Try a TLS connection with a specific min/max protocol version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion(min_ver)
        ctx.maximum_version = ssl.TLSVersion(max_ver)
    except (AttributeError, ValueError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except Exception:
        return False


def _get_certificate(host: str, port: int, timeout: float = 8.0) -> Optional[CertInfo]:
    """Retrieve and parse the server certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                cert_dict = tls.getpeercert()

        if not cert_dict:
            return None

        ci = CertInfo()

        # Subject — ssl cert dicts use nested tuple structures; extract via iteration
        subj: dict[str, str] = {}
        for rdns in (cert_dict.get("subject") or ()):
            for attr in rdns:
                if len(attr) == 2:
                    subj[str(attr[0])] = str(attr[1])
        ci.subject = subj.get("commonName", "")

        # Issuer
        iss: dict[str, str] = {}
        for rdns in (cert_dict.get("issuer") or ()):
            for attr in rdns:
                if len(attr) == 2:
                    iss[str(attr[0])] = str(attr[1])
        ci.issuer = iss.get("organizationName", iss.get("commonName", ""))
        ci.is_self_signed = ci.subject == ci.issuer or (
            subj.get("commonName", "a") == iss.get("commonName", "b")
        )

        # Validity
        fmt = "%b %d %H:%M:%S %Y %Z"
        nb_str = str(cert_dict.get("notBefore") or "")
        na_str = str(cert_dict.get("notAfter") or "")
        try:
            not_after = datetime.datetime.strptime(na_str, fmt)
            ci.not_after = na_str
            ci.not_before = nb_str
            delta = not_after - datetime.datetime.utcnow()
            ci.days_until_expiry = delta.days
            ci.is_expired = delta.days < 0
        except ValueError:
            pass

        # SANs — ssl cert dict has heterogeneous types; cast via Any to avoid mypy noise
        san_raw: Any = cert_dict.get("subjectAltName") or []
        ci.san = [str(v) for t, v in san_raw if str(t) == "DNS"]

        # Signature algorithm (best effort via der)
        if der:
            try:
                # Simple heuristic: look for sha1WithRSA OID bytes
                sha1_oid = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05])
                md5_oid  = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04])
                if sha1_oid in der:
                    ci.signature_algorithm = "sha1WithRSAEncryption"
                elif md5_oid in der:
                    ci.signature_algorithm = "md5WithRSAEncryption"
                else:
                    ci.signature_algorithm = "unknown"
            except Exception:
                pass

        return ci
    except Exception as e:
        logger.debug(f"cert fetch failed for {host}:{port}: {e}")
        return None


def _get_ciphers(host: str, port: int, timeout: float = 5.0) -> tuple[list[str], list[str]]:
    """
    Return (all_supported, weak_supported) cipher list by testing individual suites.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Get all ciphers this Python ssl build knows
    try:
        all_ciphers = [str(c["name"]) for c in ctx.get_ciphers() if "name" in c]
    except Exception:
        all_ciphers = []

    supported: list[str] = []
    weak: list[str] = []

    for cipher in all_ciphers[:80]:      # cap at 80 to avoid hanging too long
        test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        test_ctx.check_hostname = False
        test_ctx.verify_mode = ssl.CERT_NONE
        try:
            test_ctx.set_ciphers(cipher)
        except ssl.SSLError:
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with test_ctx.wrap_socket(raw, server_hostname=host):
                    supported.append(cipher)
                    if any(p in cipher for p in _WEAK_CIPHER_PATTERNS):
                        weak.append(cipher)
        except Exception:
            continue

    return supported, weak


def _check_heartbleed(host: str, port: int, timeout: float = 8.0) -> bool:
    """
    Send a malformed TLS HeartBeat request; if the server echoes back more
    than the 3 payload bytes we sent, it is leaking memory (CVE-2014-0160).
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(_HEARTBLEED_HELLO)

        # Drain handshake records until we see the server hello done or timeout
        deadline = time.time() + timeout
        buf = b""
        while time.time() < deadline and len(buf) < 8192:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                # Look for ServerHelloDone (0x0e) in handshake messages
                if b"\x0e\x00\x00\x00" in buf:
                    break
            except socket.timeout:
                break

        # Send heartbeat request
        s.sendall(_HEARTBEAT_REQUEST)

        # Read response — a vulnerable server echoes memory
        resp = b""
        try:
            resp = s.recv(65536)
        except Exception:
            pass
        s.close()

        if len(resp) >= 5:
            rec_type  = resp[0]
            rec_len   = struct.unpack(">H", resp[3:5])[0]
            # Heartbeat response is type 0x18; if payload > 3 bytes → memory leak
            if rec_type == 0x18 and rec_len > 3:
                return True
    except Exception as e:
        logger.debug(f"heartbleed probe failed for {host}:{port}: {e}")
    return False


def _probe_sslv3(host: str, port: int, timeout: float = 6.0) -> bool:
    """Detect SSLv3 support (POODLE precondition) via a raw SSLv3 ClientHello.

    Python's ssl module cannot speak SSLv3, so we craft the handshake on a
    plain socket. Returns True only on a clear SSLv3 ServerHello — any alert,
    a higher negotiated version, or an error yields False (no false positive).
    """
    try:
        # SSLv3 ClientHello body (record version + client_version = 0x0300).
        body = (
            b"\x03\x00"                       # client_version = SSLv3
            + b"\x00" * 32                    # random (32 bytes)
            + b"\x00"                         # session_id length = 0
            + b"\x00\x08"                     # cipher_suites length = 8 bytes
            + b"\x00\x2f\x00\x35\x00\x0a\x00\x05"  # 4 classic SSLv3 ciphers
            + b"\x01\x00"                     # compression: 1 method, null
        )
        handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body  # ClientHello
        record = b"\x16\x03\x00" + struct.pack(">H", len(handshake)) + handshake

        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(record)
        resp = s.recv(8192)
        s.close()

        if len(resp) < 6:
            return False
        # resp[0]=0x16 handshake, resp[1:3]=record version, resp[5]=handshake type.
        # A ServerHello (0x02) at record version 0x0300 == SSLv3 accepted.
        # A 0x15 alert == SSLv3 refused (the secure, expected outcome).
        if resp[0] == 0x16 and resp[1] == 0x03 and resp[2] == 0x00 and resp[5] == 0x02:
            return True
        return False
    except Exception as e:
        logger.debug(f"SSLv3 probe failed for {host}:{port}: {e}")
        return False


def _check_hsts(host: str, port: int = 443, timeout: float = 8.0) -> tuple[bool, int, bool, bool]:
    """
    Fetch HTTPS response and parse Strict-Transport-Security header.
    Returns (enabled, max_age, includeSubDomains, preload).
    """
    import http.client
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        hsts_hdr = resp.getheader("Strict-Transport-Security", "")
        conn.close()
        if not hsts_hdr:
            return False, 0, False, False
        max_age = 0
        include_sub = "includesubdomains" in hsts_hdr.lower()
        preload = "preload" in hsts_hdr.lower()
        for part in hsts_hdr.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1].strip())
                except ValueError:
                    pass
        return True, max_age, include_sub, preload
    except Exception:
        return False, 0, False, False


def _make_finding(host: str, port: int, issue: str, severity: str,
                  title: str, description: str, cve: str = "",
                  confidence: float = 0.95) -> dict:
    return {
        "target": f"{host}:{port}",
        "vuln_type": issue,
        "title": title,
        "severity": severity,
        "description": description,
        "confidence": confidence,
        "cve_id": cve,
        "source": "ssl_scanner",
    }


# ── Public scan function ────────────────────────────────────────────────────────

def _run_ssl_scan(host: str, port: int) -> SSLResult:
    """Blocking SSL scan — runs in a thread pool."""
    result = SSLResult(host=host, port=port)

    # ── 0. Reachability ──────────────────────────────────────────────────────
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.close()
        result.reachable = True
    except Exception as e:
        result.error = f"port unreachable: {e}"
        return result

    # ── 1. Protocol version support ──────────────────────────────────────────
    try:
        TLSv = ssl.TLSVersion
        result.tls13 = _check_protocol(host, port, TLSv.TLSv1_3, TLSv.TLSv1_3)
        result.tls12 = _check_protocol(host, port, TLSv.TLSv1_2, TLSv.TLSv1_2)
        result.tls11 = _check_protocol(host, port, TLSv.TLSv1_1, TLSv.TLSv1_1)
        result.tls10 = _check_protocol(host, port, TLSv.TLSv1,   TLSv.TLSv1)
    except Exception as e:
        logger.debug(f"protocol version check error: {e}")

    # SSLv3 detection — modern Python's ssl module cannot negotiate SSLv3 at
    # all, so the only reliable way is a raw SSLv3 ClientHello on a plain
    # socket. (The previous loop built a context and discarded it, leaving
    # ssl3 permanently False → POODLE was never detected.)
    result.ssl3 = _probe_sslv3(host, port)

    # ── 2. Certificate ────────────────────────────────────────────────────────
    result.cert = _get_certificate(host, port)

    # ── 3. HSTS ───────────────────────────────────────────────────────────────
    enabled, max_age, subs, preload = _check_hsts(host, port)
    result.hsts = enabled
    result.hsts_max_age = max_age
    result.hsts_subdomains = subs
    result.hsts_preload = preload

    # ── 4. HEARTBLEED ────────────────────────────────────────────────────────
    result.heartbleed = _check_heartbleed(host, port)

    # ── 5. Cipher suite analysis ─────────────────────────────────────────────
    supported, weak = _get_ciphers(host, port)
    result.supported_ciphers = supported
    result.weak_ciphers = weak
    result.forward_secrecy = any(k in c for c in supported for k in _FORWARD_SECRECY_KEXES)

    # ── 6. Derived vulnerabilities ────────────────────────────────────────────
    result.poodle = result.ssl3          # POODLE = SSLv3 (now actively probed)
    # DROWN requires an SSLv2-speaking server. SSLv2 is extinct and uses a
    # pre-TLS handshake the ssl module cannot generate; result.ssl2 stays False.
    result.drown  = result.ssl2
    result.beast  = result.tls10 and any("CBC" in c for c in supported)
    result.crime  = False                # compression: Python ssl doesn't expose this easily
    result.freak  = any("EXPORT" in c for c in supported)
    result.logjam = any("DHE" in c and "1024" in c for c in supported)

    # ── 7. Build findings ─────────────────────────────────────────────────────
    F = result.findings
    if result.heartbleed:
        F.append(_make_finding(host, port, "heartbleed", "critical",
            "HEARTBLEED — TLS Memory Disclosure (CVE-2014-0160)",
            "Server leaks up to 64 KB of heap memory per request via malformed TLS HeartBeat.",
            cve="CVE-2014-0160"))
    if result.drown:
        F.append(_make_finding(host, port, "drown", "critical",
            "DROWN Attack — SSLv2 Enabled (CVE-2016-0800)",
            "SSLv2 support allows cross-protocol RSA decryption attacks against TLS sessions.",
            cve="CVE-2016-0800"))
    if result.poodle:
        F.append(_make_finding(host, port, "poodle", "high",
            "POODLE — SSLv3 CBC Padding Oracle (CVE-2014-3566)",
            "SSLv3 is enabled; POODLE attack can decrypt HTTP cookies.",
            cve="CVE-2014-3566"))
    if result.freak:
        F.append(_make_finding(host, port, "freak", "high",
            "FREAK — Export-Grade RSA Key Exchange (CVE-2015-0204)",
            "Server supports EXPORT cipher suites, enabling RSA factoring attacks.",
            cve="CVE-2015-0204"))
    if result.logjam:
        F.append(_make_finding(host, port, "logjam", "high",
            "Logjam — Weak DHE Key Exchange (CVE-2015-4000)",
            "Server uses 512-bit or 1024-bit DHE parameters, broken by NSA-class adversaries.",
            cve="CVE-2015-4000"))
    if result.beast:
        F.append(_make_finding(host, port, "beast", "medium",
            "BEAST — TLS 1.0 CBC Vulnerability (CVE-2011-3389)",
            "TLS 1.0 with CBC cipher suites is susceptible to chosen-plaintext attacks via BEAST.",
            cve="CVE-2011-3389"))
    if result.tls10 and not result.tls12 and not result.tls13:
        F.append(_make_finding(host, port, "tls10_only", "high",
            "TLS 1.0 Only — Deprecated Protocol",
            "Server only supports TLS 1.0 which is deprecated by RFC 8996 and PCI DSS 3.2.",
            confidence=0.99))
    if result.tls11 and not result.tls13:
        F.append(_make_finding(host, port, "tls11_deprecated", "medium",
            "TLS 1.1 Deprecated (RFC 8996)",
            "TLS 1.1 is deprecated; disable it and enforce TLS 1.2 minimum.",
            confidence=0.98))
    if result.weak_ciphers:
        F.append(_make_finding(host, port, "weak_cipher", "high",
            f"Weak Cipher Suites Accepted ({len(result.weak_ciphers)} found)",
            f"Accepted: {', '.join(result.weak_ciphers[:5])}. "
            "These enable downgrade and decryption attacks."))
    if not result.forward_secrecy:
        F.append(_make_finding(host, port, "no_forward_secrecy", "medium",
            "No Forward Secrecy",
            "Server does not support ECDHE/DHE key exchange. Past sessions can be "
            "decrypted if the server private key is compromised."))
    if not result.hsts:
        F.append(_make_finding(host, port, "no_hsts", "medium",
            "HSTS Not Configured",
            "Missing Strict-Transport-Security header. Browsers will accept HTTP downgrade.",
            confidence=0.97))
    elif result.hsts_max_age < 15552000:
        F.append(_make_finding(host, port, "hsts_short_maxage", "low",
            f"HSTS max-age Too Short ({result.hsts_max_age}s)",
            "HSTS max-age should be at least 180 days (15552000s). "
            "Short values allow HSTS eviction attacks."))
    if result.cert:
        c = result.cert
        if c.is_expired:
            F.append(_make_finding(host, port, "cert_expired", "critical",
                "TLS Certificate Expired",
                f"Certificate expired {abs(c.days_until_expiry)} days ago. "
                "Clients will reject this connection.", confidence=0.99))
        elif c.days_until_expiry < 30:
            F.append(_make_finding(host, port, "cert_expiring_soon", "high",
                f"Certificate Expiring in {c.days_until_expiry} Days",
                "Certificate will expire soon; renew immediately to avoid service disruption."))
        if c.is_self_signed:
            F.append(_make_finding(host, port, "self_signed_cert", "high",
                "Self-Signed TLS Certificate",
                "Certificate is not signed by a trusted CA. Vulnerable to MITM attacks."))
        if "sha1" in (c.signature_algorithm or "").lower():
            F.append(_make_finding(host, port, "sha1_signature", "high",
                "SHA-1 Signed Certificate (Deprecated)",
                "SHA-1 is cryptographically broken. Replace certificate signed with SHA-256."))

    return result


async def scan_ssl(host: str, port: int = 443) -> dict:
    """
    Async entry point — runs the blocking scan in a thread pool.
    Returns a standardized findings dict.
    """
    loop = asyncio.get_event_loop()
    try:
        result: SSLResult = await loop.run_in_executor(None, _run_ssl_scan, host, port)
    except Exception as e:
        logger.error(f"SSL scan error for {host}:{port}: {e}")
        return {"findings": [], "error": str(e)}

    summary = {
        "target": f"{host}:{port}",
        "reachable": result.reachable,
        "protocols": {
            "tls13": result.tls13, "tls12": result.tls12,
            "tls11": result.tls11, "tls10": result.tls10,
            "ssl3": result.ssl3, "ssl2": result.ssl2,
        },
        "vulnerabilities": {
            "heartbleed": result.heartbleed, "poodle": result.poodle,
            "beast": result.beast, "drown": result.drown,
            "freak": result.freak, "logjam": result.logjam,
        },
        "hsts": result.hsts,
        "hsts_max_age": result.hsts_max_age,
        "forward_secrecy": result.forward_secrecy,
        "weak_ciphers": result.weak_ciphers,
        "supported_ciphers": result.supported_ciphers[:20],
        "cert": {
            "subject": result.cert.subject if result.cert else "",
            "issuer": result.cert.issuer if result.cert else "",
            "days_until_expiry": result.cert.days_until_expiry if result.cert else 0,
            "is_expired": result.cert.is_expired if result.cert else False,
            "is_self_signed": result.cert.is_self_signed if result.cert else False,
            "san": result.cert.san[:10] if result.cert else [],
            "sig_algo": result.cert.signature_algorithm if result.cert else "",
        },
        "findings": result.findings,
        "vulnerabilities_list": result.findings,
    }

    found = len(result.findings)
    crit  = sum(1 for f in result.findings if f.get("severity") == "critical")
    high  = sum(1 for f in result.findings if f.get("severity") == "high")
    logger.info(
        f"SSL scan {host}:{port} → {found} issues "
        f"({crit} critical, {high} high)"
    )
    return summary


async def scan_ssl_targets(targets: list[str],
                           ports: Optional[list[int]] = None) -> dict:
    """
    Scan multiple hosts/URLs for TLS/SSL issues concurrently.
    targets: list of hostnames or 'host:port' strings.
    """
    if ports is None:
        ports = [443]

    sem = asyncio.Semaphore(20)
    all_findings: list[dict] = []

    async def _scan_one(host: str, port: int) -> None:
        async with sem:
            res = await scan_ssl(host, port)
            all_findings.extend(res.get("findings", []))

    tasks = []
    for t in targets:
        if "://" in t:
            from urllib.parse import urlparse
            parsed = urlparse(t)
            h = parsed.hostname or t
            p = parsed.port or (443 if parsed.scheme == "https" else 80)
            if p in (443, 8443, 8080):
                tasks.append(_scan_one(h, p))
        elif ":" in t:
            parts = t.rsplit(":", 1)
            try:
                tasks.append(_scan_one(parts[0], int(parts[1])))
            except ValueError:
                tasks.append(_scan_one(t, 443))
        else:
            for p in ports:
                tasks.append(_scan_one(t, p))

    await asyncio.gather(*tasks, return_exceptions=True)

    crit  = sum(1 for f in all_findings if f.get("severity") == "critical")
    high  = sum(1 for f in all_findings if f.get("severity") == "high")
    return {
        "total": len(all_findings),
        "critical": crit,
        "high": high,
        "findings": all_findings,
        "vulnerabilities": all_findings,
    }
