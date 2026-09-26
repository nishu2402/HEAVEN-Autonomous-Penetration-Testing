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
# 64-bit block ciphers whose birthday bound makes long TLS sessions decryptable
# (SWEET32, CVE-2016-2183). 3DES is the one still commonly negotiated; IDEA is
# the other classic case. RC2/DES are 64-bit too but already caught as broken.
_SWEET32_TOKENS = ("3DES", "DES-CBC3", "IDEA")

# ── Legacy SHA-1 signature schemes (TLS 1.2 SignatureAndHashAlgorithm, RFC 5246
# §7.4.1.4.1) ────────────────────────────────────────────────────────────────
# A current server must never sign its key exchange with SHA-1. Offering ONLY
# these in a ClientHello's signature_algorithms extension is the sslyze / testssl
# technique for proving a server still accepts SHA-1 signatures in TLS 1.2.
_SIGALG_ECDSA_SHA1 = b"\x02\x03"   # hash=sha1(2), sig=ecdsa(3)  → ecdsa_sha1
_SIGALG_RSA_SHA1   = b"\x02\x01"   # hash=sha1(2), sig=rsa(1)    → rsa_pkcs1_sha1
_SIGALG_DSA_SHA1   = b"\x02\x02"   # hash=sha1(2), sig=dsa(2)    → dsa_sha1
# Ephemeral (signed-KEX) suites only, so signature_algorithms genuinely gates the
# handshake. Static-RSA suites (TLS_RSA_WITH_*) carry no signed ServerKeyExchange
# and would complete regardless — including them would create a false positive.
# A mix of ECDSA-auth and RSA-auth suites lets either server cert type negotiate;
# the negotiated suite then tells us which SHA-1 scheme the server actually used.
_SIGALG_TEST_SUITES = [
    0xC02B, 0xC02C,          # ECDHE-ECDSA AES-GCM
    0xC02F, 0xC030,          # ECDHE-RSA  AES-GCM
    0xC023, 0xC024,          # ECDHE-ECDSA AES-CBC-SHA256/384
    0xC027, 0xC028,          # ECDHE-RSA  AES-CBC-SHA256/384
    0xC009, 0xC00A,          # ECDHE-ECDSA AES-CBC-SHA
    0xC013, 0xC014,          # ECDHE-RSA  AES-CBC-SHA
    0x009E, 0x009F,          # DHE-RSA    AES-GCM
    0x0033, 0x0039,          # DHE-RSA    AES-CBC-SHA
]
# Suites whose ServerKeyExchange is an ECDHE named-curve block (curve_type +
# named_curve + pubkey) vs. a DHE block (p, g, Ys). We must know which to locate
# the SignatureAndHashAlgorithm that the server actually signed with.
_ECDHE_SUITES_ALL = {0xC02B, 0xC02C, 0xC02F, 0xC030, 0xC023, 0xC024,
                     0xC027, 0xC028, 0xC009, 0xC00A, 0xC013, 0xC014}
_DHE_SUITES_ALL = {0x009E, 0x009F, 0x0033, 0x0039}
# TLS 1.2 SignatureAndHashAlgorithm codepoints (hash byte, then sig byte).
_TLS_HASH_SHA1 = 0x02
_TLS_SIG_NAME = {1: "rsa_pkcs1_sha1", 2: "dsa_sha1", 3: "ecdsa_sha1"}

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
    dh_bits: int = 0           # measured ephemeral DH prime size (0 = no DHE)
    freak: bool = False        # EXPORT cipher support
    sweet32: bool = False       # 64-bit block cipher (3DES/IDEA) = SWEET32
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
    legacy_sigalg: str = ""     # SHA-1 sig scheme accepted in TLS 1.2 ("" = none)
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
    """Retrieve and parse the server certificate.

    CRITICAL: the socket is wrapped with ``verify_mode = CERT_NONE`` (we must be
    able to read a self-signed / expired cert without the handshake failing), and
    under CERT_NONE Python's ``getpeercert()`` returns an EMPTY dict — only
    ``getpeercert(binary_form=True)`` yields the DER. So the certificate is parsed
    from the DER with ``cryptography``; the parsed-dict path is a fallback only.
    Parsing the dict was the previous behaviour, and because it is always empty
    here it silently produced NO certificate findings at all (expired,
    self-signed, weak signature, weak key). This reads them straight from the DER.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                cert_dict = tls.getpeercert()
    except Exception as e:
        logger.debug(f"cert fetch failed for {host}:{port}: {e}")
        return None

    # Primary path: parse the DER with cryptography (works under CERT_NONE).
    if der:
        ci = _parse_cert_der(der)
        if ci is not None:
            return ci
    # Fallback: the validated-dict path (only non-empty when verification is on).
    if cert_dict:
        return _cert_from_dict(cert_dict)
    return None


def _parse_cert_der(der: bytes) -> Optional[CertInfo]:
    """Parse a DER certificate into a CertInfo using the cryptography library.

    Reads subject/issuer, validity (→ expiry), SANs, self-signed status, the
    public-key type/size and the signature hash — everything the finding block
    needs. Returns None if cryptography is unavailable or the DER won't parse
    (caller then falls back to the parsed-dict path)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
        from cryptography.x509.oid import NameOID
    except Exception:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    ci = CertInfo()

    def _cn(name) -> str:  # noqa: ANN001 - x509.Name
        try:
            attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return str(attrs[0].value) if attrs else ""
        except Exception:
            return ""

    def _org(name) -> str:  # noqa: ANN001
        try:
            attrs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            return str(attrs[0].value) if attrs else ""
        except Exception:
            return ""

    ci.subject = _cn(cert.subject)
    ci.issuer = _org(cert.issuer) or _cn(cert.issuer)
    # A cert whose issuer DN equals its subject DN is self-issued (self-signed in
    # the common case). Comparing the full Name is more reliable than CN-only.
    try:
        ci.is_self_signed = cert.subject == cert.issuer
    except Exception:
        ci.is_self_signed = bool(ci.subject) and ci.subject == _cn(cert.issuer)

    # Validity → days until expiry. Prefer the tz-aware *_utc accessors
    # (cryptography >= 42); fall back to the naive (UTC) ones on older versions.
    try:
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na_naive = na.replace(tzinfo=None) if na.tzinfo else na
        nb_naive = nb.replace(tzinfo=None) if nb.tzinfo else nb
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        ci.not_after = na_naive.strftime("%Y-%m-%d %H:%M:%S")
        ci.not_before = nb_naive.strftime("%Y-%m-%d %H:%M:%S")
        ci.days_until_expiry = (na_naive - now).days
        ci.is_expired = ci.days_until_expiry < 0
    except Exception:
        logger.debug("cert validity parse failed", exc_info=True)

    # SAN DNS names.
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        ci.san = list(san_ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        ci.san = []

    # Public key type/size.
    try:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            ci.key_type, ci.key_bits = "RSA", pub.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            ci.key_type, ci.key_bits = "DSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            ci.key_type, ci.key_bits = f"EC ({pub.curve.name})", pub.key_size
        else:
            ci.key_type = type(pub).__name__.replace("PublicKey", "")
    except Exception:
        logger.debug("cert public-key parse failed", exc_info=True)

    # Signature hash ("sha1" / "md5" / "sha256" / ...).
    try:
        ci.signature_algorithm = (cert.signature_hash_algorithm.name
                                  if cert.signature_hash_algorithm else "")
    except Exception:
        ci.signature_algorithm = ""
    return ci


def _cert_from_dict(cert_dict: dict) -> CertInfo:
    """Legacy fallback: build a CertInfo from ssl.getpeercert()'s parsed dict
    (only non-empty when the handshake was verified). Does not expose key size."""
    ci = CertInfo()
    subj: dict[str, str] = {}
    for rdns in (cert_dict.get("subject") or ()):
        for attr in rdns:
            if len(attr) == 2:
                subj[str(attr[0])] = str(attr[1])
    ci.subject = subj.get("commonName", "")
    iss: dict[str, str] = {}
    for rdns in (cert_dict.get("issuer") or ()):
        for attr in rdns:
            if len(attr) == 2:
                iss[str(attr[0])] = str(attr[1])
    ci.issuer = iss.get("organizationName", iss.get("commonName", ""))
    ci.is_self_signed = ci.subject == ci.issuer or (
        subj.get("commonName", "a") == iss.get("commonName", "b"))
    fmt = "%b %d %H:%M:%S %Y %Z"
    na_str = str(cert_dict.get("notAfter") or "")
    try:
        not_after = datetime.datetime.strptime(na_str, fmt)
        ci.not_after = na_str
        ci.not_before = str(cert_dict.get("notBefore") or "")
        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        ci.days_until_expiry = (not_after - now_utc).days
        ci.is_expired = ci.days_until_expiry < 0
    except ValueError:
        pass
    san_raw: Any = cert_dict.get("subjectAltName") or []
    ci.san = [str(v) for t, v in san_raw if str(t) == "DNS"]
    return ci


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
            logger.debug("suppressed non-fatal exception", exc_info=True)
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
            logger.debug("suppressed non-fatal exception", exc_info=True)
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


def _looks_like_ip(host: str) -> bool:
    """True if host is a literal IPv4/IPv6 address (so we skip SNI for it)."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _tls12_sigalg_probe_bytes(host: str) -> bytes:
    """Build a TLS 1.2 ClientHello that offers ONLY SHA-1 signature schemes.

    The client_version is pinned to TLS 1.2 with no supported_versions extension,
    so the server negotiates <=1.2 and the classic TLS 1.2 signature_algorithms
    rules apply (TLS 1.3 forbids SHA-1 outright, a different code path).
    """
    import os as _os

    # signature_algorithms (ext 0x000d): 2-byte list length + 2-byte-code entries.
    sigalgs = _SIGALG_ECDSA_SHA1 + _SIGALG_RSA_SHA1 + _SIGALG_DSA_SHA1
    ext_sigalg = (b"\x00\x0d"
                  + struct.pack(">H", len(sigalgs) + 2)
                  + struct.pack(">H", len(sigalgs)) + sigalgs)
    # supported_groups (ext 0x000a): secp256r1, secp384r1, x25519.
    groups = b"\x00\x17\x00\x18\x00\x1d"
    ext_groups = (b"\x00\x0a"
                  + struct.pack(">H", len(groups) + 2)
                  + struct.pack(">H", len(groups)) + groups)
    # ec_point_formats (ext 0x000b): uncompressed.
    ext_ecpf = b"\x00\x0b\x00\x02\x01\x00"
    # server_name (ext 0x0000) so name-based virtual hosts respond (skip for IPs).
    ext_sni = b""
    if host and not _looks_like_ip(host):
        try:
            sni = host.encode("idna")
        except Exception:
            sni = host.encode("ascii", "ignore")
        if sni:
            server_name = b"\x00" + struct.pack(">H", len(sni)) + sni
            sni_list = struct.pack(">H", len(server_name)) + server_name
            ext_sni = b"\x00\x00" + struct.pack(">H", len(sni_list)) + sni_list

    extensions = ext_sni + ext_groups + ext_ecpf + ext_sigalg
    ext_block = struct.pack(">H", len(extensions)) + extensions

    suites = b"".join(struct.pack(">H", s) for s in _SIGALG_TEST_SUITES)
    body = (
        b"\x03\x03"                                   # client_version = TLS 1.2
        + _os.urandom(32)                             # random
        + b"\x00"                                     # session_id length = 0
        + struct.pack(">H", len(suites)) + suites     # cipher_suites
        + b"\x01\x00"                                 # compression: 1 method, null
        + ext_block
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body   # ClientHello
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def _split_handshake(hs: bytes) -> list[tuple[int, bytes]]:
    """Split a reassembled handshake byte stream into (msg_type, body) pairs.

    Stops cleanly at any incomplete trailing message (partial flight)."""
    out: list[tuple[int, bytes]] = []
    i = 0
    while i + 4 <= len(hs):
        mtype = hs[i]
        mlen = struct.unpack(">I", b"\x00" + hs[i + 1:i + 4])[0]
        if i + 4 + mlen > len(hs):
            break
        out.append((mtype, hs[i + 4:i + 4 + mlen]))
        i += 4 + mlen
    return out


def _ske_signature_scheme(ske_body: bytes, suite: int) -> Optional[tuple[int, int]]:
    """Return the (hash, sig) SignatureAndHashAlgorithm the server signed the
    ServerKeyExchange with, or None. The KEX params come first and differ by
    suite family (ECDHE named-curve vs DHE), so we skip exactly past them."""
    try:
        if suite in _ECDHE_SUITES_ALL:
            if not ske_body or ske_body[0] != 0x03:   # 0x03 = named_curve
                return None
            pk_len = ske_body[3]                        # curve_type(1)+curve(2)+len(1)
            off = 4 + pk_len
        elif suite in _DHE_SUITES_ALL:
            off = 0
            for _ in range(3):                          # dh_p, dh_g, dh_Ys
                ln = struct.unpack(">H", ske_body[off:off + 2])[0]
                off += 2 + ln
        else:
            return None
        if off + 2 > len(ske_body):
            return None
        return ske_body[off], ske_body[off + 1]         # hash, sig
    except Exception:
        return None


def _recv_handshake_flight(sock: "socket.socket",
                           timeout: float) -> tuple[bytes, bool]:
    """Read a TLS server flight off an open socket and return (handshake_stream,
    got_alert). Reassembles TLS records into the handshake byte stream (records
    may fragment a handshake message, and one record may carry several), stopping
    at ServerHelloDone (0x0e) or an alert. Shared by the sigalg and DH probes."""
    raw = b""
    hs = b""
    got_alert = False
    deadline = time.time() + timeout
    try:
        while time.time() < deadline and len(raw) < 65536:
            try:
                chunk = sock.recv(8192)
            except Exception:
                break
            if not chunk:
                break
            raw += chunk
            hs, i = b"", 0
            while i + 5 <= len(raw):
                ctype = raw[i]
                rlen = struct.unpack(">H", raw[i + 3:i + 5])[0]
                if i + 5 + rlen > len(raw):
                    break                                  # incomplete record
                payload = raw[i + 5:i + 5 + rlen]
                if ctype == 0x15:                          # alert → server refused
                    got_alert = True
                elif ctype == 0x16:                        # handshake
                    hs += payload
                i += 5 + rlen
            msgs = _split_handshake(hs)
            if got_alert or any(t == 0x0e for t, _ in msgs):
                break
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return hs, got_alert


def _dhe_probe_bytes(host: str) -> bytes:
    """Build a TLS 1.2 ClientHello offering ONLY DHE_RSA suites with modern
    signature_algorithms, so the server completes an ephemeral DH handshake whose
    ServerKeyExchange carries the DH prime (whose bit length we then read)."""
    import os as _os
    # Modern sig algs (SHA-256/384/512, RSA-PSS) so the server signs the SKE.
    sigalgs = (b"\x04\x01\x05\x01\x06\x01\x04\x03\x05\x03\x06\x03"
               b"\x08\x04\x08\x05\x08\x06")
    ext_sigalg = (b"\x00\x0d" + struct.pack(">H", len(sigalgs) + 2)
                  + struct.pack(">H", len(sigalgs)) + sigalgs)
    ext_sni = b""
    if host and not _looks_like_ip(host):
        try:
            sni = host.encode("idna")
        except Exception:
            sni = host.encode("ascii", "ignore")
        if sni:
            server_name = b"\x00" + struct.pack(">H", len(sni)) + sni
            sni_list = struct.pack(">H", len(server_name)) + server_name
            ext_sni = b"\x00\x00" + struct.pack(">H", len(sni_list)) + sni_list
    extensions = ext_sni + ext_sigalg
    ext_block = struct.pack(">H", len(extensions)) + extensions
    suites = b"".join(struct.pack(">H", s) for s in sorted(_DHE_SUITES_ALL))
    body = (b"\x03\x03" + _os.urandom(32) + b"\x00"
            + struct.pack(">H", len(suites)) + suites + b"\x01\x00" + ext_block)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def _check_dh_params(host: str, port: int, timeout: float = 6.0) -> int:
    """Return the server's ephemeral DH prime size in BITS, or 0 if the server
    does not negotiate a classic DHE suite (so nothing to measure). Reads the
    prime straight from the ServerKeyExchange, exactly as sslyze/testssl do, so a
    weak-DH finding is objective and false-positive-free."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(_dhe_probe_bytes(host))
    except Exception as e:
        logger.debug("DH-param probe failed for %s:%s: %s", host, port, e)
        return 0
    hs, got_alert = _recv_handshake_flight(s, timeout)
    if got_alert:
        return 0
    msgs = _split_handshake(hs)
    sh = next((b for t, b in msgs if t == 0x02), None)     # ServerHello
    ske = next((b for t, b in msgs if t == 0x0c), None)    # ServerKeyExchange
    if sh is None or ske is None:
        return 0
    if len(sh) < 38 or sh[0:2] != b"\x03\x03":             # negotiated must be 1.2
        return 0
    sid_len = sh[34]
    ci = 35 + sid_len
    if ci + 2 > len(sh):
        return 0
    suite = struct.unpack(">H", sh[ci:ci + 2])[0]
    if suite not in _DHE_SUITES_ALL:                       # server didn't pick DHE
        return 0
    # DHE ServerKeyExchange begins with dh_p: uint16 length + big-endian prime.
    if len(ske) < 2:
        return 0
    p_len = struct.unpack(">H", ske[0:2])[0]
    if p_len <= 0 or 2 + p_len > len(ske):
        return 0
    return int.from_bytes(ske[2:2 + p_len], "big").bit_length()


def _check_legacy_sigalgs(host: str, port: int, timeout: float = 6.0) -> str:
    """Detect whether the server *actually signs* with SHA-1 in TLS 1.2.

    Sends a ClientHello whose signature_algorithms extension offers ONLY legacy
    SHA-1 schemes with ephemeral (signed-KEX) cipher suites, reads the whole
    server handshake flight, and parses the ServerKeyExchange to read the exact
    SignatureAndHashAlgorithm the server used. A finding is returned ONLY when
    that hash is SHA-1 — a ServerHello alone is not enough, because many servers
    ignore a restrictive list at ServerHello time and then sign with their strong
    default (which is correct behaviour and must not be flagged). This mirrors the
    sslyze / testssl approach and is false-positive-free by construction.

    Returns "ecdsa_sha1" / "rsa_pkcs1_sha1" / "dsa_sha1", else "".
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(_tls12_sigalg_probe_bytes(host))
    except Exception as e:
        logger.debug("legacy-sigalg probe failed for %s:%s: %s", host, port, e)
        return ""

    hs, got_alert = _recv_handshake_flight(s, timeout)
    if got_alert:
        return ""
    msgs = _split_handshake(hs)
    sh = next((b for t, b in msgs if t == 0x02), None)     # ServerHello
    ske = next((b for t, b in msgs if t == 0x0c), None)    # ServerKeyExchange
    if sh is None or ske is None:
        return ""
    # ServerHello body: version(2) random(32) sid_len(1) sid cipher_suite(2) ...
    if len(sh) < 38 or sh[0:2] != b"\x03\x03":             # negotiated must be 1.2
        return ""
    sid_len = sh[34]
    cs_off = 35 + sid_len
    if cs_off + 2 > len(sh):
        return ""
    suite = struct.unpack(">H", sh[cs_off:cs_off + 2])[0]
    sh_alg = _ske_signature_scheme(ske, suite)
    if not sh_alg or sh_alg[0] != _TLS_HASH_SHA1:          # server did NOT use SHA-1
        return ""
    return _TLS_SIG_NAME.get(sh_alg[1], "rsa_pkcs1_sha1")


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
    # TLS 1.3 mandates ephemeral (EC)DHE for *every* cipher suite, so a 1.3-capable
    # server always has forward secrecy. But 1.3 suite names
    # (TLS_AES_256_GCM_SHA384, …) contain none of the KEX tokens below, and
    # set_ciphers() cannot even enumerate 1.3 suites — so a modern 1.3-only server
    # would otherwise be mis-flagged "no forward secrecy". Treat 1.3 as definitive.
    result.forward_secrecy = result.tls13 or any(
        k in c for c in supported for k in _FORWARD_SECRECY_KEXES)

    # ── 5b. Legacy signature algorithms (TLS 1.2 only) ────────────────────────
    # Only meaningful when the server actually speaks TLS 1.2; TLS 1.3 forbids
    # SHA-1 signatures by protocol, so there is nothing to test there.
    result.legacy_sigalg = _check_legacy_sigalgs(host, port) if result.tls12 else ""

    # ── 5c. Ephemeral DH parameter strength ───────────────────────────────────
    # Read the actual DH prime size off the ServerKeyExchange. The old heuristic
    # (`"1024" in cipher_name`) was never true — cipher names carry no key size —
    # so weak DH was silently missed. This is a RAW-socket DHE probe, so it must
    # NOT be gated on Python's protocol detection: a server that offers only weak
    # (1024-bit) DHE ciphers makes the local OpenSSL handshake fail (SECLEVEL),
    # which would otherwise hide the very weakness we want to find. The probe
    # self-gates — it returns 0 when the server does not negotiate a classic DHE
    # suite (e.g. a TLS 1.3-only or ECDHE-only server), so it is always safe to run.
    if result.reachable:
        result.dh_bits = _check_dh_params(host, port)

    # ── 6. Derived vulnerabilities ────────────────────────────────────────────
    result.poodle = result.ssl3          # POODLE = SSLv3 (now actively probed)
    # DROWN requires an SSLv2-speaking server. SSLv2 is extinct and uses a
    # pre-TLS handshake the ssl module cannot generate; result.ssl2 stays False.
    result.drown  = result.ssl2
    result.beast  = result.tls10 and any("CBC" in c for c in supported)
    result.crime  = False                # compression: Python ssl doesn't expose this easily
    result.freak  = any("EXPORT" in c for c in supported)
    # Logjam = a genuinely 1024-bit-or-smaller DH prime, measured on the wire.
    result.logjam = 0 < result.dh_bits <= 1024
    # SWEET32: a 64-bit block cipher (3DES/IDEA) accepted for a TLS ≤1.2 session.
    # TLS 1.3 dropped these suites entirely, so only the enumerable ≤1.2 set counts.
    result.sweet32 = any(
        tok in c.upper() for c in supported for tok in _SWEET32_TOKENS)

    # ── 7. Build findings ─────────────────────────────────────────────────────
    F = result.findings
    if result.heartbleed:
        F.append(_make_finding(host, port, "heartbleed", "critical",
            "HEARTBLEED: TLS Memory Disclosure (CVE-2014-0160)",
            "Server leaks up to 64 KB of heap memory per request via malformed TLS HeartBeat.",
            cve="CVE-2014-0160"))
    if result.drown:
        F.append(_make_finding(host, port, "drown", "critical",
            "DROWN Attack: SSLv2 Enabled (CVE-2016-0800)",
            "SSLv2 support allows cross-protocol RSA decryption attacks against TLS sessions.",
            cve="CVE-2016-0800"))
    if result.poodle:
        F.append(_make_finding(host, port, "poodle", "high",
            "POODLE: SSLv3 CBC Padding Oracle (CVE-2014-3566)",
            "SSLv3 is enabled; POODLE attack can decrypt HTTP cookies.",
            cve="CVE-2014-3566"))
    if result.freak:
        F.append(_make_finding(host, port, "freak", "high",
            "FREAK: Export-Grade RSA Key Exchange (CVE-2015-0204)",
            "Server supports EXPORT cipher suites, enabling RSA factoring attacks.",
            cve="CVE-2015-0204"))
    if result.logjam:
        F.append(_make_finding(host, port, "logjam", "high",
            "Logjam: Weak DHE Key Exchange (CVE-2015-4000)",
            f"The server negotiates a {result.dh_bits}-bit ephemeral DH group "
            "(<= 1024-bit), which is breakable by a well-resourced adversary "
            "(Logjam). Configure a 2048-bit (or larger) DH group, or prefer ECDHE.",
            cve="CVE-2015-4000"))
    elif 1024 < result.dh_bits < 2048:
        F.append(_make_finding(host, port, "weak_dh_params", "medium",
            f"Weak Diffie-Hellman Group ({result.dh_bits}-bit)",
            f"The server's ephemeral DH key exchange uses a {result.dh_bits}-bit "
            "prime, below the 2048-bit minimum recommended by NIST SP 800-57 and "
            "modern TLS guidance. Use a 2048-bit-or-larger DH group (e.g. the "
            "RFC 7919 ffdhe2048+ groups) or switch to ECDHE.", confidence=0.9))
    if result.beast:
        F.append(_make_finding(host, port, "beast", "medium",
            "BEAST: TLS 1.0 CBC Vulnerability (CVE-2011-3389)",
            "TLS 1.0 with CBC cipher suites is susceptible to chosen-plaintext attacks via BEAST.",
            cve="CVE-2011-3389"))
    if result.tls10 and not result.tls12 and not result.tls13:
        F.append(_make_finding(host, port, "tls10_only", "high",
            "TLS 1.0 Only: Deprecated Protocol",
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
    if result.sweet32:
        _s32 = [c for c in supported
                if any(t in c.upper() for t in _SWEET32_TOKENS)]
        F.append(_make_finding(host, port, "sweet32", "medium",
            "SWEET32-64-bit Block Cipher (3DES) Accepted (CVE-2016-2183)",
            "The server accepts a 64-bit block cipher (e.g. 3DES/IDEA). Its "
            "birthday bound lets an attacker who can observe a long-lived TLS "
            "session recover plaintext (e.g. a session cookie) after ~2^32 "
            f"blocks. Accepted: {', '.join(_s32[:5]) or '3DES'}. Disable 3DES "
            "and IDEA and offer only AEAD suites (AES-GCM / ChaCha20-Poly1305).",
            cve="CVE-2016-2183"))
    if result.legacy_sigalg:
        _pretty = {
            "ecdsa_sha1": "ECDSA with SHA-1 (ecdsa_sha1)",
            "rsa_pkcs1_sha1": "RSA PKCS#1 with SHA-1 (rsa_pkcs1_sha1)",
        }.get(result.legacy_sigalg, result.legacy_sigalg)
        F.append(_make_finding(host, port, "tls_sha1_signature_algorithm", "low",
            f"TLS 1.2 Accepts a SHA-1 Signature Algorithm ({_pretty})",
            "The server completed a TLS 1.2 handshake after being offered ONLY "
            "SHA-1 signature schemes in the signature_algorithms extension, so it "
            f"is willing to authenticate its key exchange with {_pretty}. SHA-1 is "
            "collision-broken (SHAttered, 2017); accepting it weakens the integrity "
            "of the handshake signature and fails modern TLS baselines (Mozilla "
            "Intermediate, NIST SP 800-52r2). Configure the server to offer only "
            "SHA-256+ signature schemes (e.g. rsa_pss_rsae_sha256, "
            "ecdsa_secp256r1_sha256) and drop rsa_pkcs1_sha1 / ecdsa_sha1.",
            confidence=0.95))
    # Only assert the *absence* of forward secrecy when we actually enumerated at
    # least one TLS ≤1.2 cipher. An empty list means enumeration failed (transient
    # handshake drops), so "no FS" then would be a false positive, not a finding.
    if not result.forward_secrecy and result.supported_ciphers:
        F.append(_make_finding(host, port, "no_forward_secrecy", "medium",
            "No Forward Secrecy",
            "Server does not support ECDHE/DHE key exchange. Past sessions can be "
            "decrypted if the server private key is compromised."))
    # HSTS is a TLS-only control, so only evaluate it when TLS actually works.
    # Otherwise the HSTS HEAD never reached an HTTPS listener (e.g. a plain-HTTP
    # port): "missing HSTS" would report a header we never got to observe, and
    # the max-age branch would fire "max-age too short (0s)" from the default
    # max_age=0 — both false positives. Gating the whole block on tls_ok fixes
    # both (previously only the no_hsts branch was gated).
    tls_ok = result.tls13 or result.tls12 or result.tls11 or result.tls10
    if tls_ok:
        if not result.hsts:
            F.append(_make_finding(host, port, "no_hsts", "medium",
                "HSTS Not Configured",
                "Missing Strict-Transport-Security header. Browsers will accept HTTP downgrade.",
                confidence=0.97))
        else:
            # HSTS is present — audit each directive independently. A deep TLS
            # auditor (sslyze / testssl / Qualys SSL Labs) reports every omission,
            # because each one leaves a distinct downgrade window open. The header
            # itself (already parsed in _check_hsts) is the evidence, so these are
            # deterministic and false-positive-free.
            if result.hsts_max_age < 15552000:
                F.append(_make_finding(host, port, "hsts_short_maxage", "low",
                    f"HSTS max-age Too Short ({result.hsts_max_age}s)",
                    "HSTS max-age should be at least 180 days (15552000s). "
                    "Short values allow HSTS eviction attacks.", confidence=0.9))
            if not result.hsts_subdomains:
                F.append(_make_finding(host, port, "hsts_no_include_subdomains", "low",
                    "HSTS Omits includeSubDomains",
                    "The Strict-Transport-Security header is present but omits the "
                    "includeSubDomains directive, so HSTS does not cover subdomains. "
                    "An attacker can serve plain HTTP on a subdomain (or a "
                    "man-in-the-middle can spoof one) to plant or steal a "
                    "domain-scoped session cookie, bypassing the protection the "
                    "apex domain enforces.", confidence=0.9))
            if not result.hsts_preload:
                F.append(_make_finding(host, port, "hsts_no_preload", "info",
                    "HSTS Not Preload-Eligible (preload directive absent)",
                    "The Strict-Transport-Security header omits the preload "
                    "directive, so the site cannot be added to the browsers' "
                    "built-in HSTS preload list. Until a client has made one "
                    "successful HTTPS visit it has no HSTS entry, leaving the very "
                    "first request open to an SSL-strip downgrade (trust-on-first-"
                    "use gap). Preload eligibility also requires includeSubDomains "
                    "and max-age >= 31536000 (1 year).", confidence=0.9))
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
        sig = (c.signature_algorithm or "").lower()
        # MD5 is worse than SHA-1 (practical collisions, RapidSSL/Flame) and used
        # to be missed here because the block only checked for "sha1".
        if "md5" in sig:
            F.append(_make_finding(host, port, "md5_signature", "high",
                "MD5-Signed TLS Certificate (Broken)",
                "The certificate is signed with MD5, which is collision-broken "
                "(Flame malware, forged-CA attacks). Reissue it with a SHA-256 "
                "(or stronger) signature immediately.", confidence=0.95))
        elif "sha1" in sig:
            F.append(_make_finding(host, port, "sha1_signature", "high",
                "SHA-1 Signed Certificate (Deprecated)",
                "SHA-1 is cryptographically broken. Replace certificate signed with SHA-256."))
        # Weak public key: RSA/DSA below 2048 bits is a standard testssl/sslyze
        # finding. EC keys below ~224 bits are similarly weak. Objective and
        # false-positive-free — the bit length is read straight from the cert.
        kt = (c.key_type or "").upper()
        if c.key_bits:
            weak_key = False
            if kt.startswith(("RSA", "DSA")) and c.key_bits < 2048:
                weak_key = True
            elif kt.startswith("EC") and c.key_bits < 224:
                weak_key = True
            if weak_key:
                sev = "critical" if c.key_bits <= 1024 else "high"
                F.append(_make_finding(host, port, "weak_cert_key", sev,
                    f"Weak TLS Certificate Key ({c.key_type} {c.key_bits}-bit)",
                    f"The certificate uses a {c.key_bits}-bit {c.key_type} public "
                    "key, below the 2048-bit RSA/DSA (or 224-bit EC) minimum "
                    "recommended by NIST SP 800-57 and the CA/Browser Forum. A key "
                    "this small is factorable by a capable adversary, allowing "
                    "decryption and impersonation. Reissue the certificate with a "
                    "2048-bit (or stronger) RSA key or a P-256+ EC key.",
                    confidence=0.95))

    return result


async def scan_ssl(host: str, port: int = 443) -> dict:
    """
    Async entry point — runs the blocking scan in a thread pool.
    Returns a standardized findings dict.
    """
    loop = asyncio.get_running_loop()
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
        "hsts_include_subdomains": result.hsts_subdomains,
        "hsts_preload": result.hsts_preload,
        "forward_secrecy": result.forward_secrecy,
        "dh_bits": result.dh_bits,
        "legacy_sigalg": result.legacy_sigalg,
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

    # Defensive dedup: a caller may pass the same host:port many times (e.g. one
    # per crawled URL sharing an origin). Re-scanning a port yields identical
    # results and only risks blowing the phase timeout, so collapse to the unique
    # target set while preserving order.
    targets = list(dict.fromkeys(targets))

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
