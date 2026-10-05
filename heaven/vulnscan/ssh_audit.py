"""
HEAVEN — SSH transport crypto auditor.

A credential-free audit of an SSH server's advertised cryptographic algorithms,
the same class of finding `ssh-audit` and commercial scanners report and the exact
gap behind missed findings like *"SFTP accepts ssh-dss and ssh-rsa (SHA-1)"*.

How it works (no third-party crypto, no authentication, read-only):

1. Read the server identification string ("SSH-2.0-OpenSSH_9.6", banner lines and
   an AWS Transfer "AWS_SFTP_..." tag included).
2. Read the first binary packet, which per RFC 4253 is the server's plaintext
   SSH_MSG_KEXINIT (sent before any keys are established, so it needs no crypto).
3. Parse the ten algorithm name-lists it carries and flag the weak members:
   deprecated host-key algorithms (ssh-dss, ssh-rsa/SHA-1), SHA-1 / small-group
   key exchanges, 64-bit-block / RC4 / CBC ciphers, and MD5 / SHA-1 / 64-bit MACs.

Every finding is backed by the algorithm name the server itself advertised, so the
audit is deterministic and false-positive-free — it reports only what is on the
wire, never a guess.
"""
from __future__ import annotations

import asyncio
import re
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("ssh_audit")

_CLIENT_ID = b"SSH-2.0-HEAVEN_SSHAudit\r\n"
_SSH_MSG_KEXINIT = 20

# ── Weak-algorithm knowledge base ─────────────────────────────────────────────
# (severity, human reason). Kept conservative: only algorithms with a real,
# well-established weakness, so a positive is always defensible in a report.

_WEAK_HOSTKEY: dict[str, tuple[str, str]] = {
    "ssh-dss": ("high",
                "DSA (ssh-dss): 1024-bit, cryptographically weak; disabled by "
                "default since OpenSSH 7.0"),
    "ssh-dss-cert-v01@openssh.com": ("high", "DSA certificate host key (ssh-dss)"),
    "ssh-rsa": ("medium",
                "RSA host key with a SHA-1 signature (ssh-rsa): deprecated and "
                "disabled by default since OpenSSH 8.8 (SHA-1 is collision-broken); "
                "use rsa-sha2-256 / rsa-sha2-512"),
    "ssh-rsa-cert-v01@openssh.com": ("medium",
                "RSA/SHA-1 certificate host key (ssh-rsa-cert-v01)"),
}

_WEAK_KEX: dict[str, tuple[str, str]] = {
    "diffie-hellman-group1-sha1": ("high",
        "1024-bit MODP group + SHA-1 (Logjam-class, nation-state breakable)"),
    "diffie-hellman-group-exchange-sha1": ("medium",
        "DH group-exchange with SHA-1"),
    "diffie-hellman-group14-sha1": ("low", "2048-bit group but SHA-1 hash"),
    "rsa1024-sha1": ("high", "1024-bit RSA key transport + SHA-1"),
    "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==": ("high", "GSS group1 + SHA-1"),
    "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==": ("medium", "GSS group-exchange + SHA-1"),
}

_WEAK_CIPHER: dict[str, tuple[str, str]] = {
    "none": ("critical", "no encryption"),
    "des-cbc": ("high", "DES (56-bit)"),
    "3des-cbc": ("medium", "3DES: 64-bit block, SWEET32-class birthday attack"),
    "blowfish-cbc": ("medium", "Blowfish: 64-bit block"),
    "cast128-cbc": ("medium", "CAST-128: 64-bit block"),
    "arcfour": ("medium", "RC4 stream cipher (broken)"),
    "arcfour128": ("medium", "RC4 (broken)"),
    "arcfour256": ("medium", "RC4 (broken)"),
    "rijndael-cbc@lysator.liu.se": ("low", "non-standard AES-CBC"),
}

_WEAK_MAC: dict[str, tuple[str, str]] = {
    "none": ("critical", "no integrity protection"),
    "hmac-md5": ("medium", "MD5 (broken)"),
    "hmac-md5-96": ("medium", "MD5, 96-bit tag"),
    "hmac-md5-etm@openssh.com": ("medium", "MD5"),
    "hmac-md5-96-etm@openssh.com": ("medium", "MD5, 96-bit tag"),
    "hmac-sha1": ("low", "SHA-1 HMAC"),
    "hmac-sha1-96": ("low", "SHA-1, 96-bit tag"),
    "hmac-sha1-96-etm@openssh.com": ("low", "SHA-1, 96-bit tag"),
    "umac-64@openssh.com": ("low", "64-bit authentication tag"),
    "umac-64-etm@openssh.com": ("low", "64-bit authentication tag"),
}

# Rank helper so a grouped finding takes the most severe member's severity.
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── AWS Transfer Family (managed SFTP) ─────────────────────────────────────────
# AWS Transfer endpoints announce themselves in the SSH banner ("AWS_SFTP_...") and
# on a *.server.transfer.<region>.amazonaws.com host. Each endpoint runs a named
# "security policy" that fixes its algorithm set. Algorithms below were dropped in
# TransferSecurityPolicy-2022-03 and every later policy, so seeing any of them on
# an AWS Transfer endpoint proves it is pinned to a SUPERSEDED policy (2018-11 or
# 2020-06). Reference: AWS Transfer Family security-policy documentation.
_AWS_TRANSFER_LEGACY_MARKERS = {
    "ssh-rsa", "ssh-dss",
    "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
    "hmac-sha1", "hmac-sha1-96",
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
}


def _is_aws_transfer(banner: str, host: str) -> bool:
    b = (banner or "").lower()
    h = (host or "").lower()
    return ("aws_sftp" in b
            or ".server.transfer." in h
            or (h.startswith("s-") and "transfer" in h and "amazonaws.com" in h))


def aws_transfer_findings(host: str, port: int, banner: str,
                          algos: dict[str, list[str]]) -> list[dict]:
    """Flag an AWS Transfer endpoint pinned to a superseded security policy."""
    if not _is_aws_transfer(banner, host):
        return []
    offered = set(algos.get("host_keys", []) + algos.get("kex", [])
                  + algos.get("enc_c2s", []) + algos.get("enc_s2c", [])
                  + algos.get("mac_c2s", []) + algos.get("mac_s2c", []))
    legacy = sorted(offered & _AWS_TRANSFER_LEGACY_MARKERS)
    if not legacy:
        return []
    return [_finding(
        host, port, "aws_transfer_superseded_policy", "medium",
        "AWS Transfer Family on a Superseded Security Policy",
        f"The AWS Transfer Family SFTP endpoint {host}:{port} still offers "
        f"algorithms that TransferSecurityPolicy-2022-03 and every later policy "
        f"removed: {', '.join(legacy)}. The endpoint is therefore pinned to a "
        "superseded security policy (TransferSecurityPolicy-2018-11 or -2020-06), "
        "so it accepts weaker SSH cryptography than AWS's current baseline. Update "
        "the server's SecurityPolicyName to the latest TransferSecurityPolicy "
        "(e.g. TransferSecurityPolicy-2024-01, or a FIPS/PQ-SSH variant) in the "
        "AWS Transfer console or via update-server.",
        confidence=0.9)]


@dataclass
class SSHAudit:
    host: str
    port: int
    reachable: bool = False
    banner: str = ""
    software: str = ""
    kex: list[str] = field(default_factory=list)
    host_keys: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    error: Optional[str] = None


def _finding(host: str, port: int, vuln_type: str, severity: str, title: str,
             description: str, confidence: float = 0.95, cve: str = "") -> dict:
    return {
        "target": f"{host}:{port}",
        "vuln_type": vuln_type,
        "title": title,
        "severity": severity,
        "description": description,
        "confidence": confidence,
        "cve_id": cve,
        "source": "ssh_audit",
    }


# ── Wire parsing ──────────────────────────────────────────────────────────────

def _read_id_string(sock: socket.socket, timeout: float) -> tuple[str, bytes]:
    """Read the server identification line ("SSH-...\\r\\n").

    Returns (id_string, leftover_bytes) where leftover_bytes is any data already
    received past the ID line (often the start of the KEXINIT packet). Per RFC
    4253 the server may send banner lines before the SSH- line; we skip those.
    """
    buf = b""
    sock.settimeout(timeout)
    while b"\n" not in buf or not any(
        ln.startswith(b"SSH-") for ln in buf.split(b"\n")
    ):
        chunk = sock.recv(512)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 8192:                    # runaway pre-banner — give up
            break
    # Find the SSH- line; everything after its CRLF is binary packet data.
    idx = buf.find(b"SSH-")
    if idx < 0:
        return "", buf
    nl = buf.find(b"\n", idx)
    if nl < 0:
        return buf[idx:].decode("latin-1", "replace").strip(), b""
    id_line = buf[idx:nl].decode("latin-1", "replace").strip("\r\n ")
    return id_line, buf[nl + 1:]


def _recv_packet(sock: socket.socket, leftover: bytes, timeout: float) -> bytes:
    """Read one plaintext SSH binary packet, returning its payload bytes."""
    sock.settimeout(timeout)
    buf = leftover
    # Need the 4-byte length first.
    while len(buf) < 4:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    if len(buf) < 4:
        return b""
    pkt_len = struct.unpack(">I", buf[:4])[0]
    if pkt_len <= 0 or pkt_len > 262144:        # sanity bound (RFC max ~35000)
        return b""
    while len(buf) < 4 + pkt_len:
        chunk = sock.recv(8192)
        if not chunk:
            break
        buf += chunk
    if len(buf) < 4 + pkt_len:
        return b""
    padding_len = buf[4]
    payload = buf[5:4 + pkt_len - padding_len]
    return payload


def _read_namelist(data: bytes, off: int) -> tuple[list[str], int]:
    """Read one SSH name-list (uint32 length + comma-separated ASCII)."""
    if off + 4 > len(data):
        raise ValueError("truncated name-list length")
    ln = struct.unpack(">I", data[off:off + 4])[0]
    off += 4
    if off + ln > len(data):
        raise ValueError("truncated name-list body")
    raw = data[off:off + ln].decode("latin-1", "replace")
    off += ln
    names = [n for n in raw.split(",") if n]
    return names, off


def parse_kexinit(payload: bytes) -> dict[str, list[str]]:
    """Parse an SSH_MSG_KEXINIT payload into its ten algorithm name-lists."""
    if not payload or payload[0] != _SSH_MSG_KEXINIT:
        raise ValueError("not a KEXINIT payload")
    off = 1 + 16                                 # msg type + 16-byte cookie
    fields = [
        "kex", "host_keys",
        "enc_c2s", "enc_s2c",
        "mac_c2s", "mac_s2c",
        "comp_c2s", "comp_s2c",
        "lang_c2s", "lang_s2c",
    ]
    out: dict[str, list[str]] = {}
    for name in fields:
        names, off = _read_namelist(payload, off)
        out[name] = names
    return out


# ── Weak-algorithm classification ─────────────────────────────────────────────

def _classify_kex(name: str) -> Optional[tuple[str, str]]:
    if name in _WEAK_KEX:
        return _WEAK_KEX[name]
    # Catch-all for any other SHA-1 based exchange. Only group1 is the weak
    # 1024-bit MODP group; group14/15/16/17/18 are 2048-bit+, so their only issue
    # is the SHA-1 hash. Match "group1" NOT followed by another digit so group16
    # and group18 are not misread as group1.
    low = name.lower()
    if low.endswith("sha1") or low.endswith("sha-1"):
        if re.search(r"group1(?![0-9])", low):
            return ("high", "1024-bit group + SHA-1")
        return ("low", "SHA-1 based key exchange")
    return None


def _classify_cipher(name: str) -> Optional[tuple[str, str]]:
    if name in _WEAK_CIPHER:
        return _WEAK_CIPHER[name]
    # Any remaining CBC-mode cipher: susceptible to the SSH CBC plaintext-recovery
    # attack (CVE-2008-5161); ssh-audit flags CBC as weak.
    if name.endswith("-cbc"):
        return ("low", "CBC mode (CVE-2008-5161 plaintext recovery)")
    return None


def audit_algorithms(host: str, port: int, algos: dict[str, list[str]]) -> list[dict]:
    """Turn parsed KEXINIT name-lists into findings (one per weak category)."""
    findings: list[dict] = []

    def _group(kind_names: list[str], classifier, vuln_type: str, label: str,
               tail: str) -> None:
        hits: list[tuple[str, str, str]] = []     # (algo, sev, reason)
        for a in kind_names:
            res = classifier(a)
            if res:
                hits.append((a, res[0], res[1]))
        if not hits:
            return
        sev = max((h[1] for h in hits), key=lambda s: _SEV_RANK.get(s, 0))
        listed = "; ".join(f"{a} ({reason})" for a, _s, reason in hits)
        findings.append(_finding(
            host, port, vuln_type, sev,
            f"SSH Server Offers Weak {label} ({', '.join(h[0] for h in hits)})",
            f"The SSH server at {host}:{port} advertises {label.lower()} that are "
            f"cryptographically weak or deprecated: {listed}. {tail}",
            confidence=0.97))

    # Host keys — the headline case (ssh-dss / ssh-rsa SHA-1). A server offering
    # these for host authentication typically also accepts them for client
    # publickey authentication under the same policy.
    _group(algos.get("host_keys", []), lambda a: _WEAK_HOSTKEY.get(a),
           "ssh_weak_host_key_algo", "Host-Key Algorithms",
           "A downgrade-capable client can force the server to authenticate with "
           "the weak key type, and the same algorithms are generally accepted for "
           "client publickey authentication. Disable ssh-dss and ssh-rsa (SHA-1) "
           "and offer only rsa-sha2-*, ecdsa-sha2-* or ssh-ed25519.")
    _group(algos.get("kex", []), _classify_kex, "ssh_weak_kex",
           "Key-Exchange Algorithms",
           "Weak key exchange lets an adversary who can break the group or the "
           "hash recover the session key. Offer only curve25519-sha256, "
           "ecdh-sha2-nistp256/384/521 and diffie-hellman-group14-sha256+.")
    # Encryption — client-to-server and server-to-client are almost always equal;
    # union them and report once.
    enc = list(dict.fromkeys(algos.get("enc_c2s", []) + algos.get("enc_s2c", [])))
    _group(enc, _classify_cipher, "ssh_weak_cipher", "Ciphers",
           "Retire 3DES, RC4, DES, Blowfish/CAST and CBC-mode ciphers; offer only "
           "AEAD/CTR suites such as chacha20-poly1305 and aes*-gcm / aes*-ctr.")
    mac = list(dict.fromkeys(algos.get("mac_c2s", []) + algos.get("mac_s2c", [])))
    _group(mac, lambda a: _WEAK_MAC.get(a), "ssh_weak_mac", "MAC Algorithms",
           "Drop MD5, SHA-1 and 64-bit MACs; prefer hmac-sha2-256/512-etm and "
           "umac-128-etm.")
    return findings


# ── Blocking audit + async entry points ───────────────────────────────────────

def _run_ssh_audit(host: str, port: int, timeout: float = 8.0) -> SSHAudit:
    result = SSHAudit(host=host, port=port)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        result.error = f"port unreachable: {e}"
        return result
    result.reachable = True
    try:
        banner, leftover = _read_id_string(sock, timeout)
        result.banner = banner
        if banner.startswith("SSH-"):
            # "SSH-2.0-OpenSSH_9.6p1 Ubuntu" → software = "OpenSSH_9.6p1 Ubuntu"
            parts = banner.split("-", 2)
            result.software = parts[2].strip() if len(parts) > 2 else ""
        try:
            sock.sendall(_CLIENT_ID)
        except Exception:
            logger.debug("client id send failed", exc_info=True)
        payload = _recv_packet(sock, leftover, timeout)
    except Exception as e:
        result.error = f"handshake read failed: {e}"
        try:
            sock.close()
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
        return result
    finally:
        try:
            sock.close()
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)

    try:
        algos = parse_kexinit(payload)
    except Exception as e:
        result.error = f"kexinit parse failed: {e}"
        return result

    result.kex = algos.get("kex", [])
    result.host_keys = algos.get("host_keys", [])
    result.ciphers = list(dict.fromkeys(
        algos.get("enc_c2s", []) + algos.get("enc_s2c", [])))
    result.macs = list(dict.fromkeys(
        algos.get("mac_c2s", []) + algos.get("mac_s2c", [])))
    result.findings = audit_algorithms(host, port, algos)
    result.findings.extend(aws_transfer_findings(host, port, result.banner, algos))
    return result


async def scan_ssh(host: str, port: int = 22) -> dict:
    """Async entry point — audit one SSH server's advertised crypto."""
    loop = asyncio.get_running_loop()
    try:
        res: SSHAudit = await loop.run_in_executor(None, _run_ssh_audit, host, port)
    except Exception as e:
        logger.error("SSH audit error for %s:%s: %s", host, port, e)
        return {"findings": [], "error": str(e)}
    if res.error and not res.findings:
        logger.debug("SSH audit %s:%s → %s", host, port, res.error)
    else:
        logger.info("SSH audit %s:%s → %d issue(s) [%s]",
                    host, port, len(res.findings), res.software or res.banner)
    return {
        "target": f"{host}:{port}",
        "reachable": res.reachable,
        "banner": res.banner,
        "software": res.software,
        "kex": res.kex,
        "host_keys": res.host_keys,
        "ciphers": res.ciphers,
        "macs": res.macs,
        "findings": res.findings,
        "error": res.error,
    }
