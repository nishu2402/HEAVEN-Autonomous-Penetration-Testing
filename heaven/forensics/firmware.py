"""HEAVEN — firmware image analysis (pure-Python carving).

Reproduces the CPENT firmware workflow (binwalk-style) without requiring
binwalk: it scans a firmware ``.bin`` for embedded filesystems / compressed
blobs by magic signature, extracts printable strings, and hunts for the things
that make IoT firmware dangerous — hardcoded credentials, private keys, and
default-password config files (the ``romfile.cfg`` class of finding).

If ``binwalk`` is on PATH it is used to enrich the carve; otherwise the
pure-Python signature scan stands alone.
"""

from __future__ import annotations

import math
import re
import shutil
import subprocess  # nosec B404 — optional binwalk enrichment, fixed argv
from pathlib import Path
from typing import Any, cast

from heaven.utils.logger import get_logger

logger = get_logger("forensics.firmware")

_MAX_READ = 512 * 1024 * 1024        # defensive cap on whole-image reads

# Software / version banners worth inventorying from a firmware image. Old
# versions of these are a rich CVE surface on IoT devices.
_VERSION_PATTERNS = [
    (re.compile(r"Linux version (\d+\.\d+[\d.]*)"), "Linux kernel"),
    (re.compile(r"BusyBox v(\d+\.\d+[\d.]*)"), "BusyBox"),
    (re.compile(r"Dropbear[ _]?(?:sshd[ _])?v?(\d+\.\d+[\d.]*)"), "Dropbear SSH"),
    (re.compile(r"OpenSSL (\d+\.\d+\.\d+[a-z]?)"), "OpenSSL"),
    (re.compile(r"OpenSSH[_ ](\d+\.\d+[p\d]*)"), "OpenSSH"),
    (re.compile(r"U-Boot[ ]?(\d{4}\.\d+[\d.\-rc]*)"), "U-Boot"),
    (re.compile(r"lighttpd/(\d+\.\d+[\d.]*)"), "lighttpd"),
    (re.compile(r"(?:Apache|httpd)/(\d+\.\d+[\d.]*)"), "Apache httpd"),
    (re.compile(r"nginx/(\d+\.\d+[\d.]*)"), "nginx"),
    (re.compile(r"PHP/(\d+\.\d+[\d.]*)"), "PHP"),
    (re.compile(r"uClibc[ -]?(\d+\.\d+[\d.]*)"), "uClibc"),
    (re.compile(r"hostapd v?(\d+\.\d+[\d.]*)"), "hostapd"),
]

# Embedded Unix account lines: user:hash:uid:gid... (passwd/shadow).
_PASSWD_RE = re.compile(
    r"^([a-zA-Z0-9_.\-]{1,32}):(\$[0-9a-z]+\$[^:]+|[A-Za-z0-9./]{13}):", re.M)

# (signature bytes, label) — offsets found anywhere in the image.
_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x1f\x8b\x08", "gzip compressed data"),
    (b"\xfd7zXZ\x00", "xz compressed data"),
    (b"BZh", "bzip2 compressed data"),
    (b"\x5d\x00\x00", "LZMA compressed data"),
    (b"hsqs", "squashfs filesystem (LE)"),
    (b"sqsh", "squashfs filesystem (BE)"),
    (b"\x45\x3d\xcd\x28", "cramfs filesystem"),
    (b"\x85\x19", "jffs2 filesystem"),
    (b"UBI#", "UBI image"),
    (b"ubi!", "UBIFS"),
    (b"\x27\x05\x19\x56", "u-boot uImage header"),
    (b"\xd0\x0d\xfe\xed", "device tree blob (FDT)"),
    (b"\x7fELF", "ELF executable"),
    (b"-----BEGIN ", "PEM key/certificate block"),
    (b"\x89PNG", "PNG image"),
    (b"CrOS", "Chrome OS image"),
]

# Regexes for secrets in extracted strings.
_SECRET_PATTERNS = [
    (re.compile(r"(?i)\b(pass(word|wd)?|pwd)\s*[:=]\s*([^\s'\";]{3,})"), "password", "high"),
    (re.compile(r"(?i)\badmin\s*[:=]\s*([^\s'\";]{3,})"), "admin credential", "high"),
    (re.compile(r"(?i)\b(web_passwd|http_passwd|login_pass)\s*[:=]\s*(\S+)"),
     "web admin password (config)", "critical"),
    (re.compile(r"root:[^:]*:0:0:"), "root passwd entry", "medium"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id", "high"),
    (re.compile(r"(?i)api[_-]?key\s*[:=]\s*([A-Za-z0-9_\-]{16,})"), "API key", "high"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "embedded private key", "critical"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API key", "high"),
    (re.compile(r"(?i)\b(wpa_passphrase|wpa_psk|wl_wpa_psk)\s*[:=]\s*(\S{8,})"),
     "hardcoded WiFi passphrase", "high"),
    (re.compile(r"(?i)\b(telnetd|telnet)\b.{0,40}(enable|start|-l)"),
     "telnet service enabled", "medium"),
    (re.compile(r"(?i)mqtt://[^\s'\";]+"), "MQTT endpoint (cleartext)", "low"),
]


def _extract_versions(text: str) -> list[dict]:
    seen, out = set(), []
    for rx, product in _VERSION_PATTERNS:
        for m in rx.finditer(text):
            ver = m.group(1)
            key = (product, ver)
            if key in seen:
                continue
            seen.add(key)
            out.append({"product": product, "version": ver, "banner": m.group(0)[:60]})
            if len(out) >= 60:
                return out
    return out


def _extract_accounts(text: str) -> list[dict]:
    accounts = []
    for m in _PASSWD_RE.finditer(text):
        user, secret = m.group(1), m.group(2)
        if secret in ("x", "*", "!", "!!"):
            continue
        accounts.append({"user": user, "hash": secret[:80]})
        if len(accounts) >= 50:
            break
    return accounts


def _high_entropy_regions(data: bytes, block: int = 4096) -> int:
    """Count high-entropy blocks (encrypted/compressed regions)."""
    hits = 0
    for off in range(0, min(len(data), 64 * 1024 * 1024), block):
        chunk = data[off:off + block]
        if len(chunk) < block:
            break
        counts = [0] * 256
        for b in chunk:
            counts[b] += 1
        ent = -sum((c / block) * math.log2(c / block) for c in counts if c)
        if ent >= 7.5:
            hits += 1
    return hits


def _extract_strings(data: bytes, min_len: int = 5, cap: int = 20_000_000) -> str:
    out, cur = [], bytearray()
    for b in data[:cap]:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("latin1"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("latin1"))
    return "\n".join(out)


def _carve(data: bytes) -> list[dict]:
    found = []
    for sig, label in _SIGNATURES:
        start = 0
        hits = 0
        while hits < 200:
            idx = data.find(sig, start)
            if idx == -1:
                break
            found.append({"offset": idx, "hex_offset": hex(idx), "type": label})
            start = idx + 1
            hits += 1
    found.sort(key=lambda f: cast(int, f["offset"]))
    return found


def _binwalk(path: str) -> list[str]:
    if not shutil.which("binwalk"):
        return []
    try:
        out = subprocess.run(  # nosec B603 B607 — fixed argv, no shell
            ["binwalk", path], capture_output=True, text=True, timeout=120)
        return [ln for ln in out.stdout.splitlines() if ln.strip()][:200]
    except Exception:
        return []


def analyze_firmware(path: str, **_: Any) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    with open(p, "rb") as fh:
        data = fh.read(_MAX_READ)
    carved = _carve(data)
    strings_text = _extract_strings(data)
    versions = _extract_versions(strings_text)
    accounts = _extract_accounts(strings_text)
    entropy_regions = _high_entropy_regions(data)

    secrets, seen = [], set()
    for rx, label, sev in _SECRET_PATTERNS:
        for m in rx.finditer(strings_text):
            snippet = m.group(0)[:120]
            key = (label, snippet)
            if key in seen:
                continue
            seen.add(key)
            secrets.append({"type": label, "severity": sev, "match": snippet})
            if len(secrets) >= 200:
                break

    fs_types = sorted({c["type"] for c in carved
                       if "filesystem" in c["type"] or "UBI" in c["type"]})
    findings = []
    if secrets:
        crit = [s for s in secrets if s["severity"] in ("critical", "high")]
        if crit:
            sample = "; ".join(s["match"] for s in crit[:3])
            findings.append({
                "vuln_type": "firmware_hardcoded_secret", "severity": "critical",
                "scanner": "firmware_analyzer", "confidence": 0.85,
                "title": f"{len(crit)} hardcoded secret(s) in firmware",
                "description": ("The firmware image contains hardcoded credentials, "
                                f"keys, or password-config entries. Examples: {sample}. "
                                "These are shared across every device running this "
                                "firmware and cannot be rotated by the user."),
                "cwe": "CWE-798", "evidence": {"secrets": secrets[:50]},
                "remediation": "Remove hardcoded credentials/keys from firmware; "
                               "provision per-device secrets at first boot."})
    if fs_types:
        findings.append({
            "vuln_type": "firmware_filesystem_extractable", "severity": "info",
            "scanner": "firmware_analyzer", "confidence": 0.9,
            "title": f"Extractable embedded filesystem(s): {', '.join(fs_types)}",
            "description": ("The firmware embeds a filesystem that can be carved and "
                            "mounted offline to review binaries, config, and keys "
                            "(the standard IoT firmware-analysis path)."),
            "cwe": "CWE-1188"})
    if accounts:
        sample = ", ".join(a["user"] for a in accounts[:6])
        findings.append({
            "vuln_type": "firmware_embedded_account", "severity": "high",
            "scanner": "firmware_analyzer", "confidence": 0.85,
            "title": f"{len(accounts)} embedded account(s) with a password hash",
            "description": ("The firmware ships /etc/passwd or /etc/shadow entries "
                            f"with password hashes (users: {sample}). These are the "
                            "same on every device and are crackable offline; a root "
                            "entry is a device-wide backdoor."),
            "cwe": "CWE-798", "evidence": {"accounts": accounts[:20]},
            "remediation": "Do not ship password hashes in firmware; provision unique "
                           "device credentials at first boot."})
    if versions:
        findings.append({
            "vuln_type": "firmware_software_inventory", "severity": "info",
            "scanner": "firmware_analyzer", "confidence": 0.8,
            "title": f"{len(versions)} software component/version(s) identified",
            "description": ("Version banners were extracted from the image. Cross-"
                            "reference these against CVE feeds. IoT firmware often "
                            "ships years-old, vulnerable components: "
                            + ", ".join(f"{v['product']} {v['version']}"
                                        for v in versions[:8]) + "."),
            "cwe": "CWE-1104", "evidence": {"components": versions[:30]}})

    return {"report": {"size": len(data), "carved": carved[:200],
                       "filesystems": fs_types, "secrets": secrets[:100],
                       "software_versions": versions, "embedded_accounts": accounts,
                       "high_entropy_blocks": entropy_regions,
                       "overall_entropy": round(_shannon_bytes(data), 3)},
            "findings": findings,
            "binwalk": _binwalk(str(p)),
            "summary": (f"{len(data)} bytes · {len(carved)} embedded object(s) · "
                        f"{len(secrets)} secret(s) · {len(versions)} component(s)"
                        + (f" · {len(accounts)} account(s)" if accounts else ""))}


def _shannon_bytes(data: bytes) -> float:
    sample = data[:16 * 1024 * 1024]
    if not sample:
        return 0.0
    counts = [0] * 256
    for b in sample:
        counts[b] += 1
    n = len(sample)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)
