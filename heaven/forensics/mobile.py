"""HEAVEN — Mobile application static analysis (Android APK + iOS IPA).

Closes the mobile-device gap with an offline static review of a mobile app the
operator supplies, scored against the OWASP Mobile Top 10 (2024) / MASVS:

**Android (.apk)**
* **Permissions** — parsed from the binary AndroidManifest, with dangerous /
  privacy-sensitive permissions flagged.
* **Embedded secrets** — API keys, passwords, private keys, and cleartext
  ``http://`` endpoints found across the DEX, resources, and assets.
* **Cleartext / debug / backup posture** — usesCleartextTraffic, debuggable and
  allowBackup indicators.

**iOS (.ipa)**
* **App Transport Security** — ``NSAllowsArbitraryLoads`` (ATS disabled →
  cleartext traffic permitted).
* **Privacy permissions** — the ``NS*UsageDescription`` keys the app declares.
* **URL schemes** — custom ``CFBundleURLSchemes`` (hijack / deep-link surface).
* **Embedded secrets** — the same secret sweep across the app bundle.

Pure ``zipfile`` + ``plistlib`` + a minimal AXML string-pool parser; no external
tooling.
"""

from __future__ import annotations

import plistlib
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("forensics.mobile")

# OWASP Mobile Top 10 (2024) buckets, tagged onto each finding for the report.
_OWASP_MOBILE = {
    "apk_hardcoded_secret": "M1: Improper Credential Usage",
    "apk_cleartext_traffic": "M5: Insecure Communication",
    "apk_debuggable": "M8: Security Misconfiguration",
    "apk_backup_allowed": "M9: Insecure Data Storage",
    "apk_dangerous_permissions": "M6: Inadequate Privacy Controls",
    "ipa_hardcoded_secret": "M1: Improper Credential Usage",
    "ipa_cleartext_ats_disabled": "M5: Insecure Communication",
    "ipa_url_scheme": "M4: Insufficient Input/Output Validation",
    "ipa_privacy_permissions": "M6: Inadequate Privacy Controls",
}

# iOS Info.plist privacy-usage keys → the sensitive resource they gate.
_IOS_PRIVACY_KEYS = {
    "NSCameraUsageDescription": "Camera",
    "NSMicrophoneUsageDescription": "Microphone",
    "NSLocationWhenInUseUsageDescription": "Location (in use)",
    "NSLocationAlwaysUsageDescription": "Location (always)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Location (always)",
    "NSContactsUsageDescription": "Contacts",
    "NSPhotoLibraryUsageDescription": "Photo library",
    "NSPhotoLibraryAddUsageDescription": "Photo library (add)",
    "NSFaceIDUsageDescription": "Face ID",
    "NSHealthShareUsageDescription": "Health data",
    "NSCalendarsUsageDescription": "Calendars",
    "NSRemindersUsageDescription": "Reminders",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth",
    "NSMotionUsageDescription": "Motion & fitness",
    "NSSpeechRecognitionUsageDescription": "Speech recognition",
}

_DANGEROUS_PERMS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO", "CAMERA", "READ_CALL_LOG", "WRITE_CALL_LOG", "READ_PHONE_STATE",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
    "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
    "READ_CALENDAR", "BODY_SENSORS", "GET_ACCOUNTS", "PROCESS_OUTGOING_CALLS",
    "CALL_PHONE", "USE_FINGERPRINT",
}

_SECRET_PATTERNS = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id", "high"),
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "Google API key", "high"),
    (re.compile(rb"(?i)(secret|passwd|password|api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})"),
     "hardcoded secret", "high"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "embedded private key", "critical"),
    (re.compile(rb"http://[a-zA-Z0-9\.\-]+(?::\d+)?[^\s'\"]*"), "cleartext http URL", "medium"),
]


def _axml_strings(data: bytes) -> list[str]:
    """Extract the string pool from a binary AndroidManifest (AXML)."""
    if len(data) < 8 or struct.unpack_from("<I", data, 0)[0] not in (0x00080003, 0x00080001):
        return []
    # Find the RES_STRING_POOL_TYPE (0x0001) chunk.
    off = 8
    try:
        while off + 8 <= len(data):
            ctype = struct.unpack_from("<H", data, off)[0]
            csize = struct.unpack_from("<I", data, off + 4)[0]
            if ctype == 0x0001:  # string pool
                return _parse_string_pool(data, off, csize)
            if csize <= 0:
                break
            off += csize
    except Exception:
        logger.debug("AXML parse error", exc_info=True)
    return []


def _parse_string_pool(data: bytes, off: int, csize: int) -> list[str]:
    string_count = struct.unpack_from("<I", data, off + 8)[0]
    flags = struct.unpack_from("<I", data, off + 16)[0]
    strings_start = struct.unpack_from("<I", data, off + 20)[0]
    is_utf8 = bool(flags & 0x100)
    offsets_base = off + 28
    strings_base = off + strings_start
    out = []
    for i in range(min(string_count, 20000)):
        try:
            so = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
            pos = strings_base + so
            if is_utf8:
                # u16len (skip), u8len, bytes
                _n = data[pos]
                pos += 1 if _n < 0x80 else 2
                slen = data[pos]
                pos += 1 if slen < 0x80 else 2
                s = data[pos:pos + slen].decode("utf-8", "replace")
            else:
                slen = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                s = data[pos:pos + slen * 2].decode("utf-16-le", "replace")
            if s:
                out.append(s)
        except Exception:
            continue
    return out


def analyze_apk(path: str, **_: Any) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    try:
        zf = zipfile.ZipFile(str(p))
    except zipfile.BadZipFile:
        return {"error": "not a valid APK/ZIP file"}

    names = zf.namelist()
    if "AndroidManifest.xml" not in names:
        return {"error": "no AndroidManifest.xml — not an APK"}

    manifest_strings = _axml_strings(zf.read("AndroidManifest.xml"))
    permissions = sorted({s for s in manifest_strings if s.startswith("android.permission.")})
    dangerous = [pm for pm in permissions if pm.split(".")[-1] in _DANGEROUS_PERMS]
    debuggable = any("debuggable" in s.lower() for s in manifest_strings)
    cleartext_attr = any("usescleartexttraffic" in s.lower() for s in manifest_strings)
    allow_backup = any(s.lower() == "allowbackup" for s in manifest_strings)

    # Scan DEX + resources + assets for secrets (bounded).
    secrets, seen = [], set()
    scanned = 0
    for name in names:
        if scanned > 60:
            break
        if not (name.endswith(".dex") or name.startswith(("assets/", "res/"))
                or name in ("resources.arsc",)):
            continue
        try:
            blob = zf.read(name)
        except Exception:
            continue
        scanned += 1
        for rx, label, sev in _SECRET_PATTERNS:
            for m in rx.finditer(blob):
                snippet = m.group(0)[:120].decode("latin1", "replace")
                if label == "cleartext http URL" and (
                        "localhost" in snippet or "127.0.0.1" in snippet
                        or "schemas.android.com" in snippet or "w3.org" in snippet):
                    continue
                key = (label, snippet)
                if key in seen:
                    continue
                seen.add(key)
                secrets.append({"type": label, "severity": sev,
                                "match": snippet, "file": name})
                if len(secrets) >= 200:
                    break

    findings = _build_findings(dangerous, secrets, debuggable, cleartext_attr,
                               allow_backup)
    return {"report": {"platform": "android", "entries": len(names),
                       "permissions": permissions,
                       "dangerous_permissions": dangerous, "debuggable": debuggable,
                       "cleartext_traffic_attr": cleartext_attr,
                       "allow_backup": allow_backup,
                       "secrets": secrets[:100]},
            "findings": findings,
            "summary": (f"Android · {len(permissions)} perms ({len(dangerous)} "
                        f"dangerous) · {len(secrets)} secret(s)"
                        + (" · debuggable" if debuggable else "")
                        + (" · allowBackup" if allow_backup else ""))}


def _tag_owasp(findings: list[dict]) -> list[dict]:
    """Attach the OWASP Mobile Top 10 bucket to each finding by vuln_type."""
    for f in findings:
        bucket = _OWASP_MOBILE.get(f.get("vuln_type", ""))
        if bucket:
            f["owasp_mobile"] = bucket
    return findings


def _build_findings(dangerous, secrets, debuggable, cleartext_attr,
                    allow_backup=False):
    findings = []
    crit_secrets = [s for s in secrets if s["severity"] in ("critical", "high")]
    if crit_secrets:
        sample = "; ".join(s["match"] for s in crit_secrets[:3])
        findings.append({
            "vuln_type": "apk_hardcoded_secret", "severity": "high",
            "scanner": "apk_analyzer", "confidence": 0.8,
            "title": f"{len(crit_secrets)} hardcoded secret(s) in the APK",
            "description": ("The APK ships hardcoded credentials/keys recoverable by "
                            f"anyone who decompiles it. Examples: {sample}."),
            "cwe": "CWE-798", "evidence": {"secrets": crit_secrets[:50]},
            "remediation": "Never ship secrets in the client; fetch them from a "
                           "server behind auth and rotate the exposed keys."})
    cleartext_urls = [s for s in secrets if s["type"] == "cleartext http URL"]
    if cleartext_urls or cleartext_attr:
        findings.append({
            "vuln_type": "apk_cleartext_traffic", "severity": "medium",
            "scanner": "apk_analyzer", "confidence": 0.7,
            "title": "Cleartext HTTP traffic",
            "description": ("The app uses cleartext http:// endpoints (or permits "
                            "cleartext traffic), exposing data to network attackers."),
            "cwe": "CWE-319", "evidence": {"urls": [s["match"] for s in cleartext_urls[:20]]},
            "remediation": "Use HTTPS everywhere and set android:usesCleartextTraffic=false."})
    if debuggable:
        findings.append({
            "vuln_type": "apk_debuggable", "severity": "medium",
            "scanner": "apk_analyzer", "confidence": 0.7,
            "title": "App is debuggable",
            "description": "android:debuggable is enabled, letting anyone attach a "
                           "debugger and inspect/modify the running app.",
            "cwe": "CWE-489",
            "remediation": "Ship release builds with android:debuggable=false."})
    if allow_backup:
        findings.append({
            "vuln_type": "apk_backup_allowed", "severity": "medium",
            "scanner": "apk_analyzer", "confidence": 0.65,
            "title": "App data is backup-enabled (android:allowBackup)",
            "description": "android:allowBackup is enabled, so app data can be "
                           "extracted over ADB (`adb backup`) on a debuggable/rooted "
                           "or unlocked device, exposing locally-stored data.",
            "cwe": "CWE-530",
            "remediation": "Set android:allowBackup=false (or a strict "
                           "android:fullBackupContent rule) on the <application>."})
    if dangerous:
        findings.append({
            "vuln_type": "apk_dangerous_permissions", "severity": "low",
            "scanner": "apk_analyzer", "confidence": 0.9,
            "title": f"{len(dangerous)} dangerous permission(s) requested",
            "description": "The app requests privacy-sensitive permissions: "
                           + ", ".join(p.split(".")[-1] for p in dangerous[:12]) + ".",
            "cwe": "CWE-250", "evidence": {"permissions": dangerous}})
    return _tag_owasp(findings)


# ── iOS (.ipa) static analysis ───────────────────────────────────────────────

def _load_info_plist(zf: zipfile.ZipFile) -> tuple[dict, str]:
    """Return (Info.plist dict, app-bundle prefix) for the Payload/*.app bundle."""
    app_prefix = ""
    plist_name = ""
    for name in zf.namelist():
        parts = name.split("/")
        if len(parts) >= 3 and parts[0] == "Payload" and parts[1].endswith(".app") \
                and parts[2] == "Info.plist" and len(parts) == 3:
            app_prefix = f"Payload/{parts[1]}/"
            plist_name = name
            break
    if not plist_name:
        return {}, ""
    try:
        return plistlib.loads(zf.read(plist_name)), app_prefix
    except Exception:
        logger.debug("Info.plist parse error", exc_info=True)
        return {}, app_prefix


def _ats_allows_cleartext(info: dict) -> bool:
    ats = info.get("NSAppTransportSecurity")
    if isinstance(ats, dict):
        if ats.get("NSAllowsArbitraryLoads") is True:
            return True
        if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
            return True
    return False


def _ios_url_schemes(info: dict) -> list[str]:
    schemes: list[str] = []
    for entry in info.get("CFBundleURLTypes", []) or []:
        if isinstance(entry, dict):
            for s in entry.get("CFBundleURLSchemes", []) or []:
                if isinstance(s, str):
                    schemes.append(s)
    return schemes


def analyze_ipa(path: str, **_: Any) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    try:
        zf = zipfile.ZipFile(str(p))
    except zipfile.BadZipFile:
        return {"error": "not a valid IPA/ZIP file"}

    names = zf.namelist()
    info, app_prefix = _load_info_plist(zf)
    if not app_prefix:
        return {"error": "no Payload/*.app/Info.plist — not an IPA"}

    bundle_id = info.get("CFBundleIdentifier", "")
    display_name = info.get("CFBundleDisplayName") or info.get("CFBundleName", "")
    min_os = info.get("MinimumOSVersion", "")
    ats_cleartext = _ats_allows_cleartext(info)
    url_schemes = _ios_url_schemes(info)
    privacy = {k: _IOS_PRIVACY_KEYS[k] for k in info if k in _IOS_PRIVACY_KEYS}

    # Secret sweep across the app bundle (bounded), reusing the shared patterns.
    secrets, seen, scanned = [], set(), 0
    for name in names:
        if scanned > 80 or not name.startswith(app_prefix):
            if scanned > 80:
                break
            continue
        if name.endswith("/") or name.endswith(".png") or name.endswith(".car"):
            continue
        try:
            blob = zf.read(name)
        except Exception:
            continue
        scanned += 1
        for rx, label, sev in _SECRET_PATTERNS:
            for mo in rx.finditer(blob):
                snippet = mo.group(0)[:120].decode("latin1", "replace")
                if label == "cleartext http URL" and (
                        "localhost" in snippet or "127.0.0.1" in snippet
                        or "w3.org" in snippet or "apple.com/DTD" in snippet):
                    continue
                key = (label, snippet)
                if key in seen:
                    continue
                seen.add(key)
                secrets.append({"type": label, "severity": sev,
                                "match": snippet, "file": name})
                if len(secrets) >= 200:
                    break

    findings = _build_ipa_findings(ats_cleartext, url_schemes, privacy, secrets)
    return {"report": {"platform": "ios", "bundle_id": bundle_id,
                       "display_name": display_name, "minimum_os": min_os,
                       "ats_allows_cleartext": ats_cleartext,
                       "url_schemes": url_schemes,
                       "privacy_permissions": sorted(privacy.values()),
                       "secrets": secrets[:100]},
            "findings": findings,
            "summary": (f"iOS · {display_name or bundle_id} · "
                        f"{len(privacy)} privacy perm(s) · {len(secrets)} secret(s)"
                        + (" · ATS-cleartext" if ats_cleartext else ""))}


def _build_ipa_findings(ats_cleartext, url_schemes, privacy, secrets):
    findings = []
    crit_secrets = [s for s in secrets if s["severity"] in ("critical", "high")]
    if crit_secrets:
        sample = "; ".join(s["match"] for s in crit_secrets[:3])
        findings.append({
            "vuln_type": "ipa_hardcoded_secret", "severity": "high",
            "scanner": "ipa_analyzer", "confidence": 0.8,
            "title": f"{len(crit_secrets)} hardcoded secret(s) in the IPA",
            "description": ("The app bundle ships hardcoded credentials/keys "
                            f"recoverable from the IPA. Examples: {sample}."),
            "cwe": "CWE-798", "evidence": {"secrets": crit_secrets[:50]},
            "remediation": "Never ship secrets in the client; fetch them from a "
                           "server behind auth and rotate the exposed keys."})
    cleartext_urls = [s for s in secrets if s["type"] == "cleartext http URL"]
    if ats_cleartext or cleartext_urls:
        findings.append({
            "vuln_type": "ipa_cleartext_ats_disabled", "severity": "medium",
            "scanner": "ipa_analyzer", "confidence": 0.75,
            "title": "App Transport Security disabled / cleartext traffic",
            "description": ("The app allows arbitrary cleartext loads "
                            "(NSAllowsArbitraryLoads) or embeds http:// endpoints, "
                            "exposing data to network attackers."),
            "cwe": "CWE-319",
            "evidence": {"ats_allows_cleartext": ats_cleartext,
                         "urls": [s["match"] for s in cleartext_urls[:20]]},
            "remediation": "Remove NSAllowsArbitraryLoads; require HTTPS with ATS "
                           "and add per-domain exceptions only when unavoidable."})
    if url_schemes:
        findings.append({
            "vuln_type": "ipa_url_scheme", "severity": "low",
            "scanner": "ipa_analyzer", "confidence": 0.6,
            "title": f"{len(url_schemes)} custom URL scheme(s) registered",
            "description": ("The app registers custom URL schemes "
                            f"({', '.join(url_schemes[:8])}). Unvalidated deep links "
                            "are an input-validation and scheme-hijacking surface."),
            "cwe": "CWE-939", "evidence": {"url_schemes": url_schemes},
            "remediation": "Validate all deep-link input; prefer Universal Links "
                           "(associated domains) over custom schemes."})
    if privacy:
        findings.append({
            "vuln_type": "ipa_privacy_permissions", "severity": "info",
            "scanner": "ipa_analyzer", "confidence": 0.9,
            "title": f"{len(privacy)} privacy-sensitive permission(s) declared",
            "description": "The app declares access to: "
                           + ", ".join(sorted(privacy.values())) + ".",
            "cwe": "CWE-359", "evidence": {"permissions": sorted(privacy.values())}})
    return _tag_owasp(findings)
