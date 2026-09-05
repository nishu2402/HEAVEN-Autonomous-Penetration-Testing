"""HEAVEN — offline-artifact type detection and dispatch."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any, Callable

from heaven.utils.logger import get_logger

logger = get_logger("forensics.dispatch")

# Image / capture / binary magics for fast detection.
_IMAGE_MAGICS = (b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")
_PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
                b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
_FW_FS_SIGS = (b"hsqs", b"sqsh", b"UBI#", b"\x27\x05\x19\x56", b"\x85\x19")
_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Document / archive extension hints. .zip is intentionally excluded from the
# archive set — a PK zip is inspected by content (it may be an APK/IPA/OOXML).
_DOC_EXTS = {".pdf", ".doc", ".docx", ".docm", ".dotm", ".xls", ".xlsx", ".xlsm",
             ".ppt", ".pptx", ".pptm", ".rtf", ".msg"}
_ARCHIVE_EXTS = {".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".iso",
                 ".jar", ".war"}
_CERT_EXTS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p7b", ".csr"}


def detect_kind(path: str) -> str:
    """Return the artifact kind: binary | firmware | pcap | stego | apk | ipa |
    crypto | document | archive | unknown."""
    p = Path(path)
    ext = p.suffix.lower()
    try:
        with open(p, "rb") as f:
            head = f.read(4096)
    except OSError:
        return "unknown"

    # Extension is a strong hint first for the unambiguous ones.
    if ext in (".pcap", ".pcapng", ".cap"):
        return "pcap"
    if ext == ".apk":
        return "apk"
    if ext == ".ipa":
        return "ipa"
    if ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp"):
        return "stego"
    if ext in _DOC_EXTS:
        return "document"
    if ext in _ARCHIVE_EXTS:
        return "archive"

    # Magic-byte detection.
    if head[:5] == b"%PDF-" or head[:8] == _CFB_MAGIC or head[:5] == b"{\\rtf":
        return "document"
    if head[:4] == b"\x7fELF" or head[:2] == b"MZ" or (
            len(head) >= 4 and struct.unpack_from(">I", head, 0)[0] in (
                0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xCAFEBABF)):
        return "binary"
    if head[:4] in _PCAP_MAGICS:
        return "pcap"
    if any(head.startswith(m) for m in _IMAGE_MAGICS):
        return "stego"
    if head[:4] == b"PK\x03\x04":
        # ZIP family: APK / IPA / OOXML office document / generic archive.
        try:
            znames = zipfile.ZipFile(str(p)).namelist()
            if "AndroidManifest.xml" in znames:
                return "apk"
            # IPA: a Payload/<App>.app/Info.plist inside the zip.
            if any(n.startswith("Payload/") and n.endswith(".app/Info.plist")
                   for n in znames):
                return "ipa"
            # OOXML office document: the content-types part plus a doc folder.
            if "[Content_Types].xml" in znames and any(
                    n.startswith(("word/", "xl/", "ppt/")) for n in znames):
                return "document"
            return "archive"
        except Exception:
            logger.debug("zip inspection failed for %s", p, exc_info=True)
            return "archive"
    # Other archive containers (gzip / bzip2 / xz / 7z / rar / tar).
    if (head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00"
            or head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:4] == b"Rar!"
            or (len(head) > 262 and head[257:262] == b"ustar")):
        return "archive"
    # Firmware: filesystem signatures anywhere in the header, or a firmware ext.
    if any(sig in head for sig in _FW_FS_SIGS) or ext in (".bin", ".img", ".trx",
                                                          ".chk", ".fw", ".rom"):
        return "firmware"

    # X.509 certificate / key material — PEM markers, a cert extension, or a
    # DER ASN.1 SEQUENCE header (0x30 0x81/82/83). Checked after the more
    # specific magics above so it only ever rescues bytes that would otherwise
    # be "unknown"; the analyzer degrades gracefully if it is not really a cert.
    if b"-----BEGIN" in head and (b"CERTIFICATE-----" in head or b"PRIVATE KEY-----" in head
                                  or b"PUBLIC KEY-----" in head):
        return "certificate"
    if ext in _CERT_EXTS:
        return "certificate"
    if head[:1] == b"\x30" and len(head) >= 2 and head[1] in (0x81, 0x82, 0x83):
        return "certificate"

    # Text that looks like hashes → crypto.
    try:
        text = head.decode("utf-8", "ignore")
        import re
        if any(re.match(r"^[^:\s]*:?\$?[0-9a-fA-F$]{16,}", ln) for ln in text.splitlines()[:20]):
            return "crypto"
    except Exception:
        logger.debug("hash-text heuristic failed for %s", p, exc_info=True)
    return "unknown"


def _loader(kind: str) -> Callable[..., dict]:
    if kind == "binary":
        from heaven.forensics.binary import analyze_binary
        return analyze_binary
    if kind == "firmware":
        from heaven.forensics.firmware import analyze_firmware
        return analyze_firmware
    if kind == "pcap":
        from heaven.forensics.pcap import analyze_pcap
        return analyze_pcap
    if kind == "stego":
        from heaven.forensics.stego import analyze_stego
        return analyze_stego
    if kind == "apk":
        from heaven.forensics.mobile import analyze_apk
        return analyze_apk
    if kind == "ipa":
        from heaven.forensics.mobile import analyze_ipa
        return analyze_ipa
    if kind == "crypto":
        from heaven.forensics.crypto import analyze_crypto
        return analyze_crypto
    if kind == "certificate":
        from heaven.forensics.certificate import analyze_certificate
        return analyze_certificate
    if kind == "document":
        from heaven.forensics.document import analyze_document
        return analyze_document
    if kind == "archive":
        from heaven.forensics.archive import analyze_archive
        return analyze_archive
    raise ValueError(f"no analyzer for kind={kind}")


def _enrich(path: str, result: dict[str, Any]) -> dict[str, Any]:
    """Attach the shared per-file overview + YARA sweep to any result."""
    try:
        from heaven.forensics.common import file_overview, yara_findings
        rep = result.get("report")
        if isinstance(rep, dict):
            rep.setdefault("file_overview", file_overview(path))
        sig = yara_findings(path, path)
        if sig:
            existing = result.setdefault("findings", [])
            have = {f.get("vuln_type") for f in existing}
            existing.extend(f for f in sig if f.get("vuln_type") not in have)
    except Exception:
        logger.debug("common enrichment failed for %s", path, exc_info=True)
    return result


def analyze_artifact(path: str, kind: str = "", **kwargs: Any) -> dict[str, Any]:
    """Detect (or use given ``kind``) and run the matching analyzer.

    Returns the analyzer result plus ``{"kind": ...}``. Every result — even an
    unknown type — carries a shared ``file_overview`` (hashes, entropy, magic)
    and any YARA / signature matches, so no upload comes back empty-handed.
    """
    k = kind or detect_kind(path)
    if k == "unknown":
        from heaven.forensics.common import file_overview, yara_findings
        ov = file_overview(path)
        return {"error": f"could not determine artifact type for {path}",
                "kind": "unknown",
                "report": {"file_overview": ov} if ov else {},
                "findings": yara_findings(path, path),
                "summary": ov.get("magic", "") if ov else ""}
    result = _loader(k)(path, **kwargs)
    result["kind"] = k
    return _enrich(path, result)
