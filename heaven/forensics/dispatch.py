"""HEAVEN — offline-artifact type detection and dispatch."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any, Callable

# Image / capture / binary magics for fast detection.
_IMAGE_MAGICS = (b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")
_PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
                b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
_FW_FS_SIGS = (b"hsqs", b"sqsh", b"UBI#", b"\x27\x05\x19\x56", b"\x85\x19")


def detect_kind(path: str) -> str:
    """Return one of: binary | firmware | pcap | stego | apk | ipa | crypto | unknown."""
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

    # Magic-byte detection.
    if head[:4] == b"\x7fELF" or head[:2] == b"MZ" or (
            len(head) >= 4 and struct.unpack_from(">I", head, 0)[0] in (
                0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xCAFEBABF)):
        return "binary"
    if head[:4] in _PCAP_MAGICS:
        return "pcap"
    if any(head.startswith(m) for m in _IMAGE_MAGICS):
        return "stego"
    if head[:4] == b"PK\x03\x04":
        # ZIP: APK if it holds an AndroidManifest, else treat as archive/firmware.
        try:
            znames = zipfile.ZipFile(str(p)).namelist()
            if "AndroidManifest.xml" in znames:
                return "apk"
            # IPA: a Payload/<App>.app/Info.plist inside the zip.
            if any(n.startswith("Payload/") and n.endswith(".app/Info.plist")
                   for n in znames):
                return "ipa"
        except Exception:
            pass
    # Firmware: filesystem signatures anywhere in the header, or a firmware ext.
    if any(sig in head for sig in _FW_FS_SIGS) or ext in (".bin", ".img", ".trx",
                                                          ".chk", ".fw", ".rom"):
        return "firmware"

    # Text that looks like hashes → crypto.
    try:
        text = head.decode("utf-8", "ignore")
        import re
        if any(re.match(r"^[^:\s]*:?\$?[0-9a-fA-F$]{16,}", ln) for ln in text.splitlines()[:20]):
            return "crypto"
    except Exception:
        pass
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
    raise ValueError(f"no analyzer for kind={kind}")


def analyze_artifact(path: str, kind: str = "", **kwargs: Any) -> dict[str, Any]:
    """Detect (or use given ``kind``) and run the matching analyzer.

    Returns the analyzer result plus ``{"kind": ...}``. Unknown types return an
    error dict rather than guessing.
    """
    k = kind or detect_kind(path)
    if k == "unknown":
        return {"error": f"could not determine artifact type for {path}", "kind": "unknown"}
    result = _loader(k)(path, **kwargs)
    result["kind"] = k
    return result
