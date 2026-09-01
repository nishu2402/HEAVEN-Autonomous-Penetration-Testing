"""HEAVEN — image steganography detection.

Reproduces the CEH steganography workflow (OpenStego/steghide-style hidden
data) on an operator-supplied image:

* **Trailing data** after the image's real end-of-file marker (the most common
  "hide a zip after the JPEG" trick) — with embedded-file-signature ID.
* **LSB payloads** — extracts the least-significant-bit plane and reports when
  it decodes to printable text or is anomalously structured.
* **EXIF secrets** — comments / UserComment fields carrying data.

Pillow is used for pixel access; the trailing-data and EXIF checks are
byte-level and work regardless.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("forensics.stego")

# Where a well-formed image really ends.
_JPEG_EOI = b"\xff\xd9"
_PNG_IEND = b"IEND\xae\x42\x60\x82"
_GIF_TRAILER = b"\x3b"

# Signatures that reveal a file hidden in trailing/LSB data.
_EMBEDDED_SIGS = [
    (b"PK\x03\x04", "ZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF", "PDF document"),
    (b"\x7fELF", "ELF executable"),
    (b"-----BEGIN", "PEM key/cert"),
    (b"StegoStego", "OpenStego marker"),
]


def _trailing_data(data: bytes) -> Optional[tuple[int, bytes]]:
    """Return (offset, trailing_bytes) of data after the image's real EOF."""
    if data[:2] == b"\xff\xd8":  # JPEG
        idx = data.rfind(_JPEG_EOI)
        if idx != -1 and idx + 2 < len(data):
            return idx + 2, data[idx + 2:]
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        idx = data.rfind(_PNG_IEND)
        if idx != -1 and idx + len(_PNG_IEND) < len(data):
            return idx + len(_PNG_IEND), data[idx + len(_PNG_IEND):]
    elif data[:3] == b"GIF":
        idx = data.rfind(_GIF_TRAILER)
        if idx != -1 and idx + 1 < len(data) - 8:
            return idx + 1, data[idx + 1:]
    return None


def _id_embedded(blob: bytes) -> str:
    head = blob[:64]
    for sig, label in _EMBEDDED_SIGS:
        if sig in head or blob[:len(sig)] == sig:
            return label
    printable = sum(1 for b in blob[:200] if 32 <= b < 127)
    if printable / max(1, min(len(blob), 200)) > 0.85:
        return "ASCII text"
    return "unknown binary"


def _lsb_text(path: str) -> Optional[str]:
    """Extract the LSB plane and return decoded printable text if it looks like
    a hidden message. Bounded to the first ~4 KB of recovered bytes."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        img = Image.open(path).convert("RGB")
        raw = img.tobytes()  # R,G,B,R,G,B,... — not deprecated, fast
    except Exception:
        return None
    limit = min(len(raw), 4096 * 8)
    bits = bytearray(raw[i] & 1 for i in range(limit))
    # Pack bits → bytes
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
        if byte == 0 and len(out) > 4:
            break
    text = out.split(b"\x00", 1)[0]
    if len(text) >= 5:
        printable = sum(1 for b in text if 32 <= b < 127)
        if printable / len(text) > 0.9:
            return text.decode("latin1", "replace")
    return None


def _exif_secrets(path: str) -> list[str]:
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return []
    out = []
    try:
        img = Image.open(path)
        exif = getattr(img, "_getexif", lambda: None)()
        if exif:
            for tag_id, val in exif.items():
                name = TAGS.get(tag_id, str(tag_id))
                if name in ("UserComment", "ImageDescription", "XPComment", "Artist"):
                    sval = val.decode("latin1", "replace") if isinstance(val, bytes) else str(val)
                    if sval.strip():
                        out.append(f"{name}: {sval[:120]}")
    except Exception:
        pass
    return out


def analyze_stego(path: str, **_: Any) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    data = p.read_bytes()
    findings, report = [], {}

    trailing = _trailing_data(data)
    if trailing:
        off, blob = trailing
        kind = _id_embedded(blob)
        report["trailing_data"] = {"offset": off, "bytes": len(blob), "type": kind}
        findings.append({
            "vuln_type": "stego_trailing_data", "severity": "high",
            "scanner": "stego_analyzer", "confidence": 0.9,
            "title": f"Hidden data appended after image EOF ({kind}, {len(blob)} bytes)",
            "description": (f"{len(blob)} bytes of data follow the image's real "
                            f"end-of-file marker at offset {off}. This is the classic "
                            f"'file hidden inside an image' technique; the payload "
                            f"looks like: {kind}."),
            "cwe": "CWE-311", "evidence": {"offset": off, "type": kind,
                                           "preview": blob[:48].hex()}})

    lsb = _lsb_text(str(p))
    if lsb:
        report["lsb_text"] = lsb[:200]
        findings.append({
            "vuln_type": "stego_lsb_payload", "severity": "high",
            "scanner": "stego_analyzer", "confidence": 0.75,
            "title": "LSB steganography payload recovered",
            "description": ("The least-significant-bit plane of the image decodes to "
                            f"printable text, indicating an LSB-hidden message: "
                            f"'{lsb[:60]}'."),
            "cwe": "CWE-311", "evidence": {"recovered": lsb[:200]}})

    exif = _exif_secrets(str(p))
    if exif:
        report["exif"] = exif
        findings.append({
            "vuln_type": "stego_exif_data", "severity": "low",
            "scanner": "stego_analyzer", "confidence": 0.6,
            "title": "Data hidden in EXIF metadata",
            "description": "The image carries free-text EXIF fields that may hold a "
                           "hidden message: " + "; ".join(exif[:3]),
            "evidence": {"exif": exif}})

    return {"report": report, "findings": findings,
            "summary": (f"{len(findings)} stego indicator(s)"
                        if findings else "no steganography indicators")}
