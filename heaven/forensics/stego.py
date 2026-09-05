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

import struct
import zlib
from pathlib import Path
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("forensics.stego")

# Decompression-bomb defense for image parsing. A few-KB PNG/JPEG can declare
# enormous dimensions; decoding it to a pixel buffer would exhaust memory. We
# pin Pillow's own ceiling low (it errors above 2x this at open time) AND skip
# any pixel-level pass (tobytes) above _MAX_PIXELS, so a hostile image can never
# make HEAVEN allocate gigabytes. 64 MP covers any real-world photograph.
_MAX_PIXELS = 64_000_000
_MAX_READ = 128 * 1024 * 1024        # defensive cap on the byte-level image read


def _harden_pillow() -> None:
    try:
        from PIL import Image
        # Only lower it; never raise a stricter host setting.
        if Image.MAX_IMAGE_PIXELS is None or Image.MAX_IMAGE_PIXELS > _MAX_PIXELS:
            Image.MAX_IMAGE_PIXELS = _MAX_PIXELS
    except Exception:  # noqa: BLE001 - Pillow optional
        logger.debug("could not harden Pillow pixel ceiling", exc_info=True)


def _pixels_ok(img: Any) -> bool:
    """True when this image is small enough for a full pixel pass."""
    try:
        return (int(img.width) * int(img.height)) <= _MAX_PIXELS
    except Exception:  # noqa: BLE001
        return False

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


def _lsb_pack(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
        if byte == 0 and len(out) > 4:
            break
    return bytes(out).split(b"\x00", 1)[0]


def _lsb_text(path: str) -> Optional[dict]:
    """Recover an LSB-hidden message, trying the common embedding orders (all
    channels interleaved, then each single R/G/B channel). Returns the recovered
    text plus which order matched, or None."""
    try:
        from PIL import Image
    except ImportError:
        return None
    _harden_pillow()
    try:
        img = Image.open(path)
        if not _pixels_ok(img):
            logger.debug("skipping LSB pass on oversized image %s", path)
            return None
        raw = img.convert("RGB").tobytes()  # R,G,B,R,G,B,...
    except Exception:
        return None
    cap = min(len(raw), 4096 * 8 * 3)
    orders = [("RGB-sequential", range(0, min(len(raw), 4096 * 8)))]
    for ci, cname in enumerate(("R", "G", "B")):
        orders.append((f"{cname}-channel", range(ci, cap, 3)))
    for label, idxs in orders:
        text = _lsb_pack([raw[i] & 1 for i in idxs])
        if len(text) >= 5:
            printable = sum(1 for b in text if 32 <= b < 127)
            if printable / len(text) > 0.9:
                return {"order": label, "text": text.decode("latin1", "replace")}
    return None


def _image_meta(path: str) -> dict:
    try:
        from PIL import Image
        with Image.open(path) as img:
            meta = {"format": img.format, "mode": img.mode,
                    "width": img.width, "height": img.height}
            n = getattr(img, "n_frames", 1)
            if n and n > 1:
                meta["frames"] = n
            return meta
    except Exception:
        return {}


def _png_chunks(data: bytes) -> tuple[list[dict], Optional[int]]:
    """Walk PNG chunks; return (text-chunks, offset of data after IEND or None)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return [], None
    texts: list[dict] = []
    off = 8
    after_iend = None
    n = len(data)
    while off + 8 <= n:
        length = struct.unpack_from(">I", data, off)[0]
        ctype = data[off + 4:off + 8]
        body = data[off + 8:off + 8 + length]
        if ctype in (b"tEXt", b"iTXt"):
            try:
                kw, _, val = body.partition(b"\x00")
                texts.append({"chunk": ctype.decode(), "keyword": kw.decode("latin1", "replace")[:40],
                              "text": val.decode("latin1", "replace")[:200]})
            except Exception:
                logger.debug("PNG text chunk decode failed", exc_info=True)
        elif ctype == b"zTXt":
            try:
                kw, _, comp = body.partition(b"\x00")
                val = zlib.decompressobj().decompress(comp[1:], 1_000_000)
                texts.append({"chunk": "zTXt", "keyword": kw.decode("latin1", "replace")[:40],
                              "text": val.decode("latin1", "replace")[:200]})
            except Exception:
                logger.debug("PNG zTXt decompress failed", exc_info=True)
        off += 12 + length
        if ctype == b"IEND":
            after_iend = off if off < n else None
            break
    return texts, after_iend


def _jpeg_comments(data: bytes) -> list[str]:
    """Extract JPEG COM (0xFFFE) comment segments."""
    if data[:2] != b"\xff\xd8":
        return []
    out: list[str] = []
    i, n = 2, len(data)
    while i + 4 < n and len(out) < 20:
        if data[i] != 0xFF:
            break
        marker = data[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        seg_len = struct.unpack_from(">H", data, i + 2)[0]
        if marker == 0xFE:                        # COM
            out.append(data[i + 4:i + 2 + seg_len].decode("latin1", "replace")[:200])
        if marker == 0xDA:                        # start of scan — stop
            break
        i += 2 + seg_len
    return [c for c in out if c.strip()]


def _lsb_pairs_metric(path: str) -> Optional[dict]:
    """A chi-square-style test: LSB-embedded images have value-pair histograms
    that equalise (h[2i] ~= h[2i+1]). Returns a suspicion metric per the sample."""
    _harden_pillow()
    try:
        from PIL import Image
        with Image.open(path) as im:
            if not _pixels_ok(im):
                logger.debug("skipping LSB-pairs pass on oversized image %s", path)
                return None
            img = im.convert("L")
            px = img.tobytes()
    except Exception:
        return None
    if len(px) < 4096:
        return None
    hist = [0] * 256
    for b in px:
        hist[b] += 1
    equal, total = 0.0, 0
    for i in range(0, 256, 2):
        a, b = hist[i], hist[i + 1]
        if a + b >= 16:
            equal += abs(a - b) / (a + b)
            total += 1
    if total < 8:
        return None
    mean_diff = equal / total                     # 0 = fully equalised (stego-like)
    suspicious = mean_diff < 0.06
    return {"pair_difference": round(mean_diff, 4), "pairs_tested": total,
            "suspicious": suspicious}


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
        logger.debug("EXIF read failed for %s", path, exc_info=True)
    return out


def analyze_stego(path: str, **_: Any) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    _harden_pillow()
    # Byte-level checks scan the whole file, so bound the read: a real image is
    # small, and a hundreds-of-MB "image" is itself the anomaly, not a reason to
    # buffer it all in memory.
    with open(p, "rb") as _fh:
        data = _fh.read(_MAX_READ)
    findings: list[dict] = []
    report: dict[str, Any] = {}

    meta = _image_meta(str(p))
    if meta:
        report["image"] = meta

    # PNG text chunks + trailing data after IEND.
    png_texts, after_iend = _png_chunks(data)
    if png_texts:
        report["png_text_chunks"] = png_texts
        findings.append({
            "vuln_type": "stego_metadata_text", "severity": "low",
            "scanner": "stego_analyzer", "confidence": 0.7,
            "title": f"{len(png_texts)} PNG text chunk(s) carry embedded data",
            "description": ("The PNG has tEXt/zTXt/iTXt metadata chunks that can hide "
                            "arbitrary text/comments: "
                            + "; ".join(f"{t['keyword']}={t['text'][:30]}" for t in png_texts[:3])),
            "cwe": "CWE-311", "evidence": {"chunks": png_texts[:10]}})

    # JPEG comment segments.
    jpeg_comments = _jpeg_comments(data)
    if jpeg_comments:
        report["jpeg_comments"] = jpeg_comments
        findings.append({
            "vuln_type": "stego_jpeg_comment", "severity": "low",
            "scanner": "stego_analyzer", "confidence": 0.7,
            "title": f"{len(jpeg_comments)} JPEG comment segment(s) with data",
            "description": "The JPEG carries COM comment segments that can hide text: "
                           + "; ".join(c[:40] for c in jpeg_comments[:3]),
            "cwe": "CWE-311", "evidence": {"comments": jpeg_comments[:10]}})

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
        report["lsb_text"] = lsb["text"][:200]
        report["lsb_order"] = lsb["order"]
        findings.append({
            "vuln_type": "stego_lsb_payload", "severity": "high",
            "scanner": "stego_analyzer", "confidence": 0.8,
            "title": "LSB steganography payload recovered",
            "description": ("The least-significant-bit plane of the image "
                            f"({lsb['order']}) decodes to printable text, indicating "
                            f"an LSB-hidden message: '{lsb['text'][:60]}'."),
            "cwe": "CWE-311", "evidence": {"recovered": lsb["text"][:200],
                                           "order": lsb["order"]}})

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

    # Statistical LSB test (only meaningful when nothing was already recovered).
    lsb_stat = _lsb_pairs_metric(str(p))
    if lsb_stat:
        report["lsb_statistics"] = lsb_stat
        if lsb_stat["suspicious"] and not lsb:
            findings.append({
                "vuln_type": "stego_lsb_anomaly", "severity": "medium",
                "scanner": "stego_analyzer", "confidence": 0.55,
                "title": "Statistical LSB anomaly (possible hidden data)",
                "description": ("A chi-square-style test found the image's value-pair "
                                "histogram unusually equalised "
                                f"(pair difference {lsb_stat['pair_difference']}), a "
                                "statistical signature of LSB steganography. This is "
                                "an indicator, not proof — confirm with extraction."),
                "cwe": "CWE-311", "evidence": lsb_stat})

    return {"report": report, "findings": findings,
            "summary": (f"{len(findings)} stego indicator(s)"
                        if findings else "no steganography indicators")}
