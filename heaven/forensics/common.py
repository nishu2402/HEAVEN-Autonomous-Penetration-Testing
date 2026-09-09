"""HEAVEN — shared per-artifact enrichment applied to *every* uploaded file.

Whatever the artifact type, an analyst wants the same baseline for it: the
cryptographic hashes (to pivot on threat-intel), a coarse similarity
fingerprint, byte entropy (packing indicator), a magic/MIME identification, and
a YARA / signature sweep for known-bad content. This module computes that once
and the dispatcher stitches it onto the type-specific result, so a firmware
image and a PDF both carry a full ``file_overview`` and pick up any signature
match. Everything is derived from real bytes; nothing is fabricated.
"""

from __future__ import annotations

import hashlib
import math
import zipfile
import zlib
from pathlib import Path
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("forensics.common")

_SAMPLE = 32 * 1024 * 1024        # entropy/fingerprint sample cap
_HASH_CAP = 512 * 1024 * 1024     # hashing cap (streamed)


# ── decompression-bomb-safe readers (shared by the archive/document analyzers) ─
# A crafted upload can hide a "zip bomb": a member (or a deflate stream) that is
# tiny on disk but expands to gigabytes. ``zipfile.ZipFile.read`` and
# ``zlib.decompress`` both inflate the WHOLE thing into memory before the caller
# can slice it, so even code that only wants a small prefix can be made to
# exhaust memory. These helpers inflate incrementally and stop at a hard byte
# cap, so a hostile artifact can never make the analyzer OOM the tool.
def safe_zip_read(zf: zipfile.ZipFile, member: Any, cap: int,
                  *, ratio_limit: int = 1500) -> bytes:
    """Read at most ``cap`` DECOMPRESSED bytes from a zip member, safely.

    ``member`` may be a name or a ``ZipInfo``. A member whose declared
    uncompressed:compressed ratio is already implausible (a bomb signature) is
    skipped outright; otherwise the entry is opened and only ``cap`` bytes are
    inflated. Never raises — an unreadable/encrypted member yields ``b""``.
    """
    try:
        info = member if isinstance(member, zipfile.ZipInfo) else zf.getinfo(member)
    except KeyError:
        return b""
    comp = getattr(info, "compress_size", 0) or 0
    unc = getattr(info, "file_size", 0) or 0
    if comp and unc / max(comp, 1) > ratio_limit and unc > cap:
        logger.debug("skipping high-ratio zip entry %s (%d/%d)",
                     getattr(info, "filename", member), unc, comp)
        return b""
    try:
        with zf.open(info) as fh:               # bounded, incremental inflate
            data = fh.read(cap + 1)
    except Exception:                            # noqa: BLE001 — bad/encrypted member
        logger.debug("could not read zip entry", exc_info=True)
        return b""
    return data[:cap]


def safe_inflate(blob: bytes, wbits: int, *, max_output: int) -> bytes:
    """Inflate a raw deflate / zlib / gzip blob to at most ``max_output`` bytes.

    Uses a decompress object with a ``max_length`` so a small compressed blob
    that would expand to gigabytes (the decompression-bomb DoS) is stopped at
    the cap instead of being fully materialised in memory. Returns ``b""`` if
    ``blob`` is not compressed with the given window.
    """
    if not blob or max_output <= 0:
        return b""
    try:
        return zlib.decompressobj(wbits).decompress(blob, max_output)
    except Exception:                            # noqa: BLE001 — not a flate stream
        return b""


# ── magic / MIME identification (offline, no libmagic) ───────────────────────
def _identify(head: bytes) -> tuple[str, str]:
    """Return (human magic label, MIME type) from the file header."""
    sigs: list[tuple[bytes, int, str, str]] = [
        (b"\x7fELF", 0, "ELF binary", "application/x-executable"),
        (b"MZ", 0, "PE / DOS executable", "application/vnd.microsoft.portable-executable"),
        (b"\xca\xfe\xba\xbe", 0, "Mach-O universal / Java class", "application/x-mach-binary"),
        (b"\xfe\xed\xfa\xce", 0, "Mach-O 32-bit", "application/x-mach-binary"),
        (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit", "application/x-mach-binary"),
        (b"%PDF-", 0, "PDF document", "application/pdf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE2 compound document", "application/x-ole-storage"),
        (b"{\\rtf", 0, "RTF document", "application/rtf"),
        (b"PK\x03\x04", 0, "ZIP / OOXML / JAR", "application/zip"),
        (b"\x1f\x8b", 0, "gzip stream", "application/gzip"),
        (b"BZh", 0, "bzip2 stream", "application/x-bzip2"),
        (b"\xfd7zXZ\x00", 0, "xz stream", "application/x-xz"),
        (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", "application/x-7z-compressed"),
        (b"Rar!", 0, "RAR archive", "application/vnd.rar"),
        (b"\x89PNG", 0, "PNG image", "image/png"),
        (b"\xff\xd8\xff", 0, "JPEG image", "image/jpeg"),
        (b"GIF8", 0, "GIF image", "image/gif"),
        (b"\xd4\xc3\xb2\xa1", 0, "pcap capture", "application/vnd.tcpdump.pcap"),
        (b"\xa1\xb2\xc3\xd4", 0, "pcap capture", "application/vnd.tcpdump.pcap"),
        (b"\x0a\x0d\x0d\x0a", 0, "pcapng capture", "application/x-pcapng"),
        (b"hsqs", 0, "SquashFS filesystem", "application/octet-stream"),
        (b"UBI#", 0, "UBI firmware volume", "application/octet-stream"),
        (b"ftyp", 4, "ISO media (MP4/MOV)", "video/mp4"),
        (b"\x1aE\xdf\xa3", 0, "Matroska / WebM", "video/x-matroska"),
        (b"OggS", 0, "Ogg container", "application/ogg"),
        (b"fLaC", 0, "FLAC audio", "audio/flac"),
        (b"ID3", 0, "MP3 audio", "audio/mpeg"),
    ]
    for sig, off, label, mime in sigs:
        if head[off:off + len(sig)] == sig:
            return label, mime
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "WAV audio", "audio/wav"
    if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
        return "AVI video", "video/x-msvideo"
    if head[:5] == b"ustar" or (len(head) > 262 and head[257:262] == b"ustar"):
        return "tar archive", "application/x-tar"
    # printable-text heuristic
    sample = head[:512]
    if sample and sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126) / len(sample) > 0.95:
        return "text", "text/plain"
    return "data", "application/octet-stream"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _piecewise_fingerprint(data: bytes) -> str:
    """A coarse, honest similarity fingerprint (not ssdeep-compatible).

    The file is split into ~64 blocks; each block is reduced to one base-36
    character from an FNV-1a hash. Two files that share large runs of identical
    content share a recognizable prefix/segment — useful for clustering related
    artifacts within HEAVEN. It is a heuristic aid, not a cryptographic hash.
    """
    if not data:
        return ""
    blocks = 64
    step = max(1, len(data) // blocks)
    digest = []
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    for i in range(0, len(data), step):
        h = 2166136261
        for b in data[i:i + step]:
            h = ((h ^ b) * 16777619) & 0xFFFFFFFF
        digest.append(alphabet[h % 36])
        if len(digest) >= blocks:
            break
    return "".join(digest)


def file_overview(path: str) -> dict[str, Any]:
    """Compute hashes, entropy, magic/MIME and a fingerprint for one file."""
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        return {}
    # md5/sha1 are file-identity + threat-intel pivots (many feeds key on them),
    # never a security control, so they are marked usedforsecurity=False.
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    head = b""
    sample = bytearray()
    read = 0
    try:
        with open(p, "rb") as fh:
            while read < _HASH_CAP:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                if not head:
                    head = chunk[:512]
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                if len(sample) < _SAMPLE:
                    sample += chunk[: _SAMPLE - len(sample)]
                read += len(chunk)
    except OSError as e:
        return {"size": size, "error": str(e)}

    magic, mime = _identify(bytes(head))
    return {
        "size": size,
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "entropy": _entropy(bytes(sample)),
        "magic": magic,
        "mime": mime,
        "piecewise_fingerprint": _piecewise_fingerprint(bytes(sample)),
    }


def yara_findings(path: str, target: str) -> list[dict[str, Any]]:
    """Run the YARA / builtin signature engine and return HEAVEN findings."""
    try:
        from heaven.vulnscan.yara_engine import scan_file
        matches = scan_file(path)
    except Exception:                          # noqa: BLE001
        logger.debug("yara sweep failed for %s", path, exc_info=True)
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for m in matches:
        if m.rule in seen:
            continue
        seen.add(m.rule)
        out.append({
            "target": target, "vuln_type": f"signature_{m.rule.lower()}",
            "severity": m.severity if m.severity != "info" else "low",
            "title": f"Signature match: {m.rule.replace('_', ' ')}",
            "description": m.description, "scanner": f"{m.engine}_signature",
            "confidence": 0.8, "cwe": m.cwe, "mitre": m.mitre,
            "evidence": {"rule": m.rule, "engine": m.engine, "excerpt": m.excerpt},
            "remediation": "Confirm the match and treat the artifact as untrusted "
                           "until cleared in an isolated environment.",
        })
    return out
