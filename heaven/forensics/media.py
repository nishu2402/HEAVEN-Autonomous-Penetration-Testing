"""HEAVEN — audio / video / container artifact handling.

Media files (MP4, MOV, MKV, WebM, AVI, WAV, MP3, FLAC, Ogg, and similar) are not
security artifacts, so HEAVEN does not decode their codecs or claim to analyze
their content. What this module guarantees is an honest, non-alarming result: the
file is recognized as media, fingerprinted (hashes, entropy, magic/MIME via the
shared ``file_overview``), and swept for known-malware signatures by the always-on
engine. The point is that a real video no longer falls through to the "unknown"
path, where its raw bytes were scanned as if they were source text.
"""
from __future__ import annotations

import os
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("forensics.media")

# First-box / magic labels for a friendlier one-line summary.
_LABELS: tuple[tuple[bytes, int, str], ...] = (
    (b"ftyp", 4, "ISO base media (MP4/MOV/M4A/3GP)"),
    (b"\x1aE\xdf\xa3", 0, "Matroska / WebM"),
    (b"OggS", 0, "Ogg container"),
    (b"fLaC", 0, "FLAC audio"),
    (b"ID3", 0, "MP3 audio (ID3)"),
    (b"RIFF", 0, "RIFF (AVI / WAV)"),
    (b"FWS", 0, "Flash (uncompressed)"),
    (b"CWS", 0, "Flash (compressed)"),
)


def _container_label(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return "media file"
    for sig, off, label in _LABELS:
        if head[off:off + len(sig)] == sig:
            return label
    return "media file"


def analyze_media(path: str, **_: Any) -> dict[str, Any]:
    """Return a clean, honest result for an audio/video/container file.

    The shared enrichment step (``dispatch._enrich``) adds the file overview and
    the signature sweep, so this analyzer only supplies the framing: what the
    file is and that codec-level analysis is deliberately not performed.
    """
    if not os.path.isfile(path):
        return {"error": f"not a file: {path}", "report": {}, "findings": []}
    label = _container_label(path)
    size = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        logger.debug("could not stat media file %s", path, exc_info=True)
    return {
        "report": {
            "media_type": label,
            "note": ("Audio/video container. HEAVEN fingerprints the file and "
                     "sweeps it for known-malware signatures; codec-level "
                     "decoding is not performed."),
        },
        "findings": [],
        "summary": f"{label} · {size:,} bytes",
    }
