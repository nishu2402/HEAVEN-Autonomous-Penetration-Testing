"""HEAVEN — offline authorized-artifact analysis.

This package analyzes files an operator is authorized to examine, closing the
pentest domains that cannot be done remotely without hardware or weaponization
but are core to CEH/CPENT work:

* ``binary``   — ELF / PE / Mach-O static analysis (checksec, dangerous
                 imports, entropy / packing, exploit-mitigation posture).
* ``firmware`` — firmware image carving (embedded filesystems, keys, creds).
* ``pcap``     — packet-capture analysis (cleartext creds, DDoS indicators,
                 IoT/OT protocol messages, top talkers).
* ``crypto``   — hash identification + offline dictionary cracking, weak-hash
                 flagging, and encoded-text decoding.
* ``stego``    — image steganography detection (LSB, trailing data, embedded
                 files, EXIF secrets).
* ``mobile``   — APK static analysis (manifest, permissions, exported
                 components, embedded secrets).

Every analyzer works on a local file the operator supplies. Nothing is
fabricated: a finding reflects real bytes read from the artifact.
"""

from __future__ import annotations

__all__ = ["analyze_artifact", "detect_kind"]


def detect_kind(path: str) -> str:
    """Best-effort artifact-type detection from magic bytes / extension."""
    from heaven.forensics.dispatch import detect_kind as _d
    return _d(path)


def analyze_artifact(path: str, **kwargs):
    """Auto-detect the artifact type and run the matching analyzer."""
    from heaven.forensics.dispatch import analyze_artifact as _a
    return _a(path, **kwargs)
