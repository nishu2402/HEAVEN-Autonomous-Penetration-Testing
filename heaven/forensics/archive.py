"""HEAVEN — generic archive forensics (zip / jar / tar / gz / bz2 / xz / 7z / rar / iso).

APK/IPA/OOXML zips already route to their specialised analyzers; this handles
*every other* archive an operator might be handed. It never extracts to disk —
it reads the container's directory/metadata only — and reports:

* **Zip-slip / path traversal** — members whose path escapes the extraction
  root (``../`` or absolute / drive-letter paths, or tar symlinks pointing out).
* **Decompression bombs** — an implausible uncompressed:compressed ratio or a
  huge declared uncompressed size (the "zip bomb" DoS).
* **Dropped executables** — entries that are executables / scripts, or that use a
  deceptive double extension (``invoice.pdf.exe``).
* **Embedded secrets** — API keys / private keys inside small text members.
* **Encryption / oddities** — password-protected members, device/symlink tar
  members, and excessive entry counts.

Pure-Python (stdlib ``zipfile`` / ``tarfile`` / ``gzip`` / ``lzma`` / ``bz2``);
7z / rar / iso are detected and described from their headers without a full
parser, so they still yield a real, honest result.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("forensics.archive")

_MAX_ENTRIES = 20000
_BOMB_RATIO = 120          # uncompressed:compressed ratio that flags a bomb
_BOMB_TOTAL = 1024 * 1024 * 1024   # 1 GiB declared-uncompressed ceiling

_EXE_EXTS = {".exe", ".dll", ".scr", ".com", ".msi", ".cpl", ".ocx", ".sys",
             ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
             ".hta", ".jar", ".lnk", ".chm", ".reg", ".sh", ".elf", ".so",
             ".dylib", ".apk", ".app", ".deb", ".rpm", ".pkg", ".dmg"}
_DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
             ".jpg", ".jpeg", ".png", ".gif", ".rtf", ".csv", ".zip"}

_SECRET_RE = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(rb"ghp_[0-9A-Za-z]{36}"), "GitHub token"),
    (re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack token"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(rb"(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,60}['\"]"),
     "credential assignment"),
]


def _carve_secrets(data: bytes, source: str) -> list[dict]:
    out: list[dict] = []
    for rx, label in _SECRET_RE:
        for m in rx.finditer(data):
            out.append({"type": label, "source": source,
                        "match": m.group(0)[:80].decode("latin1", "replace")})
            if len(out) >= 8:
                return out
    return out


def _mk(target: str):
    findings: list[dict] = []

    def add(vt: str, sev: str, title: str, desc: str, **extra: Any) -> None:
        findings.append({
            "target": target, "vuln_type": vt, "severity": sev, "title": title,
            "description": desc, "scanner": "archive_analyzer",
            "confidence": extra.pop("confidence", 0.85),
            "cwe": extra.pop("cwe", ""), "remediation": extra.pop("remediation", ""),
            **extra,
        })

    return findings, add


def _is_unsafe_path(name: str) -> bool:
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return True
    parts = n.split("/")
    return ".." in parts


def _double_ext(name: str) -> bool:
    base = Path(name).name.lower()
    bits = base.split(".")
    if len(bits) < 3:
        return False
    return ("." + bits[-1]) in _EXE_EXTS and ("." + bits[-2]) in {e.lstrip("") for e in _DOC_EXTS}


# ── zip ───────────────────────────────────────────────────────────────────────
def _analyze_zip(path: str, target: str) -> dict[str, Any]:
    findings, add = _mk(target)
    report: dict[str, Any] = {"archive_type": "zip"}
    zf = zipfile.ZipFile(path)
    infos = zf.infolist()[:_MAX_ENTRIES]
    report["entries"] = len(zf.infolist())

    total_unc = total_comp = 0
    unsafe: list[str] = []
    executables: list[str] = []
    double_ext: list[str] = []
    worst_ratio = 0.0
    enc_count = 0
    for zi in infos:
        total_unc += zi.file_size
        total_comp += zi.compress_size
        if zi.flag_bits & 0x1:
            enc_count += 1
        if _is_unsafe_path(zi.filename):
            unsafe.append(zi.filename)
        ext = Path(zi.filename).suffix.lower()
        if ext in _EXE_EXTS:
            executables.append(zi.filename)
        if _double_ext(zi.filename):
            double_ext.append(zi.filename)
        if zi.compress_size > 32 and zi.file_size:
            worst_ratio = max(worst_ratio, zi.file_size / max(zi.compress_size, 1))

    report["total_uncompressed"] = total_unc
    report["total_compressed"] = total_comp
    overall_ratio = round(total_unc / total_comp, 1) if total_comp else 0
    report["compression_ratio"] = overall_ratio
    if executables:
        report["executables"] = executables[:60]
    if unsafe:
        report["unsafe_paths"] = unsafe[:60]

    # secrets in small text members
    secrets: list[dict] = []
    for zi in infos:
        if zi.file_size == 0 or zi.file_size > 512 * 1024:
            continue
        if Path(zi.filename).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif",
                                                ".zip", ".gz", ".class", ".woff"}:
            continue
        try:
            blob = zf.read(zi)[:512 * 1024]
        except Exception:                    # noqa: BLE001 (encrypted / bad member)
            continue
        secrets += _carve_secrets(blob, zi.filename)
        if len(secrets) >= 12:
            break
    if secrets:
        report["embedded_secrets"] = secrets

    # ── findings ──
    if unsafe:
        add("archive_zip_slip", "high", "Zip-slip / path traversal in archive",
            f"{len(unsafe)} member(s) use a path that escapes the extraction "
            f"directory (e.g. {unsafe[0]}). Extracting them can overwrite files "
            "outside the target folder — the zip-slip vulnerability.",
            cwe="CWE-22", confidence=0.9, evidence={"paths": unsafe[:20]},
            remediation="Never extract these paths; sanitize member names against "
                        "the destination root before extraction.")
    if (overall_ratio >= _BOMB_RATIO or worst_ratio >= _BOMB_RATIO * 4
            or total_unc >= _BOMB_TOTAL):
        add("archive_decompression_bomb", "medium", "Possible decompression bomb",
            f"The archive expands to {total_unc:,} bytes "
            f"(ratio ~{overall_ratio}:1). A hostile archive with an extreme "
            "expansion ratio can exhaust disk/memory on extraction.",
            cwe="CWE-409", confidence=0.6,
            evidence={"uncompressed": total_unc, "compressed": total_comp,
                      "ratio": overall_ratio, "worst_member_ratio": round(worst_ratio, 1)})
    if double_ext:
        add("archive_double_extension", "high", "Deceptive double-extension file",
            f"Member(s) hide an executable behind a document extension "
            f"(e.g. {double_ext[0]}). This tricks a user into running a program "
            "they think is a document.", cwe="CWE-646", confidence=0.85,
            evidence={"files": double_ext[:20]})
    elif executables:
        add("archive_dropped_executable", "medium", "Archive contains executable(s)/script(s)",
            f"The archive carries {len(executables)} executable/script file(s) "
            f"(e.g. {executables[0]}). Archives are a common delivery wrapper for "
            "malware droppers.", cwe="CWE-506", confidence=0.6,
            evidence={"files": executables[:20]})
    if enc_count:
        add("archive_encrypted", "info", "Password-protected archive member(s)",
            f"{enc_count} member(s) are encrypted. Password-protected archives are "
            "used to evade content scanning at mail gateways.", cwe="CWE-693",
            confidence=0.7, evidence={"encrypted_members": enc_count})
    if secrets:
        add("archive_embedded_secret", "high", "Secret/key inside the archive",
            "Credential/key material was found in an archived file: "
            + "; ".join(f"{s['source']}:{s['type']}" for s in secrets[:3]) + ".",
            cwe="CWE-798", confidence=0.8, evidence={"secrets": secrets[:10]})

    summary = (f"zip · {report['entries']} entries · ratio {overall_ratio}:1"
               + (f" · {len(executables)} exe/scripts" if executables else "")
               + (" · zip-slip" if unsafe else ""))
    return {"report": report, "findings": findings, "summary": summary}


# ── tar (and tar.gz/bz2/xz) ─────────────────────────────────────────────────
def _analyze_tar(path: str, target: str) -> dict[str, Any]:
    findings, add = _mk(target)
    report: dict[str, Any] = {"archive_type": "tar"}
    try:
        tf = tarfile.open(path)
    except Exception as e:                   # noqa: BLE001
        return {"report": {"error": f"unreadable tar: {e}"}, "findings": [],
                "summary": "unreadable tar"}
    unsafe: list[str] = []
    links: list[dict] = []
    executables: list[str] = []
    devices = 0
    total = 0
    count = 0
    with tf:
        for m in tf:
            count += 1
            if count > _MAX_ENTRIES:
                break
            total += m.size
            if _is_unsafe_path(m.name) or (m.issym() or m.islnk()) and _is_unsafe_path(m.linkname or ""):
                unsafe.append(m.name)
            if m.issym() or m.islnk():
                links.append({"name": m.name, "target": m.linkname})
                if m.linkname and (m.linkname.startswith("/") or ".." in m.linkname.split("/")):
                    unsafe.append(f"{m.name} -> {m.linkname}")
            if m.ischr() or m.isblk() or m.isfifo():
                devices += 1
            if Path(m.name).suffix.lower() in _EXE_EXTS:
                executables.append(m.name)
    report["entries"] = count
    report["total_uncompressed"] = total
    if links:
        report["links"] = links[:40]
    if executables:
        report["executables"] = executables[:60]

    if unsafe:
        add("archive_tar_slip", "high", "Path traversal / unsafe link in tar",
            f"{len(unsafe)} member(s) traverse outside the extraction root or link "
            f"to an absolute/parent path (e.g. {unsafe[0]}).", cwe="CWE-22",
            confidence=0.9, evidence={"paths": unsafe[:20]},
            remediation="Extract with a filter that rejects absolute/.. paths "
                        "(Python 3.12 tarfile filter='data').")
    if devices:
        add("archive_device_node", "low", "Tar contains device/special nodes",
            f"The archive declares {devices} device/FIFO node(s), which are "
            "unusual in a distributed archive and can be abused on extraction as "
            "root.", cwe="CWE-668", confidence=0.6)
    if executables:
        add("archive_dropped_executable", "medium", "Archive contains executable(s)/script(s)",
            f"{len(executables)} executable/script member(s) (e.g. {executables[0]}).",
            cwe="CWE-506", confidence=0.6, evidence={"files": executables[:20]})

    summary = f"tar · {count} entries · {total:,} bytes" + (" · unsafe paths" if unsafe else "")
    return {"report": report, "findings": findings, "summary": summary}


# ── single-stream gz / bz2 / xz ─────────────────────────────────────────────
def _analyze_stream_archive(path: str, target: str, kind: str) -> dict[str, Any]:
    findings, add = _mk(target)
    report: dict[str, Any] = {"archive_type": kind}
    opener = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[kind]
    read = 0
    sample = b""
    try:
        with opener(path, "rb") as fh:       # type: ignore[operator]
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                if not sample:
                    sample = chunk[:8192]
                read += len(chunk)
                if read > _BOMB_TOTAL:
                    add("archive_decompression_bomb", "medium",
                        "Possible decompression bomb",
                        f"The {kind} stream expands past {_BOMB_TOTAL:,} bytes and "
                        "was truncated. An oversized single-stream file is a DoS risk.",
                        cwe="CWE-409", confidence=0.55,
                        evidence={"decompressed_at_least": read})
                    break
    except Exception as e:                    # noqa: BLE001
        report["error"] = f"decompression failed: {e}"
    report["decompressed_size"] = read
    comp = Path(path).stat().st_size or 1
    report["compression_ratio"] = round(read / comp, 1)
    # If the inner stream is itself a known type, say so.
    inner = ""
    if sample[:4] == b"\x7fELF":
        inner = "ELF binary"
    elif sample[:2] == b"MZ":
        inner = "PE/DOS executable"
    elif sample[:5] == b"%PDF-":
        inner = "PDF document"
    elif sample[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        inner = "OLE compound document"
    elif sample.startswith((b"ustar", b"\x00\x00")) or b"ustar" in sample[:512]:
        inner = "tar archive"
    if inner:
        report["inner_type"] = inner
    secrets = _carve_secrets(sample, "decompressed")
    if secrets:
        report["embedded_secrets"] = secrets
        add("archive_embedded_secret", "high", "Secret/key in compressed stream",
            "Credential/key material found in the decompressed content.",
            cwe="CWE-798", confidence=0.75, evidence={"secrets": secrets[:6]})
    if report["compression_ratio"] >= _BOMB_RATIO:
        add("archive_decompression_bomb", "medium", "High-ratio compressed stream",
            f"The {kind} stream expands ~{report['compression_ratio']}:1.",
            cwe="CWE-409", confidence=0.5,
            evidence={"ratio": report["compression_ratio"], "size": read})
    summary = f"{kind} · {read:,} bytes ({report['compression_ratio']}:1)" + (f" · {inner}" if inner else "")
    return {"report": report, "findings": findings, "summary": summary}


# ── detected-but-not-fully-parsed (7z / rar / iso) ──────────────────────────
def _analyze_opaque(path: str, target: str, kind: str, note: str) -> dict[str, Any]:
    findings, add = _mk(target)
    size = Path(path).stat().st_size
    with open(path, "rb") as fh:
        head = fh.read(65536)
    report = {"archive_type": kind, "size": size, "note": note}
    secrets = _carve_secrets(head, "header")
    if secrets:
        report["embedded_secrets"] = secrets
    add("archive_detected", "info", f"{kind.upper()} archive detected",
        note, cwe="CWE-506", confidence=0.5, evidence={"size": size})
    return {"report": report, "findings": findings, "summary": f"{kind} archive · {size:,} bytes"}


def analyze_archive(path: str, **_: Any) -> dict[str, Any]:
    """Analyze a generic archive. Returns the standard analyzer result shape."""
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    with open(p, "rb") as fh:
        head = fh.read(512)
    ext = p.suffix.lower()

    try:
        if tarfile.is_tarfile(str(p)):
            out = _analyze_tar(str(p), str(p))
        elif zipfile.is_zipfile(str(p)):
            out = _analyze_zip(str(p), str(p))
        elif head[:2] == b"\x1f\x8b" or ext in (".gz", ".tgz"):
            out = _analyze_stream_archive(str(p), str(p), "gzip")
        elif head[:3] == b"BZh" or ext == ".bz2":
            out = _analyze_stream_archive(str(p), str(p), "bzip2")
        elif head[:6] == b"\xfd7zXZ\x00" or ext == ".xz":
            out = _analyze_stream_archive(str(p), str(p), "xz")
        elif head[:6] == b"7z\xbc\xaf\x27\x1c" or ext == ".7z":
            out = _analyze_opaque(str(p), str(p), "7z",
                                  "7-Zip archive (encrypted-header capable; not fully "
                                  "parsed without py7zr).")
        elif head[:4] in (b"Rar!",) or ext == ".rar":
            out = _analyze_opaque(str(p), str(p), "rar", "RAR archive (not fully parsed).")
        elif ext == ".iso" or _looks_iso(str(p)):
            out = _analyze_opaque(str(p), str(p), "iso",
                                  "ISO-9660 disk image — a common malware-delivery "
                                  "container that bypasses mark-of-the-web.")
        else:
            return {"error": f"unrecognized archive format for {path}",
                    "report": {}, "findings": []}
    except Exception as e:                    # noqa: BLE001
        logger.debug("archive analysis failed", exc_info=True)
        return {"error": f"archive analysis failed: {e}", "report": {}, "findings": []}

    out.setdefault("report", {})["archive_format"] = out.get("report", {}).get("archive_type", "")
    return out


def _looks_iso(path: str) -> bool:
    """ISO-9660 has the 'CD001' identifier at offset 0x8001."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0x8001)
            return fh.read(5) == b"CD001"
    except Exception:                         # noqa: BLE001
        return False
