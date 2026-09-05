r"""HEAVEN — document forensics (PDF / OOXML / legacy-OLE / RTF).

Malicious documents are the single most common initial-access vector in the
real world (phishing attachments), and none of it can be judged from a live
target — it is pure offline artifact work. This analyzer reads the raw bytes of
a document and reports, with evidence:

* **PDF** — active content that runs on open (``/JavaScript`` + ``/OpenAction``
  / ``/AA``), ``/Launch`` actions, embedded files, external-resource actions
  (``/URI`` / ``/GoToR`` / ``/SubmitForm``), AcroForm/XFA, encryption, and
  obfuscation via object streams. Compressed (FlateDecode) streams are inflated
  so JavaScript hidden inside a compressed object is still seen.
* **OOXML** (docx/xlsx/pptx and the macro-enabled *m variants) — VBA macros
  (``vbaProject.bin``), remote-template / remote-object *relationship* injection
  (the CVE-2017-0199 class), DDE / DDEAUTO field execution, embedded OLE
  objects, and remote (tracking) resources.
* **Legacy OLE** compound files (.doc/.xls/.ppt/.msg) — parsed with a
  pure-Python CFB reader: VBA macro storages (with MS-OVBA decompression of the
  module source and keyword triage), and Equation-Editor / packager exploit
  markers (CVE-2017-11882 / CVE-2018-0802 / Ole10Native).
* **RTF** — embedded OLE objects (``\object`` / ``\objdata``), the exploit
  object classes (``Equation.3`` → CVE-2017-11882, ``OLE2Link`` →
  CVE-2017-0199), and remote-template references.

Pure-Python and dependency-free: everything is parsed from bytes actually read
out of the file. Nothing is fabricated.
"""

from __future__ import annotations

import re
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("forensics.document")

_MAX_READ = 64 * 1024 * 1024          # defensive cap on whole-file reads
_MAX_STREAMS = 4000                   # PDF stream / CFB entry ceiling


# ── shared secret / endpoint carving (mirrors binary.py) ─────────────────────
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")
_IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SECRET_RE = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(rb"ghp_[0-9A-Za-z]{36}"), "GitHub token"),
    (re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack token"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
]
_NOISE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.2.3.4", "8.8.8.8"}


def _carve_secrets(data: bytes) -> list[dict]:
    out: list[dict] = []
    for rx, label in _SECRET_RE:
        for m in rx.finditer(data):
            out.append({"type": label, "match": m.group(0)[:80].decode("latin1", "replace")})
            if len(out) >= 20:
                return out
    return out


def _carve_urls(data: bytes, cap: int = 40) -> list[str]:
    return sorted({m.group(0).decode("latin1", "replace") for m in _URL_RE.finditer(data)})[:cap]


# ── finding helper ────────────────────────────────────────────────────────────
def _mk(target: str):
    findings: list[dict] = []

    def add(vt: str, sev: str, title: str, desc: str, **extra: Any) -> None:
        findings.append({
            "target": target, "vuln_type": vt, "severity": sev, "title": title,
            "description": desc, "scanner": "document_analyzer",
            "confidence": extra.pop("confidence", 0.85),
            "cwe": extra.pop("cwe", ""), "remediation": extra.pop("remediation", ""),
            **extra,
        })

    return findings, add


# ═════════════════════════════ PDF ═══════════════════════════════════════════
# Names whose presence indicates active / attacker-relevant content, each with a
# short reason. Counted over the whole (decompressed) document.
_PDF_MARKERS: dict[str, tuple[str, str, str]] = {
    # name : (why, cwe, base-severity)
    "/JavaScript": ("PDF-embedded JavaScript", "CWE-94", "medium"),
    "/JS": ("PDF JavaScript action", "CWE-94", "medium"),
    "/OpenAction": ("action that runs automatically when the file opens", "CWE-94", "medium"),
    "/AA": ("additional (automatic) actions on document/page events", "CWE-94", "medium"),
    "/Launch": ("Launch action — starts an external program", "CWE-78", "high"),
    "/EmbeddedFile": ("a file embedded inside the PDF", "CWE-506", "medium"),
    "/URI": ("action that opens an external URL", "CWE-601", "low"),
    "/SubmitForm": ("form that submits data to a remote URL", "CWE-201", "low"),
    "/GoToR": ("remote go-to action (opens another file/URL)", "CWE-610", "low"),
    "/GoToE": ("embedded go-to action", "CWE-610", "low"),
    "/RichMedia": ("embedded Flash/rich-media annotation", "CWE-94", "medium"),
    "/XFA": ("XFA dynamic form (historically abused for exploitation)", "CWE-611", "low"),
    "/AcroForm": ("interactive form", "CWE-200", "info"),
    "/JBIG2Decode": ("JBIG2 image filter (CVE-2021-30860 class parser bugs)", "CWE-787", "low"),
    "/ObjStm": ("object stream — commonly used to obfuscate/hide objects", "CWE-506", "info"),
    "/Encrypt": ("the document is encrypted", "CWE-311", "info"),
}


def _pdf_inflate_streams(data: bytes) -> bytes:
    """Return the raw bytes plus every FlateDecode stream inflated, concatenated.

    Malware routinely hides ``/JavaScript`` inside a compressed object stream, so
    marker detection must look at the *decompressed* content, not only the raw
    file. Each stream is inflated best-effort; failures are ignored.
    """
    extra = bytearray()
    inflated = 0
    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end == -1:
            continue
        blob = data[start:end].rstrip(b"\r\n")
        if not blob:
            continue
        for wbits in (15, -15, 47):        # zlib, raw-deflate, gzip/auto
            try:
                out = zlib.decompress(blob, wbits)
                if out:
                    extra += b"\n" + out
                    inflated += 1
                    break
            except Exception:               # noqa: BLE001 — non-flate stream
                continue
        if inflated >= _MAX_STREAMS:
            break
    return bytes(extra)


def _analyze_pdf(data: bytes, target: str) -> dict[str, Any]:
    findings, add = _mk(target)
    report: dict[str, Any] = {}

    header = data[:1024]
    mver = re.search(rb"%PDF-(\d\.\d)", header)
    report["pdf_version"] = mver.group(1).decode() if mver else "unknown"

    inflated = _pdf_inflate_streams(data)
    hay = data + inflated                    # search raw + decompressed together

    # Marker inventory.
    counts: dict[str, int] = {}
    for name in _PDF_MARKERS:
        n = hay.count(name.encode())
        if n:
            counts[name] = n
    if counts:
        report["active_content"] = counts

    # Structural signals.
    eofs = data.count(b"%%EOF")
    if eofs > 1:
        report["incremental_updates"] = eofs - 1
    npages = len(re.findall(rb"/Type\s*/Page\b", hay))
    if npages:
        report["pages"] = npages
    report["object_streams"] = counts.get("/ObjStm", 0)

    # Metadata from the Info dictionary (best-effort regex over raw bytes).
    meta: dict[str, str] = {}
    for key in (b"Producer", b"Creator", b"Author", b"CreationDate", b"ModDate", b"Title"):
        m = re.search(rb"/" + key + rb"\s*\(([^)]{0,200})\)", data)
        if m:
            meta[key.decode().lower()] = m.group(1).decode("latin1", "replace")
    if meta:
        report["metadata"] = meta

    # URIs and embedded-file names.
    uris = sorted({m.group(1).decode("latin1", "replace")
                   for m in re.finditer(rb"/URI\s*\(([^)]{1,300})\)", hay)})[:40]
    if uris:
        report["uris"] = uris
    embedded = sorted({m.group(1).decode("latin1", "replace")
                       for m in re.finditer(rb"/F\s*\(([^)]{1,200})\)", hay)
                       if b"/EmbeddedFile" in hay})[:40]
    if embedded:
        report["embedded_files"] = embedded

    # JavaScript snippets (literal /JS (...) form; the hex/stream form is caught
    # by the marker count above).
    js_snips = [m.group(1)[:400].decode("latin1", "replace")
                for m in re.finditer(rb"/JS\s*\(((?:[^()\\]|\\.){2,4000})\)", hay)][:8]
    if js_snips:
        report["javascript_snippets"] = js_snips

    secrets = _carve_secrets(hay)
    if secrets:
        report["embedded_secrets"] = secrets

    # ── findings ──
    has_js = bool(counts.get("/JavaScript") or counts.get("/JS"))
    auto = bool(counts.get("/OpenAction") or counts.get("/AA"))
    if has_js and auto:
        add("pdf_auto_javascript", "high",
            "PDF runs JavaScript automatically on open",
            "The document embeds JavaScript and an automatic action "
            "(/OpenAction or /AA), so the script executes the moment the file is "
            "opened in a reader that permits it — the classic malicious-PDF "
            "pattern.", cwe="CWE-94", confidence=0.9,
            evidence={"markers": {k: counts[k] for k in counts
                                  if k in ("/JavaScript", "/JS", "/OpenAction", "/AA")},
                      "snippets": js_snips[:3]},
            remediation="Do not open in a JavaScript-enabled reader; detonate only "
                        "in an isolated analysis VM. Disable JavaScript in the PDF reader.")
    elif has_js:
        add("pdf_javascript", "medium", "PDF embeds JavaScript",
            "The document contains embedded JavaScript. Even without an automatic "
            "trigger this is unusual for a document and is a common exploit / "
            "downloader carrier.", cwe="CWE-94", confidence=0.85,
            evidence={"snippets": js_snips[:3]})

    if counts.get("/Launch"):
        add("pdf_launch_action", "high", "PDF Launch action (external program execution)",
            "A /Launch action can start an external program or command when the "
            "document is opened or a link is clicked.", cwe="CWE-78", confidence=0.9,
            evidence={"launch_count": counts["/Launch"]},
            remediation="Treat as malicious; analyze the launch target in isolation.")

    if counts.get("/EmbeddedFile"):
        add("pdf_embedded_file", "medium", "PDF contains embedded file(s)",
            "The PDF carries embedded files. Attackers embed executables, scripts "
            "or secondary payloads for the reader to drop.", cwe="CWE-506",
            confidence=0.8, evidence={"names": embedded[:10],
                                      "count": counts["/EmbeddedFile"]})

    ext_actions = {k: counts[k] for k in ("/URI", "/GoToR", "/SubmitForm")
                   if counts.get(k)}
    if ext_actions:
        add("pdf_external_action", "low", "PDF references external resources",
            "The document opens external URLs or remote files "
            "(/URI, /GoToR, /SubmitForm). These can phish, track the opener, or "
            "pull a second-stage payload.", cwe="CWE-601", confidence=0.7,
            evidence={"actions": ext_actions, "uris": uris[:15]})

    if counts.get("/JBIG2Decode"):
        add("pdf_jbig2", "low", "PDF uses the JBIG2 image filter",
            "JBIG2 decoders have a history of memory-corruption bugs "
            "(e.g. CVE-2021-30860, FORCEDENTRY). Presence alone is not proof of "
            "exploitation but warrants scrutiny.", cwe="CWE-787", confidence=0.5)

    if counts.get("/XFA") or (counts.get("/AcroForm") and counts.get("/JS")):
        add("pdf_dynamic_form", "low", "PDF dynamic form (XFA / scripted AcroForm)",
            "Dynamic XFA forms and scripted AcroForms have been used to reach "
            "vulnerable code paths in readers.", cwe="CWE-611", confidence=0.5)

    if report["object_streams"] and report["object_streams"] >= 3 and not has_js and counts.get("/ObjStm"):
        add("pdf_obfuscation", "info", "PDF hides objects in object streams",
            "The document packs many objects into /ObjStm compressed streams. This "
            "is legitimate compression but is also used to hide malicious objects "
            "from naive scanners.", cwe="CWE-506", confidence=0.4)

    if secrets:
        add("pdf_embedded_secret", "high", "Secret/key embedded in the PDF",
            "Credential or key material was found in the document bytes: "
            + "; ".join(s["match"] for s in secrets[:3]) + ".", cwe="CWE-798",
            confidence=0.85, evidence={"secrets": secrets[:10]},
            remediation="Rotate the exposed secret and remove it from the document.")

    summary = (f"PDF {report['pdf_version']} · {report.get('pages', '?')} page(s) · "
               + (", ".join(f"{k.lstrip('/')}×{v}" for k, v in list(counts.items())[:6])
                  if counts else "no active content"))
    return {"report": report, "findings": findings, "summary": summary}


# ═════════════════════════════ OOXML ═════════════════════════════════════════
def _analyze_ooxml(path: str, target: str) -> dict[str, Any]:
    findings, add = _mk(target)
    report: dict[str, Any] = {}
    try:
        zf = zipfile.ZipFile(path)
        names = zf.namelist()[:_MAX_STREAMS]
    except Exception as e:                   # noqa: BLE001
        return {"report": {"error": f"not a readable OOXML zip: {e}"},
                "findings": [], "summary": "unreadable OOXML"}

    lower = [n.lower() for n in names]
    if any(n.startswith("word/") for n in lower):
        report["ooxml_type"] = "Word document"
    elif any(n.startswith("xl/") for n in lower):
        report["ooxml_type"] = "Excel workbook"
    elif any(n.startswith("ppt/") for n in lower):
        report["ooxml_type"] = "PowerPoint presentation"
    else:
        report["ooxml_type"] = "OOXML package"
    report["parts"] = len(names)

    # ── VBA macros: any vbaProject.bin is a CFB; hand it to the OLE analyzer. ──
    vba_parts = [n for n in names if n.lower().endswith("vbaproject.bin")]
    if vba_parts:
        try:
            vba_bytes = zf.read(vba_parts[0])[:_MAX_READ]
        except Exception:                    # noqa: BLE001
            vba_bytes = b""
        macro = _analyze_ole(vba_bytes, target, _within="vbaProject.bin") if vba_bytes else {}
        mreport = macro.get("report", {}) if isinstance(macro, dict) else {}
        kws = mreport.get("macro_keywords") or []
        streams = mreport.get("vba_modules") or []
        report["macros"] = {"present": True, "modules": streams,
                            "suspicious_keywords": kws}
        auto = [k for k in kws if k.lower() in
                ("autoopen", "auto_open", "document_open", "workbook_open",
                 "auto_close", "document_close", "autoexec")]
        sev = "high" if auto or any(
            k.lower() in ("shell", "createobject", "wscript.shell", "powershell",
                          "urldownloadtofile", "winhttprequest", "cmd.exe")
            for k in kws) else "medium"
        add("ooxml_vba_macro", sev, "Macro-enabled document (VBA project present)",
            "The document contains a VBA macro project (vbaProject.bin)."
            + (f" Auto-execution routine(s): {', '.join(auto)}." if auto else "")
            + (f" Suspicious calls: {', '.join(k for k in kws if k.lower() not in [a.lower() for a in auto])[:200]}."
               if kws else ""),
            cwe="CWE-94", confidence=0.9 if sev == "high" else 0.8,
            mitre="T1204.002",
            evidence={"modules": streams, "keywords": kws,
                      "macro_source_excerpt": mreport.get("macro_source_excerpt", "")},
            remediation="Do not enable content/macros. Extract and review the VBA "
                        "source in an isolated environment before trusting the file.")

    # ── remote-relationship (template / OLE) injection: CVE-2017-0199 class ──
    external: list[dict] = []
    for n in names:
        if not n.lower().endswith(".rels"):
            continue
        try:
            xml = zf.read(n).decode("utf-8", "replace")
        except Exception:                    # noqa: BLE001
            continue
        for m in re.finditer(r"<Relationship\b[^>]*>", xml):
            tag = m.group(0)
            if 'targetmode="external"' not in tag.lower():
                continue
            tgt = re.search(r'Target="([^"]+)"', tag)
            typ = re.search(r'Type="([^"]+)"', tag)
            ttype = (typ.group(1) if typ else "").rsplit("/", 1)[-1]
            target_url = tgt.group(1) if tgt else ""
            external.append({"part": n, "type": ttype, "target": target_url})
    if external:
        report["external_relationships"] = external[:60]
        dangerous = [e for e in external if e["type"] in
                     ("attachedTemplate", "oleObject", "frame", "slideUpdateUrl")
                     and e["target"].lower().startswith(("http", "\\\\", "//", "mhtml", "smb"))]
        remote_any = [e for e in external if e["target"].lower().startswith(("http", "\\\\", "//", "smb"))]
        if dangerous:
            add("ooxml_template_injection", "high",
                "Remote template / OLE relationship (CVE-2017-0199 class)",
                "A relationship points at a remote " +
                dangerous[0]["type"] + f" ({dangerous[0]['target']}). Opening the "
                "document fetches and can execute that remote resource — the "
                "remote-template / remote-object injection technique.",
                cwe="CWE-610", confidence=0.85, mitre="T1221",
                evidence={"relationships": dangerous},
                remediation="Block the remote host; treat as a live phishing lure.")
        elif remote_any:
            add("ooxml_remote_resource", "low",
                "Document pulls a remote resource on open",
                "The document references a remote resource (e.g. an image or "
                "stylesheet). This is often a tracking/canary beacon that confirms "
                "the file was opened and leaks the victim's IP.",
                cwe="CWE-200", confidence=0.6,
                evidence={"relationships": remote_any[:20]})

    # ── DDE / DDEAUTO field execution ──
    dde_hits: list[str] = []
    for n in names:
        if not (n.lower().endswith(".xml")):
            continue
        try:
            body = zf.read(n)
        except Exception:                    # noqa: BLE001
            continue
        if b"DDEAUTO" in body or b"DDE " in body or b" DDE" in body:
            for dm in re.finditer(rb"(DDEAUTO|DDE)\s+([^<]{1,200})", body):
                dde_hits.append(dm.group(0)[:200].decode("latin1", "replace"))
    if dde_hits:
        report["dde_fields"] = dde_hits[:20]
        add("ooxml_dde", "high", "DDE / DDEAUTO field (command execution)",
            "The document uses a DDE field, which can run an external command when "
            "the user accepts the (easily-social-engineered) update prompt.",
            cwe="CWE-78", confidence=0.85, mitre="T1559.002",
            evidence={"fields": dde_hits[:10]},
            remediation="Disable DDE (Office does by default now); treat as malicious.")

    # ── embedded OLE objects (equation editor etc.) ──
    embeds = [n for n in names if "/embeddings/" in n.lower() or "/oleobject" in n.lower()]
    if embeds:
        report["embedded_objects"] = embeds[:40]
        # Peek into embedded OLE for exploit markers.
        for n in embeds[:10]:
            try:
                ob = zf.read(n)[:2_000_000]
            except Exception:                # noqa: BLE001
                continue
            if b"Equation Native" in ob or b"\x01Ole10Native" in ob or b"Microsoft Equation 3.0" in ob:
                add("ooxml_equation_object", "high",
                    "Embedded Equation-Editor object (CVE-2017-11882 class)",
                    "An embedded OLE object references the Equation Editor, the "
                    "target of the long-lived CVE-2017-11882 / CVE-2018-0802 "
                    "memory-corruption exploits.", cwe="CWE-787", confidence=0.8,
                    evidence={"part": n},
                    remediation="Patch/disable Equation Editor; detonate in isolation.")
                break
        else:
            add("ooxml_embedded_object", "low", "Document embeds OLE object(s)",
                "Embedded OLE objects can carry executables or exploit payloads.",
                cwe="CWE-506", confidence=0.6, evidence={"parts": embeds[:15]})

    # ── metadata ──
    for core in ("docProps/core.xml", "docProps/app.xml"):
        if core in names:
            try:
                cx = zf.read(core).decode("utf-8", "replace")
            except Exception:                # noqa: BLE001
                continue
            md: dict[str, str] = {}
            for tag in ("dc:creator", "cp:lastModifiedBy", "Company", "Template",
                        "Application", "dcterms:created"):
                mm = re.search(rf"<{tag}[^>]*>([^<]{{0,120}})</{tag}>", cx)
                if mm:
                    md[tag.split(':')[-1]] = mm.group(1)
            if md:
                report.setdefault("document_metadata", {}).update(md)

    urls = _carve_urls(b"\n".join(zf.read(n)[:200000] for n in names[:200]
                                  if n.lower().endswith((".xml", ".rels", ".bin"))))
    if urls:
        report["urls"] = urls

    mac = "macro-enabled" if vba_parts else "no macros"
    summary = f"{report['ooxml_type']} · {report['parts']} parts · {mac}"
    return {"report": report, "findings": findings, "summary": summary}


# ═════════════════════════════ OLE / CFB ═════════════════════════════════════
_CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_VBA_KEYWORDS = (
    "AutoOpen", "Auto_Open", "AutoClose", "AutoExec", "Document_Open",
    "Document_Close", "Workbook_Open", "Workbook_Activate", "Shell",
    "CreateObject", "GetObject", "WScript.Shell", "WScript.Network",
    "powershell", "cmd.exe", "URLDownloadToFile", "WinHttpRequest",
    "MSXML2.XMLHTTP", "ADODB.Stream", "Environ", "Kill", "VirtualAlloc",
    "RtlMoveMemory", "CallByName", "Base64", "Chr(", "ChrW(", "Xor ",
    "ExecuteExcel4Macro", "Application.Run", "ShellExecute",
)


class _CFB:
    """Minimal, defensive pure-Python OLE2 / Compound-File-Binary reader.

    Enumerates directory entries and reads streams (both regular and mini). Only
    what document triage needs — enough to find and read VBA module streams and
    exploit-object streams. Never raises: a malformed field yields fewer entries,
    never a crash.
    """

    def __init__(self, data: bytes) -> None:
        self.ok = False
        self.entries: list[dict] = []
        self._data = data
        try:
            self._parse()
            self.ok = True
        except Exception:                    # noqa: BLE001
            logger.debug("CFB parse failed", exc_info=True)

    def _sector(self, n: int) -> bytes:
        off = (n + 1) * self.sec
        return self._data[off:off + self.sec]

    def _chain(self, start: int, fat: list[int], cap: int) -> list[int]:
        out: list[int] = []
        n = start
        seen = set()
        while 0 <= n < len(fat) and n not in (0xFFFFFFFE, 0xFFFFFFFF) and n not in seen:
            seen.add(n)
            out.append(n)
            if len(out) > cap:
                break
            n = fat[n]
        return out

    def _parse(self) -> None:
        d = self._data
        if d[:8] != _CFB_MAGIC:
            raise ValueError("bad magic")
        self.sec = 1 << struct.unpack_from("<H", d, 30)[0]
        self.mini_sec = 1 << struct.unpack_from("<H", d, 32)[0]
        num_fat = struct.unpack_from("<I", d, 44)[0]
        first_dir = struct.unpack_from("<I", d, 48)[0]
        self.mini_cutoff = struct.unpack_from("<I", d, 56)[0]
        first_minifat = struct.unpack_from("<I", d, 60)[0]
        num_minifat = struct.unpack_from("<I", d, 64)[0]
        first_difat = struct.unpack_from("<I", d, 68)[0]
        num_difat = struct.unpack_from("<I", d, 72)[0]

        # DIFAT → list of FAT sector numbers (109 in header, then chained).
        difat = list(struct.unpack_from("<109I", d, 76))
        nsec = first_difat
        for _ in range(min(num_difat, 1000)):
            if nsec in (0xFFFFFFFE, 0xFFFFFFFF):
                break
            sect = self._sector(nsec)
            vals = struct.unpack_from(f"<{self.sec // 4}I", sect)
            difat += list(vals[:-1])
            nsec = vals[-1]
        fat_sectors = [x for x in difat[:num_fat + 200] if x not in (0xFFFFFFFE, 0xFFFFFFFF)]

        # FAT
        fat: list[int] = []
        for s in fat_sectors:
            sect = self._sector(s)
            fat += list(struct.unpack_from(f"<{len(sect) // 4}I", sect))
        self.fat = fat

        # miniFAT
        minifat: list[int] = []
        for s in self._chain(first_minifat, fat, num_minifat + 200):
            sect = self._sector(s)
            minifat += list(struct.unpack_from(f"<{len(sect) // 4}I", sect))
        self.minifat = minifat

        # Directory (linear scan of all 128-byte entries in the chain).
        dir_bytes = b"".join(self._sector(s) for s in self._chain(first_dir, fat, 4000))
        entries: list[dict] = []
        root_start = root_size = 0
        for i in range(0, len(dir_bytes) - 127, 128):
            e = dir_bytes[i:i + 128]
            nlen = struct.unpack_from("<H", e, 64)[0]
            if not (0 < nlen <= 64):
                continue
            name = e[:nlen - 2].decode("utf-16-le", "replace")
            otype = e[66]
            if otype not in (1, 2, 5):       # storage / stream / root
                continue
            start = struct.unpack_from("<I", e, 116)[0]
            size = struct.unpack_from("<I", e, 120)[0]
            entries.append({"name": name, "type": otype, "start": start, "size": size})
            if otype == 5:
                root_start, root_size = start, size
        self.entries = entries[:_MAX_STREAMS]

        # Mini stream = the root entry's stream, read from the main FAT.
        self._mini_stream = self._read_fat_chain(root_start, root_size)

    def _read_fat_chain(self, start: int, size: int) -> bytes:
        out = bytearray()
        for s in self._chain(start, self.fat, (size // self.sec) + 4):
            out += self._sector(s)
        return bytes(out[:size]) if size else bytes(out)

    def read(self, entry: dict, cap: int = 4_000_000) -> bytes:
        size = min(entry["size"], cap)
        if entry["type"] == 5:
            return self._mini_stream[:size]
        if entry["size"] < self.mini_cutoff:
            out = bytearray()
            n = entry["start"]
            seen = set()
            while 0 <= n < len(self.minifat) and n not in (0xFFFFFFFE, 0xFFFFFFFF) and n not in seen:
                seen.add(n)
                off = n * self.mini_sec
                out += self._mini_stream[off:off + self.mini_sec]
                if len(out) > cap:
                    break
                n = self.minifat[n]
            return bytes(out[:size])
        return self._read_fat_chain(entry["start"], size)


def _ovba_decompress(comp: bytes) -> bytes:
    """Decompress an MS-OVBA compressed container (the VBA module source format).

    Implements the RLE/copy-token algorithm from [MS-OVBA] 2.4.1. Returns the
    decompressed bytes, best-effort — a malformed chunk stops decompression but
    keeps what was produced so far.
    """
    if not comp or comp[0] != 0x01:
        return b""
    out = bytearray()
    i = 1
    n = len(comp)
    while i < n:
        if i + 2 > n:
            break
        hdr = struct.unpack_from("<H", comp, i)[0]
        i += 2
        size = (hdr & 0x0FFF) + 3
        flag = (hdr >> 15) & 1
        chunk_end = min(i + size - 2, n)
        if flag == 0:                        # raw chunk (exactly 4096 bytes)
            out += comp[i:i + 4096]
            i += 4096
            continue
        while i < chunk_end:
            flags = comp[i]
            i += 1
            for bit in range(8):
                if i >= chunk_end:
                    break
                if not (flags >> bit) & 1:   # literal
                    out.append(comp[i])
                    i += 1
                else:                        # copy token
                    token = struct.unpack_from("<H", comp, i)[0]
                    i += 2
                    pos = len(out)
                    # bit-width of the length field depends on current output size
                    bitcount = max(4, (pos - 1).bit_length()) if pos > 1 else 4
                    length_mask = 0xFFFF >> bitcount
                    length = (token & length_mask) + 3
                    offset = (token >> (16 - bitcount)) + 1
                    src = pos - offset
                    if src < 0:
                        return bytes(out)
                    for _ in range(length):
                        out.append(out[src])
                        src += 1
        if len(out) > 8_000_000:
            break
    return bytes(out)


def _analyze_ole(data: bytes, target: str, _within: str = "") -> dict[str, Any]:
    findings, add = _mk(target)
    report: dict[str, Any] = {}
    cfb = _CFB(data)
    report["cfb_parsed"] = cfb.ok
    names = [e["name"] for e in cfb.entries]
    if names:
        report["streams"] = names[:120]

    # ── VBA macro extraction ──
    modules: list[str] = []
    keywords: set[str] = set()
    source_excerpt = ""
    is_vba = any(re.search(r"(?i)(^|/)?(vba|macros|_vba_project)$", n) for n in names) \
        or any(n.lower() in ("dir", "projectwm", "project") for n in names) \
        or b"_VBA_PROJECT" in data
    for e in cfb.entries:
        if e["type"] != 2:
            continue
        raw = cfb.read(e)
        # A VBA module stream carries a compressed container starting at 0x01.
        idx = raw.find(b"\x01")
        src = _ovba_decompress(raw[idx:]) if 0 <= idx < 4096 else b""
        text = src.decode("latin1", "replace") if src else ""
        if "Attribute VB_Name" in text or (text and any(k in text for k in _VBA_KEYWORDS)):
            modules.append(e["name"])
            for k in _VBA_KEYWORDS:
                if k in text:
                    keywords.add(k)
            if not source_excerpt:
                source_excerpt = text[:1500]
    if not modules and is_vba:
        # Fallback: keyword-scan the raw CFB (some markers survive uncompressed).
        blob = data.decode("latin1", "replace")
        for k in _VBA_KEYWORDS:
            if k in blob:
                keywords.add(k)
    if modules or keywords or is_vba:
        report["vba_modules"] = modules
        report["macro_keywords"] = sorted(keywords)
        if source_excerpt:
            report["macro_source_excerpt"] = source_excerpt

    # ── exploit-object markers ──
    if b"Equation Native" in data or b"Microsoft Equation 3.0" in data:
        report["equation_editor"] = True
    if b"\x01Ole10Native" in data or b"Ole10Native" in data:
        report["ole10native_packager"] = True

    # ── findings (skip when we are the nested vbaProject; the OOXML caller
    #     raises the macro finding with document-level context) ──
    if not _within:
        if modules or (is_vba and keywords):
            auto = sorted(k for k in keywords if k.lower() in
                          ("autoopen", "auto_open", "autoexec", "document_open",
                           "document_close", "workbook_open", "autoclose"))
            danger = sorted(k for k in keywords if k.lower() in
                            ("shell", "createobject", "wscript.shell", "powershell",
                             "cmd.exe", "urldownloadtofile", "winhttprequest",
                             "shellexecute", "virtualalloc", "rtlmovememory"))
            sev = "high" if (auto or danger) else "medium"
            add("ole_vba_macro", sev, "Legacy Office document with VBA macros",
                "The compound document contains VBA macros."
                + (f" Auto-run: {', '.join(auto)}." if auto else "")
                + (f" Dangerous calls: {', '.join(danger)}." if danger else ""),
                cwe="CWE-94", confidence=0.9 if sev == "high" else 0.75,
                mitre="T1204.002",
                evidence={"modules": modules, "keywords": sorted(keywords),
                          "source_excerpt": source_excerpt[:800]},
                remediation="Do not enable macros; review the extracted VBA in isolation.")
        if report.get("equation_editor"):
            add("ole_equation_editor", "high",
                "Embedded Equation-Editor object (CVE-2017-11882 class)",
                "The document contains an Equation-Editor OLE object, the target of "
                "CVE-2017-11882 / CVE-2018-0802.", cwe="CWE-787", confidence=0.8,
                remediation="Patch or disable EQNEDT32; detonate only in isolation.")
        if report.get("ole10native_packager"):
            add("ole_packager", "medium", "OLE Packager object (Ole10Native)",
                "An Ole10Native packager stream can embed and drop an arbitrary "
                "executable/script.", cwe="CWE-506", confidence=0.7,
                evidence={"stream": "\\x01Ole10Native"})
        secrets = _carve_secrets(data)
        if secrets:
            add("ole_embedded_secret", "high", "Secret/key embedded in the document",
                "Credential/key material found in the document bytes.", cwe="CWE-798",
                confidence=0.8, evidence={"secrets": secrets[:10]})

    summary = "OLE compound document" + (" · VBA macros" if (modules or keywords) else "")
    return {"report": report, "findings": findings, "summary": summary}


# ═════════════════════════════ RTF ═══════════════════════════════════════════
def _analyze_rtf(data: bytes, target: str) -> dict[str, Any]:
    findings, add = _mk(target)
    report: dict[str, Any] = {}
    text = data.decode("latin1", "replace")

    objects = len(re.findall(r"\\object\b", text))
    objdata = len(re.findall(r"\\objdata\b", text))
    objupdate = len(re.findall(r"\\objupdate\b", text))
    report["objects"] = objects
    if objdata:
        report["objdata_blocks"] = objdata
    if objupdate:
        report["objupdate"] = objupdate

    classes = sorted({m.group(1) for m in re.finditer(r"\\objclass ?([A-Za-z0-9._]+)", text)})
    if classes:
        report["object_classes"] = classes

    # Control-word obfuscation is a strong malicious signal in RTF exploits.
    obf = len(re.findall(r"\\bin\b", text)) + text.count("\\'")
    if obf > 200:
        report["obfuscation_score"] = obf

    templates = sorted({m.group(1) for m in
                        re.finditer(r"\\\*\\template\s*([^\s{}]+)", text)})[:10]
    if templates:
        report["remote_templates"] = templates

    low = text.lower()
    if "equation.3" in low or "equation native" in low:
        add("rtf_equation_editor", "high",
            "RTF embeds an Equation-Editor object (CVE-2017-11882 class)",
            "The RTF references the Equation Editor object class, the classic "
            "CVE-2017-11882 / CVE-2018-0802 exploit carrier.", cwe="CWE-787",
            confidence=0.85, evidence={"classes": classes},
            remediation="Patch/disable Equation Editor; analyze in isolation.")
    if "ole2link" in low or "\\objautlink" in low:
        add("rtf_ole2link", "high", "RTF OLE2Link object (CVE-2017-0199 class)",
            "The RTF uses an OLE2Link object, used by CVE-2017-0199 to fetch and "
            "run a remote payload on open.", cwe="CWE-610", confidence=0.85,
            evidence={"classes": classes},
            remediation="Block the remote host; treat as a live exploit.")
    if objdata or objects:
        add("rtf_embedded_object", "medium" if not classes else "medium",
            "RTF contains embedded OLE object(s)",
            f"The RTF embeds {objects or objdata} OLE object(s)"
            + (f" (classes: {', '.join(classes)})" if classes else "")
            + ". Embedded objects in RTF are almost always malicious.",
            cwe="CWE-506", confidence=0.7, evidence={"object_classes": classes})
    if templates:
        add("rtf_remote_template", "high", "RTF references a remote template",
            "A remote \\*\\template pull fetches content on open — a remote-content "
            "injection technique.", cwe="CWE-610", confidence=0.75,
            evidence={"templates": templates})
    if obf > 200:
        add("rtf_obfuscation", "low", "Heavily obfuscated RTF",
            "The RTF uses a large amount of control-word/hex obfuscation, a common "
            "tactic to smuggle an exploit object past scanners.", cwe="CWE-506",
            confidence=0.5, evidence={"obfuscation_score": obf})

    secrets = _carve_secrets(data)
    if secrets:
        report["embedded_secrets"] = secrets
    summary = f"RTF · {objects} embedded object(s)" + (f" · classes: {', '.join(classes[:3])}" if classes else "")
    return {"report": report, "findings": findings, "summary": summary}


# ═════════════════════════════ public entry ══════════════════════════════════
def _detect_document_kind(data: bytes, ext: str) -> str:
    if data[:5] == b"%PDF-" or ext == ".pdf":
        return "pdf"
    if data[:8] == _CFB_MAGIC:
        return "ole"
    if data[:5] == b"{\\rtf" or ext == ".rtf":
        return "rtf"
    if data[:2] == b"PK":
        return "ooxml"
    if ext in (".doc", ".xls", ".ppt", ".msg"):
        return "ole"
    if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm"):
        return "ooxml"
    return "unknown"


def analyze_document(path: str, **_: Any) -> dict[str, Any]:
    """Analyze a document artifact (PDF / OOXML / OLE / RTF).

    Returns ``{"report": {...}, "findings": [...], "summary": "..."}`` in the
    same shape as the other forensic analyzers.
    """
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    with open(p, "rb") as fh:
        data = fh.read(_MAX_READ)
    ext = p.suffix.lower()
    doc_kind = _detect_document_kind(data, ext)

    if doc_kind == "pdf":
        out = _analyze_pdf(data, str(p))
    elif doc_kind == "ooxml":
        out = _analyze_ooxml(str(p), str(p))
    elif doc_kind == "ole":
        out = _analyze_ole(data, str(p))
    elif doc_kind == "rtf":
        out = _analyze_rtf(data, str(p))
    else:
        return {"error": f"unrecognized document format for {path}",
                "report": {"detected": doc_kind}, "findings": []}

    out.setdefault("report", {})["document_format"] = doc_kind
    return out
