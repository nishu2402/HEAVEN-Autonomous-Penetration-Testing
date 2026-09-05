"""Adversarial / hostile-input tests for offline artifact analysis.

These prove that a malicious upload cannot harm HEAVEN itself: image
decompression bombs, plist entity bombs (billion-laughs / XXE), zip bombs,
oversize uploads, path-traversal filenames and truncated captures are all
handled without unbounded memory use, code execution or a crash. They exercise
the real analyzers and the real API endpoints (auth disabled for the test).
"""

from __future__ import annotations

import io
import os
import struct
import zipfile
import zlib

import pytest


# ── helpers ──────────────────────────────────────────────────────────────────
def _png_with_dims(width: int, height: int) -> bytes:
    """A syntactically valid PNG header declaring ``width`` x ``height`` (a
    handful of bytes on disk regardless of the dimensions it claims)."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # RGB, 8-bit
    chunk = b"IHDR" + ihdr
    crc = zlib.crc32(chunk) & 0xFFFFFFFF
    png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + chunk + struct.pack(">I", crc)
    # a tiny (bogus) IDAT + IEND so byte-level scanners have an end marker
    png += struct.pack(">I", 0) + b"IDAT" + struct.pack(">I", zlib.crc32(b"IDAT") & 0xFFFFFFFF)
    png += struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    return png


def _real_png(width: int = 4, height: int = 4) -> bytes:
    """A genuinely decodable small PNG (via Pillow), for positive-path checks."""
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (width, height), (10, 20, 30)).save(buf, format="PNG")
    return buf.getvalue()


def _ipa_with_plist(plist_bytes: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/App.app/Info.plist", plist_bytes)
        zf.writestr("Payload/App.app/App", b"\x00binary\x00")
    return buf.getvalue()


# ── image decompression bomb ─────────────────────────────────────────────────
def test_pillow_ceiling_is_lowered() -> None:
    pytest.importorskip("PIL")
    from PIL import Image

    from heaven.forensics import stego
    stego._harden_pillow()
    assert Image.MAX_IMAGE_PIXELS is not None
    assert Image.MAX_IMAGE_PIXELS <= stego._MAX_PIXELS


def test_pixels_ok_rejects_oversized() -> None:
    from heaven.forensics import stego

    class _Img:
        width = 40000
        height = 40000
    assert stego._pixels_ok(_Img()) is False

    class _Small:
        width = 100
        height = 100
    assert stego._pixels_ok(_Small()) is True


def test_stego_pixel_bomb_is_bounded(tmp_path) -> None:
    """A tiny PNG claiming 30000x30000 (900M px) must not trigger a giant
    allocation: the pixel passes are skipped and the analyzer still returns."""
    pytest.importorskip("PIL")
    from heaven.forensics.stego import _lsb_pairs_metric, _lsb_text, analyze_stego
    p = tmp_path / "bomb.png"
    p.write_bytes(_png_with_dims(30000, 30000))
    # The two pixel-level passes must decline the oversized image.
    assert _lsb_text(str(p)) is None
    assert _lsb_pairs_metric(str(p)) is None
    # The whole analyzer completes and returns a normal result dict, no crash.
    out = analyze_stego(str(p))
    assert isinstance(out, dict)
    assert "findings" in out


def test_stego_real_small_png_still_analyzes(tmp_path) -> None:
    pytest.importorskip("PIL")
    from heaven.forensics.stego import analyze_stego
    p = tmp_path / "ok.png"
    p.write_bytes(_real_png(8, 8))
    out = analyze_stego(str(p))
    assert isinstance(out, dict) and "findings" in out
    # Image metadata is recovered for a legitimate small image.
    assert out.get("report", {}).get("image", {}).get("width") == 8


# ── plist entity bomb (billion laughs) / XXE ─────────────────────────────────
_BILLION_LAUGHS = (
    b'<?xml version="1.0"?>\n'
    b'<!DOCTYPE plist [\n'
    b'  <!ENTITY a "aaaaaaaaaa">\n'
    b'  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
    b'  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
    b']>\n'
    b'<plist version="1.0"><dict><key>x</key><string>&c;</string></dict></plist>'
)


def test_ipa_plist_entity_bomb_is_refused(tmp_path) -> None:
    """analyze_ipa must not expand a DOCTYPE/ENTITY plist. It completes with the
    plist rejected (empty), never inflating the entities in memory."""
    from heaven.forensics.mobile import analyze_ipa
    p = tmp_path / "evil.ipa"
    p.write_bytes(_ipa_with_plist(_BILLION_LAUGHS))
    out = analyze_ipa(str(p))
    assert isinstance(out, dict)
    # The bundle id / display name come from the plist; with the bomb refused
    # they are simply absent — the analyzer did not parse (and thus expand) it.
    report = out.get("report", {})
    assert not report.get("bundle_id")


def test_load_info_plist_rejects_doctype(tmp_path) -> None:
    from heaven.forensics.mobile import _ZipBudget, _load_info_plist
    data = _ipa_with_plist(_BILLION_LAUGHS)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        info, prefix = _load_info_plist(zf, _ZipBudget())
    assert info == {}                    # refused
    assert prefix == "Payload/App.app/"  # but the bundle path was still located


def test_load_info_plist_reads_benign(tmp_path) -> None:
    import plistlib

    from heaven.forensics.mobile import _ZipBudget, _load_info_plist
    good = plistlib.dumps({"CFBundleIdentifier": "com.example.app"})
    with zipfile.ZipFile(io.BytesIO(_ipa_with_plist(good))) as zf:
        info, _prefix = _load_info_plist(zf, _ZipBudget())
    assert info.get("CFBundleIdentifier") == "com.example.app"


# ── zip bomb ─────────────────────────────────────────────────────────────────
def test_zip_budget_caps_a_large_entry() -> None:
    from heaven.forensics.mobile import _MAX_ENTRY_BYTES, _ZipBudget
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", b"\x00" * (30 * 1024 * 1024))  # 30 MB of zeros
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
        data = _ZipBudget().read(zf, "classes.dex")
    # Never materialise more than the per-entry cap, however large the entry.
    assert len(data) <= _MAX_ENTRY_BYTES


# ── truncated / garbage capture ──────────────────────────────────────────────
def test_garbage_pcap_returns_error_not_crash(tmp_path) -> None:
    pytest.importorskip("scapy")
    from heaven.forensics.pcap import analyze_pcap
    p = tmp_path / "garbage.pcap"
    p.write_bytes(os.urandom(2048))
    out = analyze_pcap(str(p))
    assert isinstance(out, dict)
    # Either a graceful error or an empty-but-valid report; never an exception.
    assert "error" in out or "report" in out


# ── API endpoints (auth disabled) ────────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    os.environ["HEAVEN_DISABLE_AUTH"] = "1"
    from fastapi.testclient import TestClient

    from heaven.api.server import create_app
    app = create_app()
    yield TestClient(app)
    os.environ.pop("HEAVEN_DISABLE_AUTH", None)


def test_endpoint_multipart_upload(client) -> None:
    png = _real_png(6, 6)
    r = client.post("/api/analyze/run",
                    files={"file": ("pixel.png", png, "image/png")}, data={"kind": ""})
    assert r.status_code == 200
    body = r.json()
    assert body["detected_kind"] == "stego"
    assert body["filename"] == "pixel.png"


def test_endpoint_base64_backcompat(client) -> None:
    import base64
    png = _real_png(6, 6)
    r = client.post("/api/analyze/run",
                    json={"filename": "p.png", "content_b64": base64.b64encode(png).decode()})
    assert r.status_code == 200
    assert r.json()["detected_kind"] == "stego"


def test_endpoint_empty_file_rejected(client) -> None:
    r = client.post("/api/analyze/run",
                    files={"file": ("empty.bin", b"", "application/octet-stream")})
    assert r.status_code == 400


def test_endpoint_pdf_report_is_base64_pdf(client) -> None:
    import base64
    png = _real_png(6, 6)
    res = client.post("/api/analyze/run",
                      files={"file": ("p.png", png, "image/png")}).json()
    r = client.post("/api/analyze/report", json={"result": res, "format": "pdf"})
    assert r.status_code == 200
    body = r.json()
    assert body["encoding"] == "base64"
    assert body["mimetype"] == "application/pdf"
    assert body["filename"].endswith(".pdf")
    pdf = base64.b64decode(body["content"])
    assert pdf[:5] == b"%PDF-"


def test_endpoint_report_rejects_bad_format(client) -> None:
    r = client.post("/api/analyze/report", json={"result": {"kind": "x"}, "format": "exe"})
    assert r.status_code == 400


def test_endpoint_decode_oversize_rejected(client) -> None:
    r = client.post("/api/analyze/decode", json={"text": "A" * (5 * 1024 * 1024)})
    assert r.status_code == 413


def test_endpoint_traversal_filename_is_safe(client) -> None:
    # A path-traversal filename must never be used as an on-disk path; the upload
    # is analyzed from a random temp file and the extension alone is reused.
    png = _real_png(6, 6)
    r = client.post("/api/analyze/run",
                    files={"file": ("../../../../etc/passwd.png", png, "image/png")})
    assert r.status_code == 200
    assert r.json()["detected_kind"] == "stego"
    assert not os.path.exists("/etc/passwd.png")
