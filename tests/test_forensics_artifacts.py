"""Tests for firmware / stego / APK analyzers + artifact dispatch."""

from __future__ import annotations

import io
import struct
import zipfile

import plistlib

from heaven.forensics.dispatch import analyze_artifact, detect_kind
from heaven.forensics.firmware import analyze_firmware
from heaven.forensics.mobile import analyze_apk, analyze_ipa
from heaven.forensics.stego import analyze_stego


# ── firmware ────────────────────────────────────────────────────────────────
def test_firmware_carves_fs_and_secret(tmp_path):
    fw = (b"\x00" * 32 + b"hsqs" + b"\x00" * 64
          + b"web_passwd=admin123\n"
          + b"-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n" + b"\x00" * 40)
    p = tmp_path / "fw.bin"
    p.write_bytes(fw)
    r = analyze_firmware(str(p))
    assert any("squashfs" in fs for fs in r["report"]["filesystems"])
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "firmware_hardcoded_secret" in vts
    assert "firmware_filesystem_extractable" in vts


# ── stego ───────────────────────────────────────────────────────────────────
def _png_bytes():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (120, 120, 120)).save(buf, "PNG")
    return buf.getvalue()


def test_stego_trailing_zip_detected(tmp_path):
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("secret.txt", "the flag")
    p = tmp_path / "s.png"
    p.write_bytes(_png_bytes() + zbuf.getvalue())
    r = analyze_stego(str(p))
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "stego_trailing_data" in vts
    assert r["report"]["trailing_data"]["type"] == "ZIP archive"


def test_stego_clean_image_no_findings(tmp_path):
    p = tmp_path / "clean.png"
    p.write_bytes(_png_bytes())
    r = analyze_stego(str(p))
    # a freshly-made flat image should not trip trailing-data detection
    assert not any(f["vuln_type"] == "stego_trailing_data" for f in r["findings"])


# ── APK ─────────────────────────────────────────────────────────────────────
def _axml_with(strings):
    sdata = b""
    offsets = []
    for s in strings:
        offsets.append(len(sdata))
        sdata += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    header_size = 28
    offarr = b"".join(struct.pack("<I", o) for o in offsets)
    strings_start = header_size + len(offarr)
    body = struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0) + offarr + sdata
    pool = struct.pack("<HHI", 0x0001, header_size, 8 + len(body)) + body
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool)) + pool


def _make_apk(path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml",
                   _axml_with(["android.permission.READ_SMS", "debuggable"]))
        z.writestr("classes.dex",
                   b"dex\n035\x00password=Sup3rSecret123 http://api.evil.com/x")
    path.write_bytes(buf.getvalue())


def test_apk_permissions_and_secrets(tmp_path):
    p = tmp_path / "app.apk"
    _make_apk(p)
    r = analyze_apk(str(p))
    assert "android.permission.READ_SMS" in r["report"]["permissions"]
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "apk_hardcoded_secret" in vts
    assert "apk_cleartext_traffic" in vts
    assert "apk_dangerous_permissions" in vts


def test_apk_rejects_non_apk_zip(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("hello.txt", "not an apk")
    p = tmp_path / "x.zip"
    p.write_bytes(buf.getvalue())
    r = analyze_apk(str(p))
    assert "error" in r


def test_apk_allow_backup_and_owasp_tags(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml",
                   _axml_with(["android.permission.CAMERA", "allowBackup"]))
        z.writestr("classes.dex", b"dex\n035\x00nothing interesting here")
    p = tmp_path / "b.apk"
    p.write_bytes(buf.getvalue())
    r = analyze_apk(str(p))
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "apk_backup_allowed" in vts
    # Every finding is tagged with an OWASP Mobile Top 10 bucket.
    assert all(f.get("owasp_mobile") for f in r["findings"])


# ── iOS IPA ──────────────────────────────────────────────────────────────────
def _make_ipa(path, *, ats_cleartext=True):
    info = {
        "CFBundleIdentifier": "com.example.demo",
        "CFBundleDisplayName": "Demo",
        "MinimumOSVersion": "12.0",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demoapp"]}],
        "NSCameraUsageDescription": "cam",
    }
    if ats_cleartext:
        info["NSAppTransportSecurity"] = {"NSAllowsArbitraryLoads": True}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(info))
        z.writestr("Payload/Demo.app/config.js",
                   b"var apiKey='AKIAABCDEFGHIJKLMNOP'; var u='http://api.demo.com/x';")
    path.write_bytes(buf.getvalue())


def test_ipa_detects_ats_secrets_schemes_and_owasp(tmp_path):
    p = tmp_path / "app.ipa"
    _make_ipa(p)
    r = analyze_ipa(str(p))
    assert r["report"]["platform"] == "ios"
    assert r["report"]["bundle_id"] == "com.example.demo"
    assert r["report"]["ats_allows_cleartext"] is True
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "ipa_hardcoded_secret" in vts
    assert "ipa_cleartext_ats_disabled" in vts
    assert "ipa_url_scheme" in vts
    assert all(f.get("owasp_mobile") for f in r["findings"])


def test_ipa_detect_kind_and_dispatch(tmp_path):
    p = tmp_path / "app.ipa"
    _make_ipa(p)
    assert detect_kind(str(p)) == "ipa"
    r = analyze_artifact(str(p))
    assert r["kind"] == "ipa" and r["report"]["platform"] == "ios"


def test_ipa_rejects_non_ipa_zip(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("hello.txt", "not an ipa")
    p = tmp_path / "x.zip"
    p.write_bytes(buf.getvalue())
    r = analyze_ipa(str(p))
    assert "error" in r


# ── dispatch ────────────────────────────────────────────────────────────────
def test_detect_kind(tmp_path):
    png = tmp_path / "i.png"
    png.write_bytes(_png_bytes())
    assert detect_kind(str(png)) == "stego"

    apk = tmp_path / "a.apk"
    _make_apk(apk)
    assert detect_kind(str(apk)) == "apk"

    fw = tmp_path / "f.bin"
    fw.write_bytes(b"\x00" * 8 + b"hsqs" + b"\x00" * 64)
    assert detect_kind(str(fw)) == "firmware"


def test_dispatch_routes_and_tags_kind(tmp_path):
    fw = tmp_path / "f.bin"
    fw.write_bytes(b"\x00" * 8 + b"hsqs" + b"\x00" * 64 + b"password=secret123\n")
    r = analyze_artifact(str(fw))
    assert r["kind"] == "firmware"


def test_dispatch_unknown_is_error(tmp_path):
    p = tmp_path / "mystery.dat"
    p.write_bytes(b"\x11\x22\x33 just some bytes that match nothing specific")
    r = analyze_artifact(str(p))
    assert r.get("kind") == "unknown" and "error" in r


def _mp4_bytes(extra: bytes = b"") -> bytes:
    # A minimal but real ISO base media header (an 'ftyp' box), plus optional
    # trailing bytes to simulate metadata atoms.
    import struct
    return (struct.pack(">I", 32) + b"ftypisom" + struct.pack(">I", 0x200)
            + b"isomiso2avc1mp41" + extra)


def test_detect_kind_media_by_magic_and_ext(tmp_path):
    # Content-based (ftyp) detection, even with a misleading extension.
    m = tmp_path / "clip.bin"
    m.write_bytes(_mp4_bytes())
    assert detect_kind(str(m)) == "media"
    # Extension-based detection for formats without a checked magic.
    for name in ("song.mp3", "clip.mov", "movie.mkv", "audio.wav"):
        f = tmp_path / name
        f.write_bytes(b"\x00" * 32)
        assert detect_kind(str(f)) == "media", name


def test_media_upload_has_no_webshell_false_positive(tmp_path):
    # The reported bug: a video whose bytes happen to contain a webshell brand
    # token was flagged as a critical PHP webshell. It must now be recognized as
    # media, carry no error, and raise no critical/high finding.
    p = tmp_path / "abhi utha hu nind se.MP4"
    p.write_bytes(_mp4_bytes(b"\x00moov\xa9toolWSO 2 handler\x00FilesMan\x00"
                             + b"\x00" * 256))
    r = analyze_artifact(str(p))
    assert r.get("kind") == "media"
    assert "error" not in r
    bad = [f for f in r.get("findings", [])
           if f.get("severity") in ("critical", "high")]
    assert bad == [], bad
