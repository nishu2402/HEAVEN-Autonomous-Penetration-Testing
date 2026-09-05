"""Tests for the generic archive analyzer (zip / tar / gz)."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile

from heaven.forensics.archive import analyze_archive
from heaven.forensics.dispatch import detect_kind


def test_zip_slip_double_ext_secret_and_bomb(tmp_path):
    p = tmp_path / "e.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../etc/cron.d/pwn", "* * * * * root sh\n")
        zf.writestr("invoice.pdf.exe", b"MZ" + b"\x00" * 400)
        zf.writestr("cfg/app.yaml", 'aws_key = "AKIA1234567890ABCDEF"\n')
        zf.writestr("bomb.txt", b"A" * 2_000_000)
    r = analyze_archive(str(p))
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "archive_zip_slip" in vts
    assert "archive_double_extension" in vts
    assert "archive_embedded_secret" in vts
    assert "archive_decompression_bomb" in vts
    assert r["report"]["unsafe_paths"] == ["../../etc/cron.d/pwn"]


def test_tar_symlink_escape(tmp_path):
    p = tmp_path / "e.tar"
    with tarfile.open(p, "w") as tf:
        data = b"echo hi\n"
        ti = tarfile.TarInfo("run.sh")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
        link = tarfile.TarInfo("passwd")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    r = analyze_archive(str(p))
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "archive_tar_slip" in vts
    assert "archive_dropped_executable" in vts


def test_gzip_inner_type_detected(tmp_path):
    p = tmp_path / "payload.gz"
    with gzip.open(p, "wb") as g:
        g.write(b"\x7fELF" + b"\x00" * 50000)
    r = analyze_archive(str(p))
    assert r["report"]["inner_type"] == "ELF binary"
    assert r["report"]["archive_type"] == "gzip"


def test_detect_kind_routes_zip_to_archive(tmp_path):
    p = tmp_path / "plain.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("a.txt", "hello")
    assert detect_kind(str(p)) == "archive"


def test_clean_zip_has_no_findings(tmp_path):
    p = tmp_path / "clean.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("readme.txt", "just docs")
        zf.writestr("data.csv", "a,b,c\n1,2,3\n")
    r = analyze_archive(str(p))
    assert r["findings"] == []
    assert r["report"]["entries"] == 2
