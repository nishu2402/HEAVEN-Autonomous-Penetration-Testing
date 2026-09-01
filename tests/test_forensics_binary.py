"""Tests for the offline binary analyzer (ELF/PE/Mach-O checksec)."""

from __future__ import annotations

import os
import struct

import pytest

from heaven.forensics.binary import _shannon, analyze_binary


def _make_elf_exec_stack() -> bytes:
    """A minimal 64-bit x86-64 ELF (ET_EXEC) with one PT_GNU_STACK program
    header marked RWX — i.e. an executable stack (NX disabled)."""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    phoff = 64
    phentsize = 56
    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type = ET_EXEC
        0x3E,       # e_machine = x86-64
        1,          # e_version
        0x401000,   # e_entry
        phoff,      # e_phoff
        0,          # e_shoff (no section headers)
        0,          # e_flags
        64,         # e_ehsize
        phentsize,  # e_phentsize
        1,          # e_phnum
        0, 0, 0,    # e_shentsize, e_shnum, e_shstrndx
    )
    # PT_GNU_STACK, flags RWX (0x7)
    ph = struct.pack("<IIQQQQQQ", 0x6474E551, 0x7, 0, 0, 0, 0, 0, 0)
    return header + ph


def test_shannon_entropy_bounds():
    assert _shannon(b"") == 0.0
    assert _shannon(b"\x00" * 1000) == 0.0            # single symbol → 0
    assert _shannon(bytes(range(256)) * 4) > 7.9      # uniform → ~8


def test_elf_exec_stack_flags_no_nx_and_no_pie(tmp_path):
    p = tmp_path / "vuln.elf"
    p.write_bytes(_make_elf_exec_stack())
    r = analyze_binary(str(p))
    rep = r["report"]
    assert rep["format"] == "elf"
    assert rep["arch"] == "x86-64"
    assert rep["bits"] == 64
    assert rep["type"] == "EXEC"
    assert rep["nx"] is False
    assert rep["pie"] is False
    vts = {f["vuln_type"] for f in r["findings"]}
    assert "no_nx" in vts
    assert "no_pie" in vts


def test_dangerous_import_flagged_via_strings(tmp_path):
    # ELF header + no section table → string fallback picks up 'system'/'gets'.
    blob = _make_elf_exec_stack() + b"\x00padding\x00system\x00gets\x00strcpy\x00"
    p = tmp_path / "b.elf"
    p.write_bytes(blob)
    r = analyze_binary(str(p))
    flagged = {i["function"] for i in r["report"]["imports_flagged"]}
    assert {"system", "gets", "strcpy"} <= flagged


def test_high_entropy_marks_packed(tmp_path):
    # Pure random (no recognizable header) → high entropy → packed indicator.
    p = tmp_path / "packed.bin"
    p.write_bytes(os.urandom(50000))
    r = analyze_binary(str(p))
    assert r["report"]["packed"] is True
    assert r["report"]["entropy"] >= 7.2


def test_malformed_elf_does_not_crash(tmp_path):
    # Valid ELF magic but garbage offsets must yield a report, not an exception.
    p = tmp_path / "bad.elf"
    p.write_bytes(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + os.urandom(50000))
    r = analyze_binary(str(p))
    assert r["report"]["format"] == "elf"


def test_missing_file_errors():
    r = analyze_binary("/nonexistent/path/xyz")
    assert "error" in r


@pytest.mark.skipif(not os.path.exists("/bin/ls"), reason="no /bin/ls")
def test_real_macho_binary_parses():
    r = analyze_binary("/bin/ls")
    rep = r["report"]
    # /bin/ls is Mach-O on macOS, ELF on Linux — either way it must parse.
    assert rep["format"] in ("macho", "elf")
    assert rep["bits"] in (32, 64)
    assert rep["arch"]
