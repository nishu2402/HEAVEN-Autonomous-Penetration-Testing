"""HEAVEN — ELF / PE / Mach-O static binary analysis (pure-Python).

Reports the exploit-mitigation posture (checksec: NX, PIE, RELRO, stack
canary, stripped), the dangerous / attacker-useful imported functions, and
entropy-based packing indicators. No external tools are required for the ELF
and PE paths (``file`` / ``nm`` are used only as an enrichment fallback when
present). Everything comes from bytes actually parsed out of the file.
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("forensics.binary")

_MAX_READ = 256 * 1024 * 1024        # defensive cap on whole-file reads

# Attacker-relevant strings carved from the binary.
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,180}")
_IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]{1,40}@[A-Za-z0-9.\-]{2,40}\.[A-Za-z]{2,12}")
_CMD_RE = re.compile(rb"(?:/bin/sh|/bin/bash|/system/bin/sh|cmd\.exe|powershell(?:\.exe)?"
                     rb"|/bin/nc\b|wget\s|curl\s)")
_SECRET_RE = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(rb"ghp_[0-9A-Za-z]{36}"), "GitHub token"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
]
_NOISE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.2.3.4", "8.8.8.8",
              "192.168.0.1", "192.168.1.1"}

# Functions whose presence in a binary's imports is worth flagging: classic
# memory-corruption sinks and command-exec primitives.
_DANGEROUS_FUNCS = {
    "gets": ("no bounds check — trivially exploitable buffer overflow", "critical"),
    "strcpy": ("unbounded string copy → buffer overflow", "high"),
    "strcat": ("unbounded string concat → buffer overflow", "high"),
    "sprintf": ("unbounded formatted write → buffer overflow", "high"),
    "vsprintf": ("unbounded formatted write → buffer overflow", "high"),
    "scanf": ("unbounded %s read → buffer overflow", "medium"),
    "sscanf": ("unbounded %s read → buffer overflow", "medium"),
    "system": ("shell command execution — command-injection sink", "high"),
    "popen": ("shell command execution — command-injection sink", "high"),
    "execve": ("process execution primitive", "medium"),
    "execlp": ("PATH-searching process execution", "medium"),
    "execvp": ("PATH-searching process execution", "medium"),
    "strncpy": ("off-by-one / non-terminated buffer risk", "low"),
    "memcpy": ("length-controlled copy — overflow if size is attacker-controlled", "low"),
    "mktemp": ("insecure temp file (race)", "low"),
    "tmpnam": ("insecure temp file (race)", "low"),
    "rand": ("non-cryptographic RNG", "low"),
    "srand": ("non-cryptographic RNG seed", "low"),
}


@dataclass
class BinaryReport:
    path: str
    format: str = "unknown"          # elf | pe | macho | unknown
    arch: str = ""
    bits: int = 0
    endian: str = ""
    type: str = ""                   # EXEC / DYN / DLL ...
    entry_point: int = 0
    stripped: Optional[bool] = None
    # checksec-style mitigations (None = unknown / N/A for the format)
    nx: Optional[bool] = None
    pie: Optional[bool] = None
    relro: str = ""                  # none | partial | full
    canary: Optional[bool] = None
    aslr: Optional[bool] = None      # PE DYNAMICBASE
    seh: Optional[bool] = None       # PE SafeSEH / SEH
    rwx_segment: bool = False
    fortified: Optional[bool] = None     # _FORTIFY_SOURCE (*_chk) functions present
    entropy: float = 0.0
    packed: bool = False
    dotnet: Optional[bool] = None        # PE: managed (.NET/CLR) image
    code_signed: Optional[bool] = None   # Mach-O: LC_CODE_SIGNATURE present
    imports_flagged: list[dict] = field(default_factory=list)
    imported_libraries: list[str] = field(default_factory=list)  # DT_NEEDED / DLLs / dylibs
    rpath: list[str] = field(default_factory=list)               # RPATH / RUNPATH / LC_RPATH
    sections: list[dict] = field(default_factory=list)           # PE section table w/ entropy
    interesting_strings: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()}
        return d


# ── entropy ─────────────────────────────────────────────────────────────────
def _shannon(data: bytes) -> float:
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
    return ent


# ── ELF ──────────────────────────────────────────────────────────────────────
_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_GNU_EH_FRAME = 0x6474E550
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_DT_BIND_NOW = 24
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_BIND_NOW = 0x8
_DF_1_PIE = 0x08000000

_EM = {0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64",
       0x08: "MIPS", 0x14: "PowerPC", 0x15: "PPC64", 0xF3: "RISC-V"}


def _analyze_elf(data: bytes, rep: BinaryReport) -> BinaryReport:
    rep.format = "elf"
    ei_class = data[4]
    ei_data = data[5]
    rep.bits = 64 if ei_class == 2 else 32
    rep.endian = "little" if ei_data == 1 else "big"
    en = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2

    if is64:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            en + "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            en + "HHIIIIIHHHHHH", data, 16)

    rep.arch = _EM.get(e_machine, f"machine-0x{e_machine:x}")
    rep.type = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type))
    rep.entry_point = e_entry
    rep.pie = (e_type == 3)  # refined by DT_FLAGS_1 below

    # Program headers → NX / RELRO / RWX, plus a PT_LOAD map for vaddr→offset.
    rep.nx = True  # default; flipped false if GNU_STACK is executable or missing-exec-load
    gnu_stack_seen = False
    relro_seg = False
    dyn_off = dyn_size = 0
    loads: list[tuple[int, int, int]] = []   # (file_offset, vaddr, filesz)
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        if base + (56 if is64 else 32) > len(data):
            break
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _align = \
                struct.unpack_from(en + "IIQQQQQQ", data, base)
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, p_flags, _align = \
                struct.unpack_from(en + "IIIIIIII", data, base)
        if p_type == _PT_LOAD:
            loads.append((p_offset, p_vaddr, p_filesz))
        if p_type == _PT_GNU_STACK:
            gnu_stack_seen = True
            if p_flags & 0x1:  # executable stack
                rep.nx = False
        elif p_type == _PT_GNU_RELRO:
            relro_seg = True
        elif p_type == _PT_DYNAMIC:
            dyn_off, dyn_size = p_offset, p_filesz
        elif p_type == _PT_LOAD and (p_flags & 0x1) and (p_flags & 0x2):
            rep.rwx_segment = True
    if not gnu_stack_seen:
        rep.nx = None  # unknown (old toolchain); don't assert

    # Dynamic section → BIND_NOW / PIE flag, NEEDED libs and RPATH/RUNPATH.
    bind_now = False
    strtab_vaddr = 0
    needed_off: list[int] = []
    rpath_off: list[int] = []
    if dyn_off and dyn_size:
        entsz = 16 if is64 else 8
        for off in range(dyn_off, min(dyn_off + dyn_size, len(data)), entsz):
            if off + entsz > len(data):
                break
            if is64:
                d_tag, d_val = struct.unpack_from(en + "qQ", data, off)
            else:
                d_tag, d_val = struct.unpack_from(en + "iI", data, off)
            if d_tag == 0:  # DT_NULL
                break
            if d_tag == _DT_BIND_NOW:
                bind_now = True
            elif d_tag == _DT_FLAGS and (d_val & _DF_BIND_NOW):
                bind_now = True
            elif d_tag == _DT_FLAGS_1 and (d_val & _DF_1_PIE):
                rep.pie = True
            elif d_tag == 1:            # DT_NEEDED
                needed_off.append(d_val)
            elif d_tag == 5:            # DT_STRTAB (vaddr)
                strtab_vaddr = d_val
            elif d_tag in (15, 29):     # DT_RPATH / DT_RUNPATH
                rpath_off.append(d_val)
    rep.relro = "full" if (relro_seg and bind_now) else ("partial" if relro_seg else "none")

    # Resolve NEEDED / RPATH strings through the dynamic string table.
    if strtab_vaddr and loads:
        strtab_off = _elf_vaddr_to_off(strtab_vaddr, loads)
        if strtab_off is not None:
            rep.imported_libraries = [s for s in
                (_elf_cstr(data, strtab_off + o) for o in needed_off) if s][:60]
            rpaths = [s for s in
                (_elf_cstr(data, strtab_off + o) for o in rpath_off) if s]
            rep.rpath = [d for r in rpaths for d in r.split(":") if d][:20]

    # Section headers → symbols (stripped?, canary, dangerous imports)
    symbols = _elf_symbols(data, en, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    if symbols is not None:
        names = symbols["names"]
        imports = symbols["imports"]
        rep.stripped = not symbols["has_symtab"]
        rep.canary = "__stack_chk_fail" in names or "__stack_chk_guard" in names
        _flag_imports(imports or names, rep)
    else:
        rep.notes.append("symbol table not parseable; used string fallback")
        _flag_imports(set(_strings_fallback(data)), rep)
    return rep


def _elf_symbols(data, en, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx):
    """Parse .dynsym/.symtab into name sets. Returns dict or None."""
    if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
        return None
    try:
        # section header string table
        shstr_base = e_shoff + e_shstrndx * e_shentsize
        if is64:
            _n, _t, _f, _a, sh_off, sh_size = struct.unpack_from(
                en + "IIQQQQ", data, shstr_base)[:6]
        else:
            _n, _t, _f, _a, sh_off, sh_size = struct.unpack_from(
                en + "IIIIII", data, shstr_base)[:6]
        shstrtab = data[sh_off:sh_off + sh_size]

        def _name(off):
            e = shstrtab.find(b"\x00", off)
            return shstrtab[off:e].decode("latin1", "replace")

        sections = {}
        for i in range(e_shnum):
            b = e_shoff + i * e_shentsize
            if is64:
                nameoff, stype, _fl, _ad, offset, size, link, _info, _al, entsz = \
                    struct.unpack_from(en + "IIQQQQIIQQ", data, b)
            else:
                nameoff, stype, _fl, _ad, offset, size, link, _info, _al, entsz = \
                    struct.unpack_from(en + "IIIIIIIIII", data, b)
            sections[_name(nameoff)] = (stype, offset, size, link, entsz)

        names: set[str] = set()
        imports: set[str] = set()
        has_symtab = ".symtab" in sections
        for symsec, strsec in ((".symtab", ".strtab"), (".dynsym", ".dynstr")):
            if symsec not in sections or strsec not in sections:
                continue
            _st, soff, ssize, _lnk, entsz = sections[symsec]
            _st2, stroff, strsize, _l2, _e2 = sections[strsec]
            strtab = data[stroff:stroff + strsize]
            entsz = entsz or (24 if is64 else 16)
            for off in range(soff, soff + ssize, entsz):
                if off + entsz > len(data):
                    break
                if is64:
                    st_name, st_info, _o, st_shndx, _v, _sz = struct.unpack_from(
                        en + "IBBHQQ", data, off)
                else:
                    st_name, _v, _sz, st_info, _o, st_shndx = struct.unpack_from(
                        en + "IIIBBH", data, off)
                e = strtab.find(b"\x00", st_name)
                nm = strtab[st_name:e].decode("latin1", "replace")
                if not nm:
                    continue
                names.add(nm)
                if st_shndx == 0 and (st_info & 0xF) in (2, 0):  # UNDEF FUNC/NOTYPE
                    imports.add(nm)
        return {"names": names, "imports": imports, "has_symtab": has_symtab}
    except Exception:
        logger.debug("ELF symbol parse failed", exc_info=True)
        return None


def _strings_fallback(data: bytes, min_len: int = 4) -> list[str]:
    out, cur = [], bytearray()
    for b in data[:2_000_000]:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("latin1"))
            cur = bytearray()
    return out


def _elf_vaddr_to_off(vaddr: int, loads: list[tuple[int, int, int]]) -> Optional[int]:
    """Map a virtual address to a file offset using the PT_LOAD segments."""
    for off, va, filesz in loads:
        if va <= vaddr < va + filesz:
            return off + (vaddr - va)
    return None


def _elf_cstr(data: bytes, off: int, cap: int = 256) -> str:
    if off < 0 or off >= len(data):
        return ""
    e = data.find(b"\x00", off, off + cap)
    if e == -1:
        e = min(off + cap, len(data))
    return data[off:e].decode("latin1", "replace")


# ── PE section table + import DLLs ────────────────────────────────────────────
_PACKER_SECTIONS = {b"UPX0", b"UPX1", b"UPX2", b".aspack", b".adata", b".nsp0",
                    b".nsp1", b".packed", b"ASPack", b".pklstb", b".petite",
                    b"MPRESS1", b"MPRESS2", b"FSG!", b".Themida", b".vmp0", b".vmp1"}


def _pe_sections(data: bytes, e_lfanew: int, nsec: int, optsize: int) -> list[dict]:
    """Parse the PE section table; per-section entropy + RWX + packer flags."""
    out: list[dict] = []
    sect_start = e_lfanew + 24 + optsize
    for i in range(min(nsec, 96)):
        base = sect_start + i * 40
        if base + 40 > len(data):
            break
        name = data[base:base + 8].rstrip(b"\x00")
        _vsize, _vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        chars = struct.unpack_from("<I", data, base + 36)[0]
        blob = data[rawptr:rawptr + min(rawsize, 8 * 1024 * 1024)] if rawptr and rawsize else b""
        ent = round(_shannon(blob), 3) if blob else 0.0
        out.append({
            "name": name.decode("latin1", "replace"),
            "raw_size": rawsize,
            "entropy": ent,
            "readable": bool(chars & 0x40000000),
            "writable": bool(chars & 0x80000000),
            "executable": bool(chars & 0x20000000),
            "rwx": bool(chars & 0x80000000) and bool(chars & 0x20000000),
            "packer_name": name in _PACKER_SECTIONS,
        })
    return out


def _pe_rva_to_off(rva: int, sections_raw: list[tuple[int, int, int]]) -> Optional[int]:
    for vaddr, rawptr, rawsize in sections_raw:
        if vaddr <= rva < vaddr + max(rawsize, 1):
            return rawptr + (rva - vaddr)
    return None


def _pe_import_dlls(data: bytes, e_lfanew: int, optsize: int, is64: bool,
                    nsec: int) -> list[str]:
    """Best-effort list of imported DLL names from the PE import directory."""
    try:
        opt = e_lfanew + 24
        # DataDirectory[1] = import table; offset differs for PE32 vs PE32+.
        dd = opt + (112 if is64 else 96)
        imp_rva = struct.unpack_from("<I", data, dd)[0]
        if not imp_rva:
            return []
        sect_start = e_lfanew + 24 + optsize
        sections_raw: list[tuple[int, int, int]] = []
        for i in range(min(nsec, 96)):
            b = sect_start + i * 40
            if b + 40 > len(data):
                break
            vaddr, rawsize, rawptr = struct.unpack_from("<III", data, b + 12)[0], \
                struct.unpack_from("<I", data, b + 16)[0], struct.unpack_from("<I", data, b + 20)[0]
            sections_raw.append((vaddr, rawptr, rawsize))
        off = _pe_rva_to_off(imp_rva, sections_raw)
        if off is None:
            return []
        dlls: list[str] = []
        for k in range(256):
            desc = off + k * 20
            if desc + 20 > len(data):
                break
            name_rva = struct.unpack_from("<I", data, desc + 12)[0]
            if name_rva == 0:
                break
            name_off = _pe_rva_to_off(name_rva, sections_raw)
            if name_off is None:
                continue
            nm = _elf_cstr(data, name_off, 64)
            if nm:
                dlls.append(nm)
        return dlls[:60]
    except Exception:
        logger.debug("PE import parse failed", exc_info=True)
        return []


# ── Mach-O load commands (dylibs / code signature / rpath) ────────────────────
def _macho_loadcmds(data: bytes, en: str, is64: bool, ncmds: int) -> dict:
    off = 32 if is64 else 28
    dylibs: list[str] = []
    rpaths: list[str] = []
    code_signed = False
    for _ in range(min(ncmds, 4000)):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(en + "II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            break
        if cmd in (0xC, 0x18, 0x8000001F):     # LC_LOAD*_DYLIB / RE-EXPORT
            name_off = struct.unpack_from(en + "I", data, off + 8)[0]
            s = _elf_cstr(data, off + name_off, 200)
            if s:
                dylibs.append(s)
        elif cmd == 0x8000001C:                # LC_RPATH
            name_off = struct.unpack_from(en + "I", data, off + 8)[0]
            s = _elf_cstr(data, off + name_off, 200)
            if s:
                rpaths.append(s)
        elif cmd == 0x1D:                      # LC_CODE_SIGNATURE
            code_signed = True
        off += cmdsize
    return {"dylibs": dylibs[:60], "rpaths": rpaths[:20], "code_signed": code_signed}


def _flag_imports(names, rep: BinaryReport) -> None:
    for fn, (why, sev) in _DANGEROUS_FUNCS.items():
        if fn in names or f"_{fn}" in names or f"{fn}@plt" in names:
            rep.imports_flagged.append({"function": fn, "why": why, "severity": sev})
    if rep.fortified is None:
        rep.fortified = any(isinstance(n, str) and n.endswith("_chk") for n in names)


def _interesting_strings(data: bytes) -> dict:
    """Carve attacker-relevant strings (endpoints, creds, commands) from a binary."""
    scan = data[:_MAX_READ]
    urls = sorted({m.group(0).decode("latin1", "replace") for m in _URL_RE.finditer(scan)})
    ips = sorted({m.group(0).decode("latin1", "replace") for m in _IP_RE.finditer(scan)}
                 - _NOISE_IPS)
    # Drop version-string false positives like "1.2.3.4" embedded in build info.
    ips = [ip for ip in ips if not all(int(o) < 40 for o in ip.split("."))][:50]
    emails = sorted({m.group(0).decode("latin1", "replace")
                     for m in _EMAIL_RE.finditer(scan)})[:30]
    cmds = sorted({m.group(0).decode("latin1", "replace") for m in _CMD_RE.finditer(scan)})[:30]
    secrets: list[dict] = []
    for rx, label in _SECRET_RE:
        for m in rx.finditer(scan):
            secrets.append({"type": label, "match": m.group(0)[:80].decode("latin1", "replace")})
            if len(secrets) >= 20:
                break
    out: dict[str, Any] = {}
    if urls[:50]:
        out["urls"] = urls[:50]
    if ips:
        out["ips"] = ips
    if emails:
        out["emails"] = emails
    if cmds:
        out["commands"] = cmds
    if secrets:
        out["secrets"] = secrets
    return out


# ── PE ────────────────────────────────────────────────────────────────────────
def _analyze_pe(data: bytes, rep: BinaryReport) -> BinaryReport:
    rep.format = "pe"
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            rep.notes.append("PE signature not found")
            return rep
        machine, nsec, _ts, _psym, _nsym, optsize, characteristics = \
            struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
        rep.arch = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM",
                    0xAA64: "ARM64"}.get(machine, f"machine-0x{machine:x}")
        rep.type = "DLL" if (characteristics & 0x2000) else "EXE"
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        rep.bits = 64 if magic == 0x20B else 32
        is64 = magic == 0x20B
        # DllCharacteristics offset: 0x46 (PE32) / 0x46 (PE32+) from optional start
        dllchar_off = opt + 0x46
        dllchar = struct.unpack_from("<H", data, dllchar_off)[0]
        rep.aslr = bool(dllchar & 0x0040)          # DYNAMICBASE
        rep.nx = bool(dllchar & 0x0100)            # NX_COMPAT (DEP)
        rep.seh = not bool(dllchar & 0x0400)       # NO_SEH bit clear => SEH present
        rep.pie = rep.aslr
        addr_entry = struct.unpack_from("<I", data, opt + 16)[0]
        rep.entry_point = addr_entry
        # .NET / managed image: DataDirectory[14] (COM descriptor) is non-zero.
        try:
            clr_rva = struct.unpack_from("<I", data, opt + (112 if is64 else 96) + 14 * 8)[0]
            rep.dotnet = bool(clr_rva)
        except Exception:  # noqa: BLE001
            rep.dotnet = None
        # Section table (entropy / RWX / packer) and imported DLLs.
        rep.sections = _pe_sections(data, e_lfanew, nsec, optsize)
        rep.imported_libraries = _pe_import_dlls(data, e_lfanew, optsize, is64, nsec)
        # Import scan (lightweight: dangerous WinAPI via strings)
        _flag_imports(set(_strings_fallback(data)), rep)
    except Exception:
        logger.debug("PE parse failed", exc_info=True)
        rep.notes.append("PE header parse error")
    return rep


# ── Mach-O ────────────────────────────────────────────────────────────────────
def _analyze_macho(data: bytes, rep: BinaryReport) -> BinaryReport:
    rep.format = "macho"
    magic = struct.unpack_from(">I", data, 0)[0]
    little = magic in (0xCEFAEDFE, 0xCFFAEDFE)
    en = "<" if little else ">"
    is64 = struct.unpack_from(en + "I", data, 0)[0] in (0xFEEDFACF, 0xCFFAEDFE)
    rep.bits = 64 if is64 else 32
    try:
        cputype, _sub, filetype, ncmds, _scmds, flags = struct.unpack_from(
            en + "iiIIII", data, 4)
        rep.arch = {7: "x86", 0x01000007: "x86-64", 12: "ARM",
                    0x0100000C: "ARM64"}.get(cputype, f"cpu-0x{cputype:x}")
        rep.type = {2: "EXEC", 6: "DYLIB", 8: "BUNDLE"}.get(filetype, str(filetype))
        rep.pie = bool(flags & 0x200000)       # MH_PIE
        rep.nx = not bool(flags & 0x20000)     # MH_ALLOW_STACK_EXECUTION clear
        lc = _macho_loadcmds(data, en, is64, ncmds)
        rep.imported_libraries = lc["dylibs"]
        rep.rpath = lc["rpaths"]
        rep.code_signed = lc["code_signed"]
        strs = set(_strings_fallback(data))
        _flag_imports(strs, rep)
        rep.canary = "__stack_chk_fail" in strs
    except Exception:
        rep.notes.append("Mach-O header parse error")
    return rep


def _fat_first_slice(data: bytes, is64: bool) -> Optional[bytes]:
    """Extract the first architecture slice from a universal Mach-O."""
    try:
        nfat = struct.unpack_from(">I", data, 4)[0]
        if not (0 < nfat < 30):
            return None
        if is64:
            _cpu, _sub, offset, size, _al = struct.unpack_from(">iiQQI", data, 8)
        else:
            _cpu, _sub, offset, size, _al = struct.unpack_from(">iiIII", data, 8)
        if offset + size <= len(data):
            return data[offset:offset + size]
    except Exception:
        return None
    return None


# ── public entry point ────────────────────────────────────────────────────────
def analyze_binary(path: str, **_: Any) -> dict[str, Any]:
    """Analyze one binary file. Returns ``{"report": {...}, "findings": [...]}``."""
    p = Path(path)
    if not p.is_file():
        return {"error": f"not a file: {path}"}
    with open(p, "rb") as fh:
        data = fh.read(_MAX_READ)
    rep = BinaryReport(path=str(p))
    rep.entropy = round(_shannon(data), 3)
    rep.packed = rep.entropy >= 7.2
    rep.interesting_strings = _interesting_strings(data)

    magic_be = struct.unpack_from(">I", data, 0)[0] if len(data) >= 4 else 0
    try:
        if data[:4] == b"\x7fELF":
            _analyze_elf(data, rep)
        elif data[:2] == b"MZ":
            _analyze_pe(data, rep)
        elif magic_be in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
            _analyze_macho(data, rep)
        elif magic_be in (0xCAFEBABE, 0xCAFEBABF):
            # Fat / universal Mach-O: analyze the first architecture slice.
            slice_data = _fat_first_slice(data, magic_be == 0xCAFEBABF)
            if slice_data:
                _analyze_macho(slice_data, rep)
                rep.notes.append("universal (fat) Mach-O — analyzed first arch slice")
            else:
                rep.notes.append("fat Mach-O header not parseable")
        else:
            rep.notes.append("unrecognized binary format")
    except Exception as e:  # noqa: BLE001 — malformed/truncated binaries must not crash
        logger.debug("binary parse error", exc_info=True)
        rep.notes.append(f"parse error ({type(e).__name__}); header may be malformed")

    _build_findings(rep)
    return {"report": rep.to_dict(), "findings": rep.findings,
            "summary": _summary(rep)}


def _summary(rep: BinaryReport) -> str:
    bits = [f"{rep.format.upper()} {rep.bits}-bit {rep.arch}".strip()]
    mit = []
    if rep.nx is not None:
        mit.append("NX" + ("" if rep.nx else "✗"))
    if rep.pie is not None:
        mit.append("PIE" + ("" if rep.pie else "✗"))
    if rep.relro:
        mit.append(f"RELRO={rep.relro}")
    if rep.canary is not None:
        mit.append("Canary" + ("" if rep.canary else "✗"))
    if rep.fortified:
        mit.append("FORTIFY")
    if mit:
        bits.append(" ".join(mit))
    if rep.packed:
        bits.append(f"packed(entropy={rep.entropy})")
    return " · ".join(bits)


def _build_findings(rep: BinaryReport) -> None:
    def add(vt, sev, title, desc, **extra):
        rep.findings.append({
            "target": rep.path, "vuln_type": vt, "severity": sev,
            "title": title, "description": desc, "scanner": "binary_analyzer",
            "confidence": 0.9, "cwe": extra.pop("cwe", ""),
            "remediation": extra.pop("remediation", ""), **extra})

    if rep.nx is False:
        add("no_nx", "high", "Executable stack (NX disabled)",
            "The binary's stack is executable (GNU_STACK is RWX). Shellcode "
            "placed on the stack can run directly, removing a key exploitation "
            "barrier.", cwe="CWE-119",
            remediation="Rebuild with a non-executable stack (remove -z execstack).")
    if rep.pie is False and rep.type in ("EXEC", "EXE"):
        add("no_pie", "medium", "No PIE / ASLR for the image",
            "The executable is not position-independent, so its code loads at a "
            "fixed address and ASLR does not randomize it. This makes ROP / "
            "ret2libc far easier.", cwe="CWE-1188",
            remediation="Rebuild with -fPIE -pie (or /DYNAMICBASE on Windows).")
    if rep.relro == "none" and rep.format == "elf":
        add("no_relro", "medium", "No RELRO (GOT is writable)",
            "The Global Offset Table is writable at runtime, enabling GOT-overwrite "
            "attacks after a memory-corruption primitive.", cwe="CWE-119",
            remediation="Rebuild with -Wl,-z,relro,-z,now for full RELRO.")
    elif rep.relro == "partial" and rep.format == "elf":
        add("partial_relro", "low", "Partial RELRO only",
            "RELRO is partial: the GOT is still writable. Enable full RELRO.",
            remediation="Rebuild with -Wl,-z,relro,-z,now.")
    if rep.canary is False:
        add("no_canary", "medium", "No stack canary",
            "No stack-smashing protector was found, so a linear stack overflow "
            "can overwrite the return address without tripping a canary.",
            cwe="CWE-121",
            remediation="Rebuild with -fstack-protector-strong.")
    if rep.rwx_segment:
        add("rwx_segment", "medium", "Writable+executable memory segment",
            "A PT_LOAD segment is mapped read/write/execute, allowing runtime "
            "code injection.", cwe="CWE-119")
    if rep.packed:
        add("packed_binary", "low", f"High entropy ({rep.entropy}) — likely packed/encrypted",
            "The file's byte entropy is very high, typical of a packed or "
            "encrypted binary. Static review is limited until it is unpacked; "
            "this is common in malware.", cwe="CWE-506")
    for imp in rep.imports_flagged:
        if imp["severity"] in ("high", "critical"):
            add(f"dangerous_import_{imp['function']}", imp["severity"],
                f"Dangerous import: {imp['function']}()",
                f"The binary imports {imp['function']}(): {imp['why']}.",
                cwe="CWE-676")
    strs = rep.interesting_strings
    if strs.get("secrets"):
        sample = "; ".join(s["match"] for s in strs["secrets"][:3])
        add("binary_embedded_secret", "high", "Embedded secret/key in the binary",
            f"Credential or key material is hardcoded in the binary: {sample}. "
            "Anyone with the file can extract it.", cwe="CWE-798",
            evidence={"secrets": strs["secrets"][:10]},
            remediation="Remove hardcoded secrets; load them from a protected store "
                        "at runtime and rotate the exposed values.")
    if strs.get("urls") or strs.get("ips"):
        add("binary_hardcoded_endpoint", "info",
            "Hardcoded network endpoint(s) in the binary",
            "The binary embeds hardcoded URLs/IP addresses. These are the servers it "
            "talks to (update, telemetry, or — in malware — command-and-control).",
            cwe="CWE-200",
            evidence={"urls": strs.get("urls", [])[:15], "ips": strs.get("ips", [])[:15]})
    if rep.fortified is False and rep.format == "elf" and rep.stripped is False:
        add("no_fortify", "low", "Built without _FORTIFY_SOURCE",
            "No fortified libc functions (*_chk) were found, so compile-time buffer "
            "checks for functions like memcpy/sprintf are not in place.",
            remediation="Rebuild with -D_FORTIFY_SOURCE=2 -O2.")
    # Insecure RPATH/RUNPATH → library-hijack (relative or world-writable dirs).
    bad_rpath = [r for r in rep.rpath
                 if r.startswith(".") or r.startswith(("/tmp", "/var/tmp"))
                 or not r.startswith(("/", "$"))]
    if bad_rpath:
        add("insecure_rpath", "medium", "Insecure RPATH/RUNPATH (library hijack)",
            "The binary's run-time library search path includes a relative or "
            f"world-writable directory ({', '.join(bad_rpath[:4])}). An attacker "
            "who can write there can plant a malicious shared library that the "
            "loader will load in preference to the real one.", cwe="CWE-426",
            evidence={"rpath": rep.rpath},
            remediation="Remove relative/writable RPATH entries; use only absolute, "
                        "trusted, non-writable library directories.")
    # RWX / packer PE sections.
    rwx_secs = [s["name"] for s in rep.sections if s.get("rwx")]
    if rwx_secs:
        add("rwx_section", "medium", "Writable+executable PE section",
            f"Section(s) {', '.join(rwx_secs[:4])} are both writable and "
            "executable, allowing self-modifying code / runtime unpacking — a "
            "common malware trait.", cwe="CWE-119",
            evidence={"sections": [s for s in rep.sections if s.get("rwx")]})
    packer_secs = [s["name"] for s in rep.sections if s.get("packer_name")]
    hi_entropy_exec = [s["name"] for s in rep.sections
                       if s.get("executable") and s.get("entropy", 0) >= 7.2]
    if packer_secs:
        add("packed_binary", "low", f"Packer section(s): {', '.join(packer_secs[:3])}",
            "The PE has sections named by a known executable packer (e.g. UPX/"
            "ASPack/Themida). The real code is compressed/encrypted until it "
            "unpacks itself at runtime.", cwe="CWE-506",
            evidence={"sections": packer_secs})
    elif hi_entropy_exec and not rep.packed:
        add("high_entropy_section", "low",
            f"High-entropy executable section(s): {', '.join(hi_entropy_exec[:3])}",
            "An executable section has near-random entropy, typical of packed or "
            "encrypted code.", cwe="CWE-506",
            evidence={"sections": [s for s in rep.sections
                                   if s["name"] in hi_entropy_exec]})
