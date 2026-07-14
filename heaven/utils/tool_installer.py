"""HEAVEN — external-tool catalog + cross-platform installer.

HEAVEN shells out to a handful of best-of-breed security binaries (nmap,
nuclei, sqlmap, ffuf, searchsploit, semgrep, docker). Every one of them has an
in-house fallback so the scanner *runs* without them — but with them installed
HEAVEN operates at full power (real SQLi exploitation proof, content fuzzing,
Exploit-DB PoC lookup, SAST, template checks). This module is the single source
of truth for:

  • what each tool is for            → ``TOOLS`` (name + purpose)
  • how to install it on this OS      → ``build_install_command`` / ``install_hint``
  • whether it is present            → ``is_present`` / ``missing_tools``
  • installing the missing ones      → ``install_tools``

The same catalog powers ``heaven install-tools`` (CLI), ``heaven doctor``,
``scripts/install.sh`` and the web System-Health panel, so the tool list and the
install instructions can never drift between them.

It is pure-stdlib (no click / no third-party imports) so it can be imported from
anywhere, including the API server and the plain-Click fallback.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ToolSpec:
    """One external binary HEAVEN can use, with per-package-manager install info."""
    name: str            # the executable name looked up on PATH
    purpose: str         # one-line description shown in doctor / health panel
    brew: Optional[str] = None      # Homebrew formula (macOS / Linuxbrew)
    apt: Optional[str] = None       # Debian/Ubuntu package
    dnf: Optional[str] = None       # Fedora/RHEL package
    pacman: Optional[str] = None    # Arch package
    pip: Optional[str] = None       # PyPI package (installed into HEAVEN's interpreter)
    go: Optional[str] = None        # `go install <pkg>` path
    url: Optional[str] = None       # manual-install docs when nothing else applies


# ── The catalog ───────────────────────────────────────────────────────────────
# Order here is the order shown to the operator (doctor, health panel, installer).
TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="nmap", purpose="Network port/service scanning",
        brew="nmap", apt="nmap", dnf="nmap", pacman="nmap",
        url="https://nmap.org/download.html",
    ),
    ToolSpec(
        name="nuclei", purpose="Template-based vulnerability checks",
        brew="nuclei", pacman="nuclei",
        go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        url="https://github.com/projectdiscovery/nuclei#install-nuclei",
    ),
    ToolSpec(
        name="sqlmap", purpose="Automated SQL-injection exploitation proof",
        brew="sqlmap", apt="sqlmap", dnf="sqlmap", pacman="sqlmap", pip="sqlmap",
        url="https://github.com/sqlmapproject/sqlmap#installation",
    ),
    ToolSpec(
        name="ffuf", purpose="Content/directory fuzzing",
        brew="ffuf", apt="ffuf", pacman="ffuf",
        go="github.com/ffuf/ffuf/v2@latest",
        url="https://github.com/ffuf/ffuf#installation",
    ),
    ToolSpec(
        name="searchsploit", purpose="Local Exploit-DB PoC lookup",
        brew="exploitdb", apt="exploitdb", pacman="exploitdb",
        url="https://gitlab.com/exploit-database/exploitdb#git",
    ),
    ToolSpec(
        name="semgrep", purpose="Static analysis (SAST)",
        brew="semgrep", pip="semgrep",
        url="https://semgrep.dev/docs/getting-started/",
    ),
    ToolSpec(
        name="docker", purpose="Container/Kubernetes recon + DVWA benchmark",
        apt="docker.io", dnf="docker", pacman="docker",
        url="https://docs.docker.com/get-docker/",
    ),
]

_BY_NAME = {t.name: t for t in TOOLS}


# ── Detection ─────────────────────────────────────────────────────────────────
def is_present(name: str) -> bool:
    """True when the tool's executable is on PATH."""
    return shutil.which(name) is not None


def get_spec(name: str) -> Optional[ToolSpec]:
    return _BY_NAME.get(name)


def tool_names() -> list[str]:
    """The canonical ordered list of external tools HEAVEN knows about."""
    return [t.name for t in TOOLS]


def missing_tools() -> list[ToolSpec]:
    """Every catalog tool not currently on PATH."""
    return [t for t in TOOLS if not is_present(t.name)]


def _pkg_manager() -> Optional[str]:
    """The system package manager available on this host, if any."""
    if sys.platform == "darwin":
        return "brew" if shutil.which("brew") else None
    if sys.platform.startswith("linux"):
        # Homebrew on Linux is valid too, but prefer the native manager.
        for mgr in ("apt-get", "dnf", "pacman"):
            if shutil.which(mgr):
                return mgr
        if shutil.which("brew"):
            return "brew"
    return None


# ── Command construction ──────────────────────────────────────────────────────
def build_install_command(spec: ToolSpec) -> Optional[list[str]]:
    """The best install command for *spec* on this host, or None if manual-only.

    Preference: native OS package manager → pip (into HEAVEN's own interpreter,
    so it lands on the same PATH) → `go install`. Linux system managers are
    wrapped in ``sudo`` (matching scripts/install.sh); pip/go/brew need no root.
    """
    mgr = _pkg_manager()
    # 1) native package manager
    if mgr == "brew" and spec.brew:
        return ["brew", "install", spec.brew]
    if mgr == "apt-get" and spec.apt:
        return ["sudo", "apt-get", "install", "-y", spec.apt]
    if mgr == "dnf" and spec.dnf:
        return ["sudo", "dnf", "install", "-y", spec.dnf]
    if mgr == "pacman" and spec.pacman:
        return ["sudo", "pacman", "-S", "--noconfirm", spec.pacman]
    # 2) pip — reliable, cross-platform, lands next to the `heaven` script
    if spec.pip and (shutil.which("pip") or shutil.which("pip3") or sys.executable):
        return [sys.executable, "-m", "pip", "install", "--upgrade", spec.pip]
    # 3) go toolchain
    if spec.go and shutil.which("go"):
        return ["go", "install", spec.go]
    return None


def install_hint(spec: ToolSpec) -> str:
    """Human-readable, platform-appropriate one-liner for how to install *spec*.

    Falls back to the cross-platform recipe list when no package manager is
    detected, so the hint is always actionable.
    """
    cmd = build_install_command(spec)
    if cmd:
        # Drop the interpreter path noise: show `pip install X` not the abspath.
        if cmd[:3] == [sys.executable, "-m", "pip"]:
            return "pip install " + " ".join(cmd[4:])
        return " ".join(cmd)
    # No usable command on this host — offer the recipes that fit this OS so we
    # never suggest `apt` on macOS or a Homebrew cask on a headless Linux box.
    parts = []
    if sys.platform == "darwin":
        if spec.brew:
            parts.append(f"brew install {spec.brew}")
        if spec.pip:
            parts.append(f"pip install {spec.pip}")
    else:
        if spec.apt:
            parts.append(f"apt install {spec.apt}")
        if spec.dnf:
            parts.append(f"dnf install {spec.dnf}")
        if spec.brew:
            parts.append(f"brew install {spec.brew}")
        if spec.pip:
            parts.append(f"pip install {spec.pip}")
    if spec.go:
        parts.append(f"go install {spec.go}")
    if spec.url:
        parts.append(spec.url)
    return "  ·  ".join(parts) if parts else (spec.url or "see project docs")


# ── Installation ──────────────────────────────────────────────────────────────
@dataclass
class InstallResult:
    """Outcome of attempting to install one tool."""
    name: str
    status: str                       # present | installed | failed | manual | planned
    command: Optional[list[str]] = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("present", "installed", "planned")


def install_tools(
    specs: Optional[list[ToolSpec]] = None,
    *,
    dry_run: bool = False,
    on_output: Optional[object] = None,
) -> list[InstallResult]:
    """Install each spec that is not already present.

    ``specs`` defaults to every missing tool. When ``dry_run`` is set, the
    command is reported (status ``planned``) but not executed. ``on_output`` is
    an optional callable receiving each line of installer stdout/stderr for live
    display; when omitted the child process inherits the parent's stdio.
    """
    if specs is None:
        specs = missing_tools()
    results: list[InstallResult] = []
    for spec in specs:
        if is_present(spec.name):
            results.append(InstallResult(spec.name, "present"))
            continue
        cmd = build_install_command(spec)
        if not cmd:
            results.append(InstallResult(
                spec.name, "manual", detail=spec.url or install_hint(spec)))
            continue
        if dry_run:
            results.append(InstallResult(spec.name, "planned", command=cmd))
            continue
        results.append(_run_install(spec, cmd, on_output))
    return results


def _run_install(spec: ToolSpec, cmd: list[str], on_output: Optional[object]) -> InstallResult:
    """Run one install command and re-verify the tool landed on PATH."""
    try:
        if callable(on_output):
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            assert proc.stdout is not None
            for line in proc.stdout:
                on_output(line.rstrip("\n"))
            rc = proc.wait()
        else:
            rc = subprocess.call(cmd)
    except FileNotFoundError as e:
        return InstallResult(spec.name, "failed", command=cmd, detail=str(e))
    except Exception as e:  # noqa: BLE001
        return InstallResult(spec.name, "failed", command=cmd, detail=str(e))

    # `brew` can exit non-zero on benign keg-link conflicts while still pouring
    # the binary, so trust PATH presence over the return code as the final word.
    if is_present(spec.name):
        return InstallResult(spec.name, "installed", command=cmd)
    detail = f"exit {rc}" if rc else "not found on PATH after install"
    return InstallResult(spec.name, "failed", command=cmd, detail=detail)
