"""
HEAVEN — Software Composition Analysis (SCA).

Parses dependency manifests / lockfiles into a list of pinned packages and
cross-references them against OSV.dev (see :mod:`heaven.vulnscan.osv_client`).
This is the concrete answer to "what if the vulnerability isn't in our
database": known-vulnerable **dependencies** almost never surface through NVD's
CPE search or HEAVEN's inline CVE table, but they are exactly what OSV catalogs.

Two entry points:

* :func:`scan_path` — walk a local codebase, parse every manifest it finds,
  and report vulnerable dependencies. This is classic SCA (``heaven sca ./app``).
* :func:`scan_manifest_text` — parse a single manifest whose *contents* HEAVEN
  captured remotely (e.g. an exposed ``/requirements.txt`` or
  ``/package-lock.json`` found by deep-recon) and report on it.

Supported ecosystems: PyPI, npm, Go, Maven, RubyGems, Packagist, crates.io.
Parsers are deliberately tolerant — a manifest we can't parse is skipped, never
fatal.
"""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Optional

from heaven.utils.logger import get_logger
from heaven.vulnscan.osv_client import OSVClient, OSVVuln, Package

logger = get_logger("vulnscan.sca")

# Filenames we know how to parse, mapped to their (parser, ecosystem).
# Populated at the bottom once the parser functions are defined.
_MANIFEST_PARSERS: dict[str, tuple[Callable[[str], list[tuple[str, str]]], str]] = {}

# Directories never worth walking for a codebase SCA.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".tox", "site-packages", "dist", "build", ".mypy_cache",
    ".pytest_cache", ".idea", ".vscode",
}


# ── individual manifest parsers: each returns [(name, version), ...] ──

def _parse_requirements_txt(text: str) -> list[tuple[str, str]]:
    """Parse a pip ``requirements.txt`` — only ``name==version`` pins."""
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "http://", "https://", "git+")):
            continue
        line = line.split("#", 1)[0].split(";", 1)[0].strip()  # drop comment/marker
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*\[[^\]]*\]?\s*==\s*([A-Za-z0-9_.\-]+)", line)
        if not m:
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_pipfile_lock(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = ""
            if isinstance(meta, dict):
                ver = str(meta.get("version", "")).lstrip("=")
            if name and ver:
                out.append((name, ver))
    return out


def _parse_poetry_lock(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return out
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        ver = pkg.get("version")
        if name and ver:
            out.append((str(name), str(ver)))
    return out


def _parse_package_lock(text: str) -> list[tuple[str, str]]:
    """npm ``package-lock.json`` — handles v1 (dependencies) and v2/v3 (packages)."""
    out: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    # v2/v3 lockfileVersion: the "packages" map keys are "node_modules/<name>".
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project
            name = path.split("node_modules/")[-1]
            ver = str(meta.get("version", ""))
            if name and ver:
                out.append((name, ver))
        if out:
            return out
    # v1 fallback: nested "dependencies".
    def _walk(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                ver = str(meta.get("version", ""))
                if ver:
                    out.append((name, ver))
                _walk(meta.get("dependencies") or {})
    _walk(data.get("dependencies") or {})
    return out


def _parse_yarn_lock(text: str) -> list[tuple[str, str]]:
    """yarn.lock v1 — ``"pkg@range":`` blocks followed by ``version "x.y.z"``."""
    out: list[tuple[str, str]] = []
    current_names: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" ") and line.endswith(":"):
            # Header line: one or more comma-separated "pkg@range" specifiers.
            current_names = []
            for spec in line[:-1].split(","):
                spec = spec.strip().strip('"')
                # strip the @range suffix; handle scoped @scope/pkg@range
                at = spec.rfind("@")
                if at > 0:
                    current_names.append(spec[:at])
        else:
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
            if m and current_names:
                for name in current_names:
                    out.append((name, m.group(1)))
                current_names = []
    return out


def _parse_composer_lock(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []) or []:
            name = pkg.get("name")
            ver = str(pkg.get("version", "")).lstrip("v")
            if name and ver:
                out.append((name, ver))
    return out


def _parse_gemfile_lock(text: str) -> list[tuple[str, str]]:
    """Gemfile.lock — the ``specs:`` block lists ``name (version)``."""
    out: list[tuple[str, str]] = []
    in_specs = False
    for raw in text.splitlines():
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if raw and not raw.startswith(" "):
                in_specs = False
                continue
            m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)$", raw)
            if m:
                out.append((m.group(1), m.group(2)))
    return out


def _parse_go_sum(text: str) -> list[tuple[str, str]]:
    """go.sum — ``module vX.Y.Z[/go.mod] hash``. Dedupe module@version."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].lstrip("v")
        if module and version and (module, version) not in seen:
            seen.add((module, version))
            out.append((module, version))
    return out


def _parse_cargo_lock(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return out
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        ver = pkg.get("version")
        if name and ver:
            out.append((str(name), str(ver)))
    return out


def _parse_nuget_lock(text: str) -> list[tuple[str, str]]:
    """NuGet ``packages.lock.json`` — resolved versions per target framework."""
    out: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for _framework, deps in (data.get("dependencies") or {}).items():
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                ver = str(meta.get("resolved") or "")
                if name and ver:
                    out.append((name, ver))
    return out


def _parse_pom_xml(text: str) -> list[tuple[str, str]]:
    """Maven pom.xml — ``groupId:artifactId`` @ version (skip property versions)."""
    out: list[tuple[str, str]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag[: root.tag.index("}") + 1]
    for dep in root.iter(f"{ns}dependency"):
        gid = dep.findtext(f"{ns}groupId", "").strip()
        aid = dep.findtext(f"{ns}artifactId", "").strip()
        ver = dep.findtext(f"{ns}version", "").strip()
        if gid and aid and ver and not ver.startswith("${"):
            out.append((f"{gid}:{aid}", ver))
    return out


_MANIFEST_PARSERS = {
    "requirements.txt": (_parse_requirements_txt, "PyPI"),
    "pipfile.lock": (_parse_pipfile_lock, "PyPI"),
    "poetry.lock": (_parse_poetry_lock, "PyPI"),
    "package-lock.json": (_parse_package_lock, "npm"),
    "yarn.lock": (_parse_yarn_lock, "npm"),
    "composer.lock": (_parse_composer_lock, "Packagist"),
    "gemfile.lock": (_parse_gemfile_lock, "RubyGems"),
    "go.sum": (_parse_go_sum, "Go"),
    "cargo.lock": (_parse_cargo_lock, "crates.io"),
    "pom.xml": (_parse_pom_xml, "Maven"),
    "packages.lock.json": (_parse_nuget_lock, "NuGet"),
}


def parse_manifest(filename: str, text: str) -> list[Package]:
    """Parse a single manifest's text into resolved :class:`Package` objects."""
    entry = _MANIFEST_PARSERS.get(Path(filename).name.lower())
    if not entry:
        return []
    parser, ecosystem = entry
    try:
        pairs = parser(text)
    except Exception as e:  # noqa: BLE001 - one bad manifest never breaks a scan
        logger.debug(f"SCA parse error for {filename}: {e}")
        return []
    seen: set[tuple[str, str]] = set()
    packages: list[Package] = []
    for name, version in pairs:
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        packages.append(Package(name=name, version=version,
                                ecosystem=ecosystem, source=filename))
    return packages


def is_supported_manifest(filename: str) -> bool:
    return Path(filename).name.lower() in _MANIFEST_PARSERS


# Public list of manifest filenames HEAVEN can parse — used by the orchestrator
# to probe a web target for *exposed* manifests worth auditing against OSV.
SUPPORTED_MANIFEST_NAMES: tuple[str, ...] = tuple(_MANIFEST_PARSERS.keys())


# ── OSV vuln → normalized HEAVEN finding ──

_A06 = "A06:2021 Vulnerable and Outdated Components"


def _vuln_to_finding(v: OSVVuln, target: str) -> dict[str, Any]:
    fix = f" Upgrade to {v.fixed_version} or later." if v.fixed_version else ""
    cve = v.primary_cve
    ident = cve or v.osv_id
    title = f"Vulnerable dependency: {v.package} {v.version} ({ident})"
    return {
        "target": target,
        "vuln_type": "vulnerable_dependency",
        "severity": v.severity,
        "title": title,
        "confidence": 0.9,   # version match against a curated advisory DB
        "cve_id": cve,
        "cvss": v.cvss_score,
        "cvss_vector": v.cvss_vector,
        "cwe": v.cwe_ids[0] if v.cwe_ids else "CWE-1104",
        "owasp": _A06,
        "source": "osv",
        "remediation": (
            f"Update {v.package} from {v.version} to a fixed release."
            + fix
        ),
        "description": (v.summary or v.details
                        or f"{v.package} {v.version} is affected by {ident}."),
        "references": [f"https://osv.dev/vulnerability/{v.osv_id}"] + v.references,
        "evidence": {
            "package": v.package,
            "installed_version": v.version,
            "ecosystem": v.ecosystem,
            "osv_id": v.osv_id,
            "aliases": v.aliases,
            "fixed_version": v.fixed_version,
            "manifest": v.source or target,
            "summary": v.summary,
            "signals": ["osv_advisory_version_match"],
            "proof": (f"{v.package}@{v.version} ({v.ecosystem}) matches the "
                      f"affected range of {v.osv_id}"),
        },
    }


# ── public API ──

def _dedupe_vulns(vulns: list[OSVVuln]) -> list[OSVVuln]:
    """Collapse duplicate advisories for the same package+CVE.

    OSV commonly returns several records for one underlying CVE (a GHSA record
    with a CVSS vector *and* a PYSEC record without one). Reporting the same CVE
    twice — once ``high``, once ``info`` — is noise, so for each
    (package, version, CVE) group we keep a single best record: the one with the
    highest CVSS score, merging aliases and a fixed version from the rest.
    Records with no CVE alias are keyed by their OSV id.
    """
    groups: dict[tuple, OSVVuln] = {}
    for v in vulns:
        cve = v.primary_cve
        key = (v.package.lower(), v.version, cve or v.osv_id)
        best = groups.get(key)
        if best is None:
            groups[key] = v
            continue
        # Merge into the higher-scored record.
        keep, drop = (best, v) if best.cvss_score >= v.cvss_score else (v, best)
        keep.aliases = sorted(set(keep.aliases) | set(drop.aliases))
        if not keep.fixed_version and drop.fixed_version:
            keep.fixed_version = drop.fixed_version
        if not keep.summary and drop.summary:
            keep.summary = drop.summary
        groups[key] = keep
    return list(groups.values())


async def scan_packages(packages: list[Package], *,
                        client: Optional[OSVClient] = None) -> list[dict[str, Any]]:
    """Cross-reference resolved packages against OSV; return normalized findings."""
    if not packages:
        return []
    client = client or OSVClient()
    vulns = _dedupe_vulns(await client.query(packages))
    findings = [_vuln_to_finding(v, v.source or "dependency") for v in vulns]
    logger.info("SCA: %d package(s) checked, %d vulnerable finding(s).",
                len(packages), len(findings))
    return findings


async def scan_manifest_text(filename: str, text: str, *,
                             target: str = "",
                             client: Optional[OSVClient] = None) -> list[dict[str, Any]]:
    """Parse one manifest's captured text and report vulnerable dependencies.

    Used when HEAVEN discovers an *exposed* manifest during recon and captured
    its body — the ``target`` (e.g. the URL) is stamped onto each finding.
    """
    packages = parse_manifest(filename, text)
    for p in packages:
        p.source = target or filename
    findings = await scan_packages(packages, client=client)
    if target:
        for f in findings:
            f["target"] = target
    return findings


async def scan_path(root: str, *, max_files: int = 200,
                    client: Optional[OSVClient] = None) -> dict[str, Any]:
    """Walk a local codebase, parse every supported manifest, and audit it.

    Returns ``{"packages": int, "manifests": [...], "findings": [...]}``.
    """
    base = Path(root).expanduser().resolve()
    if not base.exists():
        return {"packages": 0, "manifests": [], "findings": [],
                "error": f"path not found: {root}"}

    all_packages: list[Package] = []
    manifests: list[str] = []
    scanned = 0

    candidates: list[Path] = []
    if base.is_file():
        candidates = [base]
    else:
        for path in base.rglob("*"):
            if scanned >= max_files:
                break
            if path.is_dir():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if is_supported_manifest(path.name):
                candidates.append(path)
                scanned += 1

    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(base)) if base.is_dir() else str(path)
        pkgs = parse_manifest(path.name, text)
        for p in pkgs:
            p.source = rel
        if pkgs:
            manifests.append(rel)
            all_packages.extend(pkgs)

    findings = await scan_packages(all_packages, client=client)
    return {
        "packages": len(all_packages),
        "manifests": manifests,
        "findings": findings,
    }
