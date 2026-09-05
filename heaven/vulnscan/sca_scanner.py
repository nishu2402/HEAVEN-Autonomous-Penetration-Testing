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
from pathlib import Path
from typing import Any, Callable, Optional

# A pom.xml comes from the *scanned* project, which may be hostile, so parse it
# with defusedxml — stdlib ElementTree is vulnerable to entity-expansion and
# external-DTD (billion-laughs / XXE-SSRF / local file read on the analyst host).
from defusedxml.ElementTree import fromstring as _safe_xml_fromstring

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
        root = _safe_xml_fromstring(text)
    except Exception:  # noqa: BLE001 — ParseError or a defused entity/DTD rejection → skip
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


def _concrete_version(spec: str) -> str:
    """Best-effort concrete version from a version spec/range.

    OSV matches a *specific* version against an advisory's affected ranges, so a
    lockfile pin is ideal. For a manifest that only carries a range (``^4.17.0``,
    ``>=1.2,<2``) we take the first concrete version token — typically the lowest
    satisfying / installed version — which OSV then range-matches precisely. An
    unparseable / URL / git spec yields "" and is skipped.
    """
    m = re.search(r"(\d+(?:\.\d+){0,3}(?:[.\-][0-9A-Za-z]+)?)", spec or "")
    return m.group(1) if m else ""


def _parse_pyproject_toml(text: str) -> list[tuple[str, str]]:
    """pyproject.toml — PEP 621 ``[project]`` deps and Poetry dep tables."""
    out: list[tuple[str, str]] = []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return out
    proj = data.get("project", {}) or {}
    specs: list[str] = list(proj.get("dependencies", []) or [])
    for group in (proj.get("optional-dependencies", {}) or {}).values():
        specs += list(group or [])
    for s in specs:
        if not isinstance(s, str):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)", s.strip())
        if m:
            ver = _concrete_version(s[m.end():])
            if ver:
                out.append((m.group(1), ver))
    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    dep_tables = [poetry.get("dependencies", {}) or {}]
    for g in (poetry.get("group", {}) or {}).values():
        if isinstance(g, dict):
            dep_tables.append(g.get("dependencies", {}) or {})
    for table in dep_tables:
        for name, val in table.items():
            if name.lower() == "python":
                continue
            spec = val if isinstance(val, str) else (
                val.get("version", "") if isinstance(val, dict) else "")
            ver = _concrete_version(str(spec))
            if ver:
                out.append((name, ver))
    return out


def _parse_pipfile(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return out
    for section in ("packages", "dev-packages"):
        for name, val in (data.get(section) or {}).items():
            spec = val if isinstance(val, str) else (
                val.get("version", "") if isinstance(val, dict) else "")
            ver = _concrete_version(str(spec))
            if ver:
                out.append((name, ver))
    return out


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    """package.json — dependency ranges reduced to a concrete version for OSV."""
    out: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for section in ("dependencies", "devDependencies",
                    "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            ver = _concrete_version(spec)
            if ver:
                out.append((name, ver))
    return out


def _parse_go_mod(text: str) -> list[tuple[str, str]]:
    """go.mod — direct ``require`` module versions (single-line and block form)."""
    out: list[tuple[str, str]] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        line = line.split("//")[0].strip()
        m = re.match(r"^(\S+)\s+v([0-9][^\s/]*)", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_gradle(text: str) -> list[tuple[str, str]]:
    """build.gradle / .kts — ``group:artifact:version`` coordinates."""
    out: list[tuple[str, str]] = []
    for m in re.finditer(
            r"""['"]([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([0-9][A-Za-z0-9_.\-]*)['"]""",
            text):
        out.append((f"{m.group(1)}:{m.group(2)}", m.group(3)))
    return out


def _parse_csproj(text: str) -> list[tuple[str, str]]:
    """*.csproj — ``<PackageReference Include=".." Version=".." />``."""
    out: list[tuple[str, str]] = []
    for m in re.finditer(r'<PackageReference\s+[^>]*?Include="([^"]+)"[^>]*?Version="([^"]+)"', text):
        out.append((m.group(1), m.group(2)))
    for m in re.finditer(
            r'<PackageReference\s+Include="([^"]+)"\s*>\s*<Version>([^<]+)</Version>', text):
        out.append((m.group(1), m.group(2)))
    return out


_MANIFEST_PARSERS = {
    "requirements.txt": (_parse_requirements_txt, "PyPI"),
    "pipfile.lock": (_parse_pipfile_lock, "PyPI"),
    "pipfile": (_parse_pipfile, "PyPI"),
    "poetry.lock": (_parse_poetry_lock, "PyPI"),
    "pyproject.toml": (_parse_pyproject_toml, "PyPI"),
    "package-lock.json": (_parse_package_lock, "npm"),
    "package.json": (_parse_package_json, "npm"),
    "yarn.lock": (_parse_yarn_lock, "npm"),
    "composer.lock": (_parse_composer_lock, "Packagist"),
    "gemfile.lock": (_parse_gemfile_lock, "RubyGems"),
    "go.sum": (_parse_go_sum, "Go"),
    "go.mod": (_parse_go_mod, "Go"),
    "cargo.lock": (_parse_cargo_lock, "crates.io"),
    "pom.xml": (_parse_pom_xml, "Maven"),
    "build.gradle": (_parse_gradle, "Maven"),
    "build.gradle.kts": (_parse_gradle, "Maven"),
    "packages.lock.json": (_parse_nuget_lock, "NuGet"),
}

# Parsers keyed by file *suffix* (for names that vary, e.g. MyApp.csproj).
_SUFFIX_PARSERS: dict[str, tuple[Callable[[str], list[tuple[str, str]]], str]] = {
    ".csproj": (_parse_csproj, "NuGet"),
}


def parse_manifest(filename: str, text: str) -> list[Package]:
    """Parse a single manifest's text into resolved :class:`Package` objects."""
    entry = _MANIFEST_PARSERS.get(Path(filename).name.lower())
    if not entry:
        entry = _SUFFIX_PARSERS.get(Path(filename).suffix.lower())
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
    return (Path(filename).name.lower() in _MANIFEST_PARSERS
            or Path(filename).suffix.lower() in _SUFFIX_PARSERS)


# Public list of manifest filenames HEAVEN can parse — used by the orchestrator
# to probe a web target for *exposed* manifests worth auditing against OSV.
SUPPORTED_MANIFEST_NAMES: tuple[str, ...] = tuple(_MANIFEST_PARSERS.keys())


# ── OSV vuln → normalized HEAVEN finding ──

_OWASP_SUPPLY_CHAIN = "A03:2025 Software Supply Chain Failures"


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
        "owasp": _OWASP_SUPPLY_CHAIN,
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


async def _apply_kev_epss(findings: list[dict[str, Any]]) -> None:
    """Stamp CISA-KEV membership and FIRST.org EPSS onto SCA findings in place.

    Only stamps when the KEV catalog genuinely came back (the shared helper's
    ``online`` flag), so an offline run never fabricates a "not exploited /
    EPSS 0" claim. A KEV-listed dependency is bumped a step in urgency.
    """
    cves = sorted({f.get("cve_id") for f in findings if f.get("cve_id")})
    if not cves:
        return
    try:
        from heaven.vulnscan.exploit_engine import _fetch_kev_epss
        kev, epss, online = await _fetch_kev_epss(list(cves))  # type: ignore[arg-type]
    except Exception:                          # noqa: BLE001
        logger.debug("SCA KEV/EPSS enrichment failed", exc_info=True)
        return
    if not online:
        return
    for f in findings:
        cve = f.get("cve_id")
        if not cve:
            continue
        ev = f.setdefault("evidence", {})
        if cve in kev:
            f["in_kev"] = True
            ev["in_kev"] = True
            ev.setdefault("signals", []).append("cisa_kev")
            if f.get("severity") in ("medium", "low"):
                f["severity"] = "high"   # actively-exploited → escalate urgency
        score = epss.get(cve)
        if score is not None:
            f["epss"] = round(float(score), 5)
            ev["epss"] = round(float(score), 5)


def _summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """A remediation rollup: counts by ecosystem/severity and the safe upgrades."""
    by_eco: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    kev = 0
    upgrades: dict[tuple[str, str], str] = {}
    for f in findings:
        ev = f.get("evidence", {}) or {}
        by_eco[ev.get("ecosystem", "?")] = by_eco.get(ev.get("ecosystem", "?"), 0) + 1
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        if f.get("in_kev"):
            kev += 1
        fx = ev.get("fixed_version")
        if fx and ev.get("package"):
            upgrades[(ev["package"], ev.get("installed_version", ""))] = fx
    return {
        "by_ecosystem": by_eco,
        "by_severity": by_sev,
        "kev_count": kev,
        "safe_upgrades": [{"package": k[0], "from": k[1], "to": v}
                          for k, v in list(upgrades.items())[:100]],
    }


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
                    client: Optional[OSVClient] = None,
                    enrich_intel: bool = True) -> dict[str, Any]:
    """Walk a local codebase, parse every supported manifest, and audit it.

    Returns ``{"packages", "manifests", "findings", "summary"}``. When
    ``enrich_intel`` is set (default), vulnerable-dependency findings are
    stamped with live CISA-KEV / EPSS intel (best-effort, offline-safe).
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
    if enrich_intel:
        await _apply_kev_epss(findings)
    return {
        "packages": len(all_packages),
        "manifests": manifests,
        "findings": findings,
        "summary": _summarize(findings),
    }
