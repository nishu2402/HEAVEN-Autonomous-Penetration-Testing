"""
HEAVEN — Dependency-confusion (substitution) auditor.

The SCA scanner (:mod:`heaven.vulnscan.sca_scanner`) answers "is a dependency I
*have* known-vulnerable". This module answers the different, supply-chain
question a real red-teamer asks next: "is a dependency I *depend on* claimable
by somebody else on the public registry". That is the dependency-confusion
attack (Alex Birsan, 2021): a build that lists an internal package name and can
still reach the public registry will happily pull an attacker's package of the
same name — straight to remote code execution on the developer's machine or the
CI runner.

The observable, non-destructive signal is precise: a package that a manifest
lists as a dependency but that **does not exist on its public registry**. If the
name is unclaimed, an attacker can publish it. We only ever *read* public
registry metadata (an unauthenticated GET per name), never publish anything.

False-positive discipline (this is the whole game):

* **Definitive-absence only.** A finding fires only on a hard ``404`` from the
  public registry. Any timeout, network error, rate-limit, or non-404/non-200
  answer is treated as *unknown* and emits nothing — an offline run never
  fabricates a confusion finding, exactly like the OSV client.
* **Local names are suppressed.** A monorepo / workspace defines its own
  packages (``@acme/ui``) locally; those are absent from the public registry but
  are not confusable because the build resolves them in-tree. :func:`collect_local_signals`
  harvests every locally-defined package name (from ``package.json`` ``name``,
  ``pyproject.toml``/``setup.cfg`` project name, ``Cargo.toml``, ``composer.json``,
  ``*.gemspec``) and :func:`audit_packages` skips any dependency matching one.
* **Registry-resolved names only.** Specs that never resolve from a registry at
  all — ``file:``/``link:``/``portal:``/``workspace:`` protocols, VCS/URL/path
  references — are dropped before the check (they carry no registry name to
  confuse).
* **Signal-graded severity.** A bare unclaimed name is a *medium* "candidate".
  It is escalated to *high* only when there is corroborating evidence the
  project genuinely consumes internal packages from a private feed — a private
  registry configured (``.npmrc``/``.yarnrc.yml``/``pip.conf``/Poetry source/
  ``nuget.config``) or an npm *scoped* package whose scope is itself unclaimed.
  That is the configuration in which confusion is actually exploitable.

Only ecosystems with a public flat registry and a reliable per-name existence
endpoint are checked: PyPI, npm, RubyGems, crates.io, Packagist, NuGet. Go
(module paths are VCS URLs, resolved via GOPROXY) and Maven (``group:artifact``
coordinates, no flat existence endpoint) resolve by a different mechanism and
are deliberately out of scope here rather than checked imprecisely.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

try:
    import httpx
except ImportError:  # pragma: no cover - exercised via the httpx-absent path
    httpx = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger
from heaven.vulnscan.osv_client import Package

logger = get_logger("vulnscan.depconfusion")

# OWASP 2025 supply-chain category — kept identical to the SCA scanner's string
# so taxonomy/compliance mapping treats both as the same family.
_OWASP_SUPPLY_CHAIN = "A03:2025 Software Supply Chain Failures"
_CWE = "CWE-427"            # Uncontrolled Search Path Element (public-registry fallback)
_MITRE = "T1195.001 · Supply Chain Compromise: Software Dependencies"

# Generic, in-band CVSS vectors (same bands vuln_kb uses) so the standalone
# `heaven sca` output and the report show a consistent score for a class that
# has no per-finding advisory score of its own.
_CVSS = {
    "high":   ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1),
    "medium": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5),
}

# Directories never worth walking when harvesting local signals.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".tox", "site-packages", "dist", "build", ".mypy_cache",
    ".pytest_cache", ".idea", ".vscode",
}

# Specifier prefixes that never resolve from a public registry → not confusable.
_NON_REGISTRY_SPEC = re.compile(
    r"^\s*(?:file:|link:|portal:|workspace:|catalog:|git\+|git:|https?:|github:|"
    r"gitlab:|bitbucket:|npm:|\.{0,2}/)",
    re.IGNORECASE,
)


# ── public-registry existence endpoints ──────────────────────────────────────
#
# Each entry maps a HEAVEN/OSV ecosystem label to a (url_template, encoder).
# The encoder turns a package name into the path segment the registry expects.

def _enc_plain(name: str) -> str:
    return quote(name, safe="")


def _enc_npm(name: str) -> str:
    # Unscoped "lodash" → "lodash"; scoped "@acme/ui" → "@acme%2Fui".
    return quote(name, safe="@")


def _enc_path(name: str) -> str:
    # Packagist names are "vendor/package" — keep the slash as a path separator.
    return quote(name, safe="/")


def _enc_lower(name: str) -> str:
    return quote(name.lower(), safe="")


_REGISTRY: dict[str, tuple[str, Any]] = {
    "npm":       ("https://registry.npmjs.org/{e}", _enc_npm),
    "PyPI":      ("https://pypi.org/pypi/{e}/json", _enc_plain),
    "RubyGems":  ("https://rubygems.org/api/v1/gems/{e}.json", _enc_plain),
    "crates.io": ("https://crates.io/api/v1/crates/{e}", _enc_plain),
    "Packagist": ("https://repo.packagist.org/p2/{e}.json", _enc_path),
    "NuGet":     ("https://api.nuget.org/v3-flatcontainer/{e}/index.json", _enc_lower),
}

CHECKABLE_ECOSYSTEMS: frozenset[str] = frozenset(_REGISTRY)


class RegistryClient:
    """Async public-registry existence checker.

    ``exists(name, ecosystem)`` returns ``True`` (registered), ``False``
    (definitive 404 — claimable), or ``None`` (unknown: no httpx, network error,
    rate-limit, or an unsupported ecosystem). Results are memoised per process so
    a monorepo that lists the same dependency in ten manifests costs one GET.
    A generic User-Agent is sent (no project or user identity) and nothing but
    the bare package name ever leaves the process.
    """

    def __init__(self, timeout: float = 12.0, concurrency: int = 8):
        self.timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)
        self._cache: dict[tuple[str, str], Optional[bool]] = {}

    @property
    def available(self) -> bool:
        return httpx is not None

    async def exists(self, client: Any, name: str, ecosystem: str) -> Optional[bool]:
        reg = _REGISTRY.get(ecosystem)
        if reg is None or not name:
            return None
        key = (ecosystem, name.lower())
        if key in self._cache:
            return self._cache[key]
        url_tmpl, enc = reg
        url = url_tmpl.format(e=enc(name))
        result: Optional[bool] = None
        try:
            async with self._sem:
                r = await client.get(url, headers={"User-Agent": "HEAVEN-SCA"})
            if r.status_code == 200:
                result = True
            elif r.status_code == 404:
                result = False
            else:
                # 429/5xx/403 → we cannot conclude the name is unclaimed.
                logger.debug("registry %s for %s → HTTP %s (unknown)",
                             ecosystem, name, r.status_code)
                result = None
        except Exception as e:  # noqa: BLE001 — network must never break a scan
            logger.debug("registry probe failed for %s/%s: %s", ecosystem, name, e)
            result = None
        self._cache[key] = result
        return result


def _scope_of(name: str) -> str:
    """npm scope for ``@scope/pkg`` → ``@scope`` (else "")."""
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[0]
    return ""


def _finding(pkg: Package, *, severity: str, confidence: float, url: str,
             signals: list[str], rationale: str, target: str) -> dict[str, Any]:
    vector, score = _CVSS[severity]
    title = (f"Dependency-confusion candidate: {pkg.name} ({pkg.ecosystem}) "
             f"is unclaimed on the public registry")
    return {
        "target": target or pkg.source or pkg.ecosystem,
        "vuln_type": "dependency_confusion",
        "severity": severity,
        "title": title,
        "confidence": confidence,
        "cwe": _CWE,
        "owasp": _OWASP_SUPPLY_CHAIN,
        "mitre": _MITRE,
        "cvss": score,
        "cvss_vector": vector,
        "source": "dep_confusion",
        "remediation": (
            f"Claim `{pkg.name}` defensively on {pkg.ecosystem} (publish a stub you "
            f"own), or pin the build so internal packages resolve only from your "
            f"private feed with no public fallback: scope npm packages and set "
            f"`@scope:registry` in .npmrc, use pip `--index-url` (not "
            f"`--extra-index-url`) for the private feed, and verify resolver "
            f"priority so a public package of this name can never be substituted."
        ),
        "description": (
            f"`{pkg.name}` is listed as a {pkg.ecosystem} dependency"
            f"{(' in ' + pkg.source) if pkg.source else ''} but does not exist on the "
            f"public {pkg.ecosystem} registry (HTTP 404). {rationale} An attacker can "
            f"register this name and, if the build can reach the public registry, have "
            f"their package pulled in — the dependency-confusion / substitution attack."
        ),
        "references": [
            "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
            "https://owasp.org/www-project-top-ten/",
        ],
        "evidence": {
            "package": pkg.name,
            "installed_version": pkg.version,
            "ecosystem": pkg.ecosystem,
            "manifest": pkg.source or target,
            "registry_checked": url,
            "registry_status": 404,
            "signals": signals,
            "proof": (f"GET {url} → 404: `{pkg.name}` is unregistered on the public "
                      f"{pkg.ecosystem} registry and therefore claimable."),
        },
    }


async def audit_packages(
    packages: list[Package], *,
    local_names: frozenset[str] = frozenset(),
    private_registry: bool = False,
    private_registry_signals: Optional[list[str]] = None,
    target: str = "",
    client: Optional[RegistryClient] = None,
    http: Any = None,
) -> list[dict[str, Any]]:
    """Return dependency-confusion findings for packages absent from their registry.

    ``local_names`` are locally-defined package names to suppress (workspace /
    monorepo packages). ``private_registry`` (with its human-readable
    ``private_registry_signals``) escalates a bare *medium* candidate to *high* —
    that configuration is where a build can fall back to the public registry and
    be substituted. An npm *scope* is recorded in the evidence but never used to
    escalate on its own, because we cannot reliably prove from a single GET that
    the scope is unclaimed rather than owned-but-unpublished. ``client`` and
    ``http`` are injectable for testing; in production an :class:`httpx.AsyncClient`
    is created and reused for the whole batch.
    """
    checkable = [
        p for p in packages
        if p.ecosystem in CHECKABLE_ECOSYSTEMS
        and p.name
        and p.name.lower() not in local_names
    ]
    if not checkable:
        return []
    client = client or RegistryClient()
    if not client.available:
        logger.info("dependency-confusion check skipped: httpx not installed.")
        return []

    signals_base = list(private_registry_signals or [])

    async def _run(session: Any) -> list[dict[str, Any]]:
        async def _one(p: Package) -> Optional[dict[str, Any]]:
            present = await client.exists(session, p.name, p.ecosystem)
            if present is not False:          # True (claimed) or None (unknown) → skip
                return None
            signals = ["public_registry_absent"]
            scope = _scope_of(p.name)
            if scope:
                signals.append(f"scoped_package:{scope}")
            if private_registry:
                severity, confidence = "high", 0.85
                signals += signals_base
                rationale = (
                    "The project consumes packages from a private feed ("
                    + "; ".join(signals_base or ["private registry configured"])
                    + "), the configuration in which a build can fall back to the "
                    "public registry and be confused."
                )
            else:
                severity, confidence = "medium", 0.6
                rationale = (
                    "No private-registry configuration was observed, so this is a "
                    "candidate pending confirmation that the build can reach the "
                    "public registry and that the name is not already owned by your "
                    "organization."
                )
            return _finding(p, severity=severity, confidence=confidence,
                            url=_REGISTRY[p.ecosystem][0].format(
                                e=_REGISTRY[p.ecosystem][1](p.name)),
                            signals=signals, rationale=rationale, target=target)

        results = await asyncio.gather(*(_one(p) for p in checkable))
        return [f for f in results if f]

    if http is not None:
        return await _run(http)
    async with httpx.AsyncClient(timeout=client.timeout, follow_redirects=True) as session:
        return await _run(session)


# ── local-codebase signal harvesting ─────────────────────────────────────────

def _json_name(text: str) -> str:
    import json
    try:
        data = json.loads(text)
    except ValueError:
        return ""
    return str(data.get("name", "")) if isinstance(data, dict) else ""


def _toml_project_name(text: str) -> str:
    import tomllib
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return ""
    proj = data.get("project")
    if isinstance(proj, dict) and proj.get("name"):
        return str(proj["name"])
    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    if isinstance(poetry, dict) and poetry.get("name"):
        return str(poetry["name"])
    pkg = data.get("package")
    if isinstance(pkg, dict) and pkg.get("name"):  # Cargo.toml
        return str(pkg["name"])
    return ""


_PRIVATE_NPMRC = re.compile(r"(?im)^\s*(?:@[\w.-]+:)?registry\s*=", )
_PRIVATE_YARN = re.compile(r"(?im)^\s*(?:npmRegistryServer|npmScopes)\s*:")
_PRIVATE_PIP = re.compile(r"(?im)^\s*(?:extra-)?index-url\s*=")
_PRIVATE_POETRY_SRC = re.compile(r"(?is)\[\[\s*tool\.poetry\.source\s*\]\]")
_PRIVATE_NUGET = re.compile(r"(?is)<packageSources>.*<add\b")


def collect_local_signals(root: str, *, max_files: int = 400) -> dict[str, Any]:
    """Harvest locally-defined package names and private-registry configuration.

    Returns ``{"local_names": frozenset, "private_registry": bool,
    "signals": [str]}``. Bounded and never raises: a tree we cannot read yields
    empty signals, never an exception.
    """
    base = Path(root).expanduser().resolve()
    local: set[str] = set()
    signals: list[str] = []
    private = False
    scanned = 0

    paths: list[Path] = [base] if base.is_file() else []
    if base.is_dir():
        for p in base.rglob("*"):
            if scanned >= max_files:
                break
            if p.is_dir() or any(part in _SKIP_DIRS for part in p.parts):
                continue
            paths.append(p)
            scanned += 1

    for p in paths:
        fn = p.name.lower()
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            if fn == "package.json":
                nm = _json_name(text)
                if nm:
                    local.add(nm.lower())
            elif fn == "composer.json":
                nm = _json_name(text)
                if nm:
                    local.add(nm.lower())
            elif fn in ("pyproject.toml", "cargo.toml"):
                nm = _toml_project_name(text)
                if nm:
                    local.add(nm.lower())
            elif fn == "setup.cfg":
                m = re.search(r"(?im)^\s*name\s*=\s*(.+)$", text)
                if m:
                    local.add(m.group(1).strip().lower())
            elif fn.endswith(".gemspec"):
                m = re.search(r"""\.name\s*=\s*['"]([^'"]+)['"]""", text)
                if m:
                    local.add(m.group(1).strip().lower())

            # private-registry configuration signals
            if fn == ".npmrc" and _PRIVATE_NPMRC.search(text):
                private = True
                signals.append("npmrc_private_registry")
            elif fn in (".yarnrc.yml", ".yarnrc") and _PRIVATE_YARN.search(text):
                private = True
                signals.append("yarnrc_private_registry")
            elif fn in ("pip.conf", "pip.ini") and _PRIVATE_PIP.search(text):
                private = True
                signals.append("pip_index_url")
            elif fn == "pyproject.toml" and _PRIVATE_POETRY_SRC.search(text):
                private = True
                signals.append("poetry_private_source")
            elif fn in ("nuget.config", "nuget.conf") and _PRIVATE_NUGET.search(text):
                private = True
                signals.append("nuget_private_source")
        except Exception:  # noqa: BLE001 — one odd file never breaks harvesting
            logger.debug("local-signal parse skipped for %s", p, exc_info=True)

    return {
        "local_names": frozenset(local),
        "private_registry": private,
        "signals": sorted(set(signals)),
    }
