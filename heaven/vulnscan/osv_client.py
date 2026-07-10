"""
HEAVEN — OSV.dev client (Open Source Vulnerability database).

NVD's CPE matching is poor for language-ecosystem packages (npm, PyPI, Go,
Maven, …). OSV.dev is purpose-built for exactly that: give it a batch of
``{ecosystem, name, version}`` triples and it returns the known advisories that
affect each one. It's free and needs no API key.

This closes the concrete gap "what if the vulnerability isn't in our database":
OSV is a live, continuously-updated advisory feed for the dependency layer that
HEAVEN's inline CVE table and NVD-CPE search simply cannot cover.

Flow:
    1. POST /v1/querybatch  → advisory IDs affecting each package  (one round-trip)
    2. GET  /v1/vulns/{id}  → full record (summary, CVSS, aliases)  (cached to disk)

Everything degrades gracefully: no httpx, no network, or an API error yields an
empty result and never raises into a scan.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import httpx
except ImportError:  # pragma: no cover - exercised via the httpx-absent path
    httpx = None  # type: ignore[assignment]

from heaven.utils.cvss import (
    base_score_from_vector,
    score_from_label,
    severity_from_score,
)
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.osv")

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

# Per-advisory JSON is cached here so repeat scans (and offline runs) don't
# re-hit the API. OSV records are effectively immutable by ID.
_CACHE_DIR = Path(__file__).resolve().parents[2] / "data" / "cache" / "osv"


@dataclass
class Package:
    """A resolved dependency to look up."""
    name: str
    version: str
    ecosystem: str          # OSV ecosystem: PyPI, npm, Go, Maven, RubyGems, ...
    source: str = ""        # manifest path / URL the package came from

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass
class OSVVuln:
    """A single OSV advisory affecting a package."""
    osv_id: str
    package: str
    version: str
    ecosystem: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = field(default_factory=list)   # includes CVE ids
    cvss_vector: str = ""
    cvss_score: float = 0.0
    severity: str = "medium"
    cwe_ids: list[str] = field(default_factory=list)
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def primary_cve(self) -> str:
        for a in self.aliases:
            if a.upper().startswith("CVE-"):
                return a
        return ""


def _parse_severity(record: dict) -> tuple[str, float, str]:
    """Return (vector, score, label) from an OSV record's severity fields."""
    vector = ""
    for sev in record.get("severity", []) or []:
        if not isinstance(sev, dict):
            continue
        # CVSS_V3 / CVSS_V4 records carry the vector string in "score".
        if str(sev.get("type", "")).upper().startswith("CVSS") and sev.get("score"):
            vector = str(sev["score"])
            break

    score = base_score_from_vector(vector) if vector else 0.0
    if score <= 0:
        # Fall back to a qualitative label if present (common on GHSA records).
        label = str(
            (record.get("database_specific") or {}).get("severity", "")
        )
        score = score_from_label(label)
    label = severity_from_score(score)
    return vector, score, label


def _extract_fixed_version(record: dict, ecosystem: str, name: str) -> str:
    """Best-effort 'fixed in' version from the affected ranges."""
    for aff in record.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    return str(ev["fixed"])
    return ""


def _extract_cwes(record: dict) -> list[str]:
    ds = record.get("database_specific") or {}
    cwes = ds.get("cwe_ids") or ds.get("cwes") or []
    return [str(c) for c in cwes if str(c).upper().startswith("CWE-")]


class OSVClient:
    """Async OSV.dev client with on-disk per-advisory caching."""

    def __init__(self, timeout: float = 20.0, cache_dir: Optional[Path] = None):
        self.timeout = timeout
        self.cache_dir = cache_dir or _CACHE_DIR
        self._mem: dict[str, dict] = {}

    @property
    def available(self) -> bool:
        return httpx is not None

    # ── advisory detail (cached) ──

    def _cache_path(self, osv_id: str) -> Path:
        safe = osv_id.replace("/", "_").replace("..", "_")
        return self.cache_dir / f"{safe}.json"

    def _load_cached(self, osv_id: str) -> Optional[dict]:
        if osv_id in self._mem:
            return self._mem[osv_id]
        p = self._cache_path(osv_id)
        if p.exists():
            try:
                rec = json.loads(p.read_text())
                self._mem[osv_id] = rec
                return rec
            except (ValueError, OSError):
                return None
        return None

    def _store_cached(self, osv_id: str, record: dict) -> None:
        self._mem[osv_id] = record
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._cache_path(osv_id).write_text(json.dumps(record))
        except OSError as e:  # cache is best-effort
            logger.debug(f"OSV cache write failed for {osv_id}: {e}")

    async def _fetch_detail(self, client: Any, osv_id: str) -> Optional[dict]:
        cached = self._load_cached(osv_id)
        if cached is not None:
            return cached
        try:
            r = await client.get(f"{OSV_VULN_URL}{osv_id}")
            if r.status_code == 200:
                record = r.json()
                self._store_cached(osv_id, record)
                return record
            logger.debug(f"OSV detail {osv_id} → HTTP {r.status_code}")
        except Exception as e:  # noqa: BLE001 - network must never break a scan
            logger.debug(f"OSV detail fetch failed for {osv_id}: {e}")
        return None

    # ── batch query ──

    async def query(self, packages: list[Package]) -> list[OSVVuln]:
        """Look up every package and return the advisories that affect them."""
        if not packages:
            return []
        if httpx is None:
            logger.info("OSV lookup skipped: httpx not installed.")
            return []

        queries = [
            {
                "version": p.version,
                "package": {"name": p.name, "ecosystem": p.ecosystem},
            }
            for p in packages
        ]

        results: list[OSVVuln] = []
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    OSV_QUERYBATCH_URL, json={"queries": queries}
                )
                if resp.status_code != 200:
                    logger.warning(f"OSV querybatch → HTTP {resp.status_code}")
                    return []
                batch = resp.json().get("results", [])

                # Collect the unique advisory IDs, remembering which package each
                # belongs to (results align 1:1 with the queries we sent).
                id_to_pkgs: dict[str, list[Package]] = {}
                for pkg, res in zip(packages, batch):
                    for v in (res or {}).get("vulns", []) or []:
                        vid = v.get("id")
                        if vid:
                            id_to_pkgs.setdefault(vid, []).append(pkg)

                if not id_to_pkgs:
                    return []

                # Fetch details concurrently but politely.
                sem = asyncio.Semaphore(8)

                async def _detail(vid: str) -> tuple[str, Optional[dict]]:
                    async with sem:
                        return vid, await self._fetch_detail(client, vid)

                details = await asyncio.gather(
                    *(_detail(vid) for vid in id_to_pkgs)
                )

                for vid, record in details:
                    if not record:
                        continue
                    vector, score, label = _parse_severity(record)
                    aliases = [str(a) for a in record.get("aliases", []) or []]
                    refs = [
                        str(r.get("url", ""))
                        for r in record.get("references", []) or []
                        if r.get("url")
                    ]
                    for pkg in id_to_pkgs[vid]:
                        results.append(OSVVuln(
                            osv_id=vid,
                            package=pkg.name,
                            version=pkg.version,
                            ecosystem=pkg.ecosystem,
                            summary=str(record.get("summary", "")),
                            details=str(record.get("details", ""))[:2000],
                            aliases=aliases,
                            cvss_vector=vector,
                            cvss_score=score,
                            severity=label,
                            cwe_ids=_extract_cwes(record),
                            fixed_version=_extract_fixed_version(
                                record, pkg.ecosystem, pkg.name),
                            references=refs[:8],
                            source=pkg.source,
                        ))
        except Exception as e:  # noqa: BLE001 - degrade gracefully
            logger.warning(f"OSV query failed: {e}")
            return results

        return results
