"""HEAVEN — dynamic, multi-source live CVE discovery.

**The gap this closes.** HEAVEN's [cve_mapper.INLINE_CVE_DB] is a curated, offline
catalogue of ~150 high-value CVEs across ~40 products. It is fast and works
air-gapped, but it is finite: if a scan turns up a product/version that isn't in
that table — a new release, a niche service, a CVE published yesterday — the
inline DB says "clean" even though the target may be vulnerable. That is the
"*the vulnerability is not in my DB*" problem.

This module makes CVE discovery **dynamic**: given any ``(product, version)`` (or
a CPE), it queries live authoritative feeds at scan time and returns real CVE
records, so HEAVEN is never limited to what it shipped with.

**Why multi-source.** A single live feed is a single point of failure. NVD
without an API key allows only ~5 requests / 30 s and 429s aggressively; it also
404s on some queries. So :class:`LiveCVEFeed` layers sources and degrades
gracefully at every step:

  1. **NVD API v2** (primary, authoritative) — via the existing
     :class:`~heaven.vulnscan.nvd_client.NVDClient`, CPE-matched, KEV-aware.
  2. **CIRCL CVE Search** (``cve.circl.lu``, keyless fallback/augment) — a
     vendor/product search that needs no key, so lookups keep working when NVD
     is throttled or a key is absent.

Results from all reachable sources are normalised to :class:`LiveCVE`, merged,
de-duplicated by CVE id (highest CVSS wins), and — when a concrete version is
known — filtered to versions the CVE actually affects. Everything is disk-cached
(``data/cache/cve/``) so a repeat lookup is instant and offline. No ``httpx`` or
no network → an empty result, never an exception.

The verdict is honest: an inline-DB or NVD CPE-range hit is high confidence; a
keyword/product match without a verified version range is flagged
``version_confirmed=False`` so triage knows it still needs a version check.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import httpx
except ImportError:  # pragma: no cover - exercised via graceful-degradation test
    httpx = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger
from heaven.vulnscan.cve_mapper import (
    CPE_MAP,
    _fingerprint_from_banner,
    _version_in_range,
)

logger = get_logger("vulnscan.live_cve")

_CACHE_DIR = Path(__file__).resolve().parents[2] / "data" / "cache" / "cve"
CIRCL_SEARCH_URL = "https://cve.circl.lu/api/search/{vendor}/{product}"
_CACHE_TTL_S = 7 * 24 * 3600  # a CVE record is stable enough to cache for a week
# Bump when the cached LiveCVE shape changes so old entries (e.g. pre-EPSS/
# Exploit-DB enrichment) are treated as a cache miss instead of served stale.
_CACHE_SCHEMA = "v2"


@dataclass
class LiveCVE:
    """One CVE normalised across sources."""
    cve_id: str
    title: str = ""
    description: str = ""
    severity: str = "info"
    cvss: float = 0.0
    cvss_vector: str = ""
    cwe: str = ""
    published: str = ""
    references: list[str] = field(default_factory=list)
    source: str = ""              # "nvd" | "circl"
    in_kev: bool = False
    version_confirmed: bool = False  # True only if a version range actually matched
    epss: float = 0.0             # EPSS exploitation-probability (0..1), enriched
    exploit_available: bool = False  # a public Exploit-DB PoC exists
    exploit_url: str = ""         # canonical Exploit-DB URL for the best PoC

    def to_finding(self, target: str, product: str, version: str) -> dict[str, Any]:
        conf = 0.9 if self.version_confirmed else 0.55
        return {
            "target": target,
            "vuln_type": "vulnerable_service",
            "cve": self.cve_id,
            "title": f"{product} {version} — {self.cve_id}: {self.title}".strip(),
            "severity": self.severity,
            "confidence": conf,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "cwe": self.cwe,
            "epss": self.epss,
            "exploit_available": self.exploit_available,
            "evidence": {
                "source": f"live_cve_feed:{self.source}",
                "product": product, "version": version,
                "cve_id": self.cve_id, "in_kev": self.in_kev,
                "version_confirmed": self.version_confirmed,
                "epss": self.epss,
                "exploit_available": self.exploit_available,
                "exploit_url": self.exploit_url,
                "references": self.references[:5],
                "description": self.description[:500],
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id, "title": self.title, "severity": self.severity,
            "cvss": self.cvss, "cwe": self.cwe, "source": self.source,
            "in_kev": self.in_kev, "version_confirmed": self.version_confirmed,
            "epss": self.epss, "exploit_available": self.exploit_available,
            "exploit_url": self.exploit_url,
            "published": self.published, "references": self.references[:5],
        }


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


# ── Pure parsers (deterministic → unit-testable, no network) ─────────────────
def parse_circl_response(data: Any) -> list[LiveCVE]:
    """Parse a CIRCL CVE-Search product response into LiveCVE records.

    CIRCL has shipped two shapes over time: a bare list of CVE objects, and a
    ``{"results": [...]}`` / ``{"data": [...]}`` envelope. Handle all three.
    """
    items: list[dict[str, Any]] = []
    if isinstance(data, list):
        items = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        for key in ("results", "data", "cvelist", "cves"):
            val = data.get(key)
            if isinstance(val, list):
                items = [d for d in val if isinstance(d, dict)]
                break

    out: list[LiveCVE] = []
    for it in items:
        cve_id = it.get("id") or it.get("cve") or it.get("cveMetadata", {}).get("cveId", "")
        if not cve_id or not str(cve_id).upper().startswith("CVE-"):
            continue
        cvss = _circl_cvss(it)
        summary = it.get("summary") or it.get("description") or ""
        cwe = it.get("cwe", "")
        if cwe and not str(cwe).upper().startswith("CWE-"):
            cwe = f"CWE-{cwe}" if str(cwe).isdigit() else ""
        refs = it.get("references") or []
        out.append(LiveCVE(
            cve_id=str(cve_id).upper(),
            title=(summary[:200] if summary else str(cve_id)),
            description=summary,
            severity=_score_to_severity(cvss),
            cvss=cvss,
            cwe=cwe or "",
            published=str(it.get("Published") or it.get("published") or ""),
            references=[str(r) for r in refs][:8] if isinstance(refs, list) else [],
            source="circl",
        ))
    return out


def _circl_cvss(item: dict[str, Any]) -> float:
    for key in ("cvss3", "cvss", "cvss4"):
        v = item.get(key)
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            m = re.match(r"^\s*(\d+(?:\.\d+)?)", v)
            if m:
                try:
                    return float(m.group(1))
                except ValueError:
                    pass
    return 0.0


def merge_and_dedupe(records: list[LiveCVE]) -> list[LiveCVE]:
    """Collapse records by CVE id, keeping the richest (highest CVSS, then the
    one with a confirmed version, then NVD over CIRCL)."""
    best: dict[str, LiveCVE] = {}
    src_rank = {"nvd": 0, "circl": 1, "": 2}
    for r in records:
        cur = best.get(r.cve_id)
        if cur is None:
            best[r.cve_id] = r
            continue
        better = (
            (r.cvss, r.version_confirmed, -src_rank.get(r.source, 3))
            > (cur.cvss, cur.version_confirmed, -src_rank.get(cur.source, 3))
        )
        # Preserve a KEV / version-confirmed flag from whichever record had it.
        r.in_kev = r.in_kev or cur.in_kev
        cur.in_kev = r.in_kev
        if better:
            r.version_confirmed = r.version_confirmed or cur.version_confirmed
            best[r.cve_id] = r
    ordered = sorted(best.values(),
                     key=lambda c: (c.in_kev, c.cvss), reverse=True)
    return ordered


def filter_by_version(records: list[LiveCVE], product_key: str, version: str,
                      inline_lookup: Any = None) -> list[LiveCVE]:
    """Mark records whose affected-version range matches ``version``.

    We do not *drop* unmatched records (a live feed may not expose a machine-
    readable range) — we mark ``version_confirmed`` so triage can prioritise the
    proven ones. If HEAVEN's inline DB has an authoritative range for the same
    CVE id, that verdict wins.
    """
    if not version:
        return records
    inline_ranges: dict[str, list[str]] = {}
    if inline_lookup is not None:
        for rec in inline_lookup(product_key, "") or []:
            inline_ranges[rec.cve_id] = rec.affected_versions
    for r in records:
        specs = inline_ranges.get(r.cve_id)
        if specs:
            r.version_confirmed = any(_version_in_range(version, s) for s in specs)
    return records


# ── The feed ─────────────────────────────────────────────────────────────────
class LiveCVEFeed:
    """Dynamic multi-source CVE discovery for products not in the inline DB."""

    def __init__(self, *, use_nvd: bool = True, use_circl: bool = True,
                 use_epss: bool = True, use_exploitdb: bool = True,
                 max_exploit_lookups: int = 10,
                 timeout: float = 20.0, cache_dir: Optional[Path] = None):
        self.use_nvd = use_nvd
        self.use_circl = use_circl
        # EPSS (cheap, one batched call) and Exploit-DB (bounded, offline-first
        # via searchsploit/CSV) turn a bare CVSS into real-world risk: "is this
        # actually being exploited, and does a public PoC exist?".
        self.use_epss = use_epss
        self.use_exploitdb = use_exploitdb
        self.max_exploit_lookups = max_exploit_lookups
        self.timeout = timeout
        self._cache_dir = cache_dir or _CACHE_DIR

    @property
    def available(self) -> bool:
        return httpx is not None

    # -- caching -------------------------------------------------------------
    def _cache_path(self, key: str) -> Path:
        safe = re.sub(r"[^a-z0-9._-]", "_", key.lower())
        return self._cache_dir / f"{_CACHE_SCHEMA}_{safe}.json"

    def _cache_read(self, key: str) -> Optional[list[LiveCVE]]:
        p = self._cache_path(key)
        try:
            if not p.exists() or (time.time() - p.stat().st_mtime) > _CACHE_TTL_S:
                return None
            raw = json.loads(p.read_text())
            return [LiveCVE(**r) for r in raw]
        except Exception:
            return None

    def _cache_write(self, key: str, records: list[LiveCVE]) -> None:
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._cache_path(key).write_text(
                json.dumps([r.__dict__ for r in records]))
        except Exception as e:  # cache is best-effort
            logger.debug("cve cache write failed: %s", e)

    # -- discovery -----------------------------------------------------------
    async def discover(self, product: str, version: str = "", *,
                       vendor: str = "", cpe: str = "",
                       max_results: int = 25) -> list[LiveCVE]:
        """Return live CVEs for ``product`` (+ optional ``version``/``cpe``).

        Queries every enabled + reachable source, merges, de-dupes, version-
        marks and caches. Empty (never raises) when offline / no httpx.
        """
        product = (product or "").strip()
        if not product and not cpe:
            return []
        # Refuse a search keyed on a generic protocol label ("http", "ssl", …)
        # unless an explicit CPE pins the real product. The feed would otherwise
        # return every product that speaks the protocol (Apache/nginx CVEs for a
        # bare "http"), producing confident-looking false positives on unrelated
        # servers. A version does NOT rescue it — a Python http.server's "0.6" is
        # not Apache's "0.6", so "http"+version must still be rejected.
        if not cpe and _product_key(product) in _GENERIC_PRODUCT_KEYS:
            return []
        cache_key = f"{vendor}:{product}:{version}:{cpe}"
        cached = self._cache_read(cache_key)
        if cached is not None:
            return cached[:max_results]
        if not self.available:
            logger.debug("live CVE feed unavailable (no httpx)")
            return []

        gathered: list[LiveCVE] = []
        tasks = []
        if self.use_nvd:
            tasks.append(self._from_nvd(product, version, cpe))
        if self.use_circl:
            tasks.append(self._from_circl(vendor, product))
        for res in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(res, list):
                gathered.extend(res)
            elif isinstance(res, Exception):
                logger.debug("live CVE source error: %s", res)

        merged = merge_and_dedupe(gathered)
        product_key = _product_key(product)
        try:
            from heaven.vulnscan.cve_mapper import lookup_inline_cves
            merged = filter_by_version(merged, product_key, version, lookup_inline_cves)
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
        # Cap first, then enrich only what we'll actually return — no point
        # paying EPSS/Exploit-DB cost on records that get sliced off.
        merged = merged[:max_results]
        await self._enrich(merged)
        self._cache_write(cache_key, merged)
        return merged

    async def _enrich(self, records: list[LiveCVE]) -> list[LiveCVE]:
        """Add real-world risk signal to CVE records, in place.

        * **EPSS** — one batched call to the FIRST.org EPSS API (via
          :class:`NVDClient`) gives each CVE its exploitation-probability.
        * **Exploit-DB** — the top records by CVSS are checked for a public PoC
          (searchsploit offline first, CSV mirror fallback). Bounded by
          ``max_exploit_lookups`` and fully graceful — a missing tool or network
          just leaves ``exploit_available=False``.
        """
        if not records:
            return records
        cve_ids = [r.cve_id for r in records]

        if self.use_epss:
            try:
                from heaven.vulnscan.nvd_client import NVDClient
                client = NVDClient()
                try:
                    scores = await client.enrich_epss(cve_ids)
                finally:
                    await client.close()
                for r in records:
                    r.epss = scores.get(r.cve_id, r.epss)
            except Exception as e:
                logger.debug("EPSS enrichment failed: %s", e)

        if self.use_exploitdb:
            try:
                from heaven.vulnscan.exploitdb_client import lookup_cve
                top = sorted(records, key=lambda r: r.cvss,
                             reverse=True)[:self.max_exploit_lookups]
                by_id = {r.cve_id: r for r in top}
                results = await asyncio.gather(
                    *(lookup_cve(r.cve_id) for r in top),
                    return_exceptions=True)
                for res in results:
                    if isinstance(res, BaseException) or not getattr(res, "entries", None):
                        continue
                    rec = by_id.get(res.cve)
                    if rec is None:
                        continue
                    rec.exploit_available = True
                    best = res.best
                    rec.exploit_url = best.edb_url if best else ""
            except Exception as e:
                logger.debug("Exploit-DB enrichment failed: %s", e)
        return records

    async def discover_for_service(self, service: str, banner: str = "",
                                   version: str = "") -> list[LiveCVE]:
        """Convenience: resolve a service/banner to a product then discover."""
        fp = _fingerprint_from_banner(banner) if banner else None
        product_key = fp[0] if fp else _product_key(service)
        # A bare protocol label (e.g. "http") resolves via the CPE map to whatever
        # product speaks it (Apache), so a generic key must never drive a search —
        # that produced Apache CVEs on plain HTTP servers. A concrete product only.
        if product_key in _GENERIC_PRODUCT_KEYS:
            return []
        ver = version or (fp[1] if fp else "")
        vendor, product = _vendor_product_for(product_key, service)
        return await self.discover(product, ver, vendor=vendor)

    async def _from_nvd(self, product: str, version: str, cpe: str) -> list[LiveCVE]:
        try:
            from heaven.vulnscan.nvd_client import NVDClient
        except Exception:
            return []
        client = NVDClient()
        try:
            await client.load_kev_catalog()
            query_cpe = cpe or _guess_cpe(product, version)
            records = await client.search_by_cpe(query_cpe)
            out = []
            for r in records:
                out.append(LiveCVE(
                    cve_id=r.cve_id, title=r.title, description=r.description,
                    severity=r.severity, cvss=r.cvss_base, cvss_vector=r.cvss_vector,
                    cwe=r.cwe_id, published=r.published, references=r.references,
                    source="nvd", in_kev=r.in_kev,
                    # NVD's virtualMatchString applies its own version-range logic,
                    # so a returned record for a versioned CPE is version-confirmed.
                    version_confirmed=bool(version),
                ))
            return out
        finally:
            await client.close()

    async def _from_circl(self, vendor: str, product: str) -> list[LiveCVE]:
        if httpx is None or not product:
            return []
        vendor = vendor or _guess_vendor(product)
        if not vendor:
            return []
        url = CIRCL_SEARCH_URL.format(vendor=vendor, product=product)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers={"Accept": "application/json"})
                if resp.status_code != 200:
                    return []
                return parse_circl_response(resp.json())
        except Exception as e:
            logger.debug("CIRCL lookup failed for %s/%s: %s", vendor, product, e)
            return []


# ── helpers ──────────────────────────────────────────────────────────────────
def _product_key(service: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", (service or "").lower().replace("-", "_"))


# Normalised protocol labels that name no concrete product. A version-less,
# CPE-less search on one of these would return every product speaking the
# protocol, so ``discover`` refuses them (see the guard there).
_GENERIC_PRODUCT_KEYS = frozenset({
    "", "http", "https", "http_proxy", "http_alt", "www", "web", "ssl", "tls",
    "tcp", "udp", "tcpwrapped", "unknown", "service", "socks", "proxy",
    "rpcbind", "netbios_ssn", "microsoft_ds", "domain", "rtsp", "upnp", "soap",
    "ident", "ssl_http", "https_alt",
})


def _vendor_product_for(product_key: str, service: str) -> tuple[str, str]:
    """Best-effort (vendor, product) for CIRCL, using the cve_mapper CPE_MAP."""
    entries = CPE_MAP.get(product_key) or CPE_MAP.get((service or "").lower())
    if entries:
        return entries[0][0], entries[0][1]
    return "", product_key or (service or "").lower()


def _guess_vendor(product: str) -> str:
    p = product.lower()
    for entries in CPE_MAP.values():
        for vendor, prod in entries:
            if prod == p:
                return vendor
    return p  # CIRCL often accepts vendor==product for single-name projects


def _guess_cpe(product: str, version: str) -> str:
    vendor = _guess_vendor(product)
    ver = version or "*"
    return f"cpe:2.3:a:{vendor}:{product.lower()}:{ver}:*:*:*:*:*:*:*"


async def discover_cves(product: str, version: str = "", **kw: Any) -> dict[str, Any]:
    """Module entry point — returns a JSON-safe dict (CLI/API use this)."""
    feed = LiveCVEFeed()
    records = await feed.discover(product, version, **kw)
    return {
        "product": product, "version": version,
        "available": feed.available,
        "total": len(records),
        "cves": [r.to_dict() for r in records],
    }


__all__ = [
    "LiveCVEFeed", "LiveCVE", "discover_cves",
    "parse_circl_response", "merge_and_dedupe", "filter_by_version",
]
