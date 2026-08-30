"""
HEAVEN — NVD API v2 Client
Cross-references discovered services with NIST NVD for CVE lookups.
Includes EPSS enrichment and CISA KEV catalog integration.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

from heaven.config import get_config
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.nvd")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class CVERecord:
    cve_id: str
    title: str = ""
    description: str = ""
    severity: str = "info"
    cvss_base: float = 0.0
    cvss_vector: str = ""
    cvss_version: str = ""
    # CVSS v4.0 and v3.1 companions, populated when NVD publishes each metric so
    # a finding can show the current standard alongside the legacy score.
    cvss4_vector: str = ""
    cvss4_base: float = 0.0
    cvss31_vector: str = ""
    cvss31_base: float = 0.0
    cwe_id: str = ""
    epss_score: float = 0.0
    exploit_available: bool = False
    in_kev: bool = False
    published: str = ""
    references: list[str] = field(default_factory=list)
    cpe_matches: list[str] = field(default_factory=list)
    remediation: str = ""
    # True only when the queried version matches an EXACT-version CPE or a
    # lower-BOUNDED window for the product. A rangeless upper-bound-only match
    # (``versionEndExcluding`` with no start) leaves this False: NVD lists no
    # introduced-version, so an ancient build (ProFTPD 1.3.1 vs a ``<1.3.10``
    # mod_sftp CVE) cannot be *confirmed* affected — only flagged "potential".
    version_bounded: bool = False


class NVDClient:
    """Async NVD API v2 client with rate limiting and caching."""

    def __init__(self):
        self.config = get_config()
        self.api_key = self.config.api.nvd_api_key
        self._rate_limit = 0.6 if self.api_key else 6.0  # seconds between requests
        self._last_request = 0.0
        self._cache: dict[str, list[CVERecord]] = {}
        self._kev_cves: set[str] = set()
        self._client: Optional[httpx.AsyncClient] = None
        self._warned_invalid_key = False  # warn once if a set key keeps 404-ing

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Accept": "application/json"}
            if self.api_key:
                headers["apiKey"] = self.api_key
            self._client = httpx.AsyncClient(headers=headers, timeout=30.0)
        return self._client

    async def _rate_wait(self):
        elapsed = time.time() - self._last_request
        if elapsed < self._rate_limit:
            await asyncio.sleep(self._rate_limit - elapsed)
        self._last_request = time.time()

    async def load_kev_catalog(self) -> None:
        """Load CISA Known Exploited Vulnerabilities catalog."""
        try:
            client = await self._get_client()
            resp = await client.get(KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                self._kev_cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
                logger.info(f"Loaded {len(self._kev_cves)} KEV entries")
        except Exception as e:
            logger.warning(f"Failed to load KEV catalog: {e}")

    async def search_by_cpe(self, cpe: str) -> list[CVERecord]:
        """Search NVD for CVEs affecting a CPE.

        Uses NVD's ``virtualMatchString`` rather than ``cpeName``. ``cpeName``
        requires an *exact* CPE 2.3 name with a concrete version and returns
        HTTP 404 for the wildcard-version CPEs HEAVEN typically generates from
        banner fingerprints — i.e. it would silently find nothing. ``virtualMatchString``
        accepts partial / wildcard CPEs, applies NVD's own version-range matching,
        and returns 0 results (not 404) for unknown products.
        """
        cpe = _normalize_cpe(cpe)
        if cpe in self._cache:
            return self._cache[cpe]

        # The product token + concrete version being queried, so each returned
        # CVE can be classed as a genuine (exact/bounded) match vs a rangeless
        # upper-bound-only one — see _match_is_bounded.
        _cpe_parts = cpe.split(":")
        q_product = _cpe_parts[4] if len(_cpe_parts) > 4 else ""
        q_version = _cpe_parts[5] if len(_cpe_parts) > 5 else ""
        if q_version in ("*", "-"):
            q_version = ""

        await self._rate_wait()
        client = await self._get_client()

        try:
            params: dict[str, str | int] = {
                "virtualMatchString": cpe,
                "resultsPerPage": 50,
                "noRejected": "",
            }
            resp = await client.get(NVD_BASE_URL, params=params)

            if resp.status_code == 404:
                # A 404 on a well-formed query almost always means the API key
                # was rejected — NVD returns 404 (not 401/403) for a bad apiKey.
                # Without a key a valid query returns 200, so flag the likely cause.
                if self.api_key and not self._warned_invalid_key:
                    self._warned_invalid_key = True
                    logger.warning(
                        "NVD returned 404 with an API key set — the key is likely "
                        "invalid or malformed. Verify NVD_API_KEY (Settings → "
                        "Recon enrichment, or `heaven config get NVD_API_KEY`)."
                    )
                self._cache[cpe] = []
                return []

            if resp.status_code == 429:
                logger.warning("NVD API rate-limited (429) — add NVD_API_KEY to raise the limit")
                return []

            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code} for {cpe}")
                return []

            data = resp.json()
            records = []

            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Extract CVSS (prefer v4.0, keep v4.0/v3.1 companions).
                cvss = parse_cvss_metrics(cve_data.get("metrics", {}))
                cvss_base = cvss["cvss_base"]
                cvss_vector = cvss["cvss_vector"]
                cvss_version = cvss["cvss_version"]
                severity = cvss["severity"]
                cvss4_vector = cvss["cvss4_vector"]
                cvss4_base = cvss["cvss4_base"]
                cvss31_vector = cvss["cvss31_vector"]
                cvss31_base = cvss["cvss31_base"]

                # Extract description
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                # Extract CWE
                weaknesses = cve_data.get("weaknesses", [])
                cwe = ""
                for w in weaknesses:
                    for d in w.get("description", []):
                        if d.get("value", "").startswith("CWE-"):
                            cwe = d["value"]
                            break

                record = CVERecord(
                    cve_id=cve_id,
                    title=desc[:200] if desc else cve_id,
                    description=desc,
                    severity=severity,
                    cvss_base=cvss_base,
                    cvss_vector=cvss_vector,
                    cvss_version=cvss_version,
                    cvss4_vector=cvss4_vector or "",
                    cvss4_base=float(cvss4_base or 0.0),
                    cvss31_vector=cvss31_vector or "",
                    cvss31_base=float(cvss31_base or 0.0),
                    cwe_id=cwe,
                    in_kev=cve_id in self._kev_cves,
                    published=cve_data.get("published", ""),
                    references=[r.get("url", "") for r in cve_data.get("references", [])[:5]],
                    version_bounded=_match_is_bounded(
                        q_version, q_product, cve_data.get("configurations", [])),
                )
                records.append(record)

            # NVD returns oldest-first; surface KEV-listed + highest-CVSS CVEs
            # first so the most actionable results lead (and survive any cap).
            records.sort(key=lambda r: (r.in_kev, r.cvss_base), reverse=True)
            self._cache[cpe] = records
            logger.debug(f"NVD: {len(records)} CVEs for {cpe}")
            return records

        except Exception as e:
            logger.error(f"NVD API error for {cpe}: {e}")
            return []

    async def enrich_epss(self, cve_ids: list[str]) -> dict[str, float]:
        """Fetch EPSS scores for a list of CVE IDs."""
        if not cve_ids:
            return {}

        scores = {}
        client = await self._get_client()

        # EPSS API accepts comma-separated CVE IDs
        batch_size = 100
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            try:
                params = {"cve": ",".join(batch)}
                resp = await client.get(EPSS_BASE_URL, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        scores[item["cve"]] = float(item.get("epss", 0.0))
            except Exception as e:
                logger.debug(f"EPSS lookup error: {e}")

        return scores

    async def test_connectivity(self) -> dict[str, Any]:
        """Live check of NVD reachability and API-key validity.

        Makes one cheap real request. Because NVD answers a well-formed query
        with HTTP 200 when no key is set but HTTP 404 when a *bad* key is sent,
        we can tell "key works" from "key rejected" from "no key / slower tier".
        """
        sample = "cpe:2.3:a:openbsd:openssh"
        try:
            client = await self._get_client()
            resp = await client.get(
                NVD_BASE_URL,
                params={"virtualMatchString": sample, "resultsPerPage": 1},
            )
            status = resp.status_code
            if status == 200:
                total = resp.json().get("totalResults")
                return {
                    "ok": True,
                    "has_key": bool(self.api_key),
                    "status_code": status,
                    "sample_results": total,
                    "rate_limit_s": self._rate_limit,
                    "reason": (
                        "API key valid — fast tier (50 req / 30s)"
                        if self.api_key else
                        "Reachable without a key — slow tier (5 req / 30s); "
                        "add NVD_API_KEY for ~10× faster CVE lookups"
                    ),
                }
            if status == 404 and self.api_key:
                return {
                    "ok": False, "has_key": True, "status_code": status,
                    "sample_results": None, "rate_limit_s": self._rate_limit,
                    "reason": "API key rejected (NVD returns 404 for an invalid "
                              "key). Re-check NVD_API_KEY for typos / extra spaces.",
                }
            return {
                "ok": False, "has_key": bool(self.api_key), "status_code": status,
                "sample_results": None, "rate_limit_s": self._rate_limit,
                "reason": f"NVD returned HTTP {status}",
            }
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False, "has_key": bool(self.api_key), "status_code": None,
                "sample_results": None, "rate_limit_s": self._rate_limit,
                "reason": f"could not reach NVD: {e}",
            }

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


async def lookup_vulnerabilities(scan_id: str = "", cpes: Optional[list[str]] = None, **kwargs) -> dict[str, Any]:
    """Main entry point (called by orchestrator after recon phase)."""
    cpes = cpes or []
    logger.info(f"Starting vulnerability mapping for {len(cpes)} CPEs via NVD...")
    client = NVDClient()
    await client.load_kev_catalog()

    all_vulns: list[dict[str, Any]] = []
    stats = {"total_cves": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "in_kev": 0}

    for cpe in cpes:
        records = await client.search_by_cpe(cpe)
        for r in records:
            all_vulns.append({
                "cve_id": r.cve_id, "title": r.title, "severity": r.severity,
                "cvss_base": r.cvss_base, "cvss_vector": r.cvss_vector,
                "cvss_version": r.cvss_version,
                "cvss4_vector": r.cvss4_vector, "cvss4_base": r.cvss4_base,
                "cvss31_vector": r.cvss31_vector, "cvss31_base": r.cvss31_base,
                "in_kev": r.in_kev, "asset": cpe,
                "description": r.description
            })
            stats[r.severity] = stats.get(r.severity, 0) + 1
            if r.in_kev:
                stats["in_kev"] += 1

    # Enrich with EPSS
    if all_vulns:
        cve_ids = [str(v.get("cve_id", "")) for v in all_vulns]
        epss_scores = await client.enrich_epss(cve_ids)
        for v in all_vulns:
            v["epss_score"] = epss_scores.get(str(v.get("cve_id", "")), 0.0)

    await client.close()
    stats["total_cves"] = len(all_vulns)
    return {**stats, "vulnerabilities": all_vulns}


def _iter_cpe_matches(configurations: list) -> "list[dict]":
    """Flatten every ``cpeMatch`` entry across an NVD 2.0 ``configurations`` block
    (top-level nodes and any nested ``children``)."""
    out: list[dict] = []
    for cfg in configurations or []:
        for node in cfg.get("nodes", []) or []:
            out.extend(node.get("cpeMatch", []) or [])
            for child in node.get("children", []) or []:
                out.extend(child.get("cpeMatch", []) or [])
    return out


def _match_is_bounded(query_version: str, product_token: str,
                      configurations: list) -> bool:
    """True when *query_version* matches an EXACT-version CPE or a lower-bounded
    window for *product_token* in this CVE's applicability config.

    NVD's ``virtualMatchString`` matches a versioned query against a rangeless
    ``versionEndExcluding`` ceiling with **no** ``versionStartIncluding`` floor,
    so every version below the fix "matches" — even one released years before the
    vulnerable code existed (ProFTPD 1.3.1 vs a ``<1.3.10`` mod_sftp CVE, OpenSSH
    4.7 vs a ``<9.6`` CVE). Without a floor the affected set is genuinely open
    below, so such a match is treated as *potential*, not *confirmed*. A node that
    pins an exact version, or carries a real lower bound the version satisfies
    jointly with its upper bound, is a genuine confirmation.
    """
    if not query_version:
        return False
    from heaven.vulnscan.cve_mapper import _parse_ver  # lazy: avoid import cycle
    qv = _parse_ver(query_version)
    for m in _iter_cpe_matches(configurations):
        parts = (m.get("criteria", "") or "").split(":")
        if len(parts) < 6 or parts[4] != product_token:
            continue
        cpe_ver = parts[5]
        if cpe_ver not in ("*", "-", ""):
            if _parse_ver(cpe_ver) == qv:      # exact-version applicability
                return True
            continue
        vsi, vse = m.get("versionStartIncluding"), m.get("versionStartExcluding")
        if not (vsi or vse):                   # rangeless / upper-bound-only
            continue
        lo_ok = qv >= _parse_ver(vsi) if vsi else qv > _parse_ver(vse)
        vei, vee = m.get("versionEndIncluding"), m.get("versionEndExcluding")
        hi_ok = (qv <= _parse_ver(vei) if vei
                 else qv < _parse_ver(vee) if vee else True)
        if lo_ok and hi_ok:
            return True
    return False


def _normalize_cpe(cpe: str) -> str:
    """Normalise a CPE to 2.3 URI form for NVD's ``virtualMatchString``.

    nmap emits CPE 2.2 (``cpe:/a:vendor:product:version``); NVD's v2 API only
    understands 2.3 (``cpe:2.3:a:vendor:product:version:*:*:...``) and 404s on
    2.2 input. Already-2.3 strings (and anything unrecognised) pass through.
    """
    cpe = (cpe or "").strip()
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if cpe.startswith("cpe:/"):
        parts = cpe[len("cpe:/"):].split(":")          # [part, vendor, product, version, ...]
        comps = (parts + ["*"] * 11)[:11]              # 2.3 has 11 fields after the prefix
        comps = [c if c not in ("", "-") else "*" for c in comps]
        return "cpe:2.3:" + ":".join(comps)
    return cpe


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


def parse_cvss_metrics(metrics: dict) -> dict:
    """Resolve the authoritative CVSS score from an NVD ``metrics`` block.

    NVD now publishes ``cvssMetricV40`` for some CVEs; prefer it as the current
    standard, then fall back to v3.1 / v3.0 / v2 for the large body of CVEs that
    carry only those. The v4.0 and v3.1 metrics are also returned as explicit
    companions when present, so a finding can show one next to the other.
    """
    metrics = metrics or {}
    cvss_base = 0.0
    cvss_vector = cvss_version = ""
    severity = "info"
    for version_key, ver in (
        ("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"),
    ):
        if metrics.get(version_key):
            data = metrics[version_key][0].get("cvssData", {})
            cvss_base = float(data.get("baseScore", 0.0) or 0.0)
            cvss_vector = str(data.get("vectorString", "") or "")
            cvss_version = ver
            severity = (metrics[version_key][0].get("baseSeverity", "")
                        or data.get("baseSeverity", "")).lower() \
                or _score_to_severity(cvss_base)
            break

    cvss4_vector = cvss31_vector = ""
    cvss4_base = cvss31_base = 0.0
    if metrics.get("cvssMetricV40"):
        d = metrics["cvssMetricV40"][0].get("cvssData", {})
        cvss4_vector = str(d.get("vectorString", "") or "")
        cvss4_base = float(d.get("baseScore", 0.0) or 0.0)
    if metrics.get("cvssMetricV31"):
        d = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss31_vector = str(d.get("vectorString", "") or "")
        cvss31_base = float(d.get("baseScore", 0.0) or 0.0)
    return {
        "cvss_base": cvss_base, "cvss_vector": cvss_vector,
        "cvss_version": cvss_version, "severity": severity,
        "cvss4_vector": cvss4_vector, "cvss4_base": cvss4_base,
        "cvss31_vector": cvss31_vector, "cvss31_base": cvss31_base,
    }
