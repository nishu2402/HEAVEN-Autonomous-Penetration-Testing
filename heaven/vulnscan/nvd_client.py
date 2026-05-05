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
    cwe_id: str = ""
    epss_score: float = 0.0
    exploit_available: bool = False
    in_kev: bool = False
    published: str = ""
    references: list[str] = field(default_factory=list)
    cpe_matches: list[str] = field(default_factory=list)
    remediation: str = ""


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
        """Search NVD for CVEs matching a CPE string."""
        if cpe in self._cache:
            return self._cache[cpe]

        await self._rate_wait()
        client = await self._get_client()

        try:
            params = {"cpeName": cpe, "resultsPerPage": 50}
            resp = await client.get(NVD_BASE_URL, params=params)

            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code} for CPE {cpe}")
                return []

            data = resp.json()
            records = []

            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Extract CVSS
                cvss_base = 0.0
                cvss_vector = ""
                severity = "info"
                metrics = cve_data.get("metrics", {})

                for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version_key in metrics:
                        metric = metrics[version_key][0]
                        cvss_data = metric.get("cvssData", {})
                        cvss_base = cvss_data.get("baseScore", 0.0)
                        cvss_vector = cvss_data.get("vectorString", "")
                        severity = metric.get("baseSeverity", "").lower() or _score_to_severity(cvss_base)
                        break

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
                    cwe_id=cwe,
                    in_kev=cve_id in self._kev_cves,
                    published=cve_data.get("published", ""),
                    references=[r.get("url", "") for r in cve_data.get("references", [])[:5]],
                )
                records.append(record)

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

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


async def lookup_vulnerabilities(scan_id: str = "", cpes: list[str] = None, **kwargs) -> dict[str, Any]:
    """Main entry point (called by orchestrator after recon phase)."""
    cpes = cpes or []
    logger.info(f"Starting vulnerability mapping for {len(cpes)} CPEs via NVD...")
    client = NVDClient()
    await client.load_kev_catalog()

    all_vulns = []
    stats = {"total_cves": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "in_kev": 0}

    for cpe in cpes:
        records = await client.search_by_cpe(cpe)
        for r in records:
            all_vulns.append({
                "cve_id": r.cve_id, "title": r.title, "severity": r.severity,
                "cvss_base": r.cvss_base, "in_kev": r.in_kev, "asset": cpe,
                "description": r.description
            })
            stats[r.severity] = stats.get(r.severity, 0) + 1
            if r.in_kev:
                stats["in_kev"] += 1

    # Enrich with EPSS
    if all_vulns:
        cve_ids = [v["cve_id"] for v in all_vulns]
        epss_scores = await client.enrich_epss(cve_ids)
        for v in all_vulns:
            v["epss_score"] = epss_scores.get(v["cve_id"], 0.0)

    await client.close()
    stats["total_cves"] = len(all_vulns)
    return {**stats, "vulnerabilities": all_vulns}


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
