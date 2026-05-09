"""
HEAVEN — NVD API 2.0 Pipeline
Downloads, caches, and parses CVE data from NVD. Enriches with EPSS + KEV.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp


class NVDPipeline:

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.delay = 0.6 if self.api_key else 6.0  # rate limit compliance

    async def fetch_cves(self, session: aiohttp.ClientSession,
                         start: str, end: str) -> list[dict]:
        """
        Fetch CVEs from NVD API 2.0 for a date range.
        start/end format: "2020-01-01T00:00:00.000"
        Handles pagination automatically (2000 per page).
        """
        headers = {"apiKey": self.api_key} if self.api_key else {}
        start_index = 0
        params: dict[str, str | int] = {"pubStartDate": start, "pubEndDate": end,
                                        "resultsPerPage": 2000, "startIndex": start_index}
        results: list[dict[str, Any]] = []
        while True:
            async with session.get(self.NVD_API, params=params,
                                   headers=headers, timeout=aiohttp.ClientTimeout(total=60)) as r:
                if r.status == 429:
                    await asyncio.sleep(30)
                    continue
                data = await r.json()
            batch = data.get("vulnerabilities", [])
            results.extend(batch)
            total = int(data.get("totalResults", 0))
            start_index += 2000
            params["startIndex"] = start_index
            if start_index >= total:
                break
            await asyncio.sleep(self.delay)
        return results

    async def download_dataset(self, output_dir: Path,
                               start_year: int = 2018) -> Path:
        """
        Download full NVD dataset from start_year to today.
        Saves as output_dir/nvd_dataset.jsonl (one CVE per line).
        Skips if file exists and < 7 days old.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        out_file = output_dir / "nvd_dataset.jsonl"
        if out_file.exists():
            age = datetime.now().timestamp() - out_file.stat().st_mtime
            if age < 7 * 86400:
                print(f"Using cached dataset: {out_file}")
                return out_file

        async with aiohttp.ClientSession() as session:
            with open(out_file, "w") as f:
                year = start_year
                while year <= datetime.now().year:
                    start = f"{year}-01-01T00:00:00.000"
                    end = f"{year}-12-31T23:59:59.999"
                    print(f"Fetching {year}...")
                    try:
                        cves = await self.fetch_cves(session, start, end)
                        for cve in cves:
                            f.write(json.dumps(cve) + "\n")
                        print(f"  {year}: {len(cves)} CVEs")
                    except Exception as e:
                        print(f"  {year} error: {e}")
                    year += 1
        return out_file

    # Canonical 13-feature names used by NVD_model.pkl
    FEATURE_NAMES = [
        "attack_vector", "attack_complexity", "privileges_required",
        "user_interaction", "scope", "conf_impact", "integ_impact",
        "avail_impact", "vuln_age_days", "ref_count", "cpe_count",
        "epss_score_pct", "in_kev",
    ]

    def parse_dataset(self, jsonl_path: Path):
        """
        Parse NVD JSONL dataset into feature arrays for model training.

        Returns (X, y, feature_cols):
          - X: numpy array of shape (n_samples, 13) with NVD_model.pkl features
          - y: numpy array of CVSS base scores (regression target)
          - feature_cols: list of the 13 feature names
        """
        import pandas as pd

        AV_MAP  = {"NETWORK": 4, "ADJACENT_NETWORK": 3, "ADJACENT": 3,
                   "LOCAL": 2, "PHYSICAL": 1}
        AC_MAP  = {"LOW": 2, "HIGH": 1}
        PR_MAP  = {"NONE": 3, "LOW": 2, "HIGH": 1}
        UI_MAP  = {"NONE": 2, "REQUIRED": 1}
        SC_MAP  = {"CHANGED": 2, "UNCHANGED": 1}
        IMP_MAP = {"HIGH": 3, "LOW": 2, "NONE": 1}

        rows = []
        with open(jsonl_path) as fh:
            for line in fh:
                try:
                    item = json.loads(line)
                    cve = item.get("cve", item)

                    # Prefer CVSSv3.1, fall back to v3.0
                    metrics31 = (cve.get("metrics", {})
                                 .get("cvssMetricV31", [{}])[0]
                                 .get("cvssData", {}))
                    metrics30 = (cve.get("metrics", {})
                                 .get("cvssMetricV30", [{}])[0]
                                 .get("cvssData", {}))
                    metrics = metrics31 if metrics31 else metrics30
                    score = metrics.get("baseScore")
                    if score is None:
                        continue

                    published = cve.get("published", "")
                    try:
                        pub_date = datetime.fromisoformat(published[:10])
                        age_days = (datetime.now() - pub_date).days
                    except Exception:
                        age_days = 365

                    # Count references and CPE configurations
                    references = cve.get("references", [])
                    ref_count = min(len(references), 50)

                    confs = cve.get("configurations", [])
                    cpe_count = 0
                    for conf in confs:
                        for node in conf.get("nodes", []):
                            cpe_count += len(node.get("cpeMatch", []))
                    cpe_count = min(cpe_count, 20)

                    row = {
                        "attack_vector":       AV_MAP.get(metrics.get("attackVector", ""),  2),
                        "attack_complexity":   AC_MAP.get(metrics.get("attackComplexity", ""), 1),
                        "privileges_required": PR_MAP.get(metrics.get("privilegesRequired", ""), 2),
                        "user_interaction":    UI_MAP.get(metrics.get("userInteraction", ""), 1),
                        "scope":               SC_MAP.get(metrics.get("scope", ""), 1),
                        "conf_impact":         IMP_MAP.get(metrics.get("confidentialityImpact", ""), 1),
                        "integ_impact":        IMP_MAP.get(metrics.get("integrityImpact", ""), 1),
                        "avail_impact":        IMP_MAP.get(metrics.get("availabilityImpact", ""), 1),
                        "vuln_age_days":       min(age_days, 3650),
                        "ref_count":           float(ref_count),
                        "cpe_count":           float(cpe_count),
                        "epss_score_pct":      0.0,   # populated by fetch_epss post-processing
                        "in_kev":              0.0,   # populated by fetch_kev post-processing
                        "_cvss_base_score":    float(score),
                    }
                    rows.append(row)
                except Exception:
                    continue

        df = pd.DataFrame(rows)
        feature_cols = self.FEATURE_NAMES
        return df[feature_cols].values, df["_cvss_base_score"].values, feature_cols

    async def fetch_epss(self, cve_ids: list[str],
                         session: aiohttp.ClientSession) -> dict[str, float]:
        """
        Fetch EPSS exploitation probability scores from FIRST.org.
        Free, no auth. Returns {cve_id: probability 0.0-1.0}
        """
        scores = {}
        for i in range(0, len(cve_ids), 100):
            chunk = cve_ids[i:i+100]
            try:
                async with session.get(
                    "https://api.first.org/data/v1/epss",
                    params={"cve": ",".join(chunk)},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as r:
                    data = await r.json()
                for item in data.get("data", []):
                    scores[item["cve"]] = float(item.get("epss", 0.0))
            except Exception:
                pass
            await asyncio.sleep(0.5)
        return scores

    async def fetch_kev(self, session: aiohttp.ClientSession) -> set[str]:
        """
        Fetch CISA Known Exploited Vulnerabilities catalog.
        CVEs in KEV = actively exploited in the wild.
        Free, no auth.
        """
        try:
            async with session.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                data = await r.json()
            return {v["cveID"] for v in data.get("vulnerabilities", [])}
        except Exception:
            return set()

    @staticmethod
    def compute_priority_score(cvss: float, epss: float, in_kev: bool) -> float:
        """
        Composite priority score 0-10.
        KEV = always max priority.
        Weights: 50% CVSS severity + 50% EPSS exploitation probability.
        """
        if in_kev:
            return 10.0
        return round((cvss * 0.5) + (epss * 10.0 * 0.5), 2)
