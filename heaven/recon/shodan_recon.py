"""
HEAVEN — Shodan Passive Intelligence
Passive host/domain lookup via Shodan API (no active probing).
"""

from __future__ import annotations

import os

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:
    _AIOHTTP = False


class ShodanRecon:

    BASE = "https://api.shodan.io"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")

    def _has_key(self) -> bool:
        return bool(self.api_key)

    async def lookup_host(self, ip: str) -> dict:
        if not self._has_key() or not _AIOHTTP:
            return {}
        url = f"{self.BASE}/shodan/host/{ip}?key={self.api_key}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status != 200:
                        return {}
                    data = await r.json()
                    return self._parse_host(data)
        except Exception:
            return {}

    async def lookup_domain(self, domain: str) -> dict:
        if not self._has_key() or not _AIOHTTP:
            return {}
        url = f"{self.BASE}/dns/domain/{domain}?key={self.api_key}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status != 200:
                        return {}
                    data = await r.json()
                    return self._parse_domain(data, domain)
        except Exception:
            return {}

    async def search_org(self, org: str, limit: int = 100) -> list[dict]:
        if not self._has_key() or not _AIOHTTP:
            return []
        query = f"org:{org}"
        url = f"{self.BASE}/shodan/host/search?key={self.api_key}&query={query}&limit={limit}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status != 200:
                        return []
                    data = await r.json()
                    return [self._parse_host(h) for h in data.get("matches", [])]
        except Exception:
            return []

    def _parse_host(self, data: dict) -> dict:
        ports = data.get("ports") or [item.get("port") for item in data.get("data", [])]
        banners: list[str] = []
        vulns: list[str] = list(data.get("vulns", {}).keys())
        for svc in data.get("data", []):
            banner = svc.get("data", "").strip()
            if banner:
                banners.append(banner[:200])
        return {
            "ip": data.get("ip_str", ""),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "ports": ports,
            "hostnames": data.get("hostnames", []),
            "os": data.get("os"),
            "cves": vulns,
            "banners": banners,
            "source": "shodan",
        }

    def _parse_domain(self, data: dict, domain: str) -> dict:
        subdomains = data.get("subdomains", [])
        records = data.get("data", [])
        a_records = [r.get("value") for r in records if r.get("type") == "A"]
        return {
            "domain": domain,
            "subdomains": subdomains,
            "a_records": a_records,
            "record_count": len(records),
            "source": "shodan",
        }
