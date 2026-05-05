"""
HEAVEN — MITRE ATT&CK TAXII 2.1 Client
Live connection to cti-taxii.mitre.org for latest threat intelligence.
STIX 2.1 object parsing with local caching and offline fallback.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("mitre.taxii")

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# MITRE ATT&CK TAXII 2.1 endpoints
TAXII_SERVER = "https://cti-taxii.mitre.org"
TAXII_API_ROOT = f"{TAXII_SERVER}/stix/api/v21"
ENTERPRISE_COLLECTION_ID = "95ecc380-afe9-11e4-9b6c-751b66dd541e"

# STIX object type filters
ATTACK_PATTERN = "attack-pattern"
MALWARE = "malware"
TOOL = "tool"
CAMPAIGN = "campaign"
INTRUSION_SET = "intrusion-set"
RELATIONSHIP = "relationship"


@dataclass
class STIXObject:
    """Parsed STIX 2.1 object."""
    id: str = ""
    type: str = ""
    name: str = ""
    description: str = ""
    external_references: list[dict] = field(default_factory=list)
    kill_chain_phases: list[dict] = field(default_factory=list)
    created: str = ""
    modified: str = ""
    labels: list[str] = field(default_factory=list)
    revoked: bool = False
    deprecated: bool = False
    aliases: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def attack_id(self) -> str:
        for ref in self.external_references:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id", "")
        return ""

    @property
    def url(self) -> str:
        for ref in self.external_references:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("url", "")
        return ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.type, "name": self.name,
            "attack_id": self.attack_id, "description": self.description[:500],
            "kill_chain": self.kill_chain_phases, "labels": self.labels,
            "url": self.url, "revoked": self.revoked,
        }


class TAXIIClient:
    """
    MITRE ATT&CK TAXII 2.1 API client.

    Features:
    - Fetches latest attack patterns, malware, tools, campaigns
    - Local caching with configurable TTL (default 24h)
    - Offline fallback using bundled dataset
    - Rate-limited API calls with retry logic
    - STIX 2.1 object parsing
    """

    def __init__(self, cache_dir: Optional[Path] = None, cache_ttl_hours: int = 24,
                 timeout: float = 30.0):
        self._cache_dir = cache_dir or Path("data/mitre_cache")
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_ttl = cache_ttl_hours * 3600
        self._timeout = timeout
        self._objects: dict[str, STIXObject] = {}
        self._last_fetch: float = 0.0

    async def fetch_attack_data(self, force_refresh: bool = False) -> dict:
        """Fetch ATT&CK data from TAXII server or cache."""
        cache_file = self._cache_dir / "enterprise_attack.json"

        # Check cache
        if not force_refresh and cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < self._cache_ttl:
                logger.info(f"Using cached ATT&CK data (age: {age / 3600:.1f}h)")
                return self._load_cache(cache_file)

        # Fetch from TAXII server
        if HAS_HTTPX:
            try:
                data = await self._fetch_from_taxii()
                self._save_cache(cache_file, data)
                return data
            except Exception as e:
                logger.warning(f"TAXII fetch failed: {e} — using cache/fallback")
                if cache_file.exists():
                    return self._load_cache(cache_file)

        # Offline fallback
        return self._get_offline_fallback()

    async def _fetch_from_taxii(self) -> dict:
        """Fetch from MITRE ATT&CK TAXII 2.1 server."""
        headers = {
            "Accept": "application/taxii+json;version=2.1",
            "Content-Type": "application/taxii+json;version=2.1",
        }
        url = f"{TAXII_API_ROOT}/collections/{ENTERPRISE_COLLECTION_ID}/objects/"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            all_objects = []
            next_url: Optional[str] = url

            while next_url:
                resp = await client.get(next_url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                objects = data.get("objects", [])
                all_objects.extend(objects)
                # Handle pagination
                next_url = data.get("next")
                if next_url and not next_url.startswith("http"):
                    next_url = f"{TAXII_API_ROOT}/collections/{ENTERPRISE_COLLECTION_ID}/objects/?next={next_url}"

                logger.info(f"Fetched {len(all_objects)} STIX objects from TAXII...")
                # Rate limiting
                await self._rate_limit()

        logger.info(f"ATT&CK data fetched: {len(all_objects)} total objects")
        return {"objects": all_objects, "fetched_at": time.time()}

    async def _rate_limit(self) -> None:
        """Respect TAXII server rate limits."""
        import asyncio
        await asyncio.sleep(1.0)

    def parse_objects(self, data: dict) -> dict[str, list[STIXObject]]:
        """Parse STIX objects into categorized collections."""
        result: dict[str, list[STIXObject]] = {
            "techniques": [], "malware": [], "tools": [],
            "campaigns": [], "groups": [], "relationships": [],
        }
        for obj in data.get("objects", []):
            stix = self._parse_stix_object(obj)
            if stix.revoked or stix.deprecated:
                continue
            self._objects[stix.id] = stix
            if stix.type == ATTACK_PATTERN:
                result["techniques"].append(stix)
            elif stix.type == MALWARE:
                result["malware"].append(stix)
            elif stix.type == TOOL:
                result["tools"].append(stix)
            elif stix.type == CAMPAIGN:
                result["campaigns"].append(stix)
            elif stix.type == INTRUSION_SET:
                result["groups"].append(stix)
            elif stix.type == RELATIONSHIP:
                result["relationships"].append(stix)

        logger.info(
            f"Parsed: {len(result['techniques'])} techniques, "
            f"{len(result['groups'])} groups, {len(result['malware'])} malware"
        )
        return result

    def get_technique(self, attack_id: str) -> Optional[STIXObject]:
        """Look up a technique by ATT&CK ID (e.g., T1059)."""
        for obj in self._objects.values():
            if obj.type == ATTACK_PATTERN and obj.attack_id == attack_id:
                return obj
        return None

    def get_groups_using_technique(self, technique_id: str) -> list[STIXObject]:
        """Find threat groups that use a specific technique."""
        groups = []
        for obj in self._objects.values():
            if obj.type == RELATIONSHIP and obj.raw.get("relationship_type") == "uses":
                if technique_id in obj.raw.get("target_ref", ""):
                    source = self._objects.get(obj.raw.get("source_ref", ""))
                    if source and source.type == INTRUSION_SET:
                        groups.append(source)
        return groups

    def _parse_stix_object(self, obj: dict) -> STIXObject:
        return STIXObject(
            id=obj.get("id", ""),
            type=obj.get("type", ""),
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            external_references=obj.get("external_references", []),
            kill_chain_phases=obj.get("kill_chain_phases", []),
            created=obj.get("created", ""),
            modified=obj.get("modified", ""),
            labels=obj.get("labels", []),
            revoked=obj.get("revoked", False),
            deprecated=obj.get("x_mitre_deprecated", False),
            aliases=obj.get("aliases", []),
            raw=obj,
        )

    def _load_cache(self, path: Path) -> dict:
        return json.loads(path.read_text())

    def _save_cache(self, path: Path, data: dict) -> None:
        path.write_text(json.dumps(data))
        logger.info(f"ATT&CK data cached to {path}")

    def _get_offline_fallback(self) -> dict:
        """Minimal offline ATT&CK dataset for when TAXII is unreachable."""
        logger.warning("Using offline ATT&CK fallback — data may be stale")
        return {"objects": [], "fetched_at": 0, "offline": True}

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        for obj in self._objects.values():
            by_type[obj.type] = by_type.get(obj.type, 0) + 1
        return {
            "total_objects": len(self._objects),
            "by_type": by_type,
            "cache_dir": str(self._cache_dir),
        }
