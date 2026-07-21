"""Regression: version-based CVE findings must carry a real vuln_type.

The inline-CVE and NVD build paths in cve_mapper previously omitted `vuln_type`,
so every version-matched CVE (e.g. an Apache banner → Optionsbleed) persisted as
`vuln_type="unknown"` — which has no KB taxonomy entry and shows up uncategorised
in reports. They must be tagged `vulnerable_service` like the live-feed path,
which aliases to the `vulnerable_component` KB entry.
"""
from __future__ import annotations

import pytest

from heaven.vulnscan.cve_mapper import map_vulnerabilities
from heaven.devsecops.vuln_kb import lookup, normalize_key


@pytest.mark.asyncio
async def test_inline_cve_findings_are_categorised_not_unknown():
    host_results = [{
        "host": "10.0.0.5",
        "open_ports": [{
            "port": 80,
            "service": "http",
            "banner": "Apache/2.2.8 (Ubuntu)",
            "version": "2.2.8",
        }],
    }]
    # Offline: no nvd_client, no live_feed → only the inline DB path runs.
    vulns = await map_vulnerabilities(host_results)
    assert vulns, "expected inline-DB CVEs for Apache 2.2.8"
    for v in vulns:
        vt = v.get("vuln_type") or v.get("type") or "unknown"
        assert vt != "unknown", f"{v.get('cve')} persisted uncategorised"
        # And the type must resolve to a real KB taxonomy entry.
        assert lookup(vt), f"{vt} has no KB entry"
        # Every CVE finding must name the host:port it came from — a CRITICAL
        # with a blank Target reads as broken in the CLI table / kill chain.
        assert v.get("target") == "10.0.0.5:80", f"{v.get('cve')} has no target: {v.get('target')!r}"


def test_vulnerable_service_resolves_in_kb():
    assert normalize_key("vulnerable_service") in ("vulnerable_service",
                                                   "vulnerable_component")
    assert lookup("vulnerable_service"), "vulnerable_service must resolve in the KB"
    assert not lookup("unknown"), "'unknown' must remain an empty (non-)category"
