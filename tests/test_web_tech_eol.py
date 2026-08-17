"""Web-tier EOL + CVE from HTTP response headers (the "outdated PHP" gap).

The reported gap: a webapp discloses an end-of-life PHP in its
``X-Powered-By`` / ``Server`` headers, but that header-derived product+version
never reached the EOL scanner or CVE mapper (both read only nmap-derived
``open_ports[]``), so an EOL PHP was never flagged.

``heaven/recon/web_tech.py`` closes it: it extracts versioned components from
headers and runs them through the *existing* ``scan_eol_from_net`` (CWE-1104) and
``map_vulnerabilities``. These tests prove extraction is faithful (version
required, no fabrication) and that an EOL PHP 5.x header raises real EOL + CVE
findings — with honest ``http_response_header`` provenance.
"""
from __future__ import annotations

import pytest

from heaven.recon.web_tech import extract_web_components, scan_web_tech


# ── Header → component extraction (pure, no network) ─────────────────────────

def test_extract_php_from_x_powered_by():
    comps = extract_web_components({"X-Powered-By": "PHP/5.2.4"})
    php = [c for c in comps if c["service"] == "php"]
    assert php and php[0]["version"] == "5.2.4"
    assert php[0]["source_header"].lower() == "x-powered-by"


def test_extract_multiple_components_from_server_header():
    hdrs = {"Server": "Apache/2.2.8 (Ubuntu) DAV/2 mod_ssl/2.2.8 OpenSSL/0.9.8g"}
    comps = extract_web_components(hdrs)
    got = {(c["service"], c["version"]) for c in comps}
    assert ("apache", "2.2.8") in got
    # OpenSSL 0.9.8g → numeric 0.9.8 (trailing letter dropped) is expected.
    assert ("openssl", "0.9.8") in got
    # Ambiguous sub-modules (DAV, mod_ssl) are deliberately NOT surfaced.
    assert all(c["service"] not in ("dav", "mod_ssl") for c in comps)


def test_extract_requires_a_version_no_fabrication():
    # A bare product with no version must yield nothing (no guessing).
    assert extract_web_components({"Server": "Apache"}) == []
    assert extract_web_components({"X-Powered-By": "PHP"}) == []


def test_extract_dedupes_by_service_version():
    hdrs = {"Server": "nginx/1.10.3", "X-Powered-By": "nginx/1.10.3"}
    comps = extract_web_components(hdrs)
    assert len([c for c in comps if c["service"] == "nginx"]) == 1


# ── Full pipeline: EOL PHP 5.x header → EOL (CWE-1104) + CVE findings ─────────

@pytest.mark.asyncio
async def test_eol_php_header_raises_eol_and_cve():
    async def fake_fetch(url):
        return {
            "Server": "Apache/2.2.8 (Ubuntu) PHP/5.2.4 with Suhosin-Patch",
            "X-Powered-By": "PHP/5.2.4",
        }

    result = await scan_web_tech(["http://192.168.0.162/"], header_fetcher=fake_fetch)

    # A real EOL finding for PHP (CWE-1104 unsupported_software).
    eol = result["findings"]
    assert any(f.get("vuln_type") == "unsupported_software" for f in eol), eol
    php_eol = [f for f in eol
               if "php" in (f.get("evidence", {}).get("product", "")
                            or f.get("description", "")).lower()
               or "php" in str(f).lower()]
    assert php_eol, "expected an EOL finding naming PHP"
    # Provenance is honest: these came from response headers.
    assert any(f.get("evidence", {}).get("detection_source") == "http_response_header"
               for f in eol)

    # PHP 5.2.4 (2007) predates every curated PHP CVE — they are all 7/8-era —
    # so the mapper must NOT fabricate a modern-branch CVE against it. The genuine
    # signal for such an ancient install is the EOL finding above, not a
    # version-mismatched Critical. (Asserting a CVE here previously masked exactly
    # that false positive.)
    php_cves = [v for v in result["vulnerabilities"]
                if str(v.get("product", "")).lower() == "php"]
    assert php_cves == [], f"PHP 5.2.4 must not match modern-branch CVEs: {php_cves}"


@pytest.mark.asyncio
async def test_header_disclosed_version_maps_a_real_cve():
    """The header→CVE pipeline still fires on a version that GENUINELY matches a
    curated CVE (PHP 8.1.20 is inside CVE-2024-4577's 8.1.x branch window), with
    honest header provenance stamped — proving the FP fix did not sever the wiring.
    """
    async def fake_fetch(url):
        return {"X-Powered-By": "PHP/8.1.20"}

    result = await scan_web_tech(["http://10.0.0.7/"], header_fetcher=fake_fetch)
    cves = result["vulnerabilities"]
    assert cves, "expected a real CVE for in-window PHP 8.1.20"
    assert all(v.get("detection_source") == "http_response_header" for v in cves)
    assert all(str(v.get("product", "")).lower() == "php" for v in cves)
    assert any(str(v.get("cve") or v.get("cve_id") or "").startswith("CVE-")
               for v in cves)


@pytest.mark.asyncio
async def test_inventory_hosts_carry_components_but_no_ports():
    async def fake_fetch(url):
        return {"X-Powered-By": "PHP/5.2.4"}

    result = await scan_web_tech(["http://10.0.0.5/"], header_fetcher=fake_fetch)
    hosts = result["hosts"]
    assert hosts and hosts[0]["ip"] == "10.0.0.5"
    # Inventory hosts carry web_components only — NO synthetic port rows (those
    # would collide with the real nmap-proven inventory / re-map via _cve_map).
    assert hosts[0].get("web_components")
    assert "open_ports" not in hosts[0]


@pytest.mark.asyncio
async def test_current_php_not_flagged_eol():
    async def fake_fetch(url):
        return {"X-Powered-By": "PHP/8.3.10"}  # supported at time of writing

    result = await scan_web_tech(["http://10.0.0.6/"], header_fetcher=fake_fetch)
    assert not any(f.get("vuln_type") == "unsupported_software"
                   for f in result["findings"]), "current PHP must not be EOL"


@pytest.mark.asyncio
async def test_no_headers_no_findings():
    async def fake_fetch(url):
        return None

    result = await scan_web_tech(["http://10.0.0.7/"], header_fetcher=fake_fetch)
    assert result["total"] == 0
    assert result["findings"] == [] and result["vulnerabilities"] == []
