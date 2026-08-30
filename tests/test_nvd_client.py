"""Tests for the NVD v2 client — the CVE-enrichment fix.

Regression guard for the bug where NVD lookups returned zero results: the client
queried ``cpeName`` (which 404s on the wildcard CPEs HEAVEN generates) instead of
``virtualMatchString``, and a *rejected API key* (NVD answers 404, not 401) looked
identical to "no vulnerabilities found". These tests run fully offline via a fake
httpx client.
"""

from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan.nvd_client import NVDClient, _normalize_cpe


class _FakeResp:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    """Records the params of the last GET and returns a queued response."""

    def __init__(self, resp: _FakeResp):
        self.resp = resp
        self.last_params: dict = {}

    async def get(self, url, params=None, **kw):
        self.last_params = params or {}
        return self.resp

    async def aclose(self):
        pass


# ── _normalize_cpe ──────────────────────────────────────────────────

def test_normalize_cpe_22_to_23():
    # nmap emits CPE 2.2; NVD only understands 2.3
    assert (_normalize_cpe("cpe:/a:openbsd:openssh:8.2p1")
            == "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*")


def test_normalize_cpe_23_passthrough():
    cpe = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
    assert _normalize_cpe(cpe) == cpe


def test_normalize_cpe_pads_and_blanks_to_wildcard():
    # missing trailing fields and "-" placeholders become "*"
    out = _normalize_cpe("cpe:/a:nginx:nginx")
    assert out == "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"


# ── search_by_cpe uses virtualMatchString (not cpeName) ─────────────

def test_search_uses_virtual_match_string():
    client = NVDClient()
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-41773",
        "descriptions": [{"lang": "en", "value": "Apache path traversal"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8,
                    "vectorString": "AV:N"}, "baseSeverity": "CRITICAL"}]},
        "weaknesses": [{"description": [{"value": "CWE-22"}]}],
    }}]}
    fake = _FakeClient(_FakeResp(200, payload))
    client._client = fake  # inject

    recs = asyncio.run(client.search_by_cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"))

    assert "virtualMatchString" in fake.last_params
    assert "cpeName" not in fake.last_params
    assert len(recs) == 1
    assert recs[0].cve_id == "CVE-2021-41773"
    assert recs[0].cvss_base == 9.8
    assert recs[0].severity == "critical"


def test_version_bounded_distinguishes_rangeless_from_bounded():
    """A rangeless ``versionEndExcluding`` (no floor) must NOT be marked
    version_bounded for an ancient build, while an exact-version or lower-bounded
    node must. This is the ProFTPD-1.3.1 case: NVD's server-side match returns a
    <1.3.10 mod_sftp CVE for 1.3.1 (mod_sftp did not exist in 1.3.1), alongside a
    genuinely-applicable CVE that enumerates 1.3.1 explicitly.
    """
    payload = {"vulnerabilities": [
        {"cve": {  # rangeless: <1.3.10, no start bound -> POTENTIAL, not confirmed
            "id": "CVE-2026-53994",
            "descriptions": [{"lang": "en", "value": "ProFTPD mod_sftp heap overflow"}],
            "metrics": {}, "weaknesses": [],
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "1.3.10"}]}]}],
        }},
        {"cve": {  # exact-version applicability of 1.3.1 -> CONFIRMED
            "id": "CVE-2011-4130",
            "descriptions": [{"lang": "en", "value": "ProFTPD response pool UAF"}],
            "metrics": {}, "weaknesses": [],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*",
                 "versionEndIncluding": "1.3.3"},
                {"criteria": "cpe:2.3:a:proftpd:proftpd:1.3.1:*:*:*:*:*:*:*"}]}]}],
        }},
        {"cve": {  # bounded window that 1.3.1 satisfies -> CONFIRMED
            "id": "CVE-2099-0001",
            "descriptions": [{"lang": "en", "value": "bounded window"}],
            "metrics": {}, "weaknesses": [],
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.3.0", "versionEndExcluding": "1.3.5"}]}]}],
        }},
    ]}
    client = NVDClient()
    client._client = _FakeClient(_FakeResp(200, payload))
    recs = asyncio.run(client.search_by_cpe(
        "cpe:2.3:a:proftpd:proftpd:1.3.1:*:*:*:*:*:*:*"))
    bounded = {r.cve_id: r.version_bounded for r in recs}
    assert bounded["CVE-2026-53994"] is False   # rangeless -> potential
    assert bounded["CVE-2011-4130"] is True      # exact 1.3.1 -> confirmed
    assert bounded["CVE-2099-0001"] is True      # lower-bounded window -> confirmed


def test_version_bounded_false_when_no_version_queried():
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-41773",
        "descriptions": [{"lang": "en", "value": "x"}], "metrics": {}, "weaknesses": [],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "criteria": "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.0.0", "versionEndExcluding": "9.9"}]}]}],
    }}]}
    client = NVDClient()
    client._client = _FakeClient(_FakeResp(200, payload))
    # wildcard version in the query -> cannot confirm any version
    recs = asyncio.run(client.search_by_cpe(
        "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*"))
    assert recs[0].version_bounded is False


def test_search_404_with_key_flags_invalid_key():
    client = NVDClient()
    client.api_key = "bad-key"
    client._client = _FakeClient(_FakeResp(404))

    recs = asyncio.run(client.search_by_cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"))
    assert recs == []
    assert client._warned_invalid_key is True


# ── test_connectivity diagnoses key state ───────────────────────────

def test_connectivity_ok_no_key():
    client = NVDClient()
    client.api_key = ""
    client._client = _FakeClient(_FakeResp(200, {"totalResults": 123}))
    res = asyncio.run(client.test_connectivity())
    assert res["ok"] is True
    assert res["has_key"] is False
    assert res["sample_results"] == 123


def test_connectivity_invalid_key_is_404():
    client = NVDClient()
    client.api_key = "bad-key"
    client._client = _FakeClient(_FakeResp(404))
    res = asyncio.run(client.test_connectivity())
    assert res["ok"] is False
    assert res["has_key"] is True
    assert "rejected" in res["reason"].lower()


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
