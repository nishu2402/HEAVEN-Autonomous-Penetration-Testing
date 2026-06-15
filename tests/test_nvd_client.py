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
