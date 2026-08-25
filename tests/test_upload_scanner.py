"""Regression tests for the unrestricted file-upload probe (heaven/vulnscan/
upload_scanner.py). All mocked — no live server.

Pins:
  * file-upload forms are extracted from crawler input vectors, MAX_FILE_SIZE
    gets headroom (a "1" placeholder would make PHP reject the probe);
  * the probe requires authorization (it writes a file);
  * an accepted + executed dangerous-extension upload is a critical finding, a
    blocked upload yields nothing.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan.upload_scanner import (
    _stored_url,
    _upload_forms,
    scan_upload_forms,
)


# ── pure helpers ─────────────────────────────────────────────────────────────
def _endpoints():
    url = "http://t/vulnerabilities/upload/"
    return [{
        "url": url,
        "input_vectors": [
            {"url": url, "method": "POST", "param": "MAX_FILE_SIZE", "input_type": "hidden"},
            {"url": url, "method": "POST", "param": "uploaded", "input_type": "file"},
            {"url": url, "method": "POST", "param": "Upload", "input_type": "submit"},
        ],
    }]


def test_upload_forms_extracts_file_field_and_sizes_max_file_size():
    forms = _upload_forms(_endpoints())
    assert len(forms) == 1
    f = forms[0]
    assert f["file_param"] == "uploaded"
    # MAX_FILE_SIZE must not be the "1" placeholder or PHP rejects the upload
    assert int(f["others"]["MAX_FILE_SIZE"]) >= 1_000_000
    assert "Upload" in f["others"]


def test_upload_forms_ignores_forms_without_a_file_input():
    eps = [{"url": "http://t/x", "input_vectors": [
        {"url": "http://t/x", "method": "POST", "param": "q", "input_type": "text"}]}]
    assert _upload_forms(eps) == []


def test_stored_url_resolves_dvwa_relative_path():
    body = "../../hackable/uploads/heaven_probe_ab12.php succesfully uploaded!"
    got = _stored_url("http://t/vulnerabilities/upload/", body, "heaven_probe_ab12.php")
    assert got == "http://t/hackable/uploads/heaven_probe_ab12.php"


# ── authorization gate ───────────────────────────────────────────────────────
def test_probe_requires_authorization():
    res = asyncio.run(scan_upload_forms(_endpoints(), authorized=False))
    assert res.get("skipped") and "authoriz" in res["reason"].lower()


# ── end-to-end with a fake session ───────────────────────────────────────────
class _Resp:
    def __init__(self, text=""):
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return self._text

    status = 200


class _Session:
    """Fake aiohttp session usable as `async with`. Accepts (or blocks) the
    upload, then serves the stored file back — executed (PHP wrapper stripped)
    or verbatim — echoing whatever marker the POST embedded."""

    def __init__(self, accept=True, executed=True):
        self.accept, self.executed, self._marker = accept, executed, ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, url, data=None, timeout=None):
        name = "probe.php"
        for opt, _hdrs, val in getattr(data, "_fields", []):
            if opt.get("name") == "uploaded":
                name = opt.get("filename", name)
                self._marker = val.split('"')[1] if '"' in val else ""
        if not self.accept:
            return _Resp("Your image was not uploaded. Extension not allowed.")
        return _Resp(f"../../hackable/uploads/{name} succesfully uploaded!")

    def get(self, url, timeout=None):
        body = self._marker if self.executed else f'<?php echo "{self._marker}"; ?>'
        return _Resp(body)


def _patch_session(monkeypatch, sess):
    import heaven.vulnscan.upload_scanner as us
    monkeypatch.setattr(us.aiohttp, "ClientSession", lambda *a, **k: sess)
    monkeypatch.setattr(us, "aiohttp_session_kwargs", lambda: {})


@pytest.mark.asyncio
async def test_accepted_and_executed_upload_is_critical(monkeypatch):
    _patch_session(monkeypatch, _Session(accept=True, executed=True))
    res = await scan_upload_forms(_endpoints(), authorized=True)
    findings = res.get("findings", [])
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"] == "file_upload" and f["severity"] == "critical"
    assert f["evidence"]["executed"] is True
    assert f["cwe"] == "CWE-434"


@pytest.mark.asyncio
async def test_stored_but_not_executed_is_high(monkeypatch):
    _patch_session(monkeypatch, _Session(accept=True, executed=False))
    res = await scan_upload_forms(_endpoints(), authorized=True)
    f = res["findings"][0]
    assert f["severity"] == "high" and f["evidence"]["stored"] is True
    assert f["evidence"]["executed"] is False


@pytest.mark.asyncio
async def test_blocked_upload_yields_no_finding(monkeypatch):
    _patch_session(monkeypatch, _Session(accept=False))
    res = await scan_upload_forms(_endpoints(), authorized=True)
    assert res.get("findings", []) == []
