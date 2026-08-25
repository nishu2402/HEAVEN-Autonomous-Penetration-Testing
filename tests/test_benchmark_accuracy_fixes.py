"""Regression tests for the DVWA-benchmark accuracy fixes.

Each pins a real false-positive or under-count that the live benchmark surfaced:
  * anomaly path-traversal no longer fires on the bare word "localhost";
  * dir-fuzzer does not flag the front door / standard public files;
  * two findings that differ only by their evidence parameter get distinct ids
    (so multi-parameter XSS/SQLi on one endpoint no longer collapses);
  * cookie-flag and technology-disclosure findings dedup per host.
"""
from __future__ import annotations

import asyncio

import pytest


# ── anomaly path-traversal: structural signal required, not a bare word ──────
class _Resp:
    def __init__(self, text):
        self._text = text
        self.status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return self._text


class _Sess:
    def __init__(self, body):
        self._body = body

    def request(self, method, url, **kw):
        return _Resp(self._body)


def _run_traversal(body: str):
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe
    probe = WebAnomalyProbe(timeout=5.0)
    return asyncio.run(probe._test_path_traversal(_Sess(body), "http://t/p", "file", "GET"))


def test_path_traversal_ignores_bare_localhost():
    # A README / instructions page that merely contains the word "localhost"
    # is NOT a file read — the old indicator list fired here (16 FPs on DVWA).
    assert _run_traversal("Run DVWA on localhost. See the docs. /bin/sh notes.") is None


def test_path_traversal_fires_on_real_passwd():
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    r = _run_traversal(body)
    assert r is not None and r.category == "path_traversal"


def test_path_traversal_fires_on_windows_hosts():
    body = "# Copyright (c) Microsoft Corp.\n127.0.0.1       localhost\n::1  localhost\n"
    r = _run_traversal(body)
    assert r is not None


# ── dir-fuzzer: the front door and standard public files are not findings ────
@pytest.mark.parametrize("path", [
    "/", "/index.php", "/login.php", "/robots.txt", "/security.txt",
    "/.well-known/security.txt", "/favicon.ico", "/sitemap.xml",
])
def test_benign_public_paths_recognised(path):
    from heaven.vulnscan.dir_fuzzer import _is_benign_public_path
    assert _is_benign_public_path(path) is True


@pytest.mark.parametrize("path", [
    "/.git/config", "/.env", "/admin/", "/backup.sql", "/phpinfo.php",
    "/config/config.inc.php.dist",
])
def test_sensitive_paths_are_not_benign(path):
    from heaven.vulnscan.dir_fuzzer import _is_benign_public_path
    assert _is_benign_public_path(path) is False


# ── finding identity: parameter read from evidence, so params don't collapse ─
def test_param_from_evidence_disambiguates_findings(tmp_path):
    from heaven.engagement import EngagementStore
    store = EngagementStore(tmp_path / "e.db")
    store.create_engagement("e")
    base = {
        "target": "http://t/vulnerabilities/xss_s/", "vuln_type": "xss",
        "title": "Reflected XSS", "severity": "high",
    }
    id_name = store.upsert_finding("s1", {**base, "evidence": {"param": "txtName"}})
    id_msg = store.upsert_finding("s1", {**base, "evidence": {"param": "mtxMessage"}})
    assert id_name != id_msg               # distinct params → distinct rows
    assert len(store.list_findings(limit=50)) == 2


def test_same_param_still_dedups(tmp_path):
    from heaven.engagement import EngagementStore
    store = EngagementStore(tmp_path / "e.db")
    store.create_engagement("e")
    f = {"target": "http://t/x", "vuln_type": "xss", "title": "x",
         "severity": "high", "evidence": {"param": "q"}}
    a = store.upsert_finding("s1", dict(f))
    b = store.upsert_finding("s1", dict(f))
    assert a == b and len(store.list_findings(limit=50)) == 1


# ── host-level dedup: cookie flags + technology disclosure ───────────────────
@pytest.mark.parametrize("vt", [
    "cookie_no_secure", "cookie_no_samesite", "technology_disclosure",
    "server_version_disclosure",
])
def test_cookie_and_tech_disclosure_are_host_level(vt):
    from heaven.engagement import is_host_level
    assert is_host_level(vt) is True


def test_endpoint_info_disclosure_is_not_host_level():
    # A stack trace / data leak on ONE endpoint must stay per-URL.
    from heaven.engagement import is_host_level
    assert is_host_level("info_disclosure") is False
