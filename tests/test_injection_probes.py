"""Deterministic tests for the LFI / RFI / command-injection probes added to the
injection scanner. A fake 'vulnerable server' (monkeypatched _get) returns the
tell-tale responses, so detection is proven without needing a live target.
(End-to-end detection was also confirmed live against DVWA.)"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from heaven.vulnscan import injection_scanner as ij


# ── Detection-pattern unit checks ──

def test_lfi_patterns_match_passwd_and_winini():
    assert ij._inclusion_hit("root:x:0:0:root:/root:/bin/bash")          # /etc/passwd
    assert ij._inclusion_hit("[extensions]\nfoo=bar")                    # win.ini
    assert ij._inclusion_hit("PD9waHAgZWNobyAx")                         # base64('<?php')
    assert not ij._inclusion_hit("<html>nothing here</html>")


def test_cmdi_patterns_match_id_output():
    assert any(p.search("uid=33(www-data) gid=33(www-data)") for p in ij.CMDI_PATTERNS)
    assert any(p.search("...h3av3n7x7...") for p in ij.CMDI_PATTERNS)
    assert not any(p.search("<html>nothing</html>") for p in ij.CMDI_PATTERNS)


# ── Full-probe detection against a fake vulnerable server ──

def _injected_value(url: str) -> str:
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    return " ".join(v for vals in qs.values() for v in vals)


@pytest.mark.asyncio
async def test_lfi_detected_on_passwd_leak(monkeypatch):
    async def fake_get(session, url, headers=None, timeout=8.0):
        val = _injected_value(url)                    # decoded param value
        if "etc/passwd" in val:                       # traversal payload reached file
            return 200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin"
        return 200, "<html>welcome</html>"

    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_inclusion_param(object(), "http://t/index.php?page=home", "page",
                                   baseline_body="<html>welcome</html>")
    assert any(f["vuln_type"] == "lfi" for f in sc._findings), "LFI must be detected on passwd leak"


@pytest.mark.asyncio
async def test_cmdi_detected_on_id_output(monkeypatch):
    async def fake_get(session, url, headers=None, timeout=8.0):
        val = _injected_value(url)
        # "vulnerable": a shell metachar + id returns command output
        if "id" in val and any(c in val for c in ";|&`$"):
            return 200, "PING 127.0.0.1 ...\nuid=33(www-data) gid=33(www-data) groups=33"
        return 200, "<html>pinged</html>"

    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_cmdi_param(object(), "http://t/ping.php?ip=127.0.0.1", "ip",
                              baseline_body="<html>pinged</html>")
    assert any(f["vuln_type"] == "cmdi" for f in sc._findings), "CmdI must be detected on id output"


@pytest.mark.asyncio
async def test_cmdi_detected_on_real_echo_execution(monkeypatch):
    """A genuine echo execution emits the (unique) marker as standalone output."""
    import re as _re

    async def fake_get(session, url, headers=None, timeout=8.0):
        val = _injected_value(url)
        m = _re.search(r"echo\s+(h3av3n7x7\w+)", val)
        if m and any(c in val for c in ";&"):        # executed → output is the bare marker
            return 200, f"<pre>PING ok\n{m.group(1)}</pre>"
        return 200, "<pre>PING ok</pre>"

    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_cmdi_param(object(), "http://t/ping.php?ip=1", "ip",
                              baseline_body="<pre>PING ok</pre>")
    assert any(f["vuln_type"] == "cmdi" for f in sc._findings), \
        "genuine echo-marker execution must still be detected"


@pytest.mark.asyncio
async def test_cmdi_not_flagged_on_log_reflecting_other_markers(monkeypatch):
    """A log/aggregation page echoing a DIFFERENT request's echo payload must NOT
    be flagged as command injection — the live DVWA ids_log.php false positive.
    A unique per-request marker means another request's marker can't match."""
    other = ij._CMDI_MARK + "deadbeef"               # a marker from some other request

    async def fake_get(session, url, headers=None, timeout=8.0):
        # The page shows a log containing another request's echo payload verbatim,
        # but nothing is ever executed.
        return 200, f"<pre>IDS log: 127.0.0.1 ; echo {other} | & echo {other}</pre>"

    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_cmdi_param(object(), "http://t/ids_log.php?clear_log=1", "clear_log",
                              baseline_body="<pre>IDS log:</pre>")
    assert not any(f["vuln_type"] == "cmdi" for f in sc._findings), \
        "must not flag cmdi when the page only reflects another request's marker"


@pytest.mark.asyncio
async def test_clean_endpoint_yields_no_injection(monkeypatch):
    async def fake_get(session, url, headers=None, timeout=8.0):
        return 200, "<html>perfectly safe, nothing reflected</html>"

    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_inclusion_param(object(), "http://t/x?p=1", "p", "<html>perfectly safe</html>")
    await sc._test_cmdi_param(object(), "http://t/x?p=1", "p", "<html>perfectly safe</html>")
    assert sc._findings == [], "a safe endpoint must produce no false positives"
