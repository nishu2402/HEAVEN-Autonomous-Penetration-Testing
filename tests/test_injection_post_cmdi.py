"""Regression: OS command injection through a **POST** form must be detected.

DVWA's Command Injection page (``/vulnerabilities/exec/``) — like most real
command-injection sinks — is a ``method="post"`` form whose ``ip`` field is
passed straight to ``shell_exec("ping -c 4 " + ip)``. A live authenticated scan
of DVWA confirmed HEAVEN detects it, but the *default* test gate had no case
exercising the POST path: the Docker-free native benchmark modelled the exec
endpoint as GET, so a regression in POST-form command-injection handling could
have shipped green. (The native benchmark now models it as POST too; these
pure-unit tests additionally pin the path without needing flask/bs4.)

Two independent guarantees:

1. :func:`build_injection_targets` turns the crawler's POST ``input_vectors``
   for the exec form into a ``forms_by_url`` entry carrying the ``ip`` field, and
   registers the action as a scan target — the wiring that hands the scanner a
   POST form to fuzz.
2. :class:`InjectionScanner` confirms the injection over POST via the ``uid=``
   output signal (never on a benign baseline — the reflection-safe check), and
   attributes it to the ``ip`` parameter with ``method == "POST"``.
"""

from __future__ import annotations

import re

import pytest

from heaven.vulnscan import injection_scanner
from heaven.vulnscan.injection_scanner import (
    build_injection_targets,
    scan_for_injections,
)

pytestmark = pytest.mark.skipif(
    injection_scanner.aiohttp is None, reason="aiohttp not installed"
)

EXEC_URL = "http://target.test/vulnerabilities/exec/"

# Crawler-style endpoints: the exec page exposes a POST form with ip + Submit
# (exactly what web_crawler emits for ``<form method="post">``).
_EXEC_ENDPOINTS = [
    {
        "url": EXEC_URL,
        "input_vectors": [
            {"type": "form_input", "url": EXEC_URL, "method": "POST", "param": "ip"},
            {"type": "form_input", "url": EXEC_URL, "method": "POST", "param": "Submit"},
        ],
    }
]

# The shell-metacharacter shapes the id-probes use to chain `id`.
_ID_CHAIN = re.compile(r"[;|&`]\s*id\b|\$\(\s*id\s*\)")


def test_build_injection_targets_extracts_post_exec_form():
    """The crawler's POST vectors for exec become a fuzzable POST form."""
    urls, forms_by_url = build_injection_targets(_EXEC_ENDPOINTS, seed_urls=[])

    assert EXEC_URL in forms_by_url, "exec action missing from forms_by_url"
    forms = forms_by_url[EXEC_URL]
    fields = {fl["name"] for f in forms for fl in f["fields"]}
    assert "ip" in fields, "the injectable 'ip' field was not extracted"
    assert all(f["method"] == "POST" for f in forms)
    # Every POST-form action must also be a scan target, or _scan_url never
    # receives the form to test.
    assert EXEC_URL in urls


def _fake_exec_transport(monkeypatch):
    """Patch the scanner's HTTP helpers to emulate DVWA's exec-low endpoint:
    ``shell_exec("ping -c 4 " + ip)`` — a chained ``id`` runs and prints uid=…,
    anything else just pings. GETs return a benign page (no command sink)."""

    async def fake_post(session, url, data, headers=None, timeout=8.0):
        ip = str((data or {}).get("ip", ""))
        out = "PING 127.0.0.1: 4 packets transmitted, 4 received"
        if _ID_CHAIN.search(ip):  # the injected `;id` (etc.) actually executes
            out += "\nuid=33(www-data) gid=33(www-data) groups=33(www-data)"
        return 200, f"<html><body><pre>{out}</pre></body></html>"

    async def fake_get(session, url, headers=None, timeout=8.0):
        return 200, "<html><body>benign</body></html>"

    monkeypatch.setattr(injection_scanner, "_post", fake_post)
    monkeypatch.setattr(injection_scanner, "_get", fake_get)


def test_post_command_injection_is_detected(monkeypatch):
    """A POST cmdi sink is confirmed via the uid= signal and attributed to ip."""
    _fake_exec_transport(monkeypatch)

    urls, forms_by_url = build_injection_targets(_EXEC_ENDPOINTS, seed_urls=[])
    res = _run(scan_for_injections(urls, forms_by_url=forms_by_url))

    cmdi = [f for f in res["findings"] if f["vuln_type"] == "cmdi"]
    assert cmdi, f"POST command injection was not detected: {res['findings']}"
    ev = cmdi[0]["evidence"]
    assert ev["param"] == "ip"
    assert ev["method"] == "POST"
    assert cmdi[0]["cwe"] == "CWE-78"


def test_benign_post_form_yields_no_cmdi(monkeypatch):
    """A POST form whose field never reaches a shell must NOT be flagged — the
    uid= signal only fires on genuine execution, never on the benign baseline."""

    async def fake_post(session, url, data, headers=None, timeout=8.0):
        # No command sink: the value is echoed but never executed.
        return 200, f"<html><body>You searched for {(data or {}).get('q','')}</body></html>"

    async def fake_get(session, url, headers=None, timeout=8.0):
        return 200, "<html><body>benign</body></html>"

    monkeypatch.setattr(injection_scanner, "_post", fake_post)
    monkeypatch.setattr(injection_scanner, "_get", fake_get)

    endpoints = [{
        "url": "http://target.test/search",
        "input_vectors": [
            {"type": "form_input", "url": "http://target.test/search",
             "method": "POST", "param": "q"},
        ],
    }]
    urls, forms_by_url = build_injection_targets(endpoints, seed_urls=[])
    res = _run(scan_for_injections(urls, forms_by_url=forms_by_url))

    assert not [f for f in res["findings"] if f["vuln_type"] == "cmdi"], (
        "benign POST form false-positived as command injection"
    )


def _run(coro):
    import asyncio

    return asyncio.run(coro)
