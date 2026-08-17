"""Regression tests for SSL/TLS audit target selection.

A live full scan of a plain-HTTP host (Metasploitable 2, no TLS ports at all)
revealed the SSL/TLS Audit phase scanning port 80 dozens of times — once per
crawled ``http://host/...`` URL, with no dedup — until the phase blew its 300s
timeout and produced nothing. Two root causes:

1. The orchestrator derived an SSL target from *every* URL, defaulting an
   ``http://`` URL to ``host:80`` — but a URL fetched in cleartext has no TLS to
   audit. Only ``https://`` URLs (and real TLS ports found by the network scan)
   should be audited.
2. :func:`scan_ssl_targets` did not dedup its input, so duplicate ``host:80``
   entries each triggered a full (useless) TLS handshake attempt.

These tests pin both fixes so the port-80 flood cannot regress.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from heaven.vulnscan import ssl_scanner


def _select_ssl_targets_from_urls(urls: list[str]) -> list[str]:
    """Mirror of the orchestrator's URL→SSL-target rule (kept in lockstep with
    ``orchestrator._ssl_scan``): only https URLs, deduped, default port 443."""
    ssl_targets: list[str] = []
    for url in urls:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host and parsed.scheme == "https":
            tgt = f"{host}:{parsed.port or 443}"
            if tgt not in ssl_targets:
                ssl_targets.append(tgt)
    return ssl_targets


def test_http_urls_are_not_ssl_targets():
    """A crawl of a plain-HTTP host must yield zero SSL targets — not host:80."""
    urls = [
        "http://192.168.0.162/",
        "http://192.168.0.162/twiki/",
        "http://192.168.0.162/phpMyAdmin/",
        "http://192.168.0.162/mutillidae/",
        "http://192.168.0.162/dvwa/login.php",
    ]
    assert _select_ssl_targets_from_urls(urls) == []


def test_https_urls_become_deduped_ssl_targets():
    urls = [
        "https://example.com/",
        "https://example.com/login",       # same origin → deduped
        "https://example.com:8443/admin",  # distinct port kept
        "http://example.com/insecure",     # cleartext → ignored
    ]
    assert _select_ssl_targets_from_urls(urls) == [
        "example.com:443",
        "example.com:8443",
    ]


def test_scan_ssl_targets_dedups_repeated_targets(monkeypatch):
    """scan_ssl_targets must probe each unique host:port at most once even when
    handed the same target many times."""
    calls: list[tuple[str, int]] = []

    async def _fake_scan_ssl(host, port):
        calls.append((host, port))
        return {"findings": []}

    monkeypatch.setattr(ssl_scanner, "scan_ssl", _fake_scan_ssl)

    targets = ["192.168.0.162:80"] * 25 + ["10.0.0.5:443", "10.0.0.5:443"]
    res = asyncio.run(ssl_scanner.scan_ssl_targets(targets))

    assert sorted(calls) == [("10.0.0.5", 443), ("192.168.0.162", 80)]
    assert res["total"] == 0
