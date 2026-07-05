"""Native, Docker-free recall test for HEAVEN's web injection pipeline.

Runs the REAL crawler and the REAL injection scanner against a native, in-process
vulnerable app (tests/benchmarks/native/vuln_app.py) that faithfully reproduces
DVWA's SQLi behaviour — including MySQL's comment rules. This is the fast,
deterministic substitute for the emulated-Docker DVWA benchmark, and it pins two
things that a live-only test could not iterate on:

  1. **Param attribution** — the SQLi hit lands on ``id`` (the injectable field),
     not the ``Submit`` button that shares the form.
  2. **MySQL comment semantics** — the boolean oracle only fires because the
     payloads terminate with ``-- `` / ``#``. A regression back to a bare ``--``
     would break the oracle here, exactly as it did against real DVWA.

Plus a precision guard: pages that merely reflect input (``xss_r`` unescaped,
``xss_d`` escaped) must NOT be reported as SQLi.

The pure ``build_injection_targets`` unit test needs no network and always runs;
the end-to-end test skips cleanly if flask / bs4 / aiohttp are unavailable.
"""

from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan.injection_scanner import build_injection_targets


# ── Pure unit: the crawler-vector → scan-target conversion ─────────────────

def test_build_injection_targets_combines_get_form_params():
    """A DVWA-style GET form (id + Submit) becomes ONE URL carrying both params.

    This is what lets the scanner fuzz ``id`` at all: a per-field URL that
    dropped ``Submit`` (or only tested the submit button) would never reach the
    vulnerable query.
    """
    endpoints = [
        {
            "url": "http://t/vulnerabilities/sqli/",
            "input_vectors": [
                {"type": "form_input", "url": "http://t/vulnerabilities/sqli/#",
                 "method": "GET", "param": "id"},
                {"type": "form_input", "url": "http://t/vulnerabilities/sqli/#",
                 "method": "GET", "param": "Submit"},
            ],
        }
    ]
    urls, forms_by_url = build_injection_targets(endpoints, seed_urls=[])

    combined = [u for u in urls if "/vulnerabilities/sqli/" in u and "?" in u]
    assert len(combined) == 1, urls
    assert "id=" in combined[0] and "Submit=" in combined[0]
    assert forms_by_url == {}  # GET form → no POST forms


def test_build_injection_targets_post_form_becomes_form_dict():
    endpoints = [
        {
            "url": "http://t/login",
            "input_vectors": [
                {"type": "form_input", "url": "http://t/login",
                 "method": "POST", "param": "user"},
                {"type": "form_input", "url": "http://t/login",
                 "method": "POST", "param": "pass"},
            ],
        }
    ]
    urls, forms_by_url = build_injection_targets(endpoints)
    assert "http://t/login" in urls
    form = forms_by_url["http://t/login"][0]
    assert form["method"] == "POST"
    assert {f["name"] for f in form["fields"]} == {"user", "pass"}


# ── End-to-end: crawl + scan a live native target ──────────────────────────

def _find(findings: list[dict], vuln_type: str, endpoint: str) -> list[dict]:
    return [
        f for f in findings
        if f.get("vuln_type") == vuln_type and endpoint in (f.get("target") or "")
    ]


def _param_of(finding: dict) -> str:
    return (finding.get("evidence") or {}).get("param", "")


def test_native_end_to_end_recall():
    pytest.importorskip("flask")
    pytest.importorskip("bs4")
    pytest.importorskip("aiohttp")

    from heaven.recon.web_crawler import crawl_targets
    from heaven.vulnscan.injection_scanner import scan_for_injections

    from tests.benchmarks.native.vuln_app import serve

    async def _drive(base_url: str) -> dict:
        crawl = await crawl_targets([base_url], stealth_level="aggressive")
        endpoints = crawl.get("endpoints", [])
        urls, forms_by_url = build_injection_targets(endpoints, seed_urls=[base_url])
        # The combined SQLi URL must carry both id and Submit (see unit test).
        sqli_urls = [u for u in urls if "/vulnerabilities/sqli/" in u and "id=" in u]
        assert sqli_urls, f"crawler/targets missed the sqli form: {urls}"
        return await scan_for_injections(urls, forms_by_url=forms_by_url,
                                         stealth_level="aggressive")

    with serve() as base_url:
        result = asyncio.run(_drive(base_url))

    findings = result.get("findings", [])

    # 1. SQLi is detected on the sqli endpoint AND attributed to `id`, not Submit.
    sqli_hits = _find(findings, "sqli", "/vulnerabilities/sqli/")
    assert sqli_hits, f"no SQLi detected on sqli endpoint; findings={findings}"
    assert any(_param_of(f) == "id" for f in sqli_hits), (
        f"SQLi not attributed to `id` param: "
        f"{[_param_of(f) for f in sqli_hits]}"
    )
    # ...and the UNION-based technique fires on it (marker exfiltrated via a
    # rendered row), attributed to `id`.
    assert any(
        _param_of(f) == "id"
        and (f.get("evidence") or {}).get("technique") == "union"
        for f in sqli_hits
    ), "UNION-based SQLi not detected on `id`"

    # 2. BLIND SQLi (errors suppressed, nothing reflected) is detected on
    #    sqli_blind and attributed to `id`. This can ONLY be found via the
    #    boolean oracle, which relies on MySQL-correct "-- "/"#" comment payloads
    #    — so a regression to a bare "--" terminator would fail right here.
    blind_hits = _find(findings, "sqli", "/vulnerabilities/sqli_blind/")
    assert blind_hits, f"blind SQLi not detected (comment-style regression?); {findings}"
    assert any(_param_of(f) == "id" for f in blind_hits), (
        f"blind SQLi not attributed to `id`: {[_param_of(f) for f in blind_hits]}"
    )
    assert any(
        (f.get("evidence") or {}).get("technique") == "boolean_blind"
        for f in blind_hits
    ), "blind SQLi hit was not via the boolean oracle"

    # 3. Reflected XSS is detected on xss_r.
    assert _find(findings, "xss", "/vulnerabilities/xss_r/"), (
        f"no reflected XSS detected; findings={findings}"
    )

    # 4. Local File Inclusion is detected on fi and attributed to `page`
    #    (content-based: the leaked /etc/passwd trips the LFI patterns).
    lfi_hits = _find(findings, "lfi", "/vulnerabilities/fi/")
    assert lfi_hits, f"no LFI detected on fi endpoint; findings={findings}"
    assert any(_param_of(f) == "page" for f in lfi_hits), (
        f"LFI not attributed to `page`: {[_param_of(f) for f in lfi_hits]}"
    )

    # 5. OS Command Injection is detected on exec and attributed to `ip`
    #    (output-based: the injected `id` / echo marker executes).
    cmdi_hits = _find(findings, "cmdi", "/vulnerabilities/exec/")
    assert cmdi_hits, f"no command injection detected on exec; findings={findings}"
    assert any(_param_of(f) == "ip" for f in cmdi_hits), (
        f"cmdi not attributed to `ip`: {[_param_of(f) for f in cmdi_hits]}"
    )

    # 6. Precision guard: no SQLi false positives on reflective/non-injectable
    #    endpoints — the unescaped echo, the HTML-escaped echo, or the LFI
    #    "not found" (also HTML-escaped) page.
    assert not _find(findings, "sqli", "/vulnerabilities/xss_r/"), "SQLi FP on xss_r"
    assert not _find(findings, "sqli", "/vulnerabilities/xss_d/"), "SQLi FP on xss_d"
    assert not _find(findings, "sqli", "/vulnerabilities/fi/"), "SQLi FP on fi"

    # 7. Precision guard: no command-injection false positives from mere
    #    reflection — an endpoint that echoes the `; echo <marker>` payload back
    #    (escaped or not) must not be reported as cmdi (the marker only counts as
    #    real command OUTPUT, see _test_cmdi_param's reflection strip).
    assert not _find(findings, "cmdi", "/vulnerabilities/xss_r/"), "cmdi FP on xss_r"
    assert not _find(findings, "cmdi", "/vulnerabilities/xss_d/"), "cmdi FP on xss_d"
    assert not _find(findings, "cmdi", "/vulnerabilities/fi/"), "cmdi FP on fi"
