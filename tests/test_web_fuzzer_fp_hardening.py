"""Regression tests for the web-fuzzer false-positive fixes proven live on DVWA.

An authenticated DVWA benchmark scan emitted five findings that were genuine
false positives (verified live against ghcr.io/digininja/dvwa): three
``403_bypass_path_manipulation`` reports whose "bypass" merely traversed up to
the site root, one ``hidden_parameter_discovered`` for a parameter already
present in the request, and one ``http_parameter_pollution`` that was just
normal last-value semantics on a working parameter. These tests pin each fix at
the emitter so it cannot silently regress, and each keeps a positive control
proving the detector still fires on the genuine case. Nothing here touches the
network: the HTTP surface is a tiny in-process fake.
"""
from __future__ import annotations

import re
import urllib.parse

import pytest

from heaven.vulnscan.web_fuzzer import (
    _PATH_BYPASS_SUFFIXES,
    _fuzz_403_bypass,
    _fuzz_mail_header_injection,
    _fuzz_parameters,
    _set_query_param,
)


# ── in-process HTTP fake ─────────────────────────────────────────────────────
class _Resp:
    def __init__(self, status: int = 200, body: str = ""):
        self.status = status
        self._body = body
        self.headers: dict = {}
        self.url = ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._body


class _Session:
    """Fake aiohttp session dispatching every GET through a handler(url)->_Resp."""

    def __init__(self, handler):
        self._handler = handler

    def get(self, url, params=None, **kwargs):
        return self._handler(url)


_FORBIDDEN = "<html><h1>403 Forbidden</h1></html>"          # short error page
_INDEX = "<html><body>DVWA login page " + ("x" * 1300) + "</body></html>"
_PROTECTED = "<html><body>SECRET server-status " + ("y" * 1300) + "</body></html>"


# ── 1. 403 bypass: a parent-traversal that lands on the site root is not a bypass
@pytest.mark.asyncio
async def test_403_bypass_rejects_root_page_artifact():
    def handler(url):
        if url == "http://t/secret":
            return _Resp(403, _FORBIDDEN)          # the protected resource
        if url == "http://t/":
            return _Resp(200, _INDEX)              # origin root
        if url.startswith("http://t/secret"):      # any manipulated variant
            return _Resp(200, _INDEX)              # normalizes up to the root
        return _Resp(404, "not found")

    findings = await _fuzz_403_bypass(_Session(handler), "http://t/secret")
    kinds = {f["vuln_type"] for f in findings}
    assert "403_bypass_path_manipulation" not in kinds, (
        "a variant that returns the site root must not be reported as a bypass"
    )


@pytest.mark.asyncio
async def test_403_bypass_reports_genuine_same_resource_access():
    def handler(url):
        if url == "http://t/secret":
            return _Resp(403, _FORBIDDEN)
        if url == "http://t/":
            return _Resp(200, _INDEX)
        if url.startswith("http://t/secret") and url != "http://t/secret":
            return _Resp(200, _PROTECTED)          # real protected content served
        return _Resp(404, "not found")

    findings = await _fuzz_403_bypass(_Session(handler), "http://t/secret")
    kinds = {f["vuln_type"] for f in findings}
    assert "403_bypass_path_manipulation" in kinds, (
        "a variant serving the protected resource is a genuine bypass and must fire"
    )


def test_path_bypass_suffixes_exclude_parent_traversal():
    # Suffixes that inject a parent segment escape the protected resource, so they
    # can never demonstrate a bypass with the ``url + suffix`` construction.
    for suffix in _PATH_BYPASS_SUFFIXES:
        decoded = urllib.parse.unquote(suffix)
        assert ".." not in decoded, f"{suffix!r} escapes to the parent directory"


# ── 2. hidden parameter: a parameter already in the request is not "discovered"
@pytest.mark.asyncio
async def test_hidden_param_skips_already_present_param():
    def handler(url):
        # Only a genuinely-absent param ("debug") reflects the probe; the already
        # present "redirect" would also change behaviour, but must be skipped.
        if "debug=HEAVEN_PROBE" in url:
            return _Resp(200, "<html>" + ("z" * 200) + " HEAVEN_PROBE</html>")
        return _Resp(200, "<html>" + ("z" * 200) + " baseline</html>")

    findings = await _fuzz_parameters(_Session(handler), "http://t/p?redirect=x")
    params = {f["evidence"]["param"] for f in findings
              if f["vuln_type"] == "hidden_parameter_discovered"}
    assert "redirect" not in params, "a param already in the query is not hidden"
    assert "debug" in params, "a genuinely absent, processed param must still fire"


# ── 3. HTTP parameter pollution: needs a real control-vs-polluted desync ──────
@pytest.mark.asyncio
async def test_hpp_no_fp_when_single_and_duplicate_both_reflect():
    def handler(url):
        # DVWA-like: the parameter is functional, so the last value is reflected
        # whether supplied once or twice. Duplication adds nothing → not pollution.
        qvals = [v for k, v in
                 urllib.parse.parse_qsl(urllib.parse.urlparse(url).query) if k == "q"]
        if qvals:
            return _Resp(200, f"<html>{qvals[-1]}</html>")
        return _Resp(200, "<html>base</html>")

    findings = await _fuzz_parameters(_Session(handler), "http://t/s?q=1")
    kinds = {f["vuln_type"] for f in findings}
    assert "http_parameter_pollution" not in kinds, (
        "ordinary last-wins reflection is not parameter pollution"
    )


@pytest.mark.asyncio
async def test_hpp_reports_genuine_last_wins_desync():
    def handler(url):
        # Single value is filtered out; only DUPLICATING it smuggles the value
        # into the response — the signature of first/last-wins pollution.
        qvals = [v for k, v in
                 urllib.parse.parse_qsl(urllib.parse.urlparse(url).query) if k == "q"]
        if len(qvals) >= 2:
            return _Resp(200, f"<html>{qvals[-1]}</html>")   # smuggled through
        return _Resp(200, "<html>filtered</html>")           # single value dropped

    findings = await _fuzz_parameters(_Session(handler), "http://t/s?q=1")
    kinds = {f["vuln_type"] for f in findings}
    assert "http_parameter_pollution" in kinds, (
        "a genuine control-vs-polluted desync must still be reported"
    )


def test_set_query_param_replaces_all_occurrences():
    out = _set_query_param("http://t/s?q=1&q=2&z=9", "q", "TOK")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(out).query)
    assert qs["q"] == ["TOK"], "the control request must carry exactly one value"
    assert qs["z"] == ["9"], "unrelated params are preserved"


# ── 4. mail header injection: the UNIQUE canary is the only valid oracle ──────
@pytest.mark.asyncio
async def test_mail_header_injection_requires_canary_not_bare_bcc():
    # A response header that merely contains "bcc:" for an unrelated reason, with
    # our unique canary ABSENT, means the CRLF split did NOT happen — reporting it
    # would be a high-severity false positive with no proof.
    def handler(url):
        r = _Resp(200, "ok")
        r.headers = {"X-Mail-Config": "bcc: disabled by site policy"}
        return r

    findings = await _fuzz_mail_header_injection(
        _Session(handler), "http://t/contact?email=a")
    assert findings == [], "a bare 'bcc:' header without the canary is not injection"


@pytest.mark.asyncio
async def test_mail_header_injection_fires_when_canary_reflected_into_headers():
    # A vulnerable server honours the CRLF split and our unique canary lands in a
    # response header — the sound oracle, which must still fire.
    def handler(url):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        val = (q.get("email") or [""])[0]
        r = _Resp(200, "ok")
        m = re.search(r"hvn[a-z]{6}@heaven\.invalid", val)
        if m:
            r.headers = {"X-Reflected": f"Bcc:{m.group(0)}"}
        return r

    findings = await _fuzz_mail_header_injection(
        _Session(handler), "http://t/contact?email=a")
    assert any(f["vuln_type"] == "smtp_header_injection" for f in findings), (
        "a canary reflected into the response headers is a genuine injection"
    )


# ── 5. hidden parameter: a length swing within the page's own jitter is not a
#       discovery (the dynamic-page false-positive the second baseline fixes) ──
@pytest.mark.asyncio
async def test_hidden_param_length_jitter_is_not_discovery():
    # A dynamic page whose body length naturally swings ~500 bytes between two
    # identical requests. A probed param that neither reflects the probe nor
    # changes status, and whose length delta stays within that jitter, must NOT be
    # reported — previously a bare >100-byte diff flagged it.
    state = {"base_calls": 0}

    def handler(url):
        if "HEAVEN_PROBE" not in url:                  # a baseline fetch
            state["base_calls"] += 1
            n = 1000 if state["base_calls"] == 1 else 1500   # jitter 500 → thr 1000
            return _Resp(200, "<html>" + ("z" * n) + "</html>")
        # a param probe: +300 bytes vs base_len, within 2x jitter, no reflection
        return _Resp(200, "<html>" + ("z" * 1300) + "</html>")

    findings = await _fuzz_parameters(_Session(handler), "http://t/dyn")
    kinds = {f["vuln_type"] for f in findings}
    assert "hidden_parameter_discovered" not in kinds, (
        "a length swing within the page's own jitter is not a discovered parameter"
    )


@pytest.mark.asyncio
async def test_hidden_param_reflection_fires_despite_jitter():
    # Even on a jittery page, a verbatim reflection of the unique probe is a strong
    # processed-parameter signal and must still fire — recall is preserved.
    state = {"base_calls": 0}

    def handler(url):
        if "HEAVEN_PROBE" not in url:
            state["base_calls"] += 1
            n = 1000 if state["base_calls"] == 1 else 1500
            return _Resp(200, "<html>" + ("z" * n) + "</html>")
        if "debug=HEAVEN_PROBE" in url:
            return _Resp(200, "<html>reflected HEAVEN_PROBE " + ("z" * 1100) + "</html>")
        return _Resp(200, "<html>" + ("z" * 1300) + "</html>")   # within jitter

    findings = await _fuzz_parameters(_Session(handler), "http://t/dyn")
    params = {f["evidence"]["param"] for f in findings
              if f["vuln_type"] == "hidden_parameter_discovered"}
    assert "debug" in params, "a reflected probe is a discovery even on a noisy page"


@pytest.mark.asyncio
async def test_hidden_param_length_change_on_stable_page_still_fires():
    # Stable page (zero jitter): a >100-byte length change with no reflection is a
    # legitimate processed-parameter signal and is preserved (floor stays at 100).
    def handler(url):
        if "HEAVEN_PROBE" not in url:
            return _Resp(200, "<html>" + ("z" * 1000) + "</html>")   # identical both times
        if "format=HEAVEN_PROBE" in url:
            return _Resp(200, "<html>" + ("z" * 1400) + "</html>")   # +400 bytes, no reflect
        return _Resp(200, "<html>" + ("z" * 1000) + "</html>")       # unchanged

    findings = await _fuzz_parameters(_Session(handler), "http://t/dyn")
    params = {f["evidence"]["param"] for f in findings
              if f["vuln_type"] == "hidden_parameter_discovered"}
    assert "format" in params, "a clear length change on a stable page still fires"
