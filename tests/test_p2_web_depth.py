"""P2 — Advanced web-depth tests (deserialization + cache-poisoning proof).

Cache poisoning and request smuggling already had detectors in HEAVEN; P2's real
gains are:

* a genuinely new **insecure-deserialization surface** detector (Java serialized
  objects / PHP object cookies), signature-verified so a benign app is silent;
* a **precision upgrade** to the existing cache-poisoning detector — a reflected
  unkeyed header is now *confirmed* via a safe cache-busted follow-up before it
  is reported ``high``; mere reflection is downgraded to a low indicator.

The request-smuggling timing decision lives in ``advanced_attacks`` /
``web_fuzzer`` and is covered by the existing FP-hardening suite; not re-tested
here.
"""
from __future__ import annotations

import asyncio

from heaven.devsecops.vuln_kb import enrich_finding
from heaven.vulnscan.web_fuzzer import (
    _confirm_cache_poisoning,
    _fuzz_cache_poisoning,
    _fuzz_deserialization,
    _looks_java_serialized,
)


# ── async HTTP fakes ─────────────────────────────────────────────────────────

class _Headers:
    """Minimal multidict: preserves duplicate keys for Set-Cookie."""
    def __init__(self, pairs):
        self._pairs = list(pairs.items()) if isinstance(pairs, dict) else list(pairs)

    def get(self, key, default=""):
        for k, v in self._pairs:
            if k.lower() == key.lower():
                return v
        return default

    def items(self):
        return list(self._pairs)


class _Resp:
    def __init__(self, body="", headers=None, status=200):
        self._body = body
        self.headers = _Headers(headers or {})
        self.status = status

    async def text(self, errors="strict"):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    """Fake aiohttp session driven by a response function of (url, headers)."""
    def __init__(self, fn):
        self._fn = fn

    def get(self, url, headers=None, allow_redirects=True, timeout=None):
        return self._fn(url, headers or {})


# ── insecure deserialization ─────────────────────────────────────────────────

# base64("\xac\xed\x00\x05...") → begins "rO0AB"
_JAVA_SER = "rO0ABXNyABZqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJ"


def test_looks_java_serialized():
    assert _looks_java_serialized(_JAVA_SER)
    assert not _looks_java_serialized("aGVsbG8gd29ybGQ=")   # "hello world"
    assert not _looks_java_serialized("")


def _run_deser(fn):
    return asyncio.run(_fuzz_deserialization(_Session(fn), "http://t/app"))


def test_deser_java_content_type_flagged():
    def fn(url, headers):
        return _Resp("...", {"Content-Type": "application/x-java-serialized-object"})
    out = _run_deser(fn)
    assert out and out[0]["vuln_type"] == "insecure_deserialization"
    assert out[0]["severity"] == "high"
    assert out[0]["evidence"]["location"] == "Content-Type header"


def test_deser_java_cookie_flagged():
    def fn(url, headers):
        return _Resp("body", {"Content-Type": "text/html",
                              "Set-Cookie": f"session={_JAVA_SER}; Path=/"})
    out = _run_deser(fn)
    assert out and out[0]["evidence"]["indicator"] == "java_serialized_object"


def test_deser_php_cookie_flagged():
    def fn(url, headers):
        return _Resp("body", {"Content-Type": "text/html",
                              "Set-Cookie": 'data=O:8:"stdClass":1:{s:1:"a";i:1;}; Path=/'})
    out = _run_deser(fn)
    assert out and out[0]["evidence"]["indicator"] == "php_serialized_object"
    assert out[0]["severity"] == "medium"


def test_deser_benign_no_finding():
    def fn(url, headers):
        return _Resp("<html>hello</html>", {"Content-Type": "text/html",
                                            "Set-Cookie": "session=abc123; Path=/"})
    assert _run_deser(fn) == []


# ── cache poisoning: confirmed vs reflection-only ────────────────────────────

def test_confirm_cache_poisoning_positive():
    # Vulnerable + cached: the injected canary persists on the clean request.
    state = {"cached": None}

    def fn(url, headers):
        # Poison request carries the attacker header.
        if headers:
            for k, v in headers.items():
                if k == "X-Forwarded-Host":
                    state["cached"] = v            # cache stores the poisoned body
                    return _Resp(f"<link href=//{v}/x>")
        # Clean request: server serves whatever the cache holds.
        cached = state["cached"] or ""
        return _Resp(f"<link href=//{cached}/x>" if cached else "<clean/>")

    res = asyncio.run(_confirm_cache_poisoning(_Session(fn), "http://t/", "X-Forwarded-Host"))
    assert res and res["reflected_in"] == "response body"


def test_confirm_cache_poisoning_reflection_only():
    # Reflects the header but does NOT cache → clean request has no canary.
    def fn(url, headers):
        if headers:
            v = next((val for k, val in headers.items() if k == "X-Forwarded-Host"), "")
            return _Resp(f"<link href=//{v}/x>")
        return _Resp("<clean/>")                    # nothing cached
    res = asyncio.run(_confirm_cache_poisoning(_Session(fn), "http://t/", "X-Forwarded-Host"))
    assert res is None


def test_fuzz_cache_poisoning_confirmed_is_high_and_proved():
    state = {"cached": None}

    def fn(url, headers):
        if headers:
            v = next((val for k, val in headers.items()
                      if k in ("X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-For",
                               "X-Host", "X-Original-URL", "X-Rewrite-URL")), "")
            if v:
                state["cached"] = v
                return _Resp(f"<base href=//{v}/>", {"Cache-Control": "public, max-age=60"})
        cached = state["cached"] or ""
        return _Resp(f"<base href=//{cached}/>" if cached else "<clean/>",
                     {"Cache-Control": "public, max-age=60"})

    out = asyncio.run(_fuzz_cache_poisoning(_Session(fn), "http://t/"))
    hits = [f for f in out if f["vuln_type"] == "cache_poisoning_unkeyed_header"]
    assert hits and hits[0]["severity"] == "high"
    assert hits[0]["evidence"].get("proved") is True


def test_fuzz_cache_poisoning_reflection_only_is_low_indicator():
    def fn(url, headers):
        if headers:
            v = next((val for k, val in headers.items() if k.startswith("X-")), "")
            if v:
                return _Resp(f"<base href=//{v}/>", {"Cache-Control": "public"})
        return _Resp("<clean/>", {"Cache-Control": "public"})   # never caches canary

    out = asyncio.run(_fuzz_cache_poisoning(_Session(fn), "http://t/"))
    hits = [f for f in out if f["vuln_type"] == "cache_poisoning_unkeyed_header"]
    assert hits and hits[0]["severity"] in ("low", "medium")
    assert hits[0]["confidence"] <= 0.5
    assert not hits[0]["evidence"].get("proved")


def test_fuzz_cache_poisoning_benign_silent():
    def fn(url, headers):
        return _Resp("<html>static</html>", {"Cache-Control": "public"})
    out = asyncio.run(_fuzz_cache_poisoning(_Session(fn), "http://t/"))
    assert [f for f in out if f["vuln_type"] == "cache_poisoning_unkeyed_header"] == []


# ── taxonomy ─────────────────────────────────────────────────────────────────

def test_deserialization_taxonomy_complete():
    f = enrich_finding({"vuln_type": "insecure_deserialization", "severity": "high"})
    assert f["cwe"] == "CWE-502"
    assert "Integrity" in f["owasp"]
    assert f["cvss_vector"].startswith("CVSS:3.1/")
    assert f.get("mitre_technique")
