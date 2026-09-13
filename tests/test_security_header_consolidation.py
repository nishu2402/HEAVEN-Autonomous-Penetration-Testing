"""One missing security header, reported once.

Two scanners legitimately probe response headers. ``misconfig_scanner`` emits a
single ``missing_security_headers`` *bundle* (plus a ``clickjacking`` finding);
``auth_scanner`` emits one *granular* finding per header (``csp_missing``,
``no_x_content_type``, ``clickjacking_no_xfo`` …). On a host where both run, the
same missing header was reported two or three times under different vuln_types,
and the identity-based dedup can't merge them (different vuln_types are different
identities by design). ``_consolidate_header_family`` removes the misconfig
redundancies for a host ONLY when the auth granular equivalents are present for
that same host, so a mode running a single scanner never loses coverage.

These tests pin (a) the drop-only-when-covered behaviour, (b) that the parity
holds *live* against both real scanners — every header the bundle can name has a
granular emitter — so consolidation can't silently drop a header nothing else
reports, (c) the frame-ancestors precision guard, and (d) the reconciled
clickjacking severity.

See heaven/engagement.py::_consolidate_header_family,
heaven/vulnscan/misconfig_scanner.py::_check_clickjacking and
heaven/vulnscan/auth_scanner.py::_audit_security_headers.
"""

from __future__ import annotations

import asyncio

from multidict import CIMultiDict

from heaven.engagement import (
    _HEADER_BUNDLE_COVERAGE,
    _consolidate_header_family,
    dedup_findings,
)


# ── tiny aiohttp-response fake (case-insensitive headers, async context) ────────
class _Resp:
    def __init__(self, url: str, headers: dict, status: int = 200,
                 content_type: str = "text/html") -> None:
        self.url = url
        self.status = status
        self.content_type = content_type
        self.headers = CIMultiDict(headers)

    async def __aenter__(self) -> "_Resp":
        return self

    async def __aexit__(self, *_a: object) -> bool:
        return False


class _Session:
    """Returns one canned response for every GET — no network."""

    def __init__(self, url: str, headers: dict, status: int = 200,
                 content_type: str = "text/html") -> None:
        self._url, self._headers = url, headers
        self._status, self._ct = status, content_type

    def get(self, *_a: object, **_k: object) -> _Resp:
        return _Resp(self._url, self._headers, self._status, self._ct)


def _bundle(host: str, headers: list[str]) -> dict:
    return {
        "target": host, "vuln_type": "missing_security_headers", "severity": "low",
        "title": f"Missing security headers: {', '.join(headers)}",
        "confidence": 0.75, "evidence": {"missing_headers": headers},
    }


def _granular(host: str, vuln_type: str, severity: str = "medium") -> dict:
    return {"target": host, "vuln_type": vuln_type, "severity": severity,
            "title": vuln_type, "confidence": 0.98, "evidence": {}}


# ── the consolidation post-pass ────────────────────────────────────────────────
def test_bundle_dropped_when_every_named_header_has_a_granular_equivalent() -> None:
    host = "example.com"
    findings = [
        _bundle(host, ["Content-Security-Policy", "X-Frame-Options",
                       "X-Content-Type-Options"]),
        _granular(host, "csp_missing"),
        _granular(host, "clickjacking_no_xfo"),
        _granular(host, "no_x_content_type"),
    ]
    out = _consolidate_header_family(findings)
    types = [f["vuln_type"] for f in out]
    assert "missing_security_headers" not in types, types
    # every granular finding survives — each header is still reported exactly once
    assert types == ["csp_missing", "clickjacking_no_xfo", "no_x_content_type"]


def test_bundle_kept_when_a_named_header_is_not_individually_covered() -> None:
    # The bundle names X-Content-Type-Options but no granular finding reports it,
    # so dropping the bundle would lose that header — it must be kept.
    host = "example.com"
    findings = [
        _bundle(host, ["Content-Security-Policy", "X-Content-Type-Options"]),
        _granular(host, "csp_missing"),  # X-Content-Type-Options NOT covered
    ]
    out = _consolidate_header_family(findings)
    assert any(f["vuln_type"] == "missing_security_headers" for f in out)


def test_bundle_kept_when_auth_scanner_did_not_run() -> None:
    # Only misconfig findings (no granular header findings anywhere) → keep all,
    # so a network/misconfig-only mode never loses its header coverage.
    host = "example.com"
    findings = [
        _bundle(host, ["Content-Security-Policy", "X-Frame-Options"]),
        {"target": host, "vuln_type": "clickjacking", "severity": "medium",
         "title": "framable", "confidence": 0.8, "evidence": {}},
    ]
    out = _consolidate_header_family(findings)
    assert {f["vuln_type"] for f in out} == {"missing_security_headers", "clickjacking"}


def test_duplicate_clickjacking_collapses_to_the_granular_one() -> None:
    host = "example.com"
    findings = [
        {"target": host, "vuln_type": "clickjacking", "severity": "medium",
         "title": "framable", "confidence": 0.8, "evidence": {}},
        _granular(host, "clickjacking_no_xfo"),
    ]
    out = _consolidate_header_family(findings)
    types = [f["vuln_type"] for f in out]
    assert types == ["clickjacking_no_xfo"], types


def test_consolidation_is_scoped_per_host() -> None:
    # host A has the granular set; host B has only the bundle → B keeps its bundle.
    findings = [
        _bundle("a.com", ["Content-Security-Policy"]),
        _granular("a.com", "csp_missing"),
        _bundle("b.com", ["Content-Security-Policy"]),
    ]
    out = _consolidate_header_family(findings)
    bundles = {f["target"] for f in out if f["vuln_type"] == "missing_security_headers"}
    assert bundles == {"b.com"}, bundles


def test_full_pipeline_reports_each_header_once() -> None:
    # A realistic mix, including once-per-URL duplication that dedup collapses and
    # then cross-scanner duplication that consolidation collapses.
    findings = [
        _bundle("https://example.com", ["Content-Security-Policy",
                                        "X-Frame-Options", "X-Content-Type-Options"]),
        _bundle("https://example.com/login", ["Content-Security-Policy",
                                              "X-Frame-Options", "X-Content-Type-Options"]),
        _granular("https://example.com", "csp_missing"),
        _granular("https://example.com/login", "csp_missing"),
        _granular("https://example.com", "clickjacking_no_xfo"),
        _granular("https://example.com", "no_x_content_type"),
        {"target": "https://example.com", "vuln_type": "clickjacking",
         "severity": "medium", "title": "framable", "confidence": 0.8, "evidence": {}},
    ]
    out = dedup_findings(findings)
    types = sorted(f["vuln_type"] for f in out)
    # CSP once, X-Frame-Options once (clickjacking_no_xfo), X-Content-Type once —
    # no bundle, no duplicate clickjacking.
    assert types == ["clickjacking_no_xfo", "csp_missing", "no_x_content_type"], types


# ── live parity: every header the bundle can name has a granular emitter ────────
def _misconfig_bundle_headers() -> list[str]:
    """Drive the real misconfig header check with NO security headers present and
    return the exact header names it puts in the bundle."""
    from heaven.vulnscan.misconfig_scanner import _check_security_headers
    sess = _Session("http://t/", {})  # zero security headers
    out = asyncio.run(_check_security_headers(sess, "http://t/"))
    assert len(out) == 1 and out[0]["vuln_type"] == "missing_security_headers"
    return out[0]["evidence"]["missing_headers"]


def _auth_granular_types(headers: dict | None = None) -> set[str]:
    """Drive the real auth header audit and return the granular vuln_types it emits."""
    from heaven.vulnscan.auth_scanner import _audit_security_headers
    sess = _Session("http://t/", headers or {})
    out = asyncio.run(_audit_security_headers(sess, "http://t/"))
    return {f["vuln_type"] for f in out}


def test_header_coverage_parity_live() -> None:
    """VERIFY (not assume) parity: every header the misconfig bundle can name is
    (a) a key in the coverage map, and (b) individually emitted by auth_scanner —
    so consolidation can never drop a header nothing else reports."""
    bundle_headers = [h.lower() for h in _misconfig_bundle_headers()]
    assert bundle_headers, "bundle named no headers with all absent — check probe"
    auth_types = _auth_granular_types()
    for h in bundle_headers:
        assert h in _HEADER_BUNDLE_COVERAGE, f"{h} names no granular equivalent"
        covering = [g for g in _HEADER_BUNDLE_COVERAGE[h] if g in auth_types]
        assert covering, (
            f"bundle header {h!r} has no live granular emitter in auth_scanner "
            f"(auth emitted {sorted(auth_types)}) — dropping the bundle would lose it")


def test_bundle_never_names_hsts() -> None:
    # HSTS is emitted separately (ssl_scanner `no_hsts`), so it must not ride in
    # the bundle — otherwise consolidation could drop an HSTS gap nothing covers.
    assert not any("transport" in h.lower() or "hsts" in h.lower()
                   for h in _misconfig_bundle_headers())


# ── precision guard + severity reconciliation at the source ─────────────────────
def test_auth_skips_xfo_when_csp_frame_ancestors_present() -> None:
    # A CSP frame-ancestors directive blocks framing (the modern XFO replacement),
    # so "X-Frame-Options missing" would be a false positive. auth must not emit it.
    types = _auth_granular_types({"Content-Security-Policy": "frame-ancestors 'none'"})
    assert "clickjacking_no_xfo" not in types, types
    assert "csp_missing" not in types  # CSP is present, so this must not fire either


def test_misconfig_clickjacking_severity_is_medium() -> None:
    # Reconciled to the KB's canonical clickjacking class (CWE-1021, CVSS 4.7),
    # matching auth_scanner's clickjacking_no_xfo — no more low-vs-medium split.
    from heaven.vulnscan.misconfig_scanner import _check_clickjacking
    sess = _Session("http://t/", {})  # no XFO, no CSP frame-ancestors → framable
    out = asyncio.run(_check_clickjacking(sess, "http://t/"))
    assert len(out) == 1 and out[0]["vuln_type"] == "clickjacking"
    assert out[0]["severity"] == "medium", out[0]["severity"]
