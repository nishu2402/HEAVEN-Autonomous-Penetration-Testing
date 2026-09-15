"""Regression tests for the active-fuzzer URL-surface scoping.

These lock in the fix for the weekly DVWA benchmark's 900s scan timeout: the
heavy active web fuzzers (advanced exploitation, anomaly probe) used to fire
their full per-URL battery — several probes time-based — at every discovered
URL, including a target's static, parameter-less documents (DVWA's official
image ships 14 localized ``README.*.md`` files), and the CL.TE request-smuggling
probe (an origin-level property that stalls to its timeout on a normal server)
ran once per path instead of once per origin. Both wasted minutes of wall-clock
without adding any finding.
"""

from __future__ import annotations

import asyncio

from heaven.vulnscan.url_surface import has_injectable_surface, origin_of


class TestHasInjectableSurface:
    """Static, parameter-less documents are skipped; everything else is kept."""

    def test_static_parameterless_documents_are_skipped(self):
        for url in (
            "http://h:8080/README.md",
            "http://h:8080/README.ar.md",          # localized doc
            "http://h:8080/docs/DVWA_v1.3.pdf",
            "http://h:8080/robots.txt",
            "http://h:8080/security.txt",
            "http://h:8080/favicon.ico",
            "http://h:8080/assets/app.css",
            "http://h:8080/fonts/Inter.woff2",
            "http://h:8080/img/logo.png",
            "http://h:8080/release.zip",
        ):
            assert has_injectable_surface(url) is False, url

    def test_dynamic_or_parameterised_urls_are_kept(self):
        for url in (
            "http://h:8080/vulnerabilities/sqli/?id=1&Submit=Submit",  # query
            "http://h:8080/download.pdf?file=/etc/passwd",  # static ext BUT query
            "http://h:8080/vulnerabilities/exec/",          # dir / route
            "http://h:8080/index.php",                      # scripting ext
            "http://h:8080/login.php",
            "http://h:8080/",                               # root
            "http://h:8080/api/v1/users",                   # extension-less route
        ):
            assert has_injectable_surface(url) is True, url

    def test_unparseable_input_is_kept(self):
        # Err on the side of scanning rather than silently dropping a target.
        assert has_injectable_surface("not a url") is True
        assert has_injectable_surface("") is True


class TestOriginOf:
    def test_collapses_paths_to_origin(self):
        assert origin_of("http://127.0.0.1:8080/a/b?x=1") == "http://127.0.0.1:8080"
        assert origin_of("https://ex.com/deep/path") == "https://ex.com"

    def test_distinct_origins_stay_distinct(self):
        seen = {
            origin_of("http://a:80/x"),
            origin_of("http://a:81/x"),
            origin_of("https://a/x"),
        }
        assert len(seen) == 3

    def test_unparseable_input_does_not_collapse(self):
        assert origin_of("garbage") == "garbage"


class TestSmugglingRunsOncePerOrigin:
    """The CL.TE probe fires only when the caller asks (once per origin)."""

    def _run(self, monkeypatch, include_smuggling):
        import heaven.vulnscan.advanced_attacks as aa

        calls = {"clte": 0, "spray": 0}

        async def _fake_clte(url, timeout=10.0):
            calls["clte"] += 1
            return None

        async def _fake_spray(cls, session, url, service_hint=""):
            calls["spray"] += 1
            return []

        monkeypatch.setattr(aa.RequestSmugglingDetector, "detect_clte",
                            staticmethod(_fake_clte))
        monkeypatch.setattr(aa.CredentialSprayer, "spray_web_login",
                            classmethod(_fake_spray))

        # No scan_data -> JWT and race loops are skipped, so only the per-URL
        # cred spray and the gated smuggling probe run.
        asyncio.run(aa.run_advanced_tests(
            session=None, url="http://h:8080/a", scan_data=None,
            include_smuggling=include_smuggling))
        return calls

    def test_skipped_when_not_first_for_origin(self, monkeypatch):
        calls = self._run(monkeypatch, include_smuggling=False)
        assert calls["clte"] == 0        # not probed again for this origin
        assert calls["spray"] == 1       # per-URL work still runs

    def test_probed_when_first_for_origin(self, monkeypatch):
        calls = self._run(monkeypatch, include_smuggling=True)
        assert calls["clte"] == 1
