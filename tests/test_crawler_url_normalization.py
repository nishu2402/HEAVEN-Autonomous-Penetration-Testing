"""The crawler must treat a URL fragment as client-side only.

A ``#fragment`` is never sent to the server, so ``page.php#a`` and ``page.php#b``
are the SAME resource. Before this fix the crawler deduped on the full URL
(fragment included), so a page whose body links to many in-page anchors — the
canonical case is phpinfo's ~40 ``#module_*`` table-of-contents links — was
crawled, and then fully re-scanned by every downstream web audit, once PER
fragment. That burned the scan budget and produced duplicate findings keyed on
the fragmented URL. These tests pin the normalisation so the regression can't
return. See heaven/recon/web_crawler.py::_canonical_link.
"""

from __future__ import annotations

import asyncio
import http.server
import socketserver
import threading
from urllib.parse import urlparse

import pytest

from heaven.recon.web_crawler import (
    _canonical_link,
    _canonical_link_spa,
    crawl_url,
)


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://t/phpinfo.php#module_fileinfo", "http://t/phpinfo.php"),
        ("http://t/phpinfo.php#module_filter", "http://t/phpinfo.php"),
        ("http://t/p?a=1&b=2#frag", "http://t/p?a=1&b=2"),  # query is preserved
        ("http://t/p#", "http://t/p"),                       # empty fragment
        ("http://t/p", "http://t/p"),                        # no fragment: unchanged
        ("http://t/", "http://t/"),
    ],
)
def test_canonical_link_strips_fragment_only(url: str, expected: str) -> None:
    assert _canonical_link(url) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        # SPA hash-routes are distinct views a browser renders → preserved.
        ("http://t/#/admin", "http://t/#/admin"),
        ("http://t/#/search?q=1", "http://t/#/search?q=1"),
        ("http://t/#!/legacy/route", "http://t/#!/legacy/route"),
        # Same-page anchors render nothing new → collapsed (phpinfo dedup holds).
        ("http://t/phpinfo.php#module_fileinfo", "http://t/phpinfo.php"),
        ("http://t/p#section2", "http://t/p"),
        ("http://t/p", "http://t/p"),
    ],
)
def test_canonical_link_spa_keeps_routes_drops_anchors(url: str, expected: str) -> None:
    assert _canonical_link_spa(url) == expected


def test_crawler_collapses_fragment_only_links_to_one_endpoint() -> None:
    """A page linking to /page.html#a, #b, #c AND /page.html must yield exactly
    ONE /page.html endpoint, and no endpoint may carry a '#'."""
    index = (
        b'<html><body>'
        b'<a href="/page.html#module_a">a</a>'
        b'<a href="/page.html#module_b">b</a>'
        b'<a href="/page.html#module_c">c</a>'
        b'<a href="/page.html">plain</a>'
        b'</body></html>'
    )
    page = b'<html><body>ok</body></html>'

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler contract
            body = index if self.path in ("/", "/index.html") else page
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence the test server
            return

    with socketserver.TCPServer(("127.0.0.1", 0), _Handler) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            eps = asyncio.run(
                crawl_url(f"http://127.0.0.1:{port}/", max_depth=2, max_pages=50))
        finally:
            srv.shutdown()

    urls = [e.url for e in eps]
    assert not any("#" in u for u in urls), f"fragment leaked into endpoints: {urls}"
    page_hits = [u for u in urls if u.rstrip("/").endswith("page.html")]
    assert len(page_hits) == 1, f"expected /page.html once, got {page_hits}"


# ═══════════════════════════════════════════════════════════════════════════
# SPA escalation — a JS-rendered app's routes/forms are invisible to the static
# crawler, so a framework marker in the shell must escalate to the Playwright
# renderer and MERGE the rendered surface (never drop the seed page's forms).
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("marker,framework", [
    ('<app-root></app-root>', "Angular"),
    ('<div ng-version="17.0"></div>', "Angular"),
    ('<div data-reactroot></div>', "React"),
    ('<script id="__NEXT_DATA__"></script>', "Next.js"),
    ('<script src="/_nuxt/entry.js"></script>', "Nuxt"),
    ('<div data-server-rendered="true"></div>', "Vue"),
])
def test_detect_spa_frameworks(marker: str, framework: str) -> None:
    from heaven.recon.web_crawler import _detect_spa_frameworks
    assert framework in _detect_spa_frameworks(f"<html><body>{marker}</body></html>")


def test_detect_spa_frameworks_none_on_plain_html() -> None:
    from heaven.recon.web_crawler import _detect_spa_frameworks
    assert _detect_spa_frameworks("<html><body><h1>hi</h1></body></html>") == []


def _serve(body: bytes):
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return
    return socketserver.TCPServer(("127.0.0.1", 0), _Handler)


def test_static_crawl_flags_spa_framework() -> None:
    shell = b'<html><body><app-root></app-root><script src="/main.js"></script></body></html>'
    with _serve(shell) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            eps = asyncio.run(crawl_url(f"http://127.0.0.1:{port}/"))
        finally:
            srv.shutdown()
    from heaven.recon.web_crawler import _endpoints_look_spa
    assert _endpoints_look_spa(eps)
    assert "Angular" in {t for e in eps for t in e.technologies}


def test_crawl_targets_escalates_and_merges_spa(monkeypatch) -> None:
    """When a SPA marker is present and Chromium is available, crawl_targets must
    render, add client-only routes, and MERGE rendered forms onto the seed page."""
    import heaven.recon.web_crawler as wc

    shell = b'<html><body><app-root></app-root><script src="/main.js"></script></body></html>'

    async def _fake_js(url, max_pages=40, auth_config=None, evasion_headers=None):
        seed = wc.WebEndpoint(url=url, status_code=200)
        seed.forms = [{"action": url + "api/login", "method": "POST",
                       "inputs": [{"name": "username", "type": "text"},
                                  {"name": "password", "type": "password"}]}]
        seed.input_vectors = [
            {"url": url, "method": "POST", "param": "username", "type": "text"},
            {"url": url, "method": "POST", "param": "password", "type": "password"},
        ]
        route = wc.WebEndpoint(url=url + "admin/users", status_code=200)
        return [seed, route]

    monkeypatch.setattr(wc, "crawl_url_js", _fake_js)
    monkeypatch.setattr(wc, "_chromium_available", lambda: True)

    with _serve(shell) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            res = asyncio.run(wc.crawl_targets([f"http://127.0.0.1:{port}/"]))
        finally:
            srv.shutdown()

    eurls = {e["url"] for e in res["endpoints"]}
    assert any(u.endswith("/admin/users") for u in eurls)   # client-only route added
    assert res["input_vectors"] >= 2                         # rendered form vectors merged
    # The rendered seed-page login form is attributed to the seed URL, not dropped.
    all_actions = [f["action"] for forms in res["url_forms"].values() for f in forms]
    assert any(a.endswith("api/login") for a in all_actions)


def test_crawl_targets_no_escalation_without_marker(monkeypatch) -> None:
    """A plain (non-SPA) page must never invoke the browser renderer."""
    import heaven.recon.web_crawler as wc
    called = {"js": False}

    async def _fake_js(*a, **k):
        called["js"] = True
        return []

    monkeypatch.setattr(wc, "crawl_url_js", _fake_js)
    monkeypatch.setattr(wc, "_chromium_available", lambda: True)

    with _serve(b"<html><body><h1>plain</h1></body></html>") as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            asyncio.run(wc.crawl_targets([f"http://127.0.0.1:{port}/"]))
        finally:
            srv.shutdown()
    assert called["js"] is False


def test_crawl_targets_no_escalation_without_chromium(monkeypatch) -> None:
    """A SPA marker but no Chromium bundle → static-only, no render, no crash."""
    import heaven.recon.web_crawler as wc
    called = {"js": False}

    async def _fake_js(*a, **k):
        called["js"] = True
        return []

    monkeypatch.setattr(wc, "crawl_url_js", _fake_js)
    monkeypatch.setattr(wc, "_chromium_available", lambda: False)
    monkeypatch.delenv("HEAVEN_AUTO_INSTALL_BROWSER", raising=False)

    shell = b'<html><body><app-root></app-root></body></html>'
    with _serve(shell) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            asyncio.run(wc.crawl_targets([f"http://127.0.0.1:{port}/"]))
        finally:
            srv.shutdown()
    assert called["js"] is False


def test_crawl_targets_discloses_gap_without_chromium(monkeypatch) -> None:
    """Without a browser the SPA request surface is still recovered statically, and
    the residual DOM-only gap is DISCLOSED as an honest coverage note (never a
    silent no-op): the note names the framework and the exact one-command arm."""
    import heaven.recon.web_crawler as wc

    async def _fake_js(*a, **k):
        raise AssertionError("renderer must not run when Chromium is absent")

    monkeypatch.setattr(wc, "crawl_url_js", _fake_js)
    monkeypatch.setattr(wc, "_chromium_available", lambda: False)
    monkeypatch.delenv("HEAVEN_AUTO_INSTALL_BROWSER", raising=False)

    shell = b'<html><body><app-root></app-root><script src="/main.js"></script></body></html>'
    with _serve(shell) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            res = asyncio.run(wc.crawl_targets([f"http://127.0.0.1:{port}/"]))
        finally:
            srv.shutdown()

    notes = res.get("coverage_notes") or []
    assert any(n.get("type") == "spa_render_reduced_fidelity" for n in notes)
    note = next(n for n in notes if n.get("type") == "spa_render_reduced_fidelity")
    assert "Angular" in note.get("frameworks", [])
    assert "install-tools" in note.get("remediation", "")
    assert "UNDER-REPORTED" in note.get("impact", "")
    # The note reports what static analysis recovered — it is not a bare "skipped".
    assert "recovered_endpoints" in note and "recovered_input_vectors" in note


def test_crawl_targets_no_gap_note_when_no_spa(monkeypatch) -> None:
    """A plain (non-SPA) page produces no coverage note — nothing was skipped."""
    import heaven.recon.web_crawler as wc
    monkeypatch.setattr(wc, "_chromium_available", lambda: False)
    monkeypatch.delenv("HEAVEN_AUTO_INSTALL_BROWSER", raising=False)
    with _serve(b"<html><body><h1>plain</h1></body></html>") as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            res = asyncio.run(wc.crawl_targets([f"http://127.0.0.1:{port}/"]))
        finally:
            srv.shutdown()
    assert res.get("coverage_notes") == []


def test_crawl_targets_auto_provisions_browser_when_opted_in(monkeypatch) -> None:
    """With HEAVEN_AUTO_INSTALL_BROWSER=1, a SPA on a browser-less host provisions
    the renderer on demand, then renders (no coverage-gap note)."""
    import heaven.recon.web_crawler as wc
    called = {"js": False, "provision": False}

    async def _fake_js(url, max_pages=40, auth_config=None, evasion_headers=None):
        called["js"] = True
        return [wc.WebEndpoint(url=url + "admin/users", status_code=200)]

    def _fake_provision() -> bool:
        called["provision"] = True
        return True

    monkeypatch.setattr(wc, "crawl_url_js", _fake_js)
    monkeypatch.setattr(wc, "_chromium_available", lambda: False)
    monkeypatch.setattr(wc, "_ensure_chromium_once", _fake_provision)
    monkeypatch.setenv("HEAVEN_AUTO_INSTALL_BROWSER", "1")

    shell = b'<html><body><app-root></app-root><script src="/main.js"></script></body></html>'
    with _serve(shell) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            res = asyncio.run(wc.crawl_targets([f"http://127.0.0.1:{port}/"]))
        finally:
            srv.shutdown()

    assert called["provision"] is True and called["js"] is True
    assert res.get("coverage_notes") == []       # rendered → nothing skipped
    assert any(e["url"].endswith("/admin/users") for e in res["endpoints"])


def test_crawl_targets_discloses_gap_when_provisioning_fails(monkeypatch) -> None:
    """Opted in but the on-demand provision fails → still disclosed, not silent."""
    import heaven.recon.web_crawler as wc

    async def _fake_js(*a, **k):
        raise AssertionError("renderer must not run when provisioning failed")

    monkeypatch.setattr(wc, "crawl_url_js", _fake_js)
    monkeypatch.setattr(wc, "_chromium_available", lambda: False)
    monkeypatch.setattr(wc, "_ensure_chromium_once", lambda: False)
    monkeypatch.setenv("HEAVEN_AUTO_INSTALL_BROWSER", "1")

    shell = b'<html><body><app-root></app-root></body></html>'
    with _serve(shell) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            res = asyncio.run(wc.crawl_targets([f"http://127.0.0.1:{port}/"]))
        finally:
            srv.shutdown()
    assert any(n.get("type") == "spa_render_reduced_fidelity"
               for n in (res.get("coverage_notes") or []))


# ═══════════════════════════════════════════════════════════════════════════
# Browser-FREE SPA request-surface recovery — extract_js_surface() mines the
# JS bundles for endpoints + methods + PARAMETERS in pure Python, so a JS app's
# attack surface is never gated on the ~150 MB Chromium download. These pin the
# recovery and its precision (no third-party / MIME / bare-word noise).
# ═══════════════════════════════════════════════════════════════════════════

def _serve_routes(routes: dict):
    """Serve a fixed {path: (content_type, body_bytes)} map (path-aware)."""
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            ctype, body = routes.get(path, ("text/html", b"<html></html>"))
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return
    return socketserver.TCPServer(("127.0.0.1", 0), _Handler)


_JS_BUNDLE = b"""
// Realistic SPA request surface written as literals (survives minification).
fetch("/api/login", {method: "POST", body: JSON.stringify({username, password})});
axios.get("/api/users", {params: {page, size}});
$.post("/api/comment", {postId, text});
xhr.open("GET", "/api/profile?userId=1&tab=info");
// Noise that MUST be dropped:
fetch("https://cdn.thirdparty.example/lib.js");   // third-party host, out of scope
fetch("image/png");                                 // MIME type, not an endpoint
cache.get("localSettingsKey");                      // bare word, not a path
"""


def _run_surface(js_body: bytes):
    routes = {"/main.js": ("application/javascript", js_body)}
    with _serve_routes(routes) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            from heaven.recon.web_crawler import extract_js_surface
            return asyncio.run(extract_js_surface(
                [f"http://127.0.0.1:{port}/main.js"])), port
        finally:
            srv.shutdown()


def test_extract_js_surface_recovers_endpoints_methods_params() -> None:
    eps, _port = _run_surface(_JS_BUNDLE)
    by_path = {urlparse(e.url).path: e for e in eps}

    # POST body params from fetch(JSON.stringify({...})).
    assert "/api/login" in by_path
    login_vecs = {(v["method"], v["param"]) for v in by_path["/api/login"].input_vectors}
    assert ("POST", "username") in login_vecs and ("POST", "password") in login_vecs

    # axios.get params object → GET query params.
    assert "/api/users" in by_path
    user_params = {v["param"] for v in by_path["/api/users"].input_vectors}
    assert {"page", "size"} <= user_params
    assert all(v["method"] == "GET" for v in by_path["/api/users"].input_vectors)

    # jQuery $.post positional data object → POST params.
    assert "/api/comment" in by_path
    comment_vecs = {(v["method"], v["param"]) for v in by_path["/api/comment"].input_vectors}
    assert ("POST", "postId") in comment_vecs and ("POST", "text") in comment_vecs

    # XHR open() + URL query string → GET query params.
    assert "/api/profile" in by_path
    prof_params = {v["param"] for v in by_path["/api/profile"].input_vectors}
    assert {"userId", "tab"} <= prof_params


def test_extract_js_surface_drops_third_party_and_noise() -> None:
    eps, _port = _run_surface(_JS_BUNDLE)
    hosts = {urlparse(e.url).netloc for e in eps}
    # Never leaks a third-party host (scope safety) …
    assert not any("thirdparty" in h for h in hosts)
    paths = {urlparse(e.url).path for e in eps}
    # … and never invents an endpoint from a MIME type or a bare word.
    assert "image/png" not in paths
    assert not any("localSettingsKey" in p for p in paths)


def test_extract_js_surface_skips_html_and_survives_bad_bundle() -> None:
    """An HTML shell handed back for an unknown .js path is never mined, and a
    dead bundle URL is skipped without raising."""
    from heaven.recon.web_crawler import extract_js_surface
    routes = {"/app.js": ("text/html", b"<html><body>fetch('/api/x',{body:JSON.stringify({a})})</body></html>")}
    with _serve_routes(routes) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            eps = asyncio.run(extract_js_surface([
                f"http://127.0.0.1:{port}/app.js",           # served as text/html → skipped
                f"http://127.0.0.1:{port + 1}/dead.js",       # unreachable → skipped, no raise
            ]))
        finally:
            srv.shutdown()
    assert eps == []


def test_crawl_targets_recovers_spa_surface_without_browser(monkeypatch) -> None:
    """End to end: a SPA on a browser-less host still yields its JS-derived
    endpoints + input vectors to the downstream scanners (via crawl_targets), and
    the residual DOM-only gap is disclosed with the recovered counts."""
    import heaven.recon.web_crawler as wc

    async def _fake_js(*a, **k):
        raise AssertionError("renderer must not run without a browser")

    monkeypatch.setattr(wc, "crawl_url_js", _fake_js)
    monkeypatch.setattr(wc, "_chromium_available", lambda: False)
    monkeypatch.delenv("HEAVEN_AUTO_INSTALL_BROWSER", raising=False)

    shell = (b'<html><body><app-root></app-root>'
             b'<script src="/main.js"></script></body></html>')
    routes = {
        "/": ("text/html", shell),
        "/main.js": ("application/javascript", _JS_BUNDLE),
    }
    with _serve_routes(routes) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            res = asyncio.run(wc.crawl_targets([f"http://127.0.0.1:{port}/"]))
        finally:
            srv.shutdown()

    # The client-rendered request surface reached the crawl result WITHOUT a browser.
    all_paths = {urlparse(e["url"]).path for e in res["endpoints"]}
    assert {"/api/login", "/api/comment"} <= all_paths
    assert res["input_vectors"] >= 4
    # And the residual DOM-only gap is disclosed honestly with recovered counts.
    note = next(n for n in (res.get("coverage_notes") or [])
                if n.get("type") == "spa_render_reduced_fidelity")
    assert note.get("recovered_endpoints", 0) >= 2
    assert note.get("recovered_input_vectors", 0) >= 4


# ═══════════════════════════════════════════════════════════════════════════
# Crawl-trap fan-out cap — a self-regenerating site (infinite calendar / id tree
# / ?page=N / session-in-path) must not monopolise the page budget. ``max_pages``
# already bounds the crawl; these pin that the budget is spent on DISTINCT URL
# templates, so a real endpoint co-present with a trap is still reached, while
# legitimate template reuse below the cap is untouched. See
# heaven/recon/web_crawler.py::_url_template.
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("a,b", [
    ("http://t/blog/2026/11/01", "http://t/blog/2026/11/02"),        # calendar
    ("http://t/post/5", "http://t/post/6"),                          # numeric id
    ("http://t/p?page=1", "http://t/p?page=2"),                      # pagination query
    ("http://t/u/9f8e7d6c5b4a3210", "http://t/u/0123456789abcdef"),  # hex / hash id
    ("http://t/s/550e8400-e29b-41d4-a716-446655440000",
     "http://t/s/6ba7b810-9dad-11d1-80b4-00c04fd430c8"),             # uuid
])
def test_url_template_collapses_data_variants(a: str, b: str) -> None:
    from heaven.recon.web_crawler import _url_template
    assert _url_template(a) == _url_template(b)


@pytest.mark.parametrize("a,b", [
    ("http://t/admin", "http://t/login"),                            # distinct named routes
    ("http://t/api/users", "http://t/api/orders"),
    ("http://t/v1/x", "http://t/v2/x"),                              # API versions kept
    ("http://t/password-reset", "http://t/account-settings"),        # word slugs kept
    ("http://t/deadbeef", "http://t/cafebabe"),                      # hex-valid words, no digit → kept
])
def test_url_template_keeps_distinct_named_routes(a: str, b: str) -> None:
    from heaven.recon.web_crawler import _url_template
    assert _url_template(a) != _url_template(b)


def test_crawl_trap_fanout_capped_real_endpoint_survives() -> None:
    """A self-regenerating trap (500 same-template links at depth 1, each page
    spawning a fresh child) must not consume the page budget: the distinct
    ``/login`` page enqueued AFTER the trap is still crawled, and the trap
    template is bounded to the fan-out cap. Without the cap a BFS fetches
    ``max_pages`` trap pages first and never reaches /login — this pins that it
    does."""
    from heaven.recon.web_crawler import _MAX_URLS_PER_TEMPLATE, crawl_url

    index = (b"<html><body>"
             + b"".join(f'<a href="/t/{n}">t{n}</a>'.encode() for n in range(500))
             + b'<a href="/login">login</a>'
             + b"</body></html>")

    class _Trap(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler contract
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                body = index
            elif path.startswith("/t/"):
                try:
                    n = int(path[3:])
                except ValueError:
                    n = 0
                # Each trap page regenerates a fresh same-template child.
                body = f'<html><body><a href="/t/{n + 1000}">next</a></body></html>'.encode()
            else:  # /login and anything else: a plain terminal page
                body = b"<html><body>real page</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    with socketserver.TCPServer(("127.0.0.1", 0), _Trap) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            eps = asyncio.run(crawl_url(
                f"http://127.0.0.1:{port}/", max_depth=5, max_pages=100))
        finally:
            srv.shutdown()

    urls = [e.url for e in eps]
    trap_hits = [u for u in urls if "/t/" in u]
    assert any(u.rstrip("/").endswith("/login") for u in urls), \
        f"real /login crowded out by trap: {len(urls)} pages, {len(trap_hits)} trap"
    assert len(trap_hits) <= _MAX_URLS_PER_TEMPLATE, \
        f"trap template not capped: {len(trap_hits)} > {_MAX_URLS_PER_TEMPLATE}"


def test_crawl_legit_template_reuse_under_cap_fully_crawled() -> None:
    """Legitimate template reuse BELOW the cap is untouched: a shop with a modest
    set of /product/<id> pages is crawled in full (the cap only bites a runaway
    fan-out, never ordinary reuse)."""
    from heaven.recon.web_crawler import crawl_url

    n_products = 12
    index = (b"<html><body>"
             + b"".join(f'<a href="/product/{i}">p{i}</a>'.encode()
                        for i in range(n_products))
             + b"</body></html>")

    class _Shop(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler contract
            path = self.path.split("?", 1)[0]
            body = (index if path in ("/", "/index.html")
                    else b"<html><body>product</body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            return

    with socketserver.TCPServer(("127.0.0.1", 0), _Shop) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            eps = asyncio.run(crawl_url(
                f"http://127.0.0.1:{port}/", max_depth=3, max_pages=200))
        finally:
            srv.shutdown()

    product_hits = {e.url for e in eps if "/product/" in e.url}
    assert len(product_hits) == n_products, \
        f"legit reuse under cap must be fully crawled: {len(product_hits)}/{n_products}"
