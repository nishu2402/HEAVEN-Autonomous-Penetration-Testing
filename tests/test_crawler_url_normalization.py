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
