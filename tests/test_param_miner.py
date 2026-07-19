"""HEAVEN — hidden-parameter mining tests.

Spins up a tiny local HTTP server whose behaviour depends on specific query
parameters, and asserts the miner (a) finds a *reflected* hidden param, (b) finds
a *length-changing* hidden param, and — most importantly — (c) never invents a
parameter: junk names, inert names, and an app that reflects everything all
produce zero findings.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from heaven.recon.param_miner import mine_parameters

_BASE = "<html><body>" + ("x" * 400) + "</body></html>"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # reflect_all is toggled per-server via the server instance.

    def do_GET(self):  # noqa: N802
        qs = parse_qs(urlparse(self.path).query)
        body = _BASE
        reflect_all = getattr(self.server, "reflect_all", False)  # type: ignore[attr-defined]
        if reflect_all:
            # Pathological app: echoes every query value → reflection is useless.
            for vals in qs.values():
                body += "|" + "|".join(vals)
        else:
            # 'debug' is reflected (reflection signal); 'page' appends a fixed
            # block (length signal, value NOT reflected); everything else inert.
            if "debug" in qs:
                body += "<!--dbg:" + "".join(qs["debug"]) + "-->"
            if "page" in qs:
                body += "<div>" + ("P" * 250) + "</div>"
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_a):  # silence
        return


class _Server:
    def __init__(self, reflect_all: bool = False):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.reflect_all = reflect_all  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}/"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


def _mine(url: str) -> list[str]:
    res = asyncio.run(mine_parameters([url], stealth_level="aggressive"))
    return sorted(
        iv["param"]
        for ep in res.get("endpoints", [])
        for iv in ep.get("input_vectors", [])
    )


def test_finds_reflected_hidden_param():
    with _Server() as url:
        found = _mine(url)
    assert "debug" in found, f"reflected hidden param not discovered: {found}"


def test_finds_length_changing_hidden_param():
    with _Server() as url:
        found = _mine(url)
    assert "page" in found, f"length-signal hidden param not discovered: {found}"


def test_no_false_positive_on_inert_params():
    # The app only reacts to debug/page; every other wordlist name is inert and
    # must NOT be reported. This is the accuracy gate.
    with _Server() as url:
        found = _mine(url)
    spurious = [p for p in found if p not in {"debug", "page"}]
    assert not spurious, f"miner invented parameters that do nothing: {spurious}"


def test_reflect_all_app_yields_no_reflection_fp():
    # An app that echoes EVERY query value would make reflection a false signal.
    # The miner must detect this (reflects_any) and report nothing from
    # reflection alone — no length change here means zero findings.
    with _Server(reflect_all=True) as url:
        found = _mine(url)
    assert found == [], f"reflect-all app should yield no findings, got: {found}"


def test_output_shape_feeds_injection_scanner():
    # Mined params must be shaped as input_vectors so build_injection_targets
    # consumes them with no extra wiring.
    from heaven.vulnscan.injection_scanner import build_injection_targets

    with _Server() as url:
        res = asyncio.run(mine_parameters([url], stealth_level="aggressive"))
    urls, _forms = build_injection_targets(res["endpoints"], seed_urls=[])
    # The combined GET target should now carry the mined params for fuzzing.
    assert any("debug=" in u or "page=" in u for u in urls), urls


@pytest.mark.parametrize("bad", [[], ["not a url"]])
def test_empty_or_junk_targets_are_safe(bad):
    res = asyncio.run(mine_parameters(bad))
    assert res.get("mined_params", 0) == 0
