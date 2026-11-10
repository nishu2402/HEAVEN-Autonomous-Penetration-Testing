"""h2c-smuggling detector — offline, deterministic, no socket binding.

A fake in-memory transport models the vulnerable chain: a reverse proxy that
answers each guarded path over HTTP/1.1 (with its access-control status) but, on
an ``Upgrade: h2c`` (or a prior-knowledge preface), tunnels to an h2c backend
that serves the path with its *backend* status. The detector drives a real h2c
handshake and real HTTP/2 framing (hpack + hyperframe) against it, so the
confirmation path — proxy-denied-but-tunnel-reachable, with a catch-all control —
is exercised end to end without binding a socket (which the sandbox forbids).
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan import h2c_smuggling as h2c

pytest.importorskip("hpack")
pytest.importorskip("hyperframe")

from hpack import Decoder, Encoder          # noqa: E402
from hyperframe.frame import Frame, HeadersFrame, SettingsFrame  # noqa: E402

_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# ── in-memory async transport ────────────────────────────────────────────────

class _Reader:
    def __init__(self) -> None:
        self._buf = bytearray()
        self._ev = asyncio.Event()
        self._eof = False

    def feed(self, data: bytes) -> None:
        self._buf += data
        self._ev.set()

    def feed_eof(self) -> None:
        self._eof = True
        self._ev.set()

    async def _wait(self) -> None:
        self._ev.clear()
        await self._ev.wait()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            if self._eof:
                raise asyncio.IncompleteReadError(bytes(self._buf), n)
            await self._wait()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def readuntil(self, sep: bytes = b"\n") -> bytes:
        while sep not in self._buf:
            if self._eof:
                raise asyncio.IncompleteReadError(bytes(self._buf), None)
            await self._wait()
        idx = self._buf.find(sep) + len(sep)
        out = bytes(self._buf[:idx])
        del self._buf[:idx]
        return out


class _Writer:
    def __init__(self, conn: "_Conn") -> None:
        self._conn = conn

    def write(self, data: bytes) -> None:
        self._conn.on_write(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self._conn.reader.feed_eof()


class _Conn:
    """One connection's server-side state machine for the fake target."""

    def __init__(self, target: "FakeH2cTarget") -> None:
        self.target = target
        self.reader = _Reader()
        self.inbuf = bytearray()
        self.mode = "http1"
        self.settings_sent = False

    # called synchronously whenever the client writes
    def on_write(self, data: bytes) -> None:
        self.inbuf += data
        if self.mode == "http1":
            self._maybe_http1()
        if self.mode == "h2":
            self._drain_h2()

    def _maybe_http1(self) -> None:
        # A prior-knowledge client sends the HTTP/2 preface with no request line.
        if bytes(self.inbuf[:14]) == b"PRI * HTTP/2.0":
            if self.target.prior_knowledge:
                self.mode = "h2"
                return
            self.reader.feed(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            self.reader.feed_eof()
            self.inbuf.clear()
            return
        if b"\r\n\r\n" not in self.inbuf:
            return
        head, _, rest = bytes(self.inbuf).partition(b"\r\n\r\n")
        self.inbuf = bytearray(rest)
        lines = head.split(b"\r\n")
        path = lines[0].split(b" ")[1].decode() if b" " in lines[0] else "/"
        is_upgrade = b"upgrade: h2c" in head.lower()
        if is_upgrade and self.target.do_upgrade:
            self.reader.feed(b"HTTP/1.1 101 Switching Protocols\r\n"
                             b"Connection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
            self.mode = "h2"
            if self.inbuf:
                self._drain_h2()
            return
        # Plain HTTP/1.1 request → the PROXY's access-control status for the path.
        proxy_status = self.target.route(path)[0]
        self.reader.feed(
            f"HTTP/1.1 {proxy_status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .encode())
        self.reader.feed_eof()

    def _drain_h2(self) -> None:
        if bytes(self.inbuf[:len(_PREFACE)]) == _PREFACE:
            self.inbuf = self.inbuf[len(_PREFACE):]
        while len(self.inbuf) >= 9:
            fh, length = Frame.parse_frame_header(memoryview(bytes(self.inbuf[:9])))
            if len(self.inbuf) < 9 + length:
                break
            body = bytes(self.inbuf[9:9 + length])
            self.inbuf = self.inbuf[9 + length:]
            name = type(fh).__name__
            if name == "SettingsFrame":
                if "ACK" not in fh.flags and not self.settings_sent:
                    self.reader.feed(SettingsFrame().serialize())
                    self.settings_sent = True
                continue
            if name == "HeadersFrame":
                fh.parse_body(memoryview(body))
                path = dict(Decoder().decode(bytes(fh.data))).get(":path", "/")
                backend_status = self.target.route(path)[1]
                enc = Encoder()
                rframe = HeadersFrame(stream_id=fh.stream_id)
                rframe.data = enc.encode([(":status", str(backend_status))])
                rframe.flags.add("END_HEADERS")
                rframe.flags.add("END_STREAM")
                if not self.settings_sent:
                    self.reader.feed(SettingsFrame().serialize())
                    self.settings_sent = True
                self.reader.feed(rframe.serialize())


class FakeH2cTarget:
    """Configurable fake proxy+h2c-backend chain.

    ``routes`` maps a path to ``(proxy_http1_status, backend_h2_status)``. Unknown
    paths use ``default`` — importantly the random control path the detector
    tunnels, whose backend status decides the catch-all guard.
    """

    def __init__(self, routes, *, default=(404, 404),
                 do_upgrade=True, prior_knowledge=False):
        self.routes = routes
        self.default = default
        self.do_upgrade = do_upgrade
        self.prior_knowledge = prior_knowledge

    def route(self, path: str):
        return self.routes.get(path, self.default)

    async def opener(self, host, port, use_tls):
        conn = _Conn(self)
        return conn.reader, _Writer(conn)


def _scan(target: FakeH2cTarget, origin="http://proxy.test", **kw):
    return asyncio.run(h2c.scan_h2c_smuggling(
        [origin], timeout=2.0, opener=target.opener, **kw))


# ── confirmation ─────────────────────────────────────────────────────────────

def test_confirmed_bypass_via_upgrade():
    target = FakeH2cTarget({"/admin": (403, 200)}, default=(404, 404))
    out = _scan(target)
    assert len(out) == 1
    f = out[0]
    assert f["vuln_type"] == "h2c_smuggling"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-444"
    assert f["evidence"]["variant"] == "upgrade"
    paths = [b["path"] for b in f["evidence"]["bypassed_paths"]]
    assert "/admin" in paths
    bp = f["evidence"]["bypassed_paths"][0]
    assert bp["baseline_status"] == 403 and bp["tunnel_status"] == 200
    assert "access_control_differential" in f["evidence"]["signals"]


def test_confirmed_bypass_via_prior_knowledge():
    target = FakeH2cTarget({"/admin": (403, 200)}, default=(404, 404),
                           do_upgrade=False, prior_knowledge=True)
    out = _scan(target)
    assert len(out) == 1
    assert out[0]["evidence"]["variant"] == "prior-knowledge"


def test_redirect_baseline_is_treated_as_denied():
    # Proxy 302 (redirect to login) over HTTP/1.1, backend 200 over the tunnel.
    target = FakeH2cTarget({"/admin": (302, 200)}, default=(404, 404))
    out = _scan(target)
    assert len(out) == 1
    assert out[0]["evidence"]["bypassed_paths"][0]["baseline_status"] == 302


# ── false-positive guards ────────────────────────────────────────────────────

def test_no_differential_no_finding():
    # Backend also denies (403): no bypass.
    target = FakeH2cTarget({"/admin": (403, 403)}, default=(404, 404))
    assert _scan(target) == []


def test_catch_all_backend_is_suppressed():
    # The random control path returns 200 from the backend → catch-all → suppress,
    # even though /admin would otherwise look like a differential.
    target = FakeH2cTarget({"/admin": (403, 200)}, default=(404, 200))
    assert _scan(target) == []


def test_no_tunnel_no_finding():
    # Server neither upgrades nor speaks prior-knowledge h2 → no tunnel at all.
    target = FakeH2cTarget({"/admin": (403, 200)}, default=(404, 404),
                           do_upgrade=False, prior_knowledge=False)
    assert _scan(target) == []


def test_proxy_allows_path_no_finding():
    # Proxy already returns 200 over HTTP/1.1 → nothing is being bypassed.
    target = FakeH2cTarget({"/admin": (200, 200)}, default=(404, 404))
    assert _scan(target) == []


def test_recon_supplied_restricted_path_is_probed():
    target = FakeH2cTarget({"/secret-report": (403, 200)}, default=(404, 404))
    out = _scan(target, restricted_paths=["/secret-report"])
    assert len(out) == 1
    assert out[0]["evidence"]["bypassed_paths"][0]["path"] == "/secret-report"


def test_unreachable_origin_is_silent():
    class _Boom:
        async def opener(self, host, port, use_tls):
            raise ConnectionRefusedError("down")
    assert asyncio.run(h2c.scan_h2c_smuggling(
        ["http://x.test"], timeout=1.0, opener=_Boom().opener)) == []


def test_libs_absent_returns_empty(monkeypatch):
    monkeypatch.setattr(h2c, "_H2_OK", False)
    target = FakeH2cTarget({"/admin": (403, 200)})
    assert _scan(target) == []


def test_available_reflects_import():
    assert h2c.available() is h2c._H2_OK


# ── finding flows through the report/KB layer ────────────────────────────────

def test_finding_enriches_and_renders():
    from heaven.devsecops.evidence import package_finding
    from heaven.devsecops.vuln_kb import enrich_finding, lookup

    assert lookup("h2c_smuggling").get("cwe") == "CWE-444"
    target = FakeH2cTarget({"/admin": (403, 200)}, default=(404, 404))
    f = enrich_finding(_scan(target)[0])
    assert f["severity"] == "high"
    assert f.get("cvss_vector", "").startswith("CVSS:3.1/")
    md = package_finding(f).to_markdown()
    assert "/admin" in md and "403" in md and "200" in md
