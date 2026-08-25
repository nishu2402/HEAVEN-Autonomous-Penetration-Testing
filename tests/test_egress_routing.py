"""Regression tests for the network-egress routing feature.

HEAVEN can push its outbound *scanning* traffic through an anonymity path
(WireGuard tunnel / HTTP proxy / SOCKS5 / Tor) while the dashboard stays local.
These tests lock in the load-bearing contracts:

  * ``off`` (the default) is a transparent no-op — no proxy args, no env, and
    ``client_session`` is a plain ``aiohttp.ClientSession``;
  * each mode resolves to the right proxy URL and tool flags;
  * HTTP-proxy mode exports the ``*_PROXY`` env + adds ``trust_env`` to aiohttp;
  * SOCKS/Tor routes in-process aiohttp through the **built-in SOCKS5 connector**
    (no new dependency) — proven end-to-end against a loopback SOCKS5 proxy — and
    never exports a SOCKS URL to ``*_PROXY`` (that would crash httpx); it only
    *fails closed* if the connector genuinely can't be built;
  * nmap is forced to a connect scan under any proxy mode, and still yields proxy
    flags for nuclei;
  * the settings catalog exposes the egress group and a change resets the cache.
"""
import asyncio
import socket
import os

import pytest

from heaven.net import egress


@pytest.fixture(autouse=True)
def _clean_egress_env(monkeypatch):
    """Every test starts from a known-clean egress environment + cache."""
    for var in ("HEAVEN_EGRESS_MODE", "HEAVEN_EGRESS_PROXY", "HEAVEN_TOR_SOCKS",
                "HEAVEN_WG_CONFIG", "HEAVEN_WG_INTERFACE", "HEAVEN_EGRESS_KILLSWITCH",
                "HEAVEN_EGRESS_SUDO", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    egress.reset_egress()
    yield
    egress.reset_egress()


def _set(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return egress.reset_egress()


# ── off (default) is a transparent no-op ────────────────────────────────────

def test_off_is_transparent():
    cfg = egress.resolve_egress()
    assert cfg.mode == "off"
    assert not cfg.armed
    assert egress.nuclei_proxy_args() == []
    assert egress.ffuf_proxy_args() == []
    assert egress.proxychains_prefix() == []
    assert egress.aiohttp_session_kwargs() == {}
    assert egress.nmap_forces_connect_scan() is False
    assert "HTTP_PROXY" not in os.environ


def test_off_client_session_is_plain(monkeypatch):
    async def _go():
        s = egress.client_session()
        try:
            assert s._trust_env is False
        finally:
            await s.close()
    asyncio.run(_go())


# ── Tor / SOCKS ─────────────────────────────────────────────────────────────

def test_tor_defaults_to_local_socks(monkeypatch):
    cfg = _set(monkeypatch, HEAVEN_EGRESS_MODE="tor")
    assert cfg.mode == "tor"
    assert cfg.proxy_url == "socks5://127.0.0.1:9050"
    # SOCKS is now handled in-process by the built-in connector.
    assert cfg.is_socks and cfg.in_process_proxyable
    # nuclei/ffuf get native proxy flags; nmap is forced to connect scan.
    assert egress.nuclei_proxy_args() == ["-proxy", "socks5://127.0.0.1:9050"]
    assert egress.ffuf_proxy_args() == ["-x", "socks5://127.0.0.1:9050"]
    assert egress.nmap_forces_connect_scan() is True
    # A SOCKS URL is NEVER exported to *_PROXY — httpx/requests would try to load
    # a missing SOCKS backend and crash; the connector handles target aiohttp.
    assert os.environ.get("HTTP_PROXY") is None
    assert os.environ.get("ALL_PROXY") is None
    assert os.environ.get("all_proxy") is None


def test_socks_uses_in_process_connector(monkeypatch):
    """Under SOCKS/Tor with the kill-switch on, ``client_session`` no longer
    fails closed — it installs the built-in SOCKS5 connector and routes."""
    _set(monkeypatch, HEAVEN_EGRESS_MODE="tor", HEAVEN_EGRESS_KILLSWITCH="on")

    async def _go():
        s = egress.client_session()   # must NOT raise
        try:
            conn = s.connector
            assert type(conn).__name__ == "_Socks5Connector"
            assert conn._socks_host == "127.0.0.1"
            assert conn._socks_port == 9050
        finally:
            await s.close()
    asyncio.run(_go())


def test_socks_connector_preserves_caller_ssl_and_limit(monkeypatch):
    """A scanner's own ``TCPConnector(ssl=False, limit=N)`` is transparently
    replaced by a SOCKS connector that KEEPS its ssl/limit intent (so the caller
    routes through SOCKS instead of connecting direct, without behaviour drift)."""
    import aiohttp
    _set(monkeypatch, HEAVEN_EGRESS_MODE="socks5",
         HEAVEN_EGRESS_PROXY="socks5://127.0.0.1:1080")

    async def _go():
        caller = aiohttp.TCPConnector(ssl=False, limit=17)
        s = egress.client_session(connector=caller)
        try:
            conn = s.connector
            assert type(conn).__name__ == "_Socks5Connector"
            assert conn._ssl is False          # ssl intent preserved
            assert conn._limit == 17           # limit preserved
            assert conn is not caller          # the direct connector was swapped out
        finally:
            await s.close()
    asyncio.run(_go())


def test_socks_routes_through_loopback_proxy(monkeypatch):
    """End-to-end proof: aiohttp really tunnels through an in-process SOCKS5
    proxy to reach an origin — no new dependency, no leak."""
    seen_connects = []

    async def _origin(reader, writer):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(1024)
            if not chunk:
                break
            data += chunk
        body = b"EGRESS-SOCKS-OK"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                     b"Connection: close\r\n\r\n%s" % (len(body), body))
        await writer.drain()
        writer.close()

    async def _socks(reader, writer):
        greet = await reader.readexactly(2)
        await reader.readexactly(greet[1])       # method bytes
        writer.write(b"\x05\x00")                # no-auth accepted
        await writer.drain()
        hdr = await reader.readexactly(4)
        atyp = hdr[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode()
        else:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        port = int.from_bytes(await reader.readexactly(2), "big")
        seen_connects.append((host, port))
        t_reader, t_writer = await asyncio.open_connection(host, port)
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")   # success
        await writer.drain()

        async def _pipe(r, w):
            try:
                while True:
                    b = await r.read(4096)
                    if not b:
                        break
                    w.write(b)
                    await w.drain()
            except OSError:
                pass
            finally:
                try:
                    w.close()
                except OSError:
                    pass
        await asyncio.gather(_pipe(reader, t_writer), _pipe(t_reader, writer))

    async def _go():
        origin = await asyncio.start_server(_origin, "127.0.0.1", 0)
        o_port = origin.sockets[0].getsockname()[1]
        socks = await asyncio.start_server(_socks, "127.0.0.1", 0)
        s_port = socks.sockets[0].getsockname()[1]
        _set(monkeypatch, HEAVEN_EGRESS_MODE="socks5",
             HEAVEN_EGRESS_PROXY=f"socks5://127.0.0.1:{s_port}",
             HEAVEN_EGRESS_KILLSWITCH="on")
        try:
            async with egress.client_session() as session:
                async with session.get(f"http://127.0.0.1:{o_port}/probe") as r:
                    assert r.status == 200
                    assert (await r.text()) == "EGRESS-SOCKS-OK"
        finally:
            origin.close()
            socks.close()
            await origin.wait_closed()
            await socks.wait_closed()
        # The request really transited the SOCKS proxy, addressed to the origin.
        assert seen_connects == [("127.0.0.1", o_port)]

    asyncio.run(_go())


def test_socks_fails_closed_when_connector_unavailable(monkeypatch):
    """If the built-in connector can't be built (e.g. a future aiohttp renames
    the seam), SOCKS with the kill-switch ON still fails closed (no leak), and
    with it OFF proceeds direct — the safety contract is preserved."""
    monkeypatch.setattr(egress, "_socks_connector_class", lambda: None)

    _set(monkeypatch, HEAVEN_EGRESS_MODE="tor", HEAVEN_EGRESS_KILLSWITCH="on")

    async def _blocked():
        with pytest.raises(egress.EgressBlocked):
            egress.client_session()
    asyncio.run(_blocked())

    _set(monkeypatch, HEAVEN_EGRESS_MODE="tor", HEAVEN_EGRESS_KILLSWITCH="off")

    async def _direct():
        s = egress.client_session()   # must not raise; proceeds direct
        try:
            assert s._trust_env is False
        finally:
            await s.close()
    asyncio.run(_direct())


def test_socks5_mode_needs_proxy_url(monkeypatch):
    cfg = _set(monkeypatch, HEAVEN_EGRESS_MODE="socks5")
    assert cfg.error and "HEAVEN_EGRESS_PROXY" in cfg.error
    cfg = _set(monkeypatch, HEAVEN_EGRESS_MODE="socks5",
               HEAVEN_EGRESS_PROXY="127.0.0.1:1080")
    assert cfg.proxy_url == "socks5://127.0.0.1:1080"   # default scheme applied


# ── HTTP proxy ──────────────────────────────────────────────────────────────

def test_http_proxy_exports_env_and_trust_env(monkeypatch):
    cfg = _set(monkeypatch, HEAVEN_EGRESS_MODE="http",
               HEAVEN_EGRESS_PROXY="http://127.0.0.1:8080")
    assert cfg.proxy_url == "http://127.0.0.1:8080"
    assert cfg.in_process_proxyable is True
    assert os.environ["HTTP_PROXY"] == "http://127.0.0.1:8080"
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:8080"
    assert "localhost" in os.environ.get("NO_PROXY", "")
    assert egress.aiohttp_session_kwargs() == {"trust_env": True}

    async def _go():
        s = egress.client_session()
        try:
            assert s._trust_env is True
        finally:
            await s.close()
    asyncio.run(_go())


def test_http_mode_requires_proxy(monkeypatch):
    cfg = _set(monkeypatch, HEAVEN_EGRESS_MODE="http")
    assert cfg.error and "HEAVEN_EGRESS_PROXY" in cfg.error


# ── WireGuard tunnel ────────────────────────────────────────────────────────

def test_wireguard_derives_interface(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nPrivateKey=xxx\n")
    cfg = _set(monkeypatch, HEAVEN_EGRESS_MODE="wireguard", HEAVEN_WG_CONFIG=str(conf))
    assert cfg.is_tunnel
    assert cfg.wg_interface == "wg0"
    assert cfg.error is None
    # tunnel mode covers every tool at the network layer → no per-tool flags.
    assert egress.nuclei_proxy_args() == []
    assert egress.nmap_forces_connect_scan() is False
    assert egress.aiohttp_session_kwargs() == {}
    # in-process clients are fine (network layer) — no fail-closed.

    async def _go():
        s = egress.client_session()
        await s.close()
    asyncio.run(_go())


def test_wireguard_missing_config_is_flagged(monkeypatch):
    cfg = _set(monkeypatch, HEAVEN_EGRESS_MODE="wireguard",
               HEAVEN_WG_CONFIG="/nonexistent/wg9.conf")
    assert cfg.error and "not found" in cfg.error


def test_unknown_mode_is_off(monkeypatch):
    cfg = _set(monkeypatch, HEAVEN_EGRESS_MODE="banana")
    assert cfg.mode == "off"
    assert cfg.error


# ── confirm / status ────────────────────────────────────────────────────────

def test_confirm_off_is_direct(monkeypatch):
    # off mode still fetches the baseline IP; monkeypatch the fetch so the test
    # is hermetic (no real network).
    async def _fake_ip(proxy, timeout):
        return "203.0.113.7"
    monkeypatch.setattr(egress, "_http_ip", _fake_ip)
    res = asyncio.run(egress.confirm_egress(timeout=1))
    assert res["mode"] == "off"
    assert res["ok"] is True
    assert res["via"] == "direct"
    assert res["changed"] is False


def test_confirm_http_proxy_detects_change(monkeypatch):
    _set(monkeypatch, HEAVEN_EGRESS_MODE="http",
         HEAVEN_EGRESS_PROXY="http://127.0.0.1:8080")

    async def _fake_ip(proxy, timeout):
        return "198.51.100.9" if proxy else "203.0.113.7"  # proxy exit != baseline
    monkeypatch.setattr(egress, "_http_ip", _fake_ip)
    monkeypatch.setattr(egress, "_baseline_ip", None, raising=False)
    res = asyncio.run(egress.confirm_egress(timeout=1))
    assert res["mode"] == "http"
    assert res["public_ip"] == "198.51.100.9"
    assert res["baseline_ip"] == "203.0.113.7"
    assert res["changed"] is True
    assert res["ok"] is True


def test_confirm_flags_non_anonymising_proxy(monkeypatch):
    _set(monkeypatch, HEAVEN_EGRESS_MODE="http",
         HEAVEN_EGRESS_PROXY="http://127.0.0.1:8080")

    async def _fake_ip(proxy, timeout):
        return "203.0.113.7"  # same IP through proxy and direct → not anonymising
    monkeypatch.setattr(egress, "_http_ip", _fake_ip)
    monkeypatch.setattr(egress, "_baseline_ip", None, raising=False)
    res = asyncio.run(egress.confirm_egress(timeout=1))
    assert res["changed"] is False
    assert res["ok"] is False
    assert "baseline" in res["detail"]


def test_assert_ready_killswitch_raises_on_dead_proxy(monkeypatch):
    _set(monkeypatch, HEAVEN_EGRESS_MODE="http",
         HEAVEN_EGRESS_PROXY="http://127.0.0.1:8080", HEAVEN_EGRESS_KILLSWITCH="on")

    async def _fake_ip(proxy, timeout):
        return None if proxy else "203.0.113.7"   # proxy unreachable
    monkeypatch.setattr(egress, "_http_ip", _fake_ip)
    monkeypatch.setattr(egress, "_baseline_ip", None, raising=False)
    with pytest.raises(egress.EgressError):
        asyncio.run(egress.assert_ready(timeout=1))


def test_assert_ready_killswitch_off_never_raises(monkeypatch):
    _set(monkeypatch, HEAVEN_EGRESS_MODE="http",
         HEAVEN_EGRESS_PROXY="http://127.0.0.1:8080", HEAVEN_EGRESS_KILLSWITCH="off")

    async def _fake_ip(proxy, timeout):
        return None if proxy else "203.0.113.7"
    monkeypatch.setattr(egress, "_http_ip", _fake_ip)
    monkeypatch.setattr(egress, "_baseline_ip", None, raising=False)
    # returns a (failing) result but does not raise, because the kill-switch is off
    res = asyncio.run(egress.assert_ready(timeout=1))
    assert res["ok"] is False


def test_status_snapshot_shape():
    snap = egress.status()
    assert snap["mode"] == "off"
    assert "tools" in snap and "killswitch" in snap and "armed" in snap


# ── fail-closed port-scan gating (the nmap leak vector) ─────────────────────

def test_port_scan_blocked_under_socks_without_proxychains(monkeypatch):
    _set(monkeypatch, HEAVEN_EGRESS_MODE="tor", HEAVEN_EGRESS_KILLSWITCH="on")
    monkeypatch.setattr(egress.shutil, "which", lambda _n: None)  # no proxychains
    assert egress.tcp_proxy_available() is False
    assert egress.port_scan_blocked() is True


def test_port_scan_not_blocked_with_proxychains(monkeypatch):
    _set(monkeypatch, HEAVEN_EGRESS_MODE="tor", HEAVEN_EGRESS_KILLSWITCH="on")
    monkeypatch.setattr(egress.shutil, "which",
                        lambda n: "/usr/bin/proxychains4" if "proxychains" in n else None)
    assert egress.tcp_proxy_available() is True
    assert egress.port_scan_blocked() is False


def test_port_scan_not_blocked_when_killswitch_off(monkeypatch):
    _set(monkeypatch, HEAVEN_EGRESS_MODE="tor", HEAVEN_EGRESS_KILLSWITCH="off")
    monkeypatch.setattr(egress.shutil, "which", lambda _n: None)
    assert egress.port_scan_blocked() is False   # operator accepted direct fallback


def test_wireguard_never_blocks_port_scan(tmp_path, monkeypatch):
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\n")
    _set(monkeypatch, HEAVEN_EGRESS_MODE="wireguard", HEAVEN_WG_CONFIG=str(conf))
    assert egress.tcp_proxy_available() is True      # tunnel is network-layer
    assert egress.port_scan_blocked() is False


def test_off_never_blocks_port_scan():
    assert egress.tcp_proxy_available() is True
    assert egress.port_scan_blocked() is False


# ── settings catalog integration ────────────────────────────────────────────

def test_settings_catalog_has_egress_group():
    from heaven.settings_catalog import catalog_status
    groups = {g["name"] for g in catalog_status()["groups"]}
    assert "Egress / anonymity" in groups


def test_apply_settings_resets_egress_cache(tmp_path, monkeypatch):
    # Run against a throwaway .env in a temp cwd so apply_settings never touches
    # the developer's real .env (mirrors tests/test_settings.py). Pin a
    # deterministic pre-state so suite ordering / a leaked env var can't affect
    # the change-detection inside apply_settings.
    #
    # Resolve the egress module at CALL TIME via sys.modules, NOT the module-level
    # `egress` binding: an earlier test (test_advanced) nukes ``sys.modules['heaven*']``
    # and re-imports, so the top-level binding can be a *stale* module instance
    # with its own `_cache`, while apply_settings imports the current one — the two
    # caches then diverge (a test-only artifact; production has one instance).
    import importlib
    monkeypatch.chdir(tmp_path)
    # Hard invariant: apply_settings must resolve the .env INSIDE the temp dir,
    # never the developer's real one. If a future cwd-handling change regressed,
    # this fails loudly instead of silently writing to the real .env.
    from heaven.utils.env_file import resolve_env_path
    assert resolve_env_path().parent == tmp_path, (
        f"refusing to run: .env would resolve to {resolve_env_path()} "
        f"(outside the throwaway {tmp_path})")
    monkeypatch.setenv("HEAVEN_EGRESS_MODE", "off")
    monkeypatch.delenv("HEAVEN_EGRESS_PROXY", raising=False)
    monkeypatch.delenv("HEAVEN_TOR_SOCKS", raising=False)
    from heaven.settings_catalog import apply_settings

    def eg():
        return importlib.import_module("heaven.net.egress")

    eg().reset_egress()
    assert eg().resolve_egress().mode == "off"
    apply_settings({"HEAVEN_EGRESS_MODE": "tor"})
    try:
        assert eg().resolve_egress().mode == "tor"
        assert eg().resolve_egress().proxy_url == "socks5://127.0.0.1:9050"
    finally:
        apply_settings({"HEAVEN_EGRESS_MODE": "off"})   # back to off
    assert eg().resolve_egress().mode == "off"
