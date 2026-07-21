"""Regression tests for internal-network scanning accuracy.

Two real bugs made an internal/external IP target that hosts a vulnerable web
app report *nothing*:

1. nmap ran host discovery (ping) first, so firewalled internal hosts — Windows
   boxes, hardened Linux — were declared "down" and never port-scanned. Fixed by
   adding ``-Pn`` (assume the authorized target is online).

2. The web vulnerability scanners only ran against ``targets["urls"]``. A bare-IP
   target has no URL, so even after nmap found an open HTTP(S) port the crawler,
   injection, auth, fuzzer and misconfig scanners never looked at it. Fixed by
   the orchestrator deriving a URL from each discovered web port and feeding it
   into the shared targets list + a follow-up crawl.
"""

from __future__ import annotations

import asyncio

from heaven.orchestrator import ScanMode, ScanOrchestrator, build_full_scan


# ── Fix 1: nmap -Pn so firewalled internal hosts still get scanned ──────────

class TestNmapAssumesHostOnline:
    def test_scan_command_includes_Pn(self, monkeypatch):
        """scan_host must invoke nmap with -Pn — otherwise a host that blocks
        ping is skipped and its (real) open ports/vulns are never seen."""
        from heaven.recon import network_scanner as ns

        captured: dict = {}

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return b"", b""

        async def _fake_exec(*argv, **kwargs):
            captured["argv"] = list(argv)
            return _FakeProc()

        # Neutralise privilege elevation so the command is deterministic.
        monkeypatch.setattr(ns, "_nmap_sudo_prefix", lambda: [])
        monkeypatch.setattr(ns, "_have_admin_privileges", lambda: False)
        monkeypatch.setattr(ns.asyncio, "create_subprocess_exec", _fake_exec)

        asyncio.run(ns.scan_host("192.168.1.50", [80, 443]))

        argv = captured.get("argv", [])
        assert "nmap" in argv, f"nmap not invoked: {argv}"
        assert "-Pn" in argv, f"-Pn missing — firewalled hosts will be skipped: {argv}"

    def test_liveness_not_faked_by_Pn(self):
        """-Pn makes nmap report every host 'up' (reason=user-set). A host with
        no responding ports and only that forced status must NOT be counted as
        alive — otherwise every dead address in a CIDR looks reachable."""
        from heaven.recon.network_scanner import HostResult

        h = HostResult(host="10.0.0.99")
        # No open ports, no probe-confirmed status → default stays not-alive.
        assert h.is_alive is False


# ── CIDR scanning: discover-first, scan concurrently, return partial ────────
# A /24 expands to 254 addresses. The old code scanned them one-at-a-time and,
# under -Pn, full-scanned every dead one — so a Network Recon task hit its 300s
# deadline and returned NOTHING ("it's vulnerable but the scan shows nothing").

class TestCidrDiscoveryAndConcurrency:
    def test_broad_range_discovers_then_scans_only_live(self, monkeypatch):
        """A CIDR wider than the discovery threshold must sweep for live hosts
        and deep-scan ONLY the ones that answered — not all 254 dead addresses."""
        import asyncio
        from heaven.recon import network_scanner as ns

        scanned: list[str] = []

        async def fake_scan_host(host, ports, **kw):
            scanned.append(host)
            r = ns.HostResult(host=host)
            r.is_alive = True
            return r

        async def fake_discover(raw, expanded, timeout=2.0):
            assert len(expanded) > ns._DISCOVERY_THRESHOLD
            return ["192.168.1.10", "192.168.1.20"]

        monkeypatch.setattr(ns, "scan_host", fake_scan_host)
        monkeypatch.setattr(ns, "_discover_live_hosts", fake_discover)

        out = asyncio.run(ns.scan_network(["192.168.1.0/24"], port_range="80"))

        assert set(scanned) == {"192.168.1.10", "192.168.1.20"}, scanned
        assert out["discovery"] == {"range_size": 254, "hosts_up": 2}
        assert out["total_hosts"] == 2

    def test_small_explicit_list_skips_discovery(self, monkeypatch):
        """A handful of explicitly-named hosts is scanned directly (with -Pn) —
        discovery must NOT run, so a firewalled host the operator named isn't
        pruned away by a liveness sweep."""
        import asyncio
        from heaven.recon import network_scanner as ns

        scanned: list[str] = []
        disco_calls = {"n": 0}

        async def fake_scan_host(host, ports, **kw):
            scanned.append(host)
            r = ns.HostResult(host=host)
            r.is_alive = True
            return r

        async def fake_discover(raw, expanded, timeout=2.0):
            disco_calls["n"] += 1
            return expanded

        monkeypatch.setattr(ns, "scan_host", fake_scan_host)
        monkeypatch.setattr(ns, "_discover_live_hosts", fake_discover)

        asyncio.run(ns.scan_network(["10.0.0.1", "10.0.0.2", "10.0.0.3"], port_range="80"))

        assert disco_calls["n"] == 0
        assert set(scanned) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    def test_hosts_are_scanned_concurrently(self, monkeypatch):
        """Two hosts that each take ~0.2s must finish together (concurrent), not
        serialized to ~0.4s — the old sequential loop was the CIDR bottleneck."""
        import asyncio
        import time
        from heaven.recon import network_scanner as ns

        async def slow_scan_host(host, ports, **kw):
            await asyncio.sleep(0.2)
            r = ns.HostResult(host=host)
            r.is_alive = True
            return r

        monkeypatch.setattr(ns, "scan_host", slow_scan_host)

        t0 = time.monotonic()
        out = asyncio.run(ns.scan_network(["10.0.0.1", "10.0.0.2"], port_range="80"))
        elapsed = time.monotonic() - t0

        assert out["total_hosts"] == 2
        assert elapsed < 0.35, f"hosts were not scanned concurrently ({elapsed:.2f}s)"

    def test_time_budget_returns_partial_results(self, monkeypatch):
        """When the deep-scan time budget elapses, hosts still running are
        stopped and the finished ones are STILL returned — partial beats none."""
        import asyncio
        from heaven.recon import network_scanner as ns

        async def uneven_scan_host(host, ports, **kw):
            await asyncio.sleep(0.05 if host.endswith(".1") else 5.0)
            r = ns.HostResult(host=host)
            r.is_alive = True
            return r

        monkeypatch.setattr(ns, "scan_host", uneven_scan_host)

        out = asyncio.run(ns.scan_network(
            ["10.0.0.1", "10.0.0.2"], port_range="80", time_budget=0.5,
        ))
        assert out["total_hosts"] == 1
        assert out["hosts_timed_out"] == 1


class TestDiscoveryHelpers:
    def test_tcp_ping_sweep_returns_only_responders(self, monkeypatch):
        """The pure-Python liveness fallback marks a host live only if a TCP
        connect on some common port actually succeeds."""
        import asyncio
        from heaven.recon import network_scanner as ns

        live_host = "10.0.0.7"

        async def fake_open_connection(host, port):
            if host == live_host and port == 80:
                class _W:
                    def close(self):
                        pass

                    async def wait_closed(self):
                        pass
                return (object(), _W())
            raise OSError("refused")

        monkeypatch.setattr(ns.asyncio, "open_connection", fake_open_connection)
        got = asyncio.run(ns._tcp_ping_sweep(["10.0.0.7", "10.0.0.8"], timeout=0.2))
        assert got == ["10.0.0.7"]

    def test_nmap_ping_sweep_absent_nmap_returns_none(self, monkeypatch):
        """No nmap on PATH → the nmap sweep bows out (None) so the caller falls
        back to the TCP probe."""
        import asyncio
        from heaven.recon import network_scanner as ns

        monkeypatch.setattr(ns.shutil, "which", lambda _n: None)
        got = asyncio.run(ns._nmap_ping_sweep(["192.168.1.0/24"], ["192.168.1.1"]))
        assert got is None


class TestNetworkTaskTimeoutScales:
    def test_cidr_gets_a_larger_timeout_and_budget(self):
        """build_full_scan must scale the Network Recon deadline to the size of
        the range (a /24 needs far more than the 300s single-host default) and
        pass a time_budget below that deadline so partial results survive."""
        targets = {"ips": ["192.168.1.0/24"], "urls": [], "ports": "1-1000",
                   "stealth_level": "normal"}
        orch = build_full_scan(targets, scan_mode=ScanMode.NETWORK)
        net = [t for t in orch.tasks.values() if t.name == "Network Reconnaissance"][0]
        assert net.timeout > 300.0
        budget = net.kwargs.get("time_budget")
        assert budget and budget < net.timeout

    def test_single_host_keeps_default_timeout(self):
        targets = {"ips": ["10.0.0.9"], "urls": [], "ports": "1-1000",
                   "stealth_level": "normal"}
        orch = build_full_scan(targets, scan_mode=ScanMode.NETWORK)
        net = [t for t in orch.tasks.values() if t.name == "Network Reconnaissance"][0]
        assert net.timeout == 300.0


# ── Privilege capability is reported honestly + actionably ──────────────────

class TestScanCapability:
    def _fresh(self, monkeypatch, root: bool, sudo: bool):
        from heaven.recon import network_scanner as ns
        monkeypatch.setattr(ns, "_have_admin_privileges", lambda: root)
        monkeypatch.setattr(ns, "_nmap_sudo_prefix", lambda: ("sudo", "-n") if sudo else ())
        ns.scan_capability.cache_clear()
        cap = ns.scan_capability()
        ns.scan_capability.cache_clear()  # don't leak into other tests
        return cap

    def test_privileged_has_no_remedy(self, monkeypatch):
        cap = self._fresh(monkeypatch, root=True, sudo=False)
        assert cap["raw_capable"] is True
        assert cap["method"] == "root"
        assert cap["os_scan"] and cap["syn_scan"] and cap["udp_scan"]
        assert cap["remedy"] == ""

    def test_sudo_path_is_capable(self, monkeypatch):
        cap = self._fresh(monkeypatch, root=False, sudo=True)
        assert cap["raw_capable"] is True
        assert cap["method"] == "sudo"
        assert cap["remedy"] == ""

    def test_unprivileged_gives_platform_remedy(self, monkeypatch):
        import sys
        cap = self._fresh(monkeypatch, root=False, sudo=False)
        assert cap["raw_capable"] is False
        assert cap["method"] == "unprivileged"
        assert cap["remedy"], "unprivileged scan must tell the operator how to fix it"
        # The remedy must be correct for THIS platform — never suggest Linux
        # `setcap` on macOS (it doesn't exist there).
        if sys.platform == "darwin":
            assert "setcap" not in cap["remedy"]
            assert "sudo" in cap["remedy"].lower()
        elif sys.platform.startswith("win"):
            assert "Administrator" in cap["remedy"]
        else:
            assert "setcap" in cap["remedy"]


# ── Fix 2: bare-IP target → web URL bridge ──────────────────────────────────

class TestWebUrlDerivation:
    def _orch(self, mode=ScanMode.FULL):
        return ScanOrchestrator(scan_mode=mode)

    def test_http_and_https_ports_classified(self):
        o = self._orch()
        assert o._web_url_for("192.168.1.10", 80, "http") == "http://192.168.1.10/"
        assert o._web_url_for("192.168.1.10", 443, "https") == "https://192.168.1.10/"
        assert o._web_url_for("192.168.1.10", 8080, "http-proxy") == "http://192.168.1.10:8080/"
        assert o._web_url_for("192.168.1.10", 8443, "https-alt") == "https://192.168.1.10:8443/"

    def test_unknown_service_on_web_port_still_classified(self):
        o = self._orch()
        # nmap couldn't name the service, but the port number is a known web port.
        assert o._web_url_for("10.0.0.5", 443, "") == "https://10.0.0.5/"
        assert o._web_url_for("10.0.0.5", 8000, "") == "http://10.0.0.5:8000/"

    def test_non_web_ports_return_none(self):
        o = self._orch()
        assert o._web_url_for("10.0.0.5", 22, "ssh") is None
        assert o._web_url_for("10.0.0.5", 3306, "mysql") is None
        assert o._web_url_for("10.0.0.5", 0, "http") is None  # no port
        assert o._web_url_for("", 80, "http") is None          # no host


class TestWebUrlBridge:
    _WEB_HOSTS = {"hosts": [{
        "ip": "192.168.1.50",
        "open_ports": [
            {"port": 80, "service": "http"},
            {"port": 8080, "service": "http-proxy"},
            {"port": 22, "service": "ssh"},
        ],
    }]}

    def test_bare_ip_gets_web_urls_and_crawl(self):
        """A FULL scan of a bare IP whose recon finds open web ports must gain
        scannable URLs *and* a crawl task, so the web detectors actually run."""
        targets = {"ips": ["192.168.1.50"], "urls": [], "ports": "1-1000",
                   "stealth_level": "normal"}
        orch = build_full_scan(targets, scan_mode=ScanMode.FULL)
        assert targets["urls"] == []

        orch._inject_service_tasks(self._WEB_HOSTS)

        assert "http://192.168.1.50/" in targets["urls"]
        assert "http://192.168.1.50:8080/" in targets["urls"]
        crawl = [t for t in orch.tasks.values() if "discovered services" in t.name]
        assert crawl, "no follow-up crawl injected for the discovered web app"

    def test_existing_url_not_duplicated(self):
        """An origin the operator already supplied must not be added again, but
        a *different* discovered port on the same host still is."""
        targets = {"ips": [], "urls": ["http://192.168.1.50/"], "ports": "1-1000",
                   "stealth_level": "normal"}
        orch = build_full_scan(targets, scan_mode=ScanMode.FULL)
        orch._inject_service_tasks(self._WEB_HOSTS)

        assert targets["urls"].count("http://192.168.1.50/") == 1
        assert "http://192.168.1.50:8080/" in targets["urls"]

    def test_non_web_host_adds_nothing(self):
        targets = {"ips": ["10.0.0.9"], "urls": [], "ports": "1-1000",
                   "stealth_level": "normal"}
        orch = build_full_scan(targets, scan_mode=ScanMode.FULL)
        orch._inject_service_tasks({"hosts": [{
            "ip": "10.0.0.9",
            "open_ports": [{"port": 22, "service": "ssh"}],
        }]})
        assert targets["urls"] == []
        assert not [t for t in orch.tasks.values() if "discovered services" in t.name]

    def test_network_mode_does_not_bridge(self):
        """NETWORK mode has no web scanners in its pipeline, so deriving web URLs
        would be wasted work — the bridge must stay a no-op there."""
        targets = {"ips": ["192.168.1.50"], "urls": [], "ports": "1-1000",
                   "stealth_level": "normal"}
        orch = build_full_scan(targets, scan_mode=ScanMode.NETWORK)
        orch._inject_service_tasks(self._WEB_HOSTS)
        assert targets["urls"] == []
        assert not [t for t in orch.tasks.values() if "discovered services" in t.name]

    def test_derived_crawl_runs_before_vuln_scan(self):
        """The injected crawl must land in a phase that executes before VULN_SCAN
        so its endpoints are available when the web scanners gather targets."""
        from heaven.orchestrator import ScanPhase

        targets = {"ips": ["192.168.1.50"], "urls": [], "ports": "1-1000",
                   "stealth_level": "normal"}
        orch = build_full_scan(targets, scan_mode=ScanMode.FULL)
        orch._inject_service_tasks(self._WEB_HOSTS)
        crawl = [t for t in orch.tasks.values() if "discovered services" in t.name][0]

        order = [
            ScanPhase.INIT, ScanPhase.RECON, ScanPhase.AI_PARSE, ScanPhase.AD_RECON,
            ScanPhase.IOT_SCAN, ScanPhase.VULN_SCAN,
        ]
        assert order.index(crawl.phase) < order.index(ScanPhase.VULN_SCAN)
