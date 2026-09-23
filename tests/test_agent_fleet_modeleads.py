"""Phase 2 tests: mode-lead roles + surface fan-out + the mode-sync guarantee.

The point of these tests is the invariant the whole design rests on: the fleet's
set of modes is EXACTLY the scanner's set of modes, and a mode-lead only ever
proposes real per-mode scans of appropriate targets, deduped so it deepens
coverage rather than re-scanning what a full pass already covered.
"""

from __future__ import annotations

from heaven.ai.fleet import (
    AUTH_REQUIRED_MODES,
    BACKEND_MODES,
    FleetState,
    ModeLeadRole,
    all_roles,
    mode_lead_roles,
    roles_for_mode,
)
from heaven.ai.fleet.registry import scope_guard
from heaven.ai.fleet.roles import KIND_SCAN, AgentTask
from heaven.config import ScanMode


# ── scope containment guard ──────────────────────────────────────────────────
def test_scope_guard_contains_never_expands():
    st = FleetState(seed_targets={"ips": ["scanme.nmap.org"]},
                    scope=["10.0.0.0/24"], scope_domains=["corp.example"])
    g = scope_guard(st)
    assert g.allows("scanme.nmap.org")     # the seed itself
    assert g.allows("10.0.0.7")            # a host inside the scoped CIDR
    assert g.allows("host.corp.example")   # a subdomain of the scoped domain
    assert not g.allows("nmap.org")        # the seed's parent domain — never
    assert not g.allows("evil.com")        # unrelated infrastructure — never


# ── the mode-sync guarantee ──────────────────────────────────────────────────
def test_backend_modes_equal_scanmode_minus_full():
    assert set(BACKEND_MODES) == {m.value for m in ScanMode} - {"full"}


def test_one_lead_per_backend_mode():
    leads = mode_lead_roles()
    names = {r.name for r in leads}
    assert names == {f"{m}-lead" for m in BACKEND_MODES}
    assert len(leads) == len(BACKEND_MODES)


def test_full_roster_is_primitives_plus_leads():
    # 5 primitives + 16 backend leads.
    assert len(all_roles()) == 5 + len(BACKEND_MODES)
    assert len(roles_for_mode("full")) == 5 + len(BACKEND_MODES)


def test_focused_mode_runs_its_lead_only():
    web = {r.name for r in roles_for_mode("web")}
    assert "web-lead" in web
    assert "network-lead" not in web
    assert "api-lead" not in web


# ── target suitability ───────────────────────────────────────────────────────
async def test_web_lead_fans_out_urls_not_hosts():
    st = FleetState(scope=["http://t/a", "10.0.0.5"], active_mode="web")
    tasks = await ModeLeadRole("web").propose(st, None)
    targets = {t.target for t in tasks}
    assert "http://t/a" in targets
    assert "10.0.0.5" not in targets  # a web scan needs a URL
    assert all(t.kind == KIND_SCAN and t.mode == "web" for t in tasks)


async def test_network_lead_fans_out_hosts_not_urls():
    st = FleetState(scope=["http://t/a", "10.0.0.5"], active_mode="full")
    tasks = await ModeLeadRole("network").propose(st, None)
    targets = {t.target for t in tasks}
    assert "10.0.0.5" in targets
    assert "http://t/a" not in targets


async def test_exploit_lead_requires_auth():
    # Authorized run: the exploit lead fans out and flags its tasks for the gate.
    st = FleetState(scope=["10.0.0.5"], active_mode="exploit", authorized=True)
    (t,) = await ModeLeadRole("exploit").propose(st, None)
    assert t.requires_auth is True
    assert "exploit" in AUTH_REQUIRED_MODES


async def test_exploit_lead_stands_down_when_read_only():
    # Read-only run: the exploit lead proposes nothing (the scheduler would only
    # refuse it), so a read-only fleet run is quiet, not noisy.
    st = FleetState(scope=["10.0.0.5"], active_mode="exploit", authorized=False)
    assert await ModeLeadRole("exploit").propose(st, None) == []


async def test_code_analysis_leads_are_dormant_without_repo():
    # devsecops / ci have no network target type; they no-op on a host/URL surface.
    st = FleetState(scope=["http://t/a", "10.0.0.5"], active_mode="full")
    assert await ModeLeadRole("devsecops").propose(st, None) == []
    assert await ModeLeadRole("ci").propose(st, None) == []


# ── dedup / fan-out semantics ────────────────────────────────────────────────
async def test_lead_skips_target_already_scanned_in_full():
    hist = [AgentTask(kind=KIND_SCAN, target="10.0.0.5", mode="full")]
    st = FleetState(scope=["10.0.0.5"], active_mode="full", history=hist)
    # A full scan already covered this host, so the network lead adds nothing.
    assert await ModeLeadRole("network").propose(st, None) == []


async def test_lead_skips_target_already_scanned_in_its_mode():
    hist = [AgentTask(kind=KIND_SCAN, target="10.0.0.5", mode="network")]
    st = FleetState(scope=["10.0.0.5"], active_mode="network", history=hist)
    assert await ModeLeadRole("network").propose(st, None) == []


async def test_lead_fans_out_to_discovered_host_in_scope():
    # A finding surfaced a NEW host that falls inside a seeded CIDR → the lead
    # deepens onto it. This is how a run grows past its seeds — but only within
    # the scope the operator authorised.
    findings = [{"id": "1", "target": "10.9.9.9", "severity": "high", "confidence": 0.9}]
    st = FleetState(findings=findings, seed_targets={"ips": ["10.9.9.0/24"]},
                    active_mode="full")
    tasks = await ModeLeadRole("network").propose(st, None)
    assert "10.9.9.9" in {t.target for t in tasks}


async def test_lead_skips_discovered_host_out_of_scope():
    # A finding on the seed surfaced an UNRELATED host (a redirect target, a cert
    # SAN, the parent domain). It is NOT in authorised scope, so the fleet never
    # auto-scans it — the seed itself is still covered.
    findings = [{"id": "1", "target": "nmap.org", "severity": "high", "confidence": 0.9}]
    st = FleetState(findings=findings, seed_targets={"ips": ["scanme.nmap.org"]},
                    active_mode="network")
    targets = {t.target for t in await ModeLeadRole("network").propose(st, None)}
    assert "nmap.org" not in targets           # out-of-scope discovery refused
    assert "scanme.nmap.org" in targets        # the authorised seed is still scanned


async def test_lead_fans_out_to_subdomain_of_scoped_domain():
    # The operator deliberately scoped a domain subdomain-wide (kind='domain'); a
    # discovered subdomain of it is in scope and gets deepened onto.
    findings = [{"id": "1", "target": "http://api.example.com/x", "severity": "high",
                 "confidence": 0.9}]
    st = FleetState(findings=findings, scope_domains=["example.com"], active_mode="web")
    targets = {t.target for t in await ModeLeadRole("web").propose(st, None)}
    assert "http://api.example.com/x" in targets


async def test_fanout_is_capped(monkeypatch):
    monkeypatch.setenv("HEAVEN_FLEET_FANOUT_CAP", "3")
    hosts = [f"10.0.0.{i}" for i in range(20)]
    st = FleetState(scope=hosts, active_mode="network")
    tasks = await ModeLeadRole("network").propose(st, None)
    assert len(tasks) == 3
