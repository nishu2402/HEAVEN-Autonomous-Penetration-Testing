"""P1 — Dynamic closed-loop tests.

Covers the feedback engine that turns HEAVEN from a one-shot pipeline into a
scan that reacts to its own discoveries:

* :class:`ScopeGuard` — a derived host is actioned only when it is already
  inside the operator's authorised scope (never widened);
* :class:`FeedbackEngine` — lead extraction from task results / findings, dedup,
  the fan-out caps, and drain idempotency;
* ``resolve_js_endpoint`` — JS-bundle strings resolve to absolute, same-origin
  URLs and third-party / noise matches are dropped;
* the orchestrator wiring — a feedback cycle appends JS URLs into the shared
  targets list and queues a follow-up scan task for a newly-discovered in-scope
  host, while an out-of-scope host is silently ignored.
"""
from __future__ import annotations

import asyncio


from heaven.feedback import (
    CRED,
    HOST,
    TOKEN,
    URL,
    FeedbackEngine,
    ScopeGuard,
    resolve_js_endpoint,
)
from heaven.orchestrator import (
    ScanOrchestrator,
    ScanPhase,
    TaskResult,
    TaskState,
)


# ── ScopeGuard ───────────────────────────────────────────────────────────────

def test_scope_guard_domain_and_subdomain():
    g = ScopeGuard({"domains": ["example.com"], "urls": ["https://app.example.com/"]})
    assert g.allows("example.com")
    assert g.allows("api.example.com")       # subdomain of in-scope domain
    assert g.allows("app.example.com")       # exact from URL
    assert not g.allows("example.org")       # different registrable domain
    assert not g.allows("notexample.com")    # not a subdomain (suffix trick)


def test_scope_guard_ip_and_cidr():
    g = ScopeGuard({"ips": ["10.0.0.0/24", "192.168.1.5"]})
    assert g.allows("10.0.0.42")             # inside the CIDR
    assert g.allows("192.168.1.5")           # exact IP
    assert not g.allows("10.0.1.42")         # outside the CIDR
    assert not g.allows("8.8.8.8")           # unrelated public IP


def test_scope_guard_strips_scheme_and_port():
    g = ScopeGuard({"urls": ["https://target.tld:8443/app"]})
    assert g.allows("http://target.tld:9000/other")
    assert g.allows("target.tld")


# ── FeedbackEngine lead extraction ───────────────────────────────────────────

def _engine(**scope):
    return FeedbackEngine(scope or {"domains": ["example.com"], "ips": ["10.0.0.0/24"]})


def test_engine_extracts_hosts_urls_creds_tokens():
    eng = _engine()
    data = {
        "hosts": [{"host": "web.example.com"}, {"ip": "10.0.0.9"}],
        "js_endpoints": ["https://app.example.com/api/users"],
        "endpoints": [{"url": "https://app.example.com/login"}],
        "credentials": [{"username": "admin", "password": "hunter2"}],
        # A JWT embedded in some evidence blob.
        "evidence": "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456",
    }
    eng.ingest_result(data)
    kinds = {lead.kind for lead in eng.drain()}
    assert HOST in kinds and URL in kinds and CRED in kinds and TOKEN in kinds
    assert "web.example.com" in eng.hosts
    assert "10.0.0.9" in eng.hosts
    assert ("admin", "hunter2") in eng.creds
    assert eng.tokens  # at least the JWT


def test_engine_drops_out_of_scope_host():
    eng = _engine()
    eng.ingest_result({"hosts": [{"host": "evil.attacker.tld"}]})
    assert eng.drain() == []                 # nothing actioned
    assert "evil.attacker.tld" in eng.out_of_scope_hosts


def test_engine_dedup_across_ingests():
    eng = _engine()
    eng.ingest_result({"hosts": [{"host": "web.example.com"}]})
    first = eng.drain()
    # Same host again on a later result → no new lead.
    eng.ingest_result({"hosts": [{"host": "web.example.com"}]})
    assert first and eng.drain() == []


def test_engine_drain_is_idempotent():
    eng = _engine()
    eng.ingest_result({"endpoints": [{"url": "https://app.example.com/a"}]})
    assert len(eng.drain()) == 1
    assert eng.drain() == []                 # already drained


def test_engine_host_cap_bounds_fanout():
    eng = FeedbackEngine({"domains": ["example.com"]})
    eng.MAX_HOSTS = 3
    for i in range(10):
        eng.ingest_result({"hosts": [{"host": f"h{i}.example.com"}]})
    assert len(eng.hosts) == 3               # capped


def test_engine_generation_limit_stops_derived_chains():
    eng = _engine()
    # A lead at a generation past the limit is never emitted.
    out = eng.ingest_result({"hosts": [{"host": "deep.example.com"}]},
                            generation=eng._max_generations + 1)
    assert out == []


def test_engine_finding_host_and_token():
    eng = _engine()
    eng.ingest_finding({
        "vuln_type": "ssrf",
        "target": "https://web.example.com:8080/fetch",
        "evidence": "Authorization: Bearer sk-abc123DEF456ghi789",
    })
    leads = eng.drain()
    assert any(lead.kind == HOST and lead.value == "web.example.com" for lead in leads)
    assert any(lead.kind == TOKEN for lead in leads)


def test_engine_never_requeues_a_seed_host():
    """A seed target is echoed back as every finding's ``target`` and in the
    network result's ``hosts`` — it must NOT become a follow-up HOST lead (it was
    already scanned). This is the regression guard for the DYNAMIC_FOLLOWUP phase
    redundantly re-scanning the seed host across thousands of ports (the "scan
    stuck at ~44%, nothing new" symptom)."""
    eng = FeedbackEngine({"ips": ["192.168.0.162"]})
    # The network scan lists the scanned seed under "hosts"…
    eng.ingest_result({"hosts": [{"ip": "192.168.0.162", "open_ports": [{"port": 80}]}]})
    # …and every finding on it carries it as target (including a URL form).
    eng.ingest_finding({"vuln_type": "vulnerable_service", "target": "192.168.0.162"})
    eng.ingest_finding({"vuln_type": "x", "target": "http://192.168.0.162:80/"})
    host_leads = [lead for lead in eng.drain() if lead.kind == HOST]
    assert host_leads == [], f"seed host was re-queued: {[h.value for h in host_leads]}"
    assert "192.168.0.162" not in eng.hosts


def test_engine_still_follows_genuinely_new_in_scope_host():
    """A host that was NOT a seed (discovered inside an in-scope CIDR) must still
    be followed up — the seed-exclusion must not suppress real new hosts."""
    eng = FeedbackEngine({"ips": ["10.0.0.0/24"]})
    eng.ingest_result({"hosts": [{"ip": "10.0.0.7", "open_ports": [{"port": 22}]}]})
    new_hosts = [lead.value for lead in eng.drain() if lead.kind == HOST]
    assert new_hosts == ["10.0.0.7"]
    # …but only once — a later reference to it is not re-queued.
    eng.ingest_finding({"vuln_type": "y", "target": "10.0.0.7"})
    assert [lead for lead in eng.drain() if lead.kind == HOST] == []


# ── resolve_js_endpoint ──────────────────────────────────────────────────────

def test_resolve_js_relative_to_absolute_same_origin():
    r = resolve_js_endpoint("/api/v2/users", "https://app.tld/static/main.js")
    assert r == "https://app.tld/api/v2/users"


def test_resolve_js_absolute_same_origin_kept():
    r = resolve_js_endpoint("https://app.tld/api/orders", "https://app.tld/static/main.js")
    assert r == "https://app.tld/api/orders"


def test_resolve_js_third_party_dropped():
    assert resolve_js_endpoint("https://cdn.other.tld/lib.js",
                               "https://app.tld/static/main.js") is None


def test_resolve_js_noise_dropped():
    # jQuery event names / bare words / asset files are not endpoints.
    for noise in ("click", "submit", "app.png", "text/html", "{id}"):
        assert resolve_js_endpoint(noise, "https://app.tld/main.js") is None


# ── Orchestrator feedback cycle wiring ───────────────────────────────────────

def _completed(name, data):
    return TaskResult(task_id=name, name=name, state=TaskState.COMPLETED, data=data)


def _make_orch(targets):
    orch = ScanOrchestrator()
    orch.scan_targets = targets
    orch.feedback = FeedbackEngine(targets)
    return orch


def test_feedback_cycle_appends_js_urls_to_targets():
    targets = {"urls": ["https://app.example.com/"], "domains": ["example.com"]}
    orch = _make_orch(targets)
    orch.results["crawl"] = _completed("crawl", {
        "js_endpoints": ["https://app.example.com/api/hidden",
                         "https://app.example.com/api/admin"],
    })
    orch._feedback_cycle(ScanPhase.AI_PARSE)
    assert "https://app.example.com/api/hidden" in targets["urls"]
    assert "https://app.example.com/api/admin" in targets["urls"]


def test_feedback_cycle_queues_followup_for_in_scope_host():
    targets = {"urls": ["https://app.example.com/"], "domains": ["example.com"]}
    orch = _make_orch(targets)
    orch.results["recon"] = _completed("recon", {
        "hosts": [{"host": "intranet.example.com"}],
    })
    before = len(orch.tasks)
    orch._feedback_cycle(ScanPhase.RECON)
    followups = [t for t in orch.tasks.values()
                 if t.phase == ScanPhase.DYNAMIC_FOLLOWUP]
    assert len(orch.tasks) == before + 1
    assert followups and "intranet.example.com" in followups[0].name


def test_feedback_cycle_ignores_out_of_scope_host():
    targets = {"urls": ["https://app.example.com/"], "domains": ["example.com"]}
    orch = _make_orch(targets)
    orch.results["loot"] = _completed("loot", {
        "hosts": [{"host": "10.9.9.9"}, {"host": "evil.other.tld"}],
    })
    orch._feedback_cycle(ScanPhase.VULN_SCAN)
    followups = [t for t in orch.tasks.values()
                 if t.phase == ScanPhase.DYNAMIC_FOLLOWUP]
    assert followups == []                   # neither host is in scope


def test_feedback_cycle_no_duplicate_followup_for_same_host():
    targets = {"domains": ["example.com"]}
    orch = _make_orch(targets)
    orch.results["r1"] = _completed("r1", {"hosts": [{"host": "a.example.com"}]})
    orch._feedback_cycle(ScanPhase.RECON)
    orch.results["r2"] = _completed("r2", {"hosts": [{"host": "a.example.com"}]})
    orch._feedback_cycle(ScanPhase.VULN_SCAN)
    followups = [t for t in orch.tasks.values()
                 if t.phase == ScanPhase.DYNAMIC_FOLLOWUP]
    assert len(followups) == 1               # queued exactly once


def test_feedback_cycle_never_followups_the_seed_host():
    """End-to-end guard for the reported bug: scanning a single IP surfaced that
    same IP (via its findings + network result) as a "newly-discovered" host and
    queued a full DYNAMIC_FOLLOWUP re-scan of it. The seed must never get a
    follow-up task."""
    targets = {"ips": ["192.168.0.162"]}
    orch = _make_orch(targets)
    orch.results["net"] = _completed("net", {
        "hosts": [{"ip": "192.168.0.162", "open_ports": [{"port": 80}]}],
    })
    orch.results["vuln"] = _completed("vuln", {
        "findings": [{"vuln_type": "vulnerable_service", "target": "192.168.0.162"}],
    })
    before = len(orch.tasks)
    orch._feedback_cycle(ScanPhase.VULN_SCAN)
    followups = [t for t in orch.tasks.values()
                 if t.phase == ScanPhase.DYNAMIC_FOLLOWUP]
    assert followups == []                   # the seed is never re-scanned
    assert len(orch.tasks) == before


def test_scan_new_host_degrades_when_recon_empty(monkeypatch):
    # No open ports discovered → returns the base structure, never raises.
    import heaven.recon.network_scanner as ns

    async def _empty(*a, **kw):
        return {"hosts": []}

    monkeypatch.setattr(ns, "scan_network", _empty)
    orch = _make_orch({"domains": ["example.com"]})
    out = asyncio.run(orch._scan_new_host("intranet.example.com"))
    assert out["followup_host"] == "intranet.example.com"
    assert out["endpoints"] == [] and out["findings"] == []
