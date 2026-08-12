"""Perimeter-defence detection + adaptive evasion re-probe.

Covers the "the box is vulnerable but the scan found nothing because a firewall
is dropping probes" problem end to end:

* :mod:`heaven.recon.firewall_detector` — the read-only classifier (firewall /
  IDS-IPS / tarpit / WAF), its precision (a normal, closed-heavy host is NOT
  flagged), the WAF fingerprinter, and the informational-finding synthesis;
* the nmap parse now counting ``filtered`` / ``closed`` states (the firewall
  signal) and the evasion-flag builder;
* :func:`scan_network`'s adaptive pass: a filtered host triggers a bounded
  evasion re-probe that recovers ports the initial scan could not see;
* the live-count store reconcile primitives that keep the web scan count from
  ballooning (dedup + prune to the authoritative survivor set).
"""
from __future__ import annotations

import asyncio

import heaven.recon.network_scanner as ns
from heaven.recon.firewall_detector import (
    POSTURE_FIREWALL,
    POSTURE_IDS_IPS,
    POSTURE_TARPIT,
    POSTURE_WAF,
    build_perimeter_findings,
    classify_perimeter,
    waf_signature,
)


# ── classifier: precision + each posture ─────────────────────────────────────

def test_classify_firewall_from_filtered_dominance():
    v = classify_perimeter("10.0.0.5", open_count=1, filtered_count=900,
                            closed_count=2, total_probed=1000, reachable=True)
    assert v.posture == POSTURE_FIREWALL and v.detected
    assert v.confidence >= 0.8
    assert v.evasion_recommended is True
    assert "filtered" in " ".join(v.indicators).lower()


def test_classify_normal_host_is_not_flagged():
    # Metasploitable-style: closed-heavy (RST), some open, zero filtered → the
    # perimeter classifier must stay silent so a clean scan gains no false note.
    v = classify_perimeter("192.168.0.162", open_count=23, filtered_count=0,
                           closed_count=65500, total_probed=65535, reachable=True)
    assert v.detected is False
    assert v.posture == "none"


def test_classify_ids_ips_from_blocking_trajectory():
    v = classify_perimeter("10.0.0.6", open_count=3, filtered_count=0,
                           closed_count=5, total_probed=20, reachable=True,
                           blocking_trajectory=True)
    assert v.posture == POSTURE_IDS_IPS and v.detected
    assert v.evasion_recommended is True


def test_classify_tarpit_from_uniform_slow_responses():
    v = classify_perimeter("10.0.0.7", open_count=8, filtered_count=0,
                           closed_count=0, total_probed=8, reachable=True,
                           response_times_ms=[5000, 6000, 5500, 4800])
    assert v.posture == POSTURE_TARPIT and v.detected
    # A tarpit is NOT worth an evasion re-probe (it just wastes more time).
    assert v.evasion_recommended is False


def test_classify_waf_from_http_signature():
    vendor, ind = waf_signature({"Server": "cloudflare", "CF-RAY": "abc123"}, 403)
    assert vendor == "Cloudflare" and ind
    v = classify_perimeter("app.example.com", open_count=2, filtered_count=0,
                           closed_count=5, total_probed=10, reachable=True,
                           http=(vendor, ind))
    assert v.posture == POSTURE_WAF and v.detected
    # A WAF is an HTTP-layer control — the port scan already saw past it.
    assert v.evasion_recommended is False


def test_waf_signature_no_match():
    vendor, ind = waf_signature({"Server": "nginx/1.25"}, 200)
    assert vendor == "" and ind == []


def test_classify_unreachable_host_no_false_posture():
    v = classify_perimeter("10.0.0.9", open_count=0, filtered_count=0,
                           closed_count=0, total_probed=1000, reachable=False)
    assert v.detected is False


# ── finding synthesis ────────────────────────────────────────────────────────

def test_build_perimeter_findings_emits_for_detected_host():
    v = classify_perimeter("10.0.0.5", open_count=0, filtered_count=800,
                           closed_count=1, total_probed=1000, reachable=True)
    nd = {"perimeter": {"detected": True, "hosts": {"10.0.0.5": v.to_dict()}}}
    findings = build_perimeter_findings(nd)
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"] == "perimeter_defense"
    assert f["target"] == "10.0.0.5"
    assert "evade" in f["description"].lower() or "evasion" in f["description"].lower()


def test_build_perimeter_findings_empty_when_none_detected():
    assert build_perimeter_findings({"perimeter": {"detected": False, "hosts": {}}}) == []
    assert build_perimeter_findings({}) == []


def test_perimeter_finding_enriches_with_taxonomy_and_survives_dedup():
    from heaven.devsecops.vuln_kb import enrich_finding
    from heaven.engagement import _is_junk_finding, dedup_findings
    v = classify_perimeter("10.0.0.5", open_count=0, filtered_count=800,
                           closed_count=1, total_probed=1000, reachable=True)
    f = build_perimeter_findings(
        {"perimeter": {"detected": True, "hosts": {"10.0.0.5": v.to_dict()}}})[0]
    e = enrich_finding(dict(f))
    assert e.get("mitre_technique")                    # taxonomy attached, never blank
    assert e["evidence"].get("remediation")            # actionable guidance present
    assert _is_junk_finding(e) is False
    assert len(dedup_findings([e])) == 1               # not dropped by dedup


# ── nmap parse: filtered / closed tallies (the firewall signal) ──────────────

_FILTERED_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn">
 <host>
  <status state="up" reason="user-set"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <ports>
   <extraports state="filtered" count="997"/>
   <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
   <port protocol="tcp" portid="22"><state state="filtered"/></port>
   <port protocol="tcp" portid="23"><state state="closed"/></port>
  </ports>
 </host>
</nmaprun>"""


def test_parse_counts_filtered_and_closed():
    parsed = ns._parse_nmap_xml(_FILTERED_XML, "10.0.0.5")
    assert parsed is not None
    assert len(parsed["ports"]) == 1                   # only the one open port
    assert parsed["filtered_count"] == 998             # 997 bulk + 1 individual
    assert parsed["closed_count"] == 1


# ── evasion-flag builder ─────────────────────────────────────────────────────

def test_evasion_args_privileged_include_fragmentation_and_decoys():
    args = ns._nmap_evasion_args(raw_capable=True)
    assert "-f" in args and "-D" in args and "--source-port" in args


def test_evasion_args_unprivileged_only_source_port():
    args = ns._nmap_evasion_args(raw_capable=False)
    # Connect scan can't fragment/decoy (no raw sockets) — only the trusted
    # source port survives, and nothing that would silently break the scan.
    assert args == ["--source-port", "53"]
    assert "-f" not in args and "-D" not in args


# ── scan_network adaptive re-probe (mocked host scan) ────────────────────────

def test_scan_network_evasion_reprobe_recovers_filtered_ports(monkeypatch):
    """A host whose ports are all filtered on the first pass triggers a bounded
    evasion re-probe that recovers a real open port — the core "still get
    findings through a firewall" behaviour."""
    calls = {"initial": 0, "evade": 0}

    async def fake_scan_host(host, ports, **kw):
        r = ns.HostResult(host=host)
        if kw.get("evade"):
            calls["evade"] += 1
            r.open_ports = [ns.PortResult(host=host, port=445, protocol="tcp",
                                          state="open", service="microsoft-ds")]
            r.is_alive = True
        else:
            calls["initial"] += 1
            r.filtered_ports = 900
            r.closed_ports = 1
        return r

    async def fake_connect(host, ports, **kw):
        return []

    monkeypatch.setattr(ns, "scan_host", fake_scan_host)
    monkeypatch.setattr(ns, "_python_connect_scan", fake_connect)

    out = asyncio.run(ns.scan_network(["10.0.0.5"], port_range="1-1000",
                                      passive_enrich=False))
    assert calls["evade"] >= 1                          # evasion re-probe fired
    host = out["hosts"][0]
    assert 445 in [p["port"] for p in host["open_ports"]]   # port recovered
    assert out["perimeter"]["detected"] is True
    assert host["perimeter"]["posture"] == POSTURE_FIREWALL


def test_scan_network_normal_host_no_reprobe(monkeypatch):
    """A closed-heavy (normal) host must NOT trigger an evasion re-probe."""
    calls = {"evade": 0}

    async def fake_scan_host(host, ports, **kw):
        r = ns.HostResult(host=host)
        if kw.get("evade"):
            calls["evade"] += 1
        r.open_ports = [ns.PortResult(host=host, port=80, protocol="tcp",
                                      state="open", service="http")]
        r.closed_ports = 999
        r.is_alive = True
        return r

    monkeypatch.setattr(ns, "scan_host", fake_scan_host)
    out = asyncio.run(ns.scan_network(["10.0.0.8"], port_range="1-1000",
                                      passive_enrich=False))
    assert calls["evade"] == 0
    assert out["perimeter"]["detected"] is False


# ── live-count store reconcile (the balloon fix's building blocks) ───────────

def test_store_reconcile_tracks_deduped_survivors_not_raw_candidates(tmp_path):
    """The web live flush upserts the dedup_findings() survivors and prunes the
    rest each tick, so the count tracks the authoritative set — not the raw
    candidate stream that later collapses. This proves the primitives it uses."""
    from heaven.engagement import EngagementStore, dedup_findings
    store = EngagementStore(tmp_path / "e.db")
    store.record_scan_start("s1")

    # A raw candidate emitted early, plus TWO real findings.
    candidate = {"target": "10.0.0.5", "vuln_type": "sqli",
                 "title": "SQLi?", "confidence": 0.4}
    real1 = {"target": "10.0.0.5", "vuln_type": "cleartext_service",
             "title": "Telnet", "port": 23, "confidence": 0.9}
    real2 = {"target": "10.0.0.5", "vuln_type": "ftp_anonymous",
             "title": "Anon FTP", "port": 21, "confidence": 0.9}

    # Tick 1: candidate + reals present, nothing suppressed yet.
    union = [candidate, real1, real2]
    keep = {store.upsert_finding("s1", f) for f in dedup_findings(union)}
    store.prune_scan_findings("s1", keep)
    assert store.count_findings("s1") == 3

    # Tick 2: the validator emits the candidate's suppressed twin → the whole
    # identity is dropped. The reconcile removes it live; count converges to 2
    # instead of the store keeping a superseded row until completion.
    suppressed_twin = dict(candidate, suppressed=True)
    union = [candidate, real1, real2, suppressed_twin]
    keep = {store.upsert_finding("s1", f) for f in dedup_findings(union)}
    store.prune_scan_findings("s1", keep)
    assert store.count_findings("s1") == 2
