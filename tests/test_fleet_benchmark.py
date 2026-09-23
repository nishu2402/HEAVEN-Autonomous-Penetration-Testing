"""Tests for the Agent Fleet benchmark harness (``scripts/fleet_benchmark.py``).

The benchmark's live run needs a network; its comparison CORE is a pure function
over finding lists, which is what decides PASS/FAIL. These tests pin that decision
logic so the gate can never silently drift — a real regression (fleet loses a
baseline finding, invents an unsourced one, or fans out of scope) must FAIL, and a
clean superset with in-scope fan-out must PASS.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fleet_benchmark.py"


def _load():
    spec = importlib.util.spec_from_file_location("_fleet_benchmark", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass field-type resolution (which looks the
    # module up in sys.modules) works for the module's Optional-typed fields.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


bench = _load()


def _f(target, vuln="open_port", cve="", scan_id="s1", **extra):
    # A persisted finding's provenance is its detector class + the scan that
    # produced it (the store has no `source` column), so the fixtures carry those.
    d = {"target": target, "vuln_type": vuln, "cve_id": cve, "scan_id": scan_id}
    d.update(extra)
    return d


def test_superset_with_inscope_fanout_passes():
    """Fleet recovers every baseline finding AND deepens onto an in-scope host."""
    baseline = [_f("scanme.nmap.org", "ssh_weak_algos"), _f("scanme.nmap.org", "http_title")]
    fleet = baseline + [_f("scanme.nmap.org", "extra_service"),
                        _f("10.0.0.5", "smb_signing")]  # in-scope fan-out
    res = bench.compare(
        baseline, fleet,
        seed_hosts={"scanme.nmap.org"},
        in_scope_hosts={"scanme.nmap.org", "10.0.0.5"},
    )
    assert res.verdict == "PASS"
    assert res.recall == 1.0
    assert res.recovered == 2
    assert res.fleet_on_seed == 3          # 2 baseline + 1 extra on the seed host
    assert res.fan_out_findings == 1       # only the discovered 10.0.0.5 host
    assert res.fan_out_hosts == ["10.0.0.5"]
    assert res.out_of_scope_hosts == []
    assert res.provenance_ok is True


def test_missed_baseline_finding_fails_recall():
    baseline = [_f("scanme.nmap.org", "ssh_weak_algos"), _f("scanme.nmap.org", "http_title")]
    fleet = [_f("scanme.nmap.org", "ssh_weak_algos")]  # lost http_title
    res = bench.compare(baseline, fleet, seed_hosts={"scanme.nmap.org"},
                        in_scope_hosts={"scanme.nmap.org"})
    assert res.verdict == "FAIL"
    assert res.recall == 0.5
    assert len(res.missed) == 1
    assert any("http_title" in part for part in res.missed[0])


def test_unsourced_finding_fails_provenance():
    """A fleet finding with no detector class / scan id is an honesty-gate breach
    (no oracle stands behind it) → FAIL."""
    baseline = [_f("scanme.nmap.org", "ssh_weak_algos")]
    fleet = [_f("scanme.nmap.org", "ssh_weak_algos"),
             {"target": "scanme.nmap.org", "vuln_type": "", "scan_id": ""}]  # agent-authored?
    res = bench.compare(baseline, fleet, seed_hosts={"scanme.nmap.org"},
                        in_scope_hosts={"scanme.nmap.org"})
    assert res.verdict == "FAIL"
    assert res.provenance_ok is False
    assert res.unsourced  # names the offending finding


def test_out_of_scope_fanout_fails():
    """A host the FLEET reaches that the baseline does NOT, and that is not in
    authorised scope, is a real fleet-introduced scope leak → FAIL."""
    baseline = [_f("scanme.nmap.org", "ssh_weak_algos")]
    fleet = baseline + [_f("evil.example", "vulnerable_service")]  # fleet-only, unscoped
    res = bench.compare(baseline, fleet, seed_hosts={"scanme.nmap.org"},
                        in_scope_hosts={"scanme.nmap.org"})
    assert res.verdict == "FAIL"
    assert "evil.example" in res.out_of_scope_hosts
    assert "evil.example" in res.fleet_only_hosts


def test_shared_offseed_host_is_not_a_leak():
    """The real scanme.nmap.org case: the classic pipeline itself does passive
    DNS-zone recon on the parent domain, so nmap.org is a BASELINE host too. The
    fleet matching that exactly is not a fleet-introduced expansion → PASS."""
    baseline = [_f("scanme.nmap.org", "ssh_weak_algos"),
                _f("nmap.org", "dmarc_missing"), _f("nmap.org", "spf_soft_fail")]
    fleet = list(baseline)  # fleet == baseline, including the parent-zone recon
    res = bench.compare(baseline, fleet, seed_hosts={"scanme.nmap.org"},
                        in_scope_hosts={"scanme.nmap.org"})
    assert res.verdict == "PASS"
    assert res.recall == 1.0
    assert res.fan_out_hosts == ["nmap.org"]     # reported as discovered surface
    assert res.fleet_only_hosts == []            # but baseline reaches it too
    assert res.out_of_scope_hosts == []          # so it is not a leak


def test_empty_baseline_is_vacuous_pass():
    """No baseline findings (e.g. a firewalled host) → recall is vacuously 1.0 and
    the gate rests on provenance + scope only."""
    res = bench.compare([], [_f("scanme.nmap.org", "http_title")],
                        seed_hosts={"scanme.nmap.org"},
                        in_scope_hosts={"scanme.nmap.org"})
    assert res.recall == 1.0
    assert res.verdict == "PASS"


def test_vuln_type_and_scan_id_count_as_provenance():
    """A finding with a detector class and a scan id is sourced — that is the real
    per-finding provenance on a persisted row (there is no `source` column)."""
    baseline = [_f("scanme.nmap.org", "ssh")]
    fleet = [_f("scanme.nmap.org", "ssh"),
             {"target": "scanme.nmap.org", "vuln_type": "vulnerable_service",
              "scan_id": "fleet-abc"}]
    res = bench.compare(baseline, fleet, seed_hosts={"scanme.nmap.org"},
                        in_scope_hosts={"scanme.nmap.org"})
    assert res.provenance_ok is True


def test_signature_normalises_url_and_host():
    """A URL finding and a bare-host finding for the same host/vuln share a
    signature, so baseline (host) and fleet (URL) line up."""
    s_host = bench.finding_signature(_f("scanme.nmap.org", "http_title"))
    s_url = bench.finding_signature(_f("http://scanme.nmap.org/", "http_title"))
    assert s_host[0] == s_url[0] == "scanme.nmap.org"
