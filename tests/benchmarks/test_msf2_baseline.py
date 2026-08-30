"""
HEAVEN vs. Metasploitable-2 — network / service-tier benchmark.

This is the service-tier analogue of the DVWA web benchmark. It scores HEAVEN's
recall / precision on host:port service findings (backdoors, RCE service CVEs,
default credentials, cleartext protocols, EOL software) against a labelled
ground truth (``ground_truth/msf2.yaml``), using the SAME metrics layer the DVWA
and native benchmarks use — so the network number is produced by exactly the
same scoring code, not a parallel one.

Two kinds of test live here:

  * Always-on (CI, no VM): the ground truth parses, a recorded-shape fixture
    replays to a perfect score, and the new (port, category) matcher obeys its
    rules. These protect the metrics extension + ground truth without the VM.

  * Gated live run: an actual ``heaven scan -m network`` against a reachable
    Metasploitable-2 host, scored end to end. The VM is NOT bundled — you point
    the benchmark at your own authorised lab:

        HEAVEN_RUN_BENCHMARKS=1 HEAVEN_MSF2_TARGET=192.168.0.162 \\
          ./venv/bin/python -m pytest tests/benchmarks/test_msf2_baseline.py -v -s

    Optional env vars:
        HEAVEN_MSF2_PORTS         : port range/list to scan (default covers every
                                    signature service; see _DEFAULT_PORTS)
        HEAVEN_BENCH_RUNS         : repeat N times for mean±stddev (default 1)
        HEAVEN_BENCH_SCAN_TIMEOUT : per-scan timeout in seconds (default 1200)
        HEAVEN_BENCH_REPORT_DIR   : where to save reports
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from tests.benchmarks.metrics import (
    Finding,
    GroundTruth,
    GroundTruthEntry,
    aggregate,
    evaluate,
    matches,
)


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_GT_PATH = Path(__file__).parent / "ground_truth" / "msf2.yaml"
_DEFAULT_REPORT_DIR = _PROJECT_ROOT / "tests" / "benchmarks" / "reports"

# Every port a ground-truth entry lives on, plus SMB/445 and UnrealIRCd/6667 that
# surface host-level facts. Scanning this explicit set makes the benchmark fast
# and deterministic while still covering every signature service.
_DEFAULT_PORTS = (
    "21,22,23,53,80,111,139,445,512,513,514,1099,1524,2049,2121,"
    "3306,3632,5432,5900,6000,6667,8009,8180,8787"
)


# ═══════════════════════════════════════════════════════════════════════════
# Ground truth + fixture (always-on; no VM required)
# ═══════════════════════════════════════════════════════════════════════════


def _load_gt() -> GroundTruth:
    pytest.importorskip("yaml")
    return GroundTruth.load(_GT_PATH)


def test_msf2_ground_truth_parses_and_is_network_tier() -> None:
    """The shipped MSF2 ground truth must load, validate, and be network-tier."""
    gt = _load_gt()
    assert gt.target_app == "metasploitable-2"
    assert len(gt.vulnerabilities) >= 25
    # The signature must-find set — enough distinct criticals to be meaningful.
    assert gt.required_count >= 10
    from tests.benchmarks.metrics import CANONICAL_CATEGORIES
    for e in gt.vulnerabilities:
        assert e.tier == "network", f"{e.id} should be network tier"
        assert e.category in CANONICAL_CATEGORIES, e.category
    # No two entries share a (port, category) key — otherwise one finding would
    # be credited to two entries and the score would be ambiguous.
    keys = [(e.port, e.category) for e in gt.vulnerabilities]
    assert len(keys) == len(set(keys)), "duplicate (port, category) in msf2.yaml"


# A fixture of realistic HEAVEN finding shapes — one per required signature vuln
# plus a few supporting findings — modelled on a real Metasploitable-2 scan. It
# lets CI prove the ground truth + matcher score a correct run at 100/100 without
# needing the live VM.
_FIXTURE_FINDINGS: list[dict] = [
    {"target": "192.168.0.162:21", "vuln_type": "vulnerable_service",
     "severity": "critical", "title": "vsftpd 2.3.4 backdoor command execution"},
    {"target": "192.168.0.162:139", "vuln_type": "vulnerable_service",
     "severity": "critical", "title": "Samba username map script command execution (RCE)"},
    {"target": "192.168.0.162:3632", "vuln_type": "vulnerable_service",
     "severity": "critical", "title": "distccd remote command execution"},
    {"target": "192.168.0.162:1524", "vuln_type": "backdoor_shell",
     "severity": "critical", "title": "Unauthenticated Backdoor Shell (port 1524)"},
    {"target": "192.168.0.162:8787", "vuln_type": "dangerous_service_exposed",
     "severity": "critical", "title": "Distributed Ruby (dRuby) Exposed (port 8787)"},
    {"target": "192.168.0.162:2049", "vuln_type": "nfs_export_exposed",
     "severity": "critical", "title": "NFS Share Exported to the World"},
    {"target": "192.168.0.162:1099", "vuln_type": "dangerous_service_exposed",
     "severity": "high", "title": "Java RMI Registry Exposed (port 1099)"},
    {"target": "192.168.0.162:8180", "vuln_type": "tomcat_manager_default_creds",
     "severity": "critical", "title": "Apache Tomcat Manager Default Credentials"},
    {"target": "192.168.0.162:5432", "vuln_type": "weak_db_credentials",
     "severity": "critical", "title": "PostgreSQL Default Credentials"},
    {"target": "192.168.0.162:5900", "vuln_type": "vnc_weak_credentials",
     "severity": "critical", "title": "VNC Server Accepts a Default Password"},
    {"target": "ssh://192.168.0.162:22", "vuln_type": "default_credentials",
     "severity": "critical", "title": "SSH Default Credentials: user:user"},
    # Supporting findings (labelled, non-required).
    {"target": "192.168.0.162:21", "vuln_type": "cleartext_service",
     "severity": "high", "title": "Cleartext Service Exposed: FTP (port 21)"},
    {"target": "192.168.0.162:21", "vuln_type": "ftp_anonymous",
     "severity": "medium", "title": "Anonymous FTP Login Allowed"},
    {"target": "192.168.0.162:3306", "vuln_type": "unsupported_software",
     "severity": "high", "title": "Unsupported / End-of-Life Software: MySQL 5.0.51"},
    {"target": "192.168.0.162:2121", "vuln_type": "vulnerable_service",
     "severity": "medium", "title": "ProFTPD 1.3.1 mod_sql heap overflow"},
    {"target": "192.168.0.162:2121", "vuln_type": "vulnerable_service",
     "severity": "medium", "title": "ProFTPD 1.3.1 mod_tls buffer overflow"},
    {"target": "192.168.0.162", "vuln_type": "smb_signing_not_required",
     "severity": "high", "title": "SMB Signing Not Required"},
    {"target": "192.168.0.162", "vuln_type": "smb_null_session",
     "severity": "medium", "title": "SMB Null Session Allows Share Enumeration"},
    {"target": "192.168.0.162", "vuln_type": "potential_vulnerable_service",
     "severity": "low", "title": "Potential vulnerable service: Vnc (version unconfirmed)"},
]


def test_msf2_fixture_replays_to_perfect_score() -> None:
    """A correct-shape scan of the signature set scores 100/100 through evaluate().

    This is the end-to-end wiring proof for CI: ground truth + Finding.from_heaven
    (port parsing) + the network matcher must credit every signature vuln as a
    required TP and leave zero unmatched findings.
    """
    gt = _load_gt()
    findings = [Finding.from_heaven(d) for d in _FIXTURE_FINDINGS]
    result = evaluate(findings, gt)

    assert result.recall == pytest.approx(1.0), (
        f"missed required: {sorted(set(e.id for e in gt.vulnerabilities if e.detection_required) - result.detected_required_ids)}"
    )
    assert result.precision == pytest.approx(1.0), (
        f"unmatched (each an FP to fix or a real finding to label): "
        f"{[(f.category, f.port, f.url) for f in result.unmatched_findings]}"
    )
    # Two ProFTPD findings collapse onto one cluster entry — that entry is
    # detected once, and both findings still count as true positives.
    assert "msf2-proftpd-cve-cluster" in result.detected_gt_ids
    assert result.matched_finding_count == len(_FIXTURE_FINDINGS)


# ═══════════════════════════════════════════════════════════════════════════
# Network matcher unit rules (always-on)
# ═══════════════════════════════════════════════════════════════════════════


def _net_gt(**kw) -> GroundTruthEntry:
    d = dict(
        id="n", endpoint="", method="GET", parameter=None,
        category="vulnerable_service", subtypes_ok=[], owasp="", cwe="",
        severity="critical", difficulty="low", detection_required=True,
        notes="", tier="network", port=21,
    )
    d.update(kw)
    return GroundTruthEntry(**d)


class TestNetworkMatcher:
    def test_port_and_category_match(self) -> None:
        f = Finding(url="192.168.0.162:21", vuln_type="vulnerable_service", port=21)
        assert matches(f, _net_gt(port=21)) is True

    def test_wrong_port_does_not_match(self) -> None:
        f = Finding(url="192.168.0.162:21", vuln_type="vulnerable_service", port=21)
        assert matches(f, _net_gt(port=2121)) is False

    def test_wrong_category_does_not_match(self) -> None:
        f = Finding(url="192.168.0.162:21", vuln_type="cleartext_service", port=21)
        assert matches(f, _net_gt(port=21, category="vulnerable_service")) is False

    def test_scheme_prefixed_target_parses_port(self) -> None:
        f = Finding.from_heaven({"target": "ssh://192.168.0.162:22",
                                 "vuln_type": "default_credentials"})
        assert f.port == 22
        assert matches(f, _net_gt(port=22, category="weak_auth")) is True

    def test_host_level_entry_matches_only_port_less_finding(self) -> None:
        host_gt = _net_gt(port=None, category="smb_signing")
        host_finding = Finding(url="192.168.0.162", vuln_type="smb_signing_not_required")
        port_finding = Finding(url="192.168.0.162:445", vuln_type="smb_signing_not_required", port=445)
        assert matches(host_finding, host_gt) is True
        # A port-specific finding must NOT satisfy a host-level entry, or it would
        # be double-credited alongside its own port entry.
        assert matches(port_finding, host_gt) is False

    def test_bare_host_target_has_no_port(self) -> None:
        f = Finding.from_heaven({"target": "192.168.0.162", "vuln_type": "smb_null_session"})
        assert f.port is None

    def test_web_tier_unaffected_by_port(self) -> None:
        # A web GT entry (default tier) still matches purely on path + category,
        # ignoring the parsed port entirely.
        web_gt = GroundTruthEntry(
            id="w", endpoint="/sqli/", method="GET", parameter="id", category="sqli",
            subtypes_ok=[], owasp="", cwe="", severity="high", difficulty="low",
            detection_required=True, notes="",
        )
        f = Finding.from_heaven({"target": "http://127.0.0.1:8080/sqli/?id=1",
                                 "vuln_type": "sqli", "evidence": {"parameter": "id"}})
        assert matches(f, web_gt) is True


# ═══════════════════════════════════════════════════════════════════════════
# Live run against a real Metasploitable-2 host (gated)
# ═══════════════════════════════════════════════════════════════════════════


def _runs() -> int:
    return max(1, int(os.environ.get("HEAVEN_BENCH_RUNS", "1")))


def _scan_timeout() -> int:
    return int(os.environ.get("HEAVEN_BENCH_SCAN_TIMEOUT", "1200"))


def _report_dir() -> Path:
    return Path(os.environ.get("HEAVEN_BENCH_REPORT_DIR", str(_DEFAULT_REPORT_DIR)))


def _find_heaven_cli() -> str:
    venv_heaven = _PROJECT_ROOT / "venv" / "bin" / "heaven"
    if venv_heaven.exists():
        return str(venv_heaven)
    if shutil.which("heaven"):
        return "heaven"
    pytest.skip("heaven CLI not found — run `pip install -e .` first")
    return ""


def _reachable(host: str, ports: tuple[int, ...] = (21, 22, 139), timeout: float = 2.0) -> bool:
    for p in ports:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((host, p))
            return True
        except OSError:
            continue
        finally:
            s.close()
    return False


def _run_heaven_network_scan(target: str, engagement_db: Path) -> tuple[Path, float]:
    """Invoke ``heaven scan -m network`` against ``target``; persist findings."""
    heaven = _find_heaven_cli()
    engagement_name = engagement_db.stem
    engagement_db.parent.mkdir(parents=True, exist_ok=True)
    ports = os.environ.get("HEAVEN_MSF2_PORTS", _DEFAULT_PORTS)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        env = {**os.environ, "HEAVEN_DATA_DIR": str(tmp_path)}

        subprocess.run(
            [heaven, "engage", "init", engagement_name, "--client", "benchmark"],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
        )
        subprocess.run(
            [heaven, "scope", "add", target, "--engagement", engagement_name, "--kind", "ip"],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
        )

        # A bare IP / hostname is a --target (network), not a --url (web).
        scan_cmd = [
            heaven, "scan", "-t", target, "-m", "network", "-p", ports,
            "--engagement", engagement_name, "--i-have-authorization",
            "--skip-dep-check", "--no-use-scope",
        ]
        start = time.time()
        result = subprocess.run(
            scan_cmd, cwd=tmp_path, env=env, capture_output=True, text=True,
            timeout=_scan_timeout(),
        )
        duration = time.time() - start
        if result.returncode != 0:
            print("HEAVEN stdout:\n" + result.stdout[-2000:])
            print("HEAVEN stderr:\n" + result.stderr[-2000:])
            pytest.fail(f"heaven scan exited {result.returncode}")

        produced = tmp_path / "engagements" / f"{engagement_name}.db"
        if not produced.exists():
            pytest.fail(f"engagement DB not produced at {produced}")
        shutil.copy(produced, engagement_db)
        return engagement_db, duration


def _findings_from_db(db_path: Path) -> list[Finding]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    findings: list[Finding] = []
    try:
        cur = conn.execute(
            "SELECT id, target, vuln_type, title, severity, confidence, "
            "evidence_json AS evidence FROM findings"
        )
        for row in cur:
            r = dict(row)
            ev = r.get("evidence")
            if isinstance(ev, str):
                try:
                    r["evidence"] = json.loads(ev)
                except json.JSONDecodeError:
                    r["evidence"] = {}
            findings.append(Finding.from_heaven(r))
    except sqlite3.OperationalError as e:
        pytest.fail(f"could not read findings from {db_path}: {e}")
    finally:
        conn.close()
    return findings


@pytest.mark.skipif(
    not os.environ.get("HEAVEN_RUN_BENCHMARKS"),
    reason="live benchmark — set HEAVEN_RUN_BENCHMARKS=1 (and HEAVEN_MSF2_TARGET) to run",
)
def test_heaven_vs_msf2_live() -> None:
    """Scan a real Metasploitable-2 host and score recall / precision vs. GT."""
    from heaven import __version__ as _heaven_version
    from tests.benchmarks.reporters.markdown_report import (
        render_aggregated_markdown_report,
        render_markdown_report,
    )

    target = os.environ.get("HEAVEN_MSF2_TARGET", "").strip()
    if not target:
        pytest.skip("set HEAVEN_MSF2_TARGET=<metasploitable-2 host> to run the live benchmark")
    if not _reachable(target):
        pytest.skip(f"Metasploitable-2 target {target} not reachable (ports 21/22/139 closed)")

    gt = _load_gt()
    gt.base_url = target  # report header only; matching is by (port, category)
    report_dir = _report_dir()
    report_dir.mkdir(parents=True, exist_ok=True)

    run_results = []
    for i in range(_runs()):
        db = report_dir / f"msf2_run{i + 1}.db"
        if db.exists():
            db.unlink()
        _, duration = _run_heaven_network_scan(target, db)
        findings = _findings_from_db(db)
        result = evaluate(findings, gt, duration_seconds=duration)
        run_results.append(result)

        md = render_markdown_report(result, gt, scanner_name="HEAVEN",
                                    scanner_version=_heaven_version)
        (report_dir / f"msf2_run{i + 1}.md").write_text(md, encoding="utf-8")

    agg = aggregate(run_results)
    agg_md = render_aggregated_markdown_report(agg, scanner_name="HEAVEN",
                                               scanner_version=_heaven_version)
    (report_dir / "msf2_aggregated.md").write_text(agg_md, encoding="utf-8")

    last = run_results[-1]
    print()
    print("=" * 70)
    print(f"HEAVEN vs. Metasploitable-2 (network tier) — {_runs()} run(s)")
    print("=" * 70)
    print(f"Precision: {agg.mean_precision * 100:.1f}% ± {agg.std_precision * 100:.1f}%  "
          f"({last.matched_finding_count}/"
          f"{last.matched_finding_count + last.unmatched_finding_count} findings real)")
    print(f"Recall:    {agg.mean_recall * 100:.1f}% ± {agg.std_recall * 100:.1f}%  "
          f"({len(last.detected_required_ids)}/{last.total_required} required signature vulns)")
    print(f"F1:        {agg.mean_f1 * 100:.1f}%")
    print(f"Required signature vulns missed: {agg.missed_required_min}–{agg.missed_required_max}")
    print(f"Mean scan duration: {agg.mean_duration_s:.1f}s")
    if last.unmatched_findings:
        print("Unmatched (potential FPs / unlabelled reals):")
        for f in last.unmatched_findings:
            print(f"  - {f.category:20} port={f.port!s:6} {f.url}")
    print(f"Reports written to: {report_dir}")
    print("=" * 70)

    assert all(r.total_gt > 0 for r in run_results), "ground truth empty?"
    # Recall floor on the signature set. These are deterministic, non-timing
    # findings (planted backdoors, default creds, exposed services), so a real
    # scan finds essentially all of them; 0.9 allows a single transient miss
    # (a dropped probe on a loaded VM) rather than flaking. A drop well below
    # this is a real detection regression.
    assert agg.mean_recall >= 0.9, (
        f"MSF2 signature recall {agg.mean_recall:.0%} below the 0.9 floor — "
        "service-tier detection regressed."
    )
