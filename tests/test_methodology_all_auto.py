"""Regression tests for the "all-AUTO" methodology reconciliation.

Every methodology / compliance framework on the Methodology Coverage page is
data-driven (`heaven/methodology.py` parses `docs/methodology/*.md`). This task
took the nine non-WSTG frameworks to **all technically-assessable controls
automated, 0 partial, 0 manual** — each control named to a real, pre-existing
HEAVEN detector or tool feature. Controls a remote/credentialed scan genuinely
cannot evidence (governance, physical, endpoint, target-side logging, social
engineering, …) are consolidated per theme into an honest **out-of-band
(analyst-attested)** prose note — 0 counted rows, exactly like WSTG's Business
Logic — never fabricated as a scan result.

These tests lock that in so the page can never silently regress to the old
partial/manual state, and so the one genuinely-unmapped real emitter
(`perimeter_defense` → `firewall_detector`) keeps lighting its rows.
"""
from __future__ import annotations

from heaven import methodology as M

# Expected count of *counted* (technically-assessable, all-AUTO) rows per doc.
# The residual governance/physical/endpoint controls live in per-theme
# out-of-band prose notes and are deliberately not counted.
EXPECTED_AUTOMATED = {
    "owasp_testing_guide": 86,
    "nist_800_115": 20,
    "ptes": 29,
    "cyber_essentials": 17,
    "cyber_essentials_plus": 19,
    "iso_27001": 17,
    "pci_dss": 18,
    "cis_controls_v8": 15,
    "nist_csf": 11,
    "soc2": 10,
}


def _by_name() -> dict:
    return {s["name"]: s for s in M.load_standards()}


# ── 1. Every framework: 0 partial, 0 manual; all counted rows automated ───────
def test_every_framework_is_fully_automated() -> None:
    stds = _by_name()
    # Exactly the ten known standards are present.
    assert set(stds) == set(EXPECTED_AUTOMATED), sorted(stds)
    for name, want in EXPECTED_AUTOMATED.items():
        summ = stds[name]["summary"]
        assert summ["partial"] == 0, f"{name} has {summ['partial']} partial rows"
        assert summ["manual"] == 0, f"{name} has {summ['manual']} manual rows"
        assert summ["automated"] == summ["total"] == want, (
            f"{name}: automated={summ['automated']} total={summ['total']} want={want}")


def test_no_row_is_partial_or_manual_anywhere() -> None:
    for std in M.load_standards():
        for cat in std["categories"]:
            for row in cat["rows"]:
                assert row["status"] == "automated", (
                    f"{std['name']} {row['id']} is {row['status']}: {row['coverage']!r}")


# ── 2. Out-of-band controls are honestly noted, not counted ───────────────────
def test_out_of_band_controls_are_analyst_attested_not_counted() -> None:
    stds = _by_name()
    # (framework, out-of-band control id that must NOT appear as a counted row)
    excluded = [
        ("nist_800_115", "§3.1"), ("nist_800_115", "§5.3"),
        ("cyber_essentials", "CE-MW-1"), ("cyber_essentials", "CE-AC-4"),
        ("cyber_essentials_plus", "CEP-MW-1"),
        ("iso_27001", "A.7.1"), ("iso_27001", "A.6.3"),
        ("pci_dss", "9.x"), ("pci_dss", "12.x"),
        ("cis_controls_v8", "CSC-10"), ("cis_controls_v8", "CSC-17"),
        ("nist_csf", "GV.OC"), ("nist_csf", "RC.RP"),
        ("soc2", "CC1"), ("soc2", "CC6.8"),
    ]
    for name, cid in excluded:
        ids = {r["id"] for c in stds[name]["categories"] for r in c["rows"]}
        assert cid not in ids, f"{name}: {cid} should be out-of-band, not a counted row"

    # Every non-WSTG framework carries at least one honest out-of-band note.
    for name in EXPECTED_AUTOMATED:
        if name == "owasp_testing_guide":
            continue
        notes = " ".join(c["note"].lower() for c in stds[name]["categories"])
        assert ("out-of-band" in notes or "analyst-attested" in notes), (
            f"{name} has no out-of-band / analyst-attested note")


# ── 3. The one unmapped real emitter now lights its rows ──────────────────────
def test_perimeter_defense_maps_to_firewall_detector() -> None:
    assert M.modules_for_vuln("perimeter_defense") == ("firewall_detector",)


def test_overlay_lights_reclassified_rows_on_real_findings() -> None:
    findings = [{"vuln_type": vt} for vt in (
        "perimeter_defense",       # firewall_detector
        "broken_access_control",   # access_control / idor_scanner
        "vulnerable_dependency",   # sca_scanner
        "sensitive_file",          # exposure_scanner
    )]
    built = M.build(findings)
    stds = {s["name"]: s for s in built["standards"]}
    # (framework, formerly non-AUTO row id that must now light)
    expect_lit = [
        ("nist_800_115", "§3.3"),       # ruleset review via firewall_detector
        ("ptes", "Identifying defenses"),
        ("cis_controls_v8", "CSC-13"),  # network monitoring & defense
        ("cis_controls_v8", "CSC-3"),   # data protection via exposure_scanner
        ("nist_csf", "DE.CM"),
        ("nist_csf", "GV.SC"),          # supply chain via sca_scanner
        ("soc2", "CC7.2"),
        ("soc2", "CC6.1b"),             # authorization via access_control
        ("pci_dss", "7.x"),             # least privilege
    ]
    for name, rid in expect_lit:
        rows = {r["id"]: r for c in stds[name]["categories"] for r in c["rows"]}
        assert rid in rows, f"{name}: row {rid} missing"
        assert rows[rid]["exercised"] is True, f"{name} {rid} did not light"


# ── 4. Representative reclassifications name the right real module ─────────────
def test_representative_rows_name_real_modules() -> None:
    stds = _by_name()
    cases = [
        # (framework, row id, token that must appear in the coverage cell)
        ("nist_800_115", "§3.3", "firewall_detector"),
        ("nist_800_115", "§6.3", "scan --mode"),   # pipe-parse bug fixed
        ("nist_800_115", "§8.3", "retest_report"),
        ("ptes", "Customised exploitation avenue", "attack_chain_planner"),
        ("ptes", "Identifying defenses", "firewall_detector"),
        ("iso_27001", "A.5.9", "inventory"),
        ("iso_27001", "A.8.16", "watcher"),
        ("cis_controls_v8", "CSC-2", "sbom"),
        ("nist_csf", "ID.IM", "retest_report"),
        ("soc2", "CC4.1", "watcher"),
    ]
    for name, rid, token in cases:
        rows = {r["id"]: r for c in stds[name]["categories"] for r in c["rows"]}
        assert rid in rows, f"{name}: row {rid} missing"
        assert rows[rid]["status"] == "automated", f"{name} {rid} not AUTO"
        assert token in rows[rid]["coverage"], (
            f"{name} {rid} coverage {rows[rid]['coverage']!r} lacks {token!r}")


def test_no_wrong_sca_scanner_path_remains() -> None:
    # The module is heaven.vulnscan.sca_scanner, never heaven.devsecops.sca_scanner.
    for std in M.load_standards():
        for cat in std["categories"]:
            for row in cat["rows"]:
                assert "devsecops.sca_scanner" not in row["coverage"], (
                    f"{std['name']} {row['id']} still names devsecops.sca_scanner")
