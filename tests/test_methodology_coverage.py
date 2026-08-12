"""Regression tests for the live methodology-coverage source of truth.

`heaven/methodology.py` turns the static mapping docs — the OWASP/NIST/PTES
pen-test methodologies and the compliance/control frameworks (Cyber Essentials,
ISO 27001, PCI DSS, CIS v8, NIST CSF, SOC 2) — into a structured matrix and
overlays the active engagement's real findings. It is the
single source consumed by the API (`/api/methodology`), the CLI
(`heaven methodology coverage`) and the React page, so these tests lock in the
parsing, the automated/manual classification, and the finding→detector overlay.
"""
from __future__ import annotations

from heaven import methodology as M


# ── Parsing + summary computation ────────────────────────────────────────────

def test_all_standards_parse_with_computed_summaries() -> None:
    stds = M.load_standards()
    names = {s["name"] for s in stds}
    assert {"owasp_testing_guide", "nist_800_115", "ptes"}.issubset(names)
    for s in stds:
        summ = s["summary"]
        # The summary is computed from the rows, so it must be internally
        # consistent — never hand-typed drift.
        assert summ["total"] == summ["automated"] + summ["partial"] + summ["manual"]
        assert summ["covered"] == summ["automated"] + summ["partial"]
        assert summ["total"] > 0
        assert s["categories"], f"{s['name']} parsed no categories"


def test_row_classification_from_coverage_cell() -> None:
    assert M._classify("`heaven.vulnscan.injection_scanner`") == "automated"
    assert M._classify("(manual)") == "manual"
    assert M._classify("(manual — partial via `web_crawler`)") == "partial"
    assert M._classify("`heaven.vulnscan.injection_scanner` (partial — needs auth)") == "partial"
    assert M._classify("(manual — server-side)") == "manual"


def test_wstg_test_ids_are_extracted() -> None:
    owasp = next(s for s in M.load_standards() if s["name"] == "owasp_testing_guide")
    ids = {r["id"] for c in owasp["categories"] for r in c["rows"]}
    # A few well-known WSTG ids must be present and used as row ids.
    assert "WSTG-INPV-05" in ids   # SQL injection
    assert "WSTG-ATHZ-04" in ids   # IDOR


# ── Finding → detector overlay ───────────────────────────────────────────────

def test_module_map_resolves_common_vuln_types() -> None:
    assert "injection_scanner" in M.modules_for_vuln("sql_injection")
    assert "injection_scanner" in M.modules_for_vuln("xss")
    assert "ssl_scanner" in M.modules_for_vuln("weak_tls")
    assert "idor_scanner" in M.modules_for_vuln("idor")
    assert M.modules_for_vuln("") == ()
    assert M.modules_for_vuln("totally_unknown_type") == ()


def test_overlay_lights_only_rows_whose_detector_fired() -> None:
    findings = [
        {"vuln_type": "sql_injection", "owasp": "A05:2025 Injection"},
        {"vuln_type": "idor"},
        {"vuln_type": "weak_tls"},
    ]
    built = M.build(findings)
    owasp = next(s for s in built["standards"] if s["name"] == "owasp_testing_guide")

    # SQLi row is exercised (injection_scanner produced a finding) …
    sqli = _find_row(owasp, "WSTG-INPV-05")
    assert sqli["exercised"] is True and sqli["exercised_count"] >= 1
    # IDOR row is exercised (idor_scanner) …
    idor = _find_row(owasp, "WSTG-ATHZ-04")
    assert idor["exercised"] is True
    # A row whose detector never fired is NOT exercised (honest overlay).
    graphql = _find_row(owasp, "WSTG-APIT-01")
    assert graphql["exercised"] is False and graphql["exercised_count"] == 0

    eng = built["engagement"]
    assert eng["findings_total"] == 3
    assert "injection_scanner" in eng["modules_active"]
    assert owasp["summary"]["exercised"] >= 2


def test_empty_engagement_has_zero_exercised() -> None:
    built = M.build([])
    for s in built["standards"]:
        assert s["summary"]["exercised"] == 0
        for c in s["categories"]:
            for r in c["rows"]:
                assert r["exercised"] is False
    assert built["engagement"]["findings_total"] == 0


def _find_row(standard: dict, row_id: str) -> dict:
    for c in standard["categories"]:
        for r in c["rows"]:
            if r["id"] == row_id:
                return r
    raise AssertionError(f"row {row_id} not found")


# ── Compliance / control frameworks (Cyber Essentials, ISO 27001, PCI, …) ─────

# The seven compliance frameworks added alongside the three pen-test
# methodologies. Each is a doc under docs/methodology/ driven by the exact same
# live-overlay machinery.
_COMPLIANCE_STEMS = (
    "cyber_essentials", "cyber_essentials_plus", "iso_27001",
    "pci_dss", "cis_controls_v8", "nist_csf", "soc2",
)


def _standard(built: dict, name: str) -> dict:
    return next(s for s in built["standards"] if s["name"] == name)


def test_all_ten_standards_present_and_ordered() -> None:
    stds = M.load_standards()
    names = [s["name"] for s in stds]
    # Ten in total: three methodologies then the seven compliance frameworks.
    assert names[:3] == ["owasp_testing_guide", "nist_800_115", "ptes"]
    for stem in _COMPLIANCE_STEMS:
        assert stem in names, f"{stem} doc missing"
    # Methodologies always sort before the compliance frameworks.
    assert names.index("ptes") < names.index("cyber_essentials")
    # Every stem carries display metadata for the UI selector.
    for stem in _COMPLIANCE_STEMS:
        assert M.STANDARD_META[stem]["title"]


def test_compliance_frameworks_parse_with_consistent_summaries() -> None:
    stds = {s["name"]: s for s in M.load_standards()}
    for stem in _COMPLIANCE_STEMS:
        s = stds[stem]
        summ = s["summary"]
        assert s["categories"], f"{stem} parsed no categories"
        assert summ["total"] > 0
        assert summ["total"] == summ["automated"] + summ["partial"] + summ["manual"]
        assert summ["covered"] == summ["automated"] + summ["partial"]
        # An honest compliance map always carries some manual/organizational
        # controls a remote scanner cannot evidence.
        assert summ["manual"] > 0, f"{stem} claims 100% automation — suspicious"


def test_new_vuln_types_resolve_to_real_detectors() -> None:
    # The compliance rows only light up because these real, scanner-emitted
    # vuln_types now map to their detector token.
    assert M.modules_for_vuln("vulnerable_service") == ("cve_mapper",)
    assert M.modules_for_vuln("unsupported_software") == ("eol_scanner",)
    assert M.modules_for_vuln("vulnerable_dependency") == ("sca_scanner",)
    assert "network_exposure" in M.modules_for_vuln("telnet")
    assert "network_exposure" in M.modules_for_vuln("snmp_default_community")
    assert "access_control" in M.modules_for_vuln("broken_access_control")


def test_prefix_fallback_for_open_ended_families() -> None:
    # SAST emits sast_<rule> at runtime — a fixed dict can't enumerate it.
    assert M.modules_for_vuln("sast_sql_injection") == ("sast_runner",)
    assert M.modules_for_vuln("sast_hardcoded_secret") == ("sast_runner",)
    assert M.modules_for_vuln("wordpress_plugin_outdated") == ("cms_scanner",)
    assert M.modules_for_vuln("api_actuator_exposed") == ("api_scanner",)
    # Exact entries still win over the prefix table.
    assert M.modules_for_vuln("graphql_dos") == ("api_scanner",)


def test_vulnerability_finding_lights_the_patch_management_controls() -> None:
    # A single known-CVE service finding must exercise the "vulnerability /
    # patch management" control across every framework that has one.
    built = M.build([{"vuln_type": "vulnerable_service"}])
    expectations = {
        "cyber_essentials": "CE-UP-2",      # Security Update Management
        "iso_27001": "A.8.8",               # Management of technical vulnerabilities
        "pci_dss": "6.3.3",                 # Security patches installed
        "cis_controls_v8": "CSC-7.1",       # Continuous Vulnerability Management
        "nist_csf": "ID.RA-01",             # Vulnerabilities identified
        "soc2": "CC7.1",                    # Detect vulnerabilities
    }
    for stem, row_id in expectations.items():
        row = _find_row(_standard(built, stem), row_id)
        assert row["exercised"] is True, f"{stem}:{row_id} did not light up"
        assert row["exercised_count"] >= 1


def test_organizational_controls_never_fabricate_coverage() -> None:
    # Even with findings present, a governance/organizational control (no
    # detector) must stay un-exercised and classified manual.
    built = M.build([
        {"vuln_type": "vulnerable_service"},
        {"vuln_type": "default_credentials"},
        {"vuln_type": "weak_tls"},
    ])
    iso = _standard(built, "iso_27001")
    people = _find_row(iso, "A.6.3")   # security awareness training — organizational
    assert people["status"] == "manual"
    assert people["exercised"] is False and people["exercised_count"] == 0


def test_compliance_frameworks_idle_with_no_findings() -> None:
    built = M.build([])
    for stem in _COMPLIANCE_STEMS:
        assert _standard(built, stem)["summary"]["exercised"] == 0


def test_cli_standard_aliases_resolve_to_real_doc_stems() -> None:
    # The `heaven methodology coverage --standard` aliases must all resolve to a
    # stem that actually exists as a parsed standard (CLI ↔ docs stay in sync).
    from heaven.cli.methodology import _STANDARD_ALIAS, _resolve_standard

    stems = {s["name"] for s in M.load_standards()}
    for alias, stem in _STANDARD_ALIAS.items():
        assert stem in stems, f"alias {alias!r} → unknown stem {stem!r}"
        assert _resolve_standard(alias) == stem
    # A bare stem passes through unchanged; an unknown value is left as-is so the
    # command can report it as unavailable.
    assert _resolve_standard("iso_27001") == "iso_27001"
    assert _resolve_standard("nope") == "nope"
