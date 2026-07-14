"""Regression tests for the live methodology-coverage source of truth.

`heaven/methodology.py` turns the static OWASP/NIST/PTES mapping docs into a
structured matrix and overlays the active engagement's real findings. It is the
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
        {"vuln_type": "sql_injection", "owasp": "A03:2021 Injection"},
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
