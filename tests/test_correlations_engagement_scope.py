"""Combined Risk (finding correlation) must follow the ACTIVE engagement.

Regression for a reported bug: switching the engagement left the Combined Risk
page showing the same combinations, even after a refresh. Root cause — the
``GET /api/correlations/{scan_id}`` endpoint built its finding set from the
globally newest ``report_*.json`` on disk, with no engagement scoping, so every
engagement resolved to whichever scan wrote the most recent report file.

These tests drive the real FastAPI app through TestClient with two engagements
that hold distinct, independently correlating findings, and pin that:
  * the active engagement's findings (not another's) drive the combinations;
  * flipping the active pointer flips the result;
  * an active-but-empty engagement returns nothing rather than leaking a
    different engagement's (or the latest report's) findings;
  * with NO active engagement (fresh / CLI-only install) it still falls back to
    the latest report JSON.

See heaven/api/server.py::_engagement_findings and get_correlations.
"""

from __future__ import annotations

import json

import pytest


def _pair(host: str) -> list[dict]:
    """An LFI + unrestricted-upload pair on one host — a known amplification
    chain (local file inclusion + file upload -> RCE) the engine correlates."""
    return [
        {"target": host, "vuln_type": "lfi", "title": "Local file inclusion",
         "severity": "high", "confidence": 0.9,
         "evidence": {"proof_output": "root:x:0:0:"}},
        {"target": host, "vuln_type": "file_upload", "title": "Unrestricted upload",
         "severity": "high", "confidence": 0.9, "evidence": {}},
    ]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Point the whole app at an isolated data dir and disable auth."""
    monkeypatch.setenv("HEAVEN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    from heaven.config import reload_config
    reload_config()

    from heaven.engagement import EngagementStore

    def make_engagement(name: str, host: str) -> None:
        store = EngagementStore(tmp_path / "engagements" / f"{name}.db", create=True)
        for f in _pair(host):
            store.upsert_finding(f"scan_{name}", f)

    yield tmp_path, make_engagement

    # Don't let the tmp data_dir leak into the config singleton for later tests.
    monkeypatch.delenv("HEAVEN_DATA_DIR", raising=False)
    monkeypatch.delenv("HEAVEN_DISABLE_AUTH", raising=False)
    reload_config()


def _client():
    from fastapi.testclient import TestClient

    from heaven.api.server import create_app
    return TestClient(create_app())


def _component_hosts(summary: dict) -> set[str]:
    hosts: set[str] = set()
    for combo in summary.get("combinations", []):
        for comp in combo.get("components", []):
            if comp.get("target"):
                hosts.add(comp["target"])
    return hosts


def test_correlations_follow_the_active_engagement(env):
    """The core fix: the active engagement decides which findings correlate, and
    switching the active pointer switches the Combined Risk result."""
    tmp_path, make_engagement = env
    make_engagement("eng_alpha", "http://alpha.example/")
    make_engagement("eng_bravo", "http://bravo.example/")

    from heaven.engagement import set_active_engagement
    client = _client()

    set_active_engagement("eng_alpha")
    a = client.get("/api/correlations/latest")
    assert a.status_code == 200, a.text
    a = a.json()
    assert a["total_input_findings"] == 2, a
    assert a["total_combinations"] >= 1, a
    assert _component_hosts(a) == {"http://alpha.example/"}, _component_hosts(a)

    # Flip the engagement — the correlations must now reflect bravo, not alpha.
    set_active_engagement("eng_bravo")
    b = client.get("/api/correlations/latest").json()
    assert b["total_input_findings"] == 2, b
    assert _component_hosts(b) == {"http://bravo.example/"}, _component_hosts(b)


def test_active_but_empty_engagement_does_not_leak_another(env):
    """An engagement with no findings must yield zero combinations even when a
    different engagement (and the newest report on disk) is full — never fall
    through to some other engagement's data."""
    tmp_path, make_engagement = env
    make_engagement("eng_full", "http://full.example/")

    # A populated report file on disk (older API bug would surface this).
    (tmp_path / f"report_{'z' * 8}.json").write_text(
        json.dumps({"findings": _pair("http://from-report.example/")})
    )

    from heaven.engagement import EngagementStore, set_active_engagement
    EngagementStore(tmp_path / "engagements" / "eng_empty.db", create=True)  # no findings
    set_active_engagement("eng_empty")

    r = _client().get("/api/correlations/latest").json()
    assert r["total_input_findings"] == 0, r
    assert r["total_combinations"] == 0, r
    assert _component_hosts(r) == set()


def test_falls_back_to_report_when_no_active_engagement(env):
    """Fresh / CLI-only install: no engagement DBs at all, only a report JSON on
    disk. Correlations should still work off that report."""
    tmp_path, _make = env
    # No engagement DBs are created here.
    (tmp_path / f"report_{'a' * 8}.json").write_text(
        json.dumps({"findings": _pair("http://report-only.example/")})
    )

    from heaven.engagement import clear_active_engagement
    clear_active_engagement()

    r = _client().get("/api/correlations/latest").json()
    assert r["total_input_findings"] == 2, r
    assert _component_hosts(r) == {"http://report-only.example/"}, _component_hosts(r)
