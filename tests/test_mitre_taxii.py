"""Tests for the `heaven mitre` TAXII wiring (refresh + technique lookup).

Uses a tiny mocked STIX 2.1 dataset so the whole fetch → parse → lookup path is
exercised deterministically, without touching the live MITRE server.
"""

from __future__ import annotations

import json

import pytest

from heaven.mitre.taxii_client import HAS_HTTPX, TAXIIClient

pytestmark = pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")

# Minimal STIX 2.1: one technique, one group, one "uses" relationship.
_STIX = {
    "objects": [
        {
            "id": "attack-pattern--tid1", "type": "attack-pattern",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command interpreters.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999",
                 "url": "https://attack.mitre.org/techniques/T9999"},
            ],
        },
        {"id": "intrusion-set--g1", "type": "intrusion-set", "name": "TestGroup"},
        {"id": "relationship--r1", "type": "relationship",
         "relationship_type": "uses",
         "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--tid1"},
    ],
    "fetched_at": 0,
}


@pytest.fixture()
def _mock_taxii(monkeypatch, tmp_path):
    # Resolve the class through the LIVE module (not a module-top import) so the
    # patch lands on the same object the CLI imports, even if an earlier test in
    # the suite reloaded heaven.mitre.taxii_client.
    from heaven.mitre import taxii_client as tc

    async def _fake_fetch(self, force_refresh=False):  # replaces fetch entirely
        return _STIX

    async def _boom(self):  # safety net: no test may hit the real TAXII server
        raise AssertionError("real TAXII network fetch attempted in a test")

    monkeypatch.setattr(tc.TAXIIClient, "fetch_attack_data", _fake_fetch)
    monkeypatch.setattr(tc.TAXIIClient, "_fetch_from_taxii", _boom)
    monkeypatch.chdir(tmp_path)  # cache/index writes land under tmp
    return tmp_path


def test_refresh_writes_index_and_reports_counts(_mock_taxii, monkeypatch):
    from click.testing import CliRunner
    from heaven.cli import cli
    res = CliRunner().invoke(cli, ["mitre", "refresh", "--force", "--check"])
    assert res.exit_code == 0, res.output
    assert "1 techniques" in res.output or "techniques" in res.output
    idx = _mock_taxii / "data" / "mitre_cache" / "technique_index.json"
    assert idx.exists()
    data = json.loads(idx.read_text())
    assert data["T9999"]["name"] == "Command and Scripting Interpreter"


def test_technique_lookup_finds_group(_mock_taxii):
    from click.testing import CliRunner
    from heaven.cli import cli
    # populate the cache first
    CliRunner().invoke(cli, ["mitre", "refresh", "--force"])
    res = CliRunner().invoke(cli, ["mitre", "technique", "T9999"])
    assert res.exit_code == 0, res.output
    assert "Command and Scripting Interpreter" in res.output
    assert "TestGroup" in res.output


def test_technique_unknown_id_exits_nonzero(_mock_taxii):
    from click.testing import CliRunner
    from heaven.cli import cli
    CliRunner().invoke(cli, ["mitre", "refresh", "--force"])
    res = CliRunner().invoke(cli, ["mitre", "technique", "T0000"])
    assert res.exit_code == 1


def test_parse_and_lookup_direct(tmp_path):
    """The client's own fetch→parse→lookup contract (no CLI)."""
    client = TAXIIClient(cache_dir=tmp_path / "cache")
    parsed = client.parse_objects(_STIX)
    assert len(parsed["techniques"]) == 1
    tech = client.get_technique("T9999")
    assert tech is not None and tech.attack_id == "T9999"
    groups = client.get_groups_using_technique(tech.id)
    assert [g.name for g in groups] == ["TestGroup"]
