"""Honesty / provenance audit for the Agent Fleet.

The whole design rests on one rule: an agent PROPOSES, a deterministic oracle
VERIFIES, and only oracle output becomes a finding. These tests enforce that rule
structurally, so it cannot regress silently:

  * every role returns only :class:`AgentTask` objects — never a finding;
  * no role holds a handle to the store, so a role *cannot* persist anything;
  * the only finding-write path is :meth:`Blackboard.record_findings`, and it
    writes exactly what it is given (an oracle's confirmed output), nothing more.
"""

from __future__ import annotations

import inspect

from heaven.ai.fleet import Blackboard, FleetState, all_roles
from heaven.ai.fleet.roles import AgentTask


class _RecordingStore:
    def __init__(self):
        self.upserts: list[tuple[str, dict]] = []

    def upsert_finding(self, scan_id, finding):
        self.upserts.append((scan_id, finding))
        return finding.get("id", "x")


def _rich_state() -> FleetState:
    return FleetState(
        findings=[{"id": "1", "target": "http://t/x", "vuln_type": "xss",
                   "title": "XSS", "severity": "medium", "confidence": 0.55}],
        scope=["http://t/x", "10.0.0.5"],
        seed_targets={"ips": ["10.0.0.5"], "urls": ["http://t/x"]},
        active_mode="full",
    )


async def test_no_role_emits_a_finding():
    """Every role proposes AgentTasks only — never a finding-shaped object."""
    state = _rich_state()
    for role in all_roles():
        tasks = await role.propose(state, None)  # deterministic path, no brain
        assert isinstance(tasks, list)
        for t in tasks:
            assert isinstance(t, AgentTask), (
                f"{role.name} returned a non-task {type(t)} — roles must never "
                "produce findings"
            )


def test_no_role_can_reach_the_store():
    """A role must not carry a store/blackboard handle; it has no way to persist,
    so persistence can only ever happen via the executor's oracle path."""
    for role in all_roles():
        for attr in ("store", "blackboard", "engagement_store", "db"):
            assert not hasattr(role, attr), (
                f"{role.name} exposes '{attr}' — roles must be pure proposers"
            )


def test_record_findings_is_the_only_write_path():
    """record_findings persists exactly what it is handed (oracle output) and is
    the single seam that touches upsert_finding."""
    store = _RecordingStore()
    bb = Blackboard(store)
    confirmed = [
        {"id": "a", "target": "http://t/x", "severity": "high"},
        {"id": "b", "target": "http://t/y", "severity": "low"},
    ]
    written = bb.record_findings("scan-1", confirmed)
    assert written == 2
    assert [f["id"] for (_sid, f) in store.upserts] == ["a", "b"]
    # No embellishment: what went in is what was written.
    assert store.upserts[0][1] is confirmed[0]


def test_blackboard_source_only_reads_upsert_once():
    """Guard against a second finding-write path sneaking into the blackboard: the
    module body calls upsert_finding in exactly one place (record_findings)."""
    import heaven.ai.fleet.blackboard as bbmod

    src = inspect.getsource(bbmod)
    assert src.count("upsert_finding(") == 1
