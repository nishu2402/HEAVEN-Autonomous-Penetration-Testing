"""The lab matrix is the machine-checked form of HEAVEN's honesty rule:

    a scan mode earns its "10/10" only when it is green against a real,
    reproducible vulnerable lab for its domain, and its label promises exactly
    what it delivers.

These tests fail the build the moment that drifts — a mode with no lab, a GREEN
claim pointing at a lab artifact that was moved or deleted, a hardware/agent-
gated mode quietly claiming it is proven, or an exploit added to the corpus with
no proving lab recorded.
"""

from __future__ import annotations

from heaven import labs
from heaven.config import ScanMode
from heaven.vulnscan.exploit_engine import list_exploits


def test_matrix_has_no_violations():
    """The single source of truth: validate() must be empty."""
    issues = labs.validate()
    assert not issues, "\n".join(f"{i.where}: {i.problem}" for i in issues)


def test_every_scan_mode_is_documented():
    for mode in ScanMode:
        assert labs.mode_labs(mode), f"{mode.value} has no lab entry"


def test_green_modes_point_at_a_real_lab():
    """A GREEN mode must be anchored to something real: an in-repo lab artifact
    that exists on disk, or a concrete external target — never an empty claim."""
    for mode in ScanMode:
        for lab in labs.mode_labs(mode):
            if lab.status != labs.GREEN:
                continue
            # In-repo artifacts, when named, must exist on disk.
            if lab.kind in (labs.COMPOSE, labs.NATIVE):
                p = lab.artifact_path()
                assert p is not None and p.exists(), \
                    f"{mode.value}: GREEN lab artifact missing {lab.artifact}"
            # And every GREEN lab is anchored to an existing artifact or a target.
            anchored = bool(lab.target) or (
                lab.artifact_path() is not None and lab.artifact_path().exists())
            assert anchored, f"{mode.value}: GREEN lab has no artifact or target"


def test_hardware_and_agent_gated_modes_keep_their_gate():
    """Wireless (needs an RF radio) and Sniff (needs an on-segment agent) may
    prove their network-reachable subset live, but the gate must never be hidden:
    each must retain an explicit NEEDS_HARDWARE / NEEDS_AGENT entry naming the
    part it genuinely cannot reach. The RF / active-capture result is never
    simulated to manufacture a green."""
    assert any(lab.status == labs.NEEDS_HARDWARE
               for lab in labs.mode_labs(ScanMode.WIRELESS)), \
        "WIRELESS must keep its RF (needs-hardware) gate visible"
    assert any(lab.status == labs.NEEDS_AGENT
               for lab in labs.mode_labs(ScanMode.SNIFF)), \
        "SNIFF must keep its on-segment-agent gate visible"
    # SNIFF's active capture genuinely cannot be reached from a network scanner
    # (and its LLMNR/NBT-NS multicast is UDP, which Docker Desktop for Mac's NAT
    # drops), so it stays gated overall.
    assert labs.mode_status(ScanMode.SNIFF) == labs.NEEDS_AGENT


def test_every_corpus_exploit_has_a_proving_lab():
    corpus = {e["exploit_id"] for e in list_exploits()}
    for eid in corpus:
        assert eid in labs.EXPLOIT_LABS, f"{eid} has no proving lab recorded"
    # and the ledger names no exploit that isn't in the live corpus
    for eid in labs.EXPLOIT_LABS:
        assert eid in corpus, f"ledger names removed exploit {eid}"


def test_gated_statuses_carry_a_note():
    """Every non-proven status must explain the gap, so 'needs-lab' is never a
    silent dead end."""
    for mode in ScanMode:
        for lab in labs.mode_labs(mode):
            if lab.status not in (labs.GREEN, labs.PARTIAL):
                assert lab.note, f"{mode.value}/{lab.name} gated without a note"


def test_matrix_rows_serialisable():
    rows = labs.matrix_rows()
    assert rows and all({"mode", "status", "proves"} <= set(r) for r in rows)
    summary = labs.status_summary()
    assert sum(summary.values()) == len(list(ScanMode))
