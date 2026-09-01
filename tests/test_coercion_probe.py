"""Tests for the NTLM coercion-surface probe (heaven.recon.coercion_probe).

The per-host RPC bind is monkeypatched so finding-shaping is verified without a
live SMB target. The probe must only ever *bind* (never coerce), which the
evidence note records.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.recon import coercion_probe as c


pytestmark = pytest.mark.skipif(not c.HAS_IMPACKET, reason="impacket unavailable")


def test_interface_table_covers_three_methods():
    methods = {row[1] for row in c._COERCION_INTERFACES}
    assert methods == {"SpoolSample", "PetitPotam", "DFSCoerce"}


def test_finding_lists_available_methods(monkeypatch):
    monkeypatch.setattr(c, "_probe_host", lambda *a, **k: [
        {"label": "MS-RPRN (PrinterBug)", "method": "SpoolSample",
         "pipe": "spoolss", "interface": "12345678-1234-ABCD-EF00-0123456789AB"},
        {"label": "MS-EFSR (PetitPotam)", "method": "PetitPotam",
         "pipe": "lsarpc", "interface": "c681d488-d850-11d0-8c52-00c04fd90f7e"},
    ])
    findings = asyncio.run(c.coercion_surface_probe("10.0.0.10"))
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_type"] == "ntlm_coercion" and f["severity"] == "high"
    assert "SpoolSample" in f["description"] and "PetitPotam" in f["description"]
    assert len(f["evidence"]["methods"]) == 2
    # Never issues the coercion call — bind only.
    assert "bind only" in f["evidence"]["note"]


def test_no_exposed_interface_yields_nothing(monkeypatch):
    monkeypatch.setattr(c, "_probe_host", lambda *a, **k: [])
    assert asyncio.run(c.coercion_surface_probe("10.0.0.10")) == []


def test_missing_host_returns_empty():
    assert asyncio.run(c.coercion_surface_probe("")) == []
