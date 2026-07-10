"""Tests for the LLM vulnerability-hypothesis agent (propose → verify).

The contract that matters: the LLM only *prioritises what to probe*; every
reported finding comes from a real detector, active probing is authorization-
gated, and the whole thing degrades to a no-op without an LLM key.
"""
from __future__ import annotations

import pytest

from heaven.ai.vuln_hypothesis import (
    VulnHypothesis, VulnHypothesisAgent, verify_hypotheses,
)


class _StubGateway:
    def __init__(self, available: bool):
        self._available = available

    @property
    def available(self) -> bool:
        return self._available


# ── graceful degradation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_propose_degrades_without_gateway():
    agent = VulnHypothesisAgent(gateway=_StubGateway(available=False))
    assert agent.available is False
    out = await agent.propose(profile={"tech_stack": ["php"]}, endpoints=[])
    assert out.hypotheses == []


# ── verification is authorization-gated ──────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_requires_authorization():
    hyps = [VulnHypothesis(vuln_class="sqli", target_url="http://x/?id=1", param="id")]
    res = await verify_hypotheses(hyps, authorized=False)
    assert res["findings"] == []
    assert res["skipped"] == "authorization required"


# ── verification uses a REAL detector (end-to-end vs. the native app) ─────────

def _serve():
    pytest.importorskip("flask")
    pytest.importorskip("aiohttp")
    from tests.benchmarks.native.vuln_app import serve
    return serve()


@pytest.mark.asyncio
async def test_verify_confirms_real_sqli_from_hypothesis():
    with _serve() as base_url:
        hyps = [VulnHypothesis(
            vuln_class="sqli", param="id",
            target_url=f"{base_url}/vulnerabilities/sqli/?id=1",
            rationale="numeric id looks like a raw query parameter", prior=0.7,
        )]
        res = await verify_hypotheses(hyps, authorized=True)

    assert res["probed_targets"] == 1
    sqli = [f for f in res["findings"] if f.get("vuln_type") == "sqli"]
    assert sqli, "the real injection detector should confirm the SQLi"
    # The confirmed finding carries the triggering hypothesis for transparency…
    assert sqli[0]["evidence"]["llm_hypothesis"]["vuln_class"] == "sqli"
    # …but it came from a real oracle, not the model.
    assert sqli[0]["source"] in ("injection_scanner", "llm_hypothesis_verified")


@pytest.mark.asyncio
async def test_verify_no_finding_on_clean_endpoint():
    with _serve() as base_url:
        # A leaf with no injectable surface and no links to follow — the probe
        # runs but confirms nothing, so no finding is fabricated.
        hyps = [VulnHypothesis(
            vuln_class="sqli", param="", target_url=f"{base_url}/not-a-real-page")]
        res = await verify_hypotheses(hyps, authorized=True)
    assert [f for f in res["findings"] if f.get("vuln_type") == "sqli"] == []
