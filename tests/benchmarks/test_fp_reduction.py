"""Scored A/B benchmark for the boolean-blind SQLi reproduction pass.

The native functional benchmark (``test_native_benchmark.py``) already shows the
FP hardening costs *zero* recall on the standard surface (100% P/R/F1). But that
target is deterministic, so it cannot exercise the failure mode the reproduction
pass actually defends against: a **non-deterministic** page whose true/false
responses differ once by chance and thus fool a single-shot boolean oracle.

This benchmark builds exactly that controlled surface — one genuinely-injectable
endpoint and one flaky-but-not-injectable endpoint — and scores the boolean
scanner's precision with the reproduction pass ON vs OFF. It writes the numbers
to ``reports/fp_reduction.md`` and asserts the pass strictly improves precision
with no recall loss.

Everything is deterministic (a controlled ``_get`` stand-in, no network), so the
number is reproducible by anyone.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote

import pytest

import heaven.vulnscan.injection_scanner as inj

# Realistic page wrapper so the boolean signal is tiny next to the chrome.
_CHROME = "<html><head><title>app</title></head><body>" + ("x" * 4000)
_FOOT = ("y" * 400) + "</body></html>"


def _page(body: str) -> str:
    return _CHROME + body + _FOOT


_ROW = _page("<pre>First name: admin\nSurname: admin</pre>")
_EMPTY = _page("")


def _make_fake_get(state: dict):
    """A controlled `_get` stand-in serving two endpoints:

    * ``/genuine`` — a real boolean oracle: TRUE(1=1) returns the row, FALSE(1=2)
      hides it, on *every* round. Reproduces → a true positive under both modes.
    * ``/flaky``   — NOT injectable: its first true/false pair happens to differ
      (fooling a single-shot oracle) but it never reproduces. A false positive
      unless the reproduction pass rejects it.
    """
    async def fake_get(session, url, headers=None, timeout=8.0):
        u = unquote(url)
        is_true = "1=1" in u
        if "genuine" in u:
            return 200, (_ROW if is_true else _EMPTY)
        # /flaky: only the very first true/false pair looks like an oracle.
        state["flaky"] = state.get("flaky", 0) + 1
        if state["flaky"] <= 2:
            return 200, (_ROW if is_true else _EMPTY)
        return 200, _ROW  # afterwards always the baseline row → never confirms
    return fake_get


async def _boolean_findings(monkeypatch, require_reproduction: bool) -> set[str]:
    """Run the boolean scanner over both endpoints; return the set of endpoints
    it flagged as SQLi (by path)."""
    monkeypatch.setattr(inj, "REQUIRE_BOOLEAN_REPRODUCTION", require_reproduction)
    flagged: set[str] = set()
    for name in ("genuine", "flaky"):
        monkeypatch.setattr(inj, "_get", _make_fake_get({}))
        scanner = inj.InjectionScanner()
        await scanner._test_sqli_boolean_param(
            None, f"http://t/{name}?id=1", "id", _ROW)
        if scanner._findings:
            flagged.add(name)
    return flagged


def _precision_recall(flagged: set[str]) -> tuple[float, float, int, int]:
    """genuine=true positive, flaky=false positive."""
    tp = 1 if "genuine" in flagged else 0
    fp = 1 if "flaky" in flagged else 0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / 1  # exactly one real vuln
    return precision, recall, tp, fp


@pytest.mark.asyncio
async def test_boolean_reproduction_improves_precision(monkeypatch):
    off = _precision_recall(await _boolean_findings(monkeypatch, False))
    on = _precision_recall(await _boolean_findings(monkeypatch, True))

    p_off, r_off, tp_off, fp_off = off
    p_on, r_on, tp_on, fp_on = on

    # Reproduction pass strictly improves precision …
    assert p_on > p_off, (p_on, p_off)
    # … removes the flaky false positive …
    assert fp_on == 0 and fp_off == 1
    # … and costs no recall (the genuine oracle is still found).
    assert r_on == r_off == 1.0

    _write_report(off, on)


def _write_report(off, on) -> None:
    p_off, r_off, tp_off, fp_off = off
    p_on, r_on, tp_on, fp_on = on
    reports = Path(__file__).resolve().parent / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    md = (
        "# Boolean-blind SQLi — reproduction-pass FP benchmark\n\n"
        "Controlled A/B on a surface with 1 genuine boolean-SQLi endpoint and 1\n"
        "flaky (non-deterministic, not-injectable) endpoint. `genuine` is the\n"
        "only true positive; `flaky` is a false positive unless rejected.\n\n"
        "| Mode | Precision | Recall | True positives | False positives |\n"
        "|---|---|---|---|---|\n"
        f"| Reproduction OFF (single-shot oracle) | {p_off:.0%} | {r_off:.0%} | {tp_off} | {fp_off} |\n"
        f"| Reproduction ON (default) | {p_on:.0%} | {r_on:.0%} | {tp_on} | {fp_on} |\n\n"
        f"**Result:** the reproduction pass lifts boolean-SQLi precision "
        f"{p_off:.0%} → {p_on:.0%} on the flaky surface with no recall loss.\n"
    )
    (reports / "fp_reduction.md").write_text(md)
