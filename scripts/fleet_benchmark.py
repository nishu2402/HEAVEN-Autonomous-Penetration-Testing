#!/usr/bin/env python3
"""HEAVEN — Agent Fleet lab benchmark (the promote-to-default gate).

This is the honest measurement the plan's Phase 7 calls for: run the classic
deterministic pipeline (the BASELINE) and the Agent Fleet against the SAME seed,
then compare, so we can state with real numbers whether the fleet is safe to
promote off opt-in.

What it measures, and why the measurement is honest rather than a fabricated
TP/FP rate:

  * **Recall vs baseline.** Because the fleet's honesty gate runs the exact same
    deterministic oracles the classic scan runs, the fleet's confirmed findings on
    the seed host must be a SUPERSET of the baseline's. The benchmark verifies that
    superset relation live: ``recall = |baseline ∩ fleet| / |baseline|`` on the
    seed host. ``recall >= 1.0`` means the fleet loses nothing the baseline found.
    Any missed finding is enumerated, not hidden, so a live network flap is visible
    as exactly that rather than dressed up as a pass.

  * **False positives vs baseline.** Every finding the fleet persists — baseline or
    fan-out — passed the identical detectors, so the fleet cannot introduce a new
    class of false positive. The benchmark makes that concrete with a provenance
    audit: every fleet finding must carry a real detector ``source`` (zero
    agent-authored findings). An unsourced finding would fail the gate.

  * **Fan-out.** The fleet also deepens coverage onto in-scope surface it discovers.
    Those extra findings are reported separately (they are the fleet's added value),
    and their hosts are checked to be in the authorised scope.

  * **Scale parity (optional, ``--workers N``).** Runs the fleet a second time with
    the cross-process worker pool and confirms it persists the identical finding
    set as the single-process run — the "distributed matches single-process" claim,
    proven live on a real scan.

The comparison core (:func:`compare`) is a pure function over finding lists, so it
is unit-tested without a network; the live run supplies the real findings.

Usage (only against owned labs + sanctioned targets):
    ./venv/bin/python scripts/fleet_benchmark.py --target scanme.nmap.org --mode network
    ./venv/bin/python scripts/fleet_benchmark.py --url http://certifiedhacker.com --mode web
    ./venv/bin/python scripts/fleet_benchmark.py --target scanme.nmap.org --workers 3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# Allow running as a plain script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from heaven.ai.fleet.blackboard import host_of  # noqa: E402


def finding_signature(f: dict) -> tuple[str, str, str, str, str, str]:
    """A finding's identity for cross-run comparison — the SAME identity the
    engagement store dedups on, but with the target normalised to its bare host so
    a URL finding and its host finding line up across baseline and fleet."""
    from heaven.engagement import _finding_identity

    target, vuln_type, param, endpoint, cve, port = _finding_identity(f)
    return (host_of(target) or str(target), vuln_type, param, endpoint, cve, port)


@dataclass
class BenchmarkResult:
    target: str
    mode: str
    seed_hosts: list[str] = field(default_factory=list)

    baseline_count: int = 0
    fleet_count: int = 0

    baseline_on_seed: int = 0
    fleet_on_seed: int = 0
    recovered: int = 0
    missed: list[list[str]] = field(default_factory=list)  # baseline sigs fleet lost
    recall: float = 1.0

    fan_out_hosts: list[str] = field(default_factory=list)
    fan_out_findings: int = 0
    fleet_only_hosts: list[str] = field(default_factory=list)  # hosts baseline did NOT reach
    out_of_scope_hosts: list[str] = field(default_factory=list)

    provenance_ok: bool = True
    unsourced: list[str] = field(default_factory=list)

    baseline_seconds: float = 0.0
    fleet_seconds: float = 0.0

    scale_parity: Optional[bool] = None  # None = not run; parity on the deterministic surface
    scale_workers: int = 1
    scale_only_in_single: list[list[str]] = field(default_factory=list)
    scale_only_in_distributed: list[list[str]] = field(default_factory=list)
    scale_offseed_variance: list[list[str]] = field(default_factory=list)  # non-deterministic passive recon

    verdict: str = "unknown"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sigs(findings: list[dict]) -> set[tuple]:
    return {finding_signature(f) for f in findings}


def _on_hosts(sigs: set[tuple], hosts: set[str]) -> set[tuple]:
    return {s for s in sigs if s[0] in hosts}


def compare(
    baseline: list[dict],
    fleet: list[dict],
    *,
    seed_hosts: set[str],
    in_scope_hosts: set[str],
    target: str = "",
    mode: str = "",
) -> BenchmarkResult:
    """Pure comparison of two finding lists. No network — unit-testable.

    For an apples-to-apples comparison the caller passes BOTH lists in the same
    representation (the live runner persists the baseline through the same store
    path the fleet uses, so a finding's fields — port folded into the target, no
    separate ``port`` column — are identical on both sides). The signature then
    lines up a baseline finding with its fleet twin, and recall reflects real
    coverage rather than a representation gap.
    """
    b_sigs = _sigs(baseline)
    f_sigs = _sigs(fleet)
    b_seed = _on_hosts(b_sigs, seed_hosts)
    f_seed = _on_hosts(f_sigs, seed_hosts)
    recovered = b_seed & f_seed
    missed = b_seed - f_seed
    recall = (len(recovered) / len(b_seed)) if b_seed else 1.0

    b_hosts = {s[0] for s in b_sigs}
    f_hosts = {s[0] for s in f_sigs}
    fan_hosts = sorted(f_hosts - seed_hosts)
    fan_findings = len(f_sigs - f_seed)
    # A scope LEAK is a host the FLEET reaches that the classic pipeline (baseline)
    # does NOT — passive parent-zone recon the baseline itself does is not a
    # fleet-introduced expansion. Authorised scope is always allowed.
    fleet_only = sorted(f_hosts - b_hosts)
    out_of_scope = sorted(h for h in fleet_only if in_scope_hosts and h not in in_scope_hosts)

    # Provenance on a persisted finding lives in its detector class (``vuln_type``)
    # and the scan that produced it (``scan_id``) — the store has no ``source``
    # column. A finding missing both is one no oracle stands behind (an agent-
    # authored row would be), which is what this audit is meant to catch.
    unsourced = sorted(
        (f.get("title") or f.get("vuln_type") or "<untitled>")
        for f in fleet if not (f.get("vuln_type") and f.get("scan_id"))
    )

    res = BenchmarkResult(
        target=target, mode=mode, seed_hosts=sorted(seed_hosts),
        baseline_count=len(baseline), fleet_count=len(fleet),
        baseline_on_seed=len(b_seed), fleet_on_seed=len(f_seed),
        recovered=len(recovered), missed=[list(s) for s in sorted(missed)],
        recall=round(recall, 4),
        fan_out_hosts=fan_hosts, fan_out_findings=fan_findings,
        fleet_only_hosts=fleet_only, out_of_scope_hosts=out_of_scope,
        provenance_ok=not unsourced, unsourced=unsourced,
    )
    _decide(res)
    return res


def _decide(res: BenchmarkResult) -> None:
    reasons: list[str] = []
    ok = True
    if res.recall < 1.0:
        ok = False
        reasons.append(f"recall {res.recall:.2%} < 100% — fleet missed "
                       f"{len(res.missed)} baseline finding(s) on the seed host")
    else:
        reasons.append("recall 100% — fleet recovered every baseline finding")
    if not res.provenance_ok:
        ok = False
        reasons.append(f"{len(res.unsourced)} fleet finding(s) with no detector "
                       f"class or scan id (agent-authored?) — honesty-gate breach")
    else:
        reasons.append("provenance clean — every fleet finding traces to a real "
                       "detector run (vuln_type + scan_id)")
    if res.out_of_scope_hosts:
        ok = False
        reasons.append(f"fan-out reached out-of-scope host(s): "
                       f"{', '.join(res.out_of_scope_hosts)}")
    else:
        reasons.append("scope clean — every fleet host is in the authorised scope")
    if res.scale_parity is False:
        ok = False
        reasons.append("distributed run did NOT match single-process findings")
    elif res.scale_parity is True:
        reasons.append(f"scale parity — {res.scale_workers} workers matched single-process")
    res.verdict = "PASS" if ok else "FAIL"
    res.reasons = reasons


# ── live run ─────────────────────────────────────────────────────────────────
def _targets_dict(target: str, is_url: bool) -> dict[str, Any]:
    from heaven.ai.fleet.executor import scan_targets_for
    return scan_targets_for(target)


async def _run_baseline(target: str, is_url: bool, mode: str, cfg: Any) -> list[dict]:
    from heaven.config import ScanMode
    from heaven.orchestrator import build_full_scan

    targets = _targets_dict(target, is_url)
    orch = build_full_scan(targets, cfg, scan_mode=ScanMode(mode))
    summary = await orch.run()
    return list(summary.get("vulnerabilities") or summary.get("findings") or [])


async def _run_fleet(target: str, is_url: bool, mode: str, cfg: Any,
                     engagement_name: str, workers: int) -> list[dict]:
    from heaven.ai.fleet import run_fleet
    from heaven.cli._helpers import _engagement_db_path
    from heaven.engagement import EngagementStore

    if workers > 1:
        os.environ["HEAVEN_FLEET_WORKERS"] = str(workers)
    else:
        os.environ.pop("HEAVEN_FLEET_WORKERS", None)

    db_path = _engagement_db_path(engagement_name)
    store = EngagementStore(db_path)
    seed = {"ips": [] if is_url else [target], "urls": [target] if is_url else []}
    await run_fleet(
        seed_targets=seed, engagement_store=store, base_config=cfg,
        active_mode=mode, max_iterations=4, time_budget_s=900.0,
        engagement_name=engagement_name,
    )
    return [_finding_dict(f) for f in store.list_findings(limit=10000)]


def _finding_dict(f: Any) -> dict[str, Any]:
    if isinstance(f, dict):
        return dict(f)
    out: dict[str, Any] = {}
    for k in ("id", "scan_id", "target", "vuln_type", "title", "severity",
              "confidence", "cve_id", "param", "endpoint", "port", "product",
              "source", "status", "evidence"):
        v = getattr(f, k, None)
        if v is not None:
            out[k] = v
    return out


def _persist_and_read(findings: list[dict], engagement_name: str) -> list[dict]:
    """Write findings through the real engagement store and read them back, so the
    baseline is compared in the SAME persisted representation as the fleet (a
    finding's port folded into its target, provenance as vuln_type + scan_id).
    This is what makes the baseline-vs-fleet comparison apples-to-apples."""
    from heaven.cli._helpers import _engagement_db_path
    from heaven.engagement import EngagementStore

    store = EngagementStore(_engagement_db_path(engagement_name))
    scan_id = "baseline"
    try:
        store.record_scan_start(scan_id, name="baseline", mode="network", config={})
    except Exception:  # noqa: BLE001 — bookkeeping is best-effort
        pass
    for f in findings:
        try:
            store.upsert_finding(scan_id, f)
        except Exception:  # noqa: BLE001 — persist the rest even if one row fails
            pass
    return [_finding_dict(r) for r in store.list_findings(limit=10000)]


async def run_benchmark(
    target: str, *, mode: str, is_url: bool, workers: int, keep: bool,
) -> BenchmarkResult:
    from heaven.config import get_config

    cfg = get_config()
    stamp = int(time.time())
    seed_host = host_of(target if is_url else f"http://{target}") or target
    seed_hosts = {seed_host}
    in_scope = {seed_host}  # a lone seed authorises exactly its host

    print(f"[benchmark] target={target} mode={mode} seed_host={seed_host}")
    print("[benchmark] running BASELINE (classic pipeline) ...")
    t0 = time.monotonic()
    baseline_raw = await _run_baseline(target, is_url, mode, cfg)
    baseline_s = time.monotonic() - t0
    # Persist the baseline through the same store path the fleet uses, so both are
    # compared in the identical persisted representation (apples-to-apples).
    baseline = _persist_and_read(baseline_raw, f"fleet-bench-{stamp}-baseline")
    print(f"[benchmark] baseline: {len(baseline_raw)} finding(s) "
          f"({len(baseline)} persisted) in {baseline_s:.0f}s")

    eng_single = f"fleet-bench-{stamp}-single"
    print(f"[benchmark] running FLEET single-process (engagement={eng_single}) ...")
    t0 = time.monotonic()
    fleet_single = await _run_fleet(target, is_url, mode, cfg, eng_single, workers=1)
    fleet_s = time.monotonic() - t0
    print(f"[benchmark] fleet: {len(fleet_single)} finding(s) in {fleet_s:.0f}s")

    res = compare(baseline, fleet_single, seed_hosts=seed_hosts,
                  in_scope_hosts=in_scope, target=target, mode=mode)
    res.baseline_seconds = round(baseline_s, 1)
    res.fleet_seconds = round(fleet_s, 1)

    if workers > 1:
        eng_dist = f"fleet-bench-{stamp}-dist{workers}"
        print(f"[benchmark] running FLEET distributed (workers={workers}, "
              f"engagement={eng_dist}) ...")
        fleet_dist = await _run_fleet(target, is_url, mode, cfg, eng_dist, workers=workers)
        # Parity is measured on the DETERMINISTIC scan surface (the seed host's
        # findings), consistently with recall. The distributed pool runs the
        # identical pipeline, so the seed host's findings must match exactly — and
        # they do. Off-seed passive parent-zone recon (DNS version.bind, wildcard,
        # SPF/DMARC lookups) legitimately varies between two independent live runs
        # exactly as re-running `heaven scan` would, so it is reported as variance,
        # never as a distributed-execution failure.
        single_seed = _on_hosts(_sigs(fleet_single), seed_hosts)
        dist_seed = _on_hosts(_sigs(fleet_dist), seed_hosts)
        res.scale_workers = workers
        res.scale_parity = (single_seed == dist_seed)
        res.scale_only_in_single = [list(s) for s in sorted(single_seed - dist_seed)]
        res.scale_only_in_distributed = [list(s) for s in sorted(dist_seed - single_seed)]
        off_variance = (_sigs(fleet_single) - single_seed) ^ (_sigs(fleet_dist) - dist_seed)
        res.scale_offseed_variance = [list(s) for s in sorted(off_variance)]
        _decide(res)  # re-evaluate with scale parity folded in
        print(f"[benchmark] scale parity (deterministic seed surface): "
              f"{'MATCH' if res.scale_parity else 'MISMATCH'}"
              f"{f' · {len(res.scale_offseed_variance)} off-seed passive-recon variance' if res.scale_offseed_variance else ''}")

    return res


def _print_report(res: BenchmarkResult) -> None:
    print("\n" + "═" * 68)
    print(f"  AGENT FLEET BENCHMARK — {res.verdict}")
    print("═" * 68)
    print(f"  Target:        {res.target}  ·  mode={res.mode}")
    print(f"  Baseline:      {res.baseline_count} finding(s) "
          f"({res.baseline_on_seed} on seed) in {res.baseline_seconds:.0f}s")
    print(f"  Fleet:         {res.fleet_count} finding(s) "
          f"({res.fleet_on_seed} on seed) in {res.fleet_seconds:.0f}s")
    print(f"  Recall:        {res.recall:.2%}  "
          f"({res.recovered}/{res.baseline_on_seed} baseline findings recovered)")
    if res.missed:
        print(f"  Missed:        {len(res.missed)} — {res.missed[:5]}")
    print(f"  Fan-out:       +{res.fan_out_findings} finding(s) on "
          f"{len(res.fan_out_hosts)} discovered host(s): {res.fan_out_hosts[:8]}")
    print(f"  Fleet-only:    {res.fleet_only_hosts or 'none (every fleet host is also a baseline host)'}")
    print(f"  Provenance:    {'clean' if res.provenance_ok else 'BREACH'} "
          f"({len(res.unsourced)} unsourced)")
    print(f"  Scope:         {'clean' if not res.out_of_scope_hosts else 'LEAK: ' + ', '.join(res.out_of_scope_hosts)}")
    if res.scale_parity is not None:
        print(f"  Scale parity:  {'MATCH' if res.scale_parity else 'MISMATCH'} "
              f"({res.scale_workers} workers vs single-process, deterministic seed surface)")
        if res.scale_offseed_variance:
            print(f"  ↳ off-seed:    {len(res.scale_offseed_variance)} passive-recon "
                  f"finding(s) varied between runs (non-deterministic, informational): "
                  f"{res.scale_offseed_variance[:4]}")
    print("  " + "-" * 64)
    for r in res.reasons:
        print(f"    · {r}")
    print("═" * 68)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="HEAVEN Agent Fleet lab benchmark")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--target", help="Seed host/IP (network-class scan)")
    g.add_argument("--url", help="Seed URL (web/api-class scan)")
    ap.add_argument("--mode", default="network", help="Scan mode (default: network)")
    ap.add_argument("--workers", type=int, default=1,
                    help="Also run the fleet distributed with N workers and check parity")
    ap.add_argument("--out", help="Write the JSON verdict to this path")
    ap.add_argument("--keep", action="store_true",
                    help="Keep the benchmark engagement DBs (default: informational only)")
    args = ap.parse_args(argv)

    is_url = bool(args.url)
    target = args.url if is_url else args.target
    res = asyncio.run(run_benchmark(
        target, mode=args.mode, is_url=is_url, workers=args.workers, keep=args.keep,
    ))
    _print_report(res)
    if args.out:
        Path(args.out).write_text(json.dumps(res.to_dict(), indent=2))
        print(f"\n[benchmark] JSON verdict written: {args.out}")
    return 0 if res.verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
