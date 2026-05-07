"""
HEAVEN — False-Positive Suppression Layer.

A real pen-tester double-checks every "finding" before putting it in a report.
This module does the same: every candidate finding goes through second-stage
validation that explicitly tries to *reject* it before accepting it.

The goal is to produce findings with calibrated confidence, not to claim
"99.99% accuracy". Confidence values returned here are coarse buckets that
have actual meaning:

    0.95+    Strong: at least two independent signals confirmed it
    0.80-95  High: one signal confirmed and was reproducible
    0.60-80  Medium: one signal seen, not reproducible
    0.40-60  Low: probable false positive — present but heavily caveated
    < 0.40   Discarded — never makes it into a report

This file does NOT execute exploits. It re-runs the same probe types as the
primary validator and looks for noise patterns: dynamic content, network
jitter, rate limiting, WAF interference.
"""

from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.fp_suppress")


@dataclass
class SuppressionVerdict:
    """Result of running FP suppression against a candidate finding."""
    keep: bool
    final_confidence: float
    bucket: str           # "strong" | "high" | "medium" | "low" | "discarded"
    reasons: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


def _bucket_for(conf: float) -> str:
    if conf >= 0.95:
        return "strong"
    if conf >= 0.80:
        return "high"
    if conf >= 0.60:
        return "medium"
    if conf >= 0.40:
        return "low"
    return "discarded"


async def _measure_baseline(session, method: str, url: str, param: str,
                            samples: int = 5, timeout: float = 10.0) -> dict:
    """
    Measure baseline timing and response size for the unmodified endpoint.
    Used to detect dynamic content, rate-limiting, and CDN jitter that would
    otherwise look like a vulnerability signal.
    """
    if aiohttp is None:
        return {"available": False}

    timings_ms: list[float] = []
    sizes: list[int] = []
    statuses: list[int] = []

    benign_value = "heaven_baseline_probe"
    for _ in range(samples):
        t0 = time.time()
        try:
            kwargs: dict[str, Any] = {
                "timeout": aiohttp.ClientTimeout(total=timeout),
                "allow_redirects": True,
            }
            if method.upper() == "GET":
                kwargs["params"] = {param: benign_value}
            else:
                kwargs["data"] = {param: benign_value}
            async with session.request(method, url, **kwargs) as resp:
                body = await resp.text()
                timings_ms.append((time.time() - t0) * 1000)
                sizes.append(len(body))
                statuses.append(resp.status)
        except Exception:
            # Network error — record a sentinel
            timings_ms.append(timeout * 1000)
            sizes.append(0)
            statuses.append(0)
        await asyncio.sleep(0.1)  # gentle pacing

    if not timings_ms:
        return {"available": False}

    return {
        "available": True,
        "samples": samples,
        "timing_mean_ms": statistics.mean(timings_ms),
        "timing_stdev_ms": statistics.stdev(timings_ms) if len(timings_ms) > 1 else 0.0,
        "timing_max_ms": max(timings_ms),
        "size_mean": statistics.mean(sizes),
        "size_stdev": statistics.stdev(sizes) if len(sizes) > 1 else 0.0,
        "status_consistent": len(set(statuses)) == 1,
    }


async def suppress_sqli_fp(session, finding: dict, url: str, param: str,
                           method: str = "GET") -> SuppressionVerdict:
    """
    Re-test a SQLi candidate against baseline noise.

    A SQLi candidate from the primary validator includes a `technique` field
    in evidence — different techniques get different second-stage checks.
    """
    technique = finding.get("evidence", {}).get("technique", "")
    initial_conf = float(finding.get("confidence", 0.0))
    reasons: list[str] = []

    baseline = await _measure_baseline(session, method, url, param, samples=5)
    if not baseline.get("available"):
        return SuppressionVerdict(
            keep=True, final_confidence=initial_conf * 0.7,
            bucket=_bucket_for(initial_conf * 0.7),
            reasons=["baseline_unavailable_keep_low_conf"],
            evidence={"baseline": baseline},
        )

    # Time-based SQLi: re-run the payload, compare to baseline timing distribution
    if technique == "time_based_blind":
        payload = finding.get("evidence", {}).get("payload", "")
        # Confirm the delay is reproducible AND clearly above baseline noise
        confirmation_delays = []
        for _ in range(3):
            t0 = time.time()
            try:
                kwargs: dict[str, Any] = {
                    "timeout": aiohttp.ClientTimeout(total=15),
                    "allow_redirects": True,
                }
                if method.upper() == "GET":
                    kwargs["params"] = {param: payload}
                else:
                    kwargs["data"] = {param: payload}
                async with session.request(method, url, **kwargs) as resp:
                    await resp.text()
                confirmation_delays.append((time.time() - t0) * 1000)
            except Exception:
                confirmation_delays.append(15000)
            await asyncio.sleep(0.2)

        # Threshold: payload-induced delay must be at least 2.5s above baseline
        # mean PLUS at least 5x the baseline stdev (rejects noisy CDNs).
        threshold = baseline["timing_mean_ms"] + max(2500, 5 * baseline["timing_stdev_ms"])
        passing = sum(1 for d in confirmation_delays if d > threshold)

        evidence = {
            "baseline": baseline,
            "confirmation_delays_ms": confirmation_delays,
            "threshold_ms": threshold,
        }

        if passing >= 2:
            reasons.append(f"time_diff_reproducible_{passing}/3")
            final_conf = min(0.97, initial_conf + 0.05)
        elif passing == 1:
            reasons.append("time_diff_intermittent_1/3")
            final_conf = max(0.50, initial_conf - 0.20)
        else:
            reasons.append("time_diff_not_reproducible")
            final_conf = max(0.20, initial_conf - 0.50)

        return SuppressionVerdict(
            keep=final_conf >= 0.40, final_confidence=final_conf,
            bucket=_bucket_for(final_conf), reasons=reasons, evidence=evidence,
        )

    # Boolean inference: re-test true/false pair, check that diff is reproducible
    if technique == "boolean_inference":
        evidence_diff = finding.get("evidence", {}).get("length_diff", 0)
        size_noise = baseline.get("size_stdev", 0)

        # If the original "diff" is within 2× the baseline content jitter, it's noise
        if evidence_diff <= 2 * size_noise and evidence_diff < 100:
            reasons.append(f"length_diff_within_baseline_noise (diff={evidence_diff:.0f}, stdev={size_noise:.0f})")
            final_conf = max(0.20, initial_conf - 0.55)
        elif evidence_diff > 5 * size_noise:
            reasons.append("length_diff_above_baseline_noise")
            final_conf = min(0.95, initial_conf + 0.03)
        else:
            reasons.append("length_diff_inconclusive")
            final_conf = max(0.45, initial_conf - 0.25)

        return SuppressionVerdict(
            keep=final_conf >= 0.40, final_confidence=final_conf,
            bucket=_bucket_for(final_conf), reasons=reasons,
            evidence={"baseline": baseline, "length_diff": evidence_diff},
        )

    # Error-based: error pattern in body is high-signal but check for "always errors"
    if technique == "error_based":
        # Re-probe with benign payload — if we still see SQL error keywords on
        # benign input, the page just dumps errors (low signal, not a vuln signal).
        try:
            kwargs2: dict[str, Any] = {
                "timeout": aiohttp.ClientTimeout(total=10),
                "allow_redirects": True,
            }
            if method.upper() == "GET":
                kwargs2["params"] = {param: "heaven_benign_input"}
            else:
                kwargs2["data"] = {param: "heaven_benign_input"}
            async with session.request(method, url, **kwargs2) as resp:
                benign_body = (await resp.text()).lower()
        except Exception:
            benign_body = ""

        sql_errors = ("sql syntax", "mysql", "postgresql", "sqlite", "ora-",
                      "syntax error", "sqlstate")
        benign_has_errors = any(e in benign_body for e in sql_errors)

        if benign_has_errors:
            reasons.append("benign_payload_also_triggers_errors_likely_FP")
            final_conf = max(0.30, initial_conf - 0.45)
        else:
            reasons.append("error_only_on_payload_strong_signal")
            final_conf = min(0.96, initial_conf + 0.05)

        return SuppressionVerdict(
            keep=final_conf >= 0.40, final_confidence=final_conf,
            bucket=_bucket_for(final_conf), reasons=reasons,
            evidence={"benign_body_has_sql_errors": benign_has_errors},
        )

    # Unknown technique — just pass through with mild confidence cut
    return SuppressionVerdict(
        keep=True, final_confidence=max(0.50, initial_conf - 0.10),
        bucket=_bucket_for(max(0.50, initial_conf - 0.10)),
        reasons=["unknown_technique_pass_through"], evidence={"baseline": baseline},
    )


async def suppress_xss_fp(session, finding: dict, url: str, param: str,
                          method: str = "GET") -> SuppressionVerdict:
    """
    Re-test an XSS candidate.

    Real XSS = canary lands in a *parsed* HTML/JS context. Our reflection check
    can fire when the canary just appears in escaped form. This pass re-checks
    that the canary lands unescaped.
    """
    initial_conf = float(finding.get("confidence", 0.0))
    canary = finding.get("evidence", {}).get("canary", "")
    if not canary:
        return SuppressionVerdict(
            keep=True, final_confidence=initial_conf,
            bucket=_bucket_for(initial_conf),
            reasons=["no_canary_in_evidence_pass_through"],
        )

    # Send the unique canary; verify it appears unescaped
    test_payload = f"<{canary}>"
    try:
        kwargs: dict[str, Any] = {
            "timeout": aiohttp.ClientTimeout(total=10),
            "allow_redirects": True,
        }
        if method.upper() == "GET":
            kwargs["params"] = {param: test_payload}
        else:
            kwargs["data"] = {param: test_payload}
        async with session.request(method, url, **kwargs) as resp:
            body = await resp.text()
    except Exception as e:
        return SuppressionVerdict(
            keep=True, final_confidence=initial_conf * 0.7,
            bucket=_bucket_for(initial_conf * 0.7),
            reasons=[f"reflection_check_failed:{type(e).__name__}"],
        )

    # Check what *form* the canary appears in
    has_unescaped = test_payload in body
    has_escaped = (f"&lt;{canary}&gt;" in body) or (f"\\u003c{canary}\\u003e" in body)
    has_url_encoded = (f"%3C{canary}%3E" in body) or (f"%3c{canary}%3e" in body)

    reasons = []
    if has_unescaped:
        reasons.append("canary_reflected_unescaped_strong_signal")
        final_conf = min(0.97, initial_conf + 0.05)
    elif has_escaped or has_url_encoded:
        reasons.append("canary_reflected_but_escaped_likely_safe")
        final_conf = max(0.20, initial_conf - 0.55)
    elif canary in body:
        reasons.append("canary_substring_present_context_unclear")
        final_conf = max(0.50, initial_conf - 0.20)
    else:
        reasons.append("canary_not_found_likely_FP")
        final_conf = 0.20

    return SuppressionVerdict(
        keep=final_conf >= 0.40, final_confidence=final_conf,
        bucket=_bucket_for(final_conf), reasons=reasons,
        evidence={
            "has_unescaped_canary": has_unescaped,
            "has_escaped_canary": has_escaped,
            "has_url_encoded": has_url_encoded,
        },
    )


async def suppress_ssrf_fp(session, finding: dict, url: str, param: str,
                           method: str = "GET") -> SuppressionVerdict:
    """SSRF FP suppression — needs OOB callback or response oracle."""
    initial_conf = float(finding.get("confidence", 0.0))
    has_oob = finding.get("evidence", {}).get("oob_callback_received", False)
    has_metadata = finding.get("evidence", {}).get("cloud_metadata_in_response", False)

    if has_oob:
        # OOB callback is hard to fake — high confidence
        return SuppressionVerdict(
            keep=True, final_confidence=min(0.98, initial_conf + 0.10),
            bucket="strong", reasons=["oob_callback_received"],
        )
    if has_metadata:
        return SuppressionVerdict(
            keep=True, final_confidence=min(0.96, initial_conf + 0.05),
            bucket=_bucket_for(min(0.96, initial_conf + 0.05)),
            reasons=["cloud_metadata_leaked_in_response"],
        )
    # Neither — heavy confidence cut
    return SuppressionVerdict(
        keep=initial_conf >= 0.50,
        final_confidence=max(0.30, initial_conf - 0.30),
        bucket=_bucket_for(max(0.30, initial_conf - 0.30)),
        reasons=["no_oob_no_metadata_response_only_signal"],
    )


# ── Generic suppression dispatcher ──

SUPPRESSORS = {
    "sqli": suppress_sqli_fp,
    "xss": suppress_xss_fp,
    "ssrf": suppress_ssrf_fp,
}


async def suppress_finding(session, finding: dict) -> SuppressionVerdict:
    """
    Dispatch a finding through its FP-suppressor.
    For vuln types without a specific suppressor, we pass through with a small
    confidence haircut to be conservative.
    """
    vuln_type = (finding.get("vuln_type") or finding.get("type") or "").lower()
    url = finding.get("target_url") or finding.get("target") or finding.get("url")
    param = finding.get("param", "")
    method = finding.get("method", "GET")

    if vuln_type not in SUPPRESSORS or not url:
        initial_conf = float(finding.get("confidence", 0.5))
        return SuppressionVerdict(
            keep=True, final_confidence=max(0.40, initial_conf - 0.05),
            bucket=_bucket_for(max(0.40, initial_conf - 0.05)),
            reasons=["no_specific_suppressor_pass_through"],
        )

    suppressor = SUPPRESSORS[vuln_type]
    try:
        return await suppressor(session, finding, url, param, method)
    except Exception as e:
        logger.warning(f"FP suppressor {vuln_type} crashed: {e}")
        initial_conf = float(finding.get("confidence", 0.5))
        return SuppressionVerdict(
            keep=True, final_confidence=initial_conf * 0.8,
            bucket=_bucket_for(initial_conf * 0.8),
            reasons=[f"suppressor_error:{type(e).__name__}"],
        )


def apply_verdict(finding: dict, verdict: SuppressionVerdict) -> dict:
    """Mutate a finding dict with the suppressor's verdict."""
    finding["confidence"] = round(verdict.final_confidence, 3)
    finding["confidence_bucket"] = verdict.bucket
    finding["fp_check_reasons"] = verdict.reasons
    finding["fp_check_evidence"] = verdict.evidence
    finding["suppressed"] = not verdict.keep
    if not verdict.keep:
        finding["result"] = "false_positive"
    return finding
