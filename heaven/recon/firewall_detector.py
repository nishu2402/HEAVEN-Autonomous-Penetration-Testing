"""
HEAVEN — Perimeter Defense Detector

Read-only heuristics that decide, from an *already-collected* scan result,
whether a target sits behind a packet-filtering firewall, an active IDS/IPS
that is rate-blocking the scanner, a slow-loris tarpit, or (for web targets) a
Web Application Firewall — and, crucially, what to DO about it so the scan still
yields findings.

Why this exists
---------------
The single most common "the tool found nothing but the box is clearly
vulnerable" cause on internal and enterprise engagements is a perimeter defence
silently dropping the scanner's probes. nmap under ``-Pn`` faithfully reaches
the host, but a stateful firewall answers most ports with *nothing* (state
``filtered``) rather than a TCP RST (``closed``), and an IPS may let the first
few connections through and then start dropping them once a rate threshold is
crossed. Either way the naive read is "0 open ports → nothing here", which is
wrong: the services are there, the perimeter is just hiding them.

This module turns that invisible failure into (a) an explicit, reported
observation and (b) a signal the scanner acts on — a bounded evasion re-probe
(fragmented packets, a trusted source port, slower timing) that routinely gets
results back through a filtering firewall on an *authorized* test.

Design contract (matches the rest of HEAVEN)
--------------------------------------------
* **Pure + deterministic + read-only.** Every function here only *classifies*
  data another component already observed. Nothing here sends a packet, so it is
  safe to call unconditionally and trivial to unit-test.
* **Conservative.** A verdict is emitted only when the evidence is unambiguous
  (e.g. many ``filtered`` ports and almost no ``closed`` ones). A normal host —
  where unopened ports come back ``closed`` (RST) — is classified ``none`` and
  produces no finding, so this never adds false positives to a clean scan.
* **Honest.** Detecting a firewall is not "a vulnerability" — a firewall is good
  security. The surfaced finding is informational; its value is telling the
  operator *why* results may be thin and exactly how to still get them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("firewall")

# ── Postures ─────────────────────────────────────────────────────────────────
POSTURE_NONE = "none"
POSTURE_FIREWALL = "firewall"        # stateful packet filter dropping probes
POSTURE_IDS_IPS = "ids_ips"          # active, rate-based blocking mid-scan
POSTURE_TARPIT = "tarpit"            # slow-loris sinkhole wasting scanner time
POSTURE_WAF = "waf"                  # HTTP-layer web application firewall

_POSTURE_LABEL = {
    POSTURE_NONE: "None",
    POSTURE_FIREWALL: "Packet-filtering firewall",
    POSTURE_IDS_IPS: "Active IDS/IPS (rate-blocking)",
    POSTURE_TARPIT: "Tarpit / sinkhole",
    POSTURE_WAF: "Web Application Firewall",
}


@dataclass
class PerimeterVerdict:
    """The classification for one host, plus the operator-facing guidance."""
    host: str
    posture: str = POSTURE_NONE
    detected: bool = False
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return _POSTURE_LABEL.get(self.posture, self.posture)

    @property
    def evasion_recommended(self) -> bool:
        """True when a bounded evasion re-probe is worth attempting — i.e. the
        perimeter is *actively hiding ports* (firewall/IPS), as opposed to a WAF
        (an HTTP-layer control the port scan already saw past) or a tarpit (where
        re-probing just wastes more time)."""
        return self.posture in (POSTURE_FIREWALL, POSTURE_IDS_IPS)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "posture": self.posture,
            "label": self.label,
            "detected": self.detected,
            "confidence": round(self.confidence, 2),
            "indicators": list(self.indicators),
            "recommendation": self.recommendation,
            "evidence": dict(self.evidence),
        }


# ── WAF fingerprint table ─────────────────────────────────────────────────────
# vendor → list of case-insensitive substrings that, if present in ANY response
# header name/value (or a Set-Cookie / Server value), identify the WAF/CDN. Kept
# deliberately specific so a bare "cloudflare" CDN header doesn't over-trigger on
# unrelated infrastructure. Every match is a real, observed header — never a
# guess. Sources: public WAF fingerprint corpora (wafw00f-style) trimmed to the
# high-precision markers.
_WAF_SIGNATURES: dict[str, tuple[str, ...]] = {
    "Cloudflare": ("cf-ray", "cf-cache-status", "__cfduid", "cf-mitigated",
                   "server: cloudflare"),
    "Akamai": ("akamaighost", "akamai-", "x-akamai", "ak-bmsc"),
    "Imperva / Incapsula": ("incap_ses", "visid_incap", "x-iinfo", "x-cdn: incapsula"),
    "AWS WAF / CloudFront": ("x-amzn-requestid", "x-amz-cf-id", "awselb", "x-amz-waf"),
    "Sucuri CloudProxy": ("x-sucuri-id", "x-sucuri-cache", "server: sucuri"),
    "F5 BIG-IP ASM": ("bigipserver", "ts01", "x-waf-event", "x-cnection"),
    "Barracuda": ("barra_counter_session", "barracuda"),
    "Fortinet FortiWeb": ("fortiwafsid", "fortigate", "fortiweb"),
    "ModSecurity": ("mod_security", "modsecurity", "server: mod_security"),
    "Wordfence": ("wordfence", "x-wordfence"),
    "Citrix NetScaler": ("ns_af", "citrix_ns_id", "nsc_"),
    "Azure Front Door / WAF": ("x-azure-ref", "x-fd-", "azurefd"),
}

# HTTP status codes a WAF characteristically returns when it blocks a request
# that a normal origin would 200/404. A block-page status alone is weak, so it
# is only used as a *supporting* indicator alongside a header/canary signal.
_WAF_BLOCK_STATUSES = frozenset({403, 406, 419, 429, 501, 999})


def waf_signature(
    headers: Optional[dict[str, Any]] = None,
    status: Optional[int] = None,
    body: str = "",
) -> tuple[str, list[str]]:
    """Identify a WAF/CDN in front of a web target from its response.

    Returns ``(vendor, indicators)`` — ``("", [])`` when nothing matched. Purely
    string-matching over headers the caller already fetched; sends nothing.
    """
    indicators: list[str] = []
    vendor = ""
    # Flatten headers into one lowercased "name: value" haystack per entry so a
    # signature can match either a header NAME (e.g. "cf-ray") or a value
    # (e.g. "server: cloudflare").
    hay: list[str] = []
    for k, v in (headers or {}).items():
        name = str(k).lower()
        val = str(v).lower()
        hay.append(name)
        hay.append(f"{name}: {val}")
        hay.append(val)
    body_low = (body or "").lower()

    for name, needles in _WAF_SIGNATURES.items():
        for needle in needles:
            if any(needle in h for h in hay) or needle in body_low:
                vendor = name
                indicators.append(f"WAF fingerprint: '{needle}' → {name}")
                break
        if vendor:
            break

    if vendor and status in _WAF_BLOCK_STATUSES:
        indicators.append(f"WAF-style block status {status}")
    return vendor, indicators


# ── Core classifier ───────────────────────────────────────────────────────────
# Tunables (module-level so tests can reference them and operators can reason
# about the thresholds). All chosen to favour precision over recall.
_MIN_FILTERED_FOR_FIREWALL = 20      # need a meaningful number of dropped ports
_FILTERED_TO_CLOSED_RATIO = 3.0      # filtered must dominate closed (RST) by this
_TARPIT_MEDIAN_MS = 4000.0           # uniformly slow responses ⇒ likely a tarpit


def classify_perimeter(
    host: str,
    *,
    open_count: int,
    filtered_count: int,
    closed_count: int,
    total_probed: int = 0,
    reachable: bool = True,
    response_times_ms: Optional[list[float]] = None,
    blocking_trajectory: bool = False,
    http: Optional[tuple[str, list[str]]] = None,
) -> PerimeterVerdict:
    """Classify one host's perimeter posture from its collected scan signals.

    Parameters
    ----------
    open_count / filtered_count / closed_count
        Port-state tallies from the nmap parse (``filtered`` = silently dropped,
        the firewall signal; ``closed`` = TCP RST, the *no*-firewall signal).
    total_probed
        How many ports were probed (defaults to the sum of the three states).
    reachable
        Whether the host answered at all (any open/closed port, or a probe).
    response_times_ms
        Per-open-port response times, used only for tarpit detection.
    blocking_trajectory
        True when the scanner observed ports answering early then connections
        being dropped — the fingerprint of an IPS crossing a rate threshold.
    http
        Optional ``(waf_vendor, indicators)`` from :func:`waf_signature`.
    """
    probed = total_probed or (open_count + filtered_count + closed_count)
    verdict = PerimeterVerdict(host=host)
    verdict.evidence = {
        "open": open_count, "filtered": filtered_count,
        "closed": closed_count, "probed": probed, "reachable": reachable,
    }

    # A host that returned nothing at all carries no perimeter signal — don't
    # guess (it may simply be down or fully closed to us).
    if not reachable and open_count == 0 and filtered_count == 0 and closed_count == 0:
        verdict.recommendation = (
            "No response on any probed port. If you know the host is up, it is "
            "fully firewalled from this vantage point — scan from an in-scope "
            "network segment or confirm the allowed source with the firewall owner."
        )
        return verdict

    # 1) WAF (HTTP layer) — an explicit fingerprint wins for web targets. It does
    #    not hide ports, so it never blocks the port scan; it shapes web testing.
    if http:
        waf_vendor, waf_ind = http
        if waf_vendor:
            verdict.posture = POSTURE_WAF
            verdict.detected = True
            verdict.confidence = 0.85
            verdict.indicators = list(waf_ind) or [f"WAF fingerprint: {waf_vendor}"]
            verdict.evidence["waf_vendor"] = waf_vendor
            verdict.recommendation = (
                f"A Web Application Firewall ({waf_vendor}) is in front of the "
                "application. HEAVEN auto-enables payload obfuscation (encoding / "
                "case / comment variants) to reduce signature blocking; for full "
                "coverage, test the origin directly (bypassing the CDN/WAF) or have "
                "the WAF allowlist the tester IP for the engagement."
            )
            return verdict

    # 2) Active IPS — early success then drops. The strongest "your results are
    #    being throttled" signal; slowing down is the fix.
    if blocking_trajectory:
        verdict.posture = POSTURE_IDS_IPS
        verdict.detected = True
        verdict.confidence = 0.7
        verdict.indicators = [
            "Ports answered early in the scan, then connections began timing out "
            "— consistent with rate-based IPS blocking of the scanner."
        ]
        verdict.recommendation = (
            "An IPS appears to be rate-blocking the scan. Re-run slower "
            "(`--stealth paranoid`, which caps parallelism and adds scan delay) to "
            "stay under the rate threshold, or coordinate a tester-IP allowlist. "
            "HEAVEN's adaptive re-probe already retried the missed ports slowly."
        )
        return verdict

    # 3) Tarpit — many "open" ports, uniformly very slow. Suspicious, not a win.
    rts = [t for t in (response_times_ms or []) if t and t > 0]
    if open_count >= 3 and len(rts) >= 3 and median(rts) >= _TARPIT_MEDIAN_MS:
        verdict.posture = POSTURE_TARPIT
        verdict.detected = True
        verdict.confidence = 0.55
        verdict.indicators = [
            f"{open_count} ports 'open' but responding very slowly "
            f"(median {median(rts):.0f} ms) — consistent with a tarpit/sinkhole."
        ]
        verdict.recommendation = (
            "The host answers slowly and uniformly on many ports, a tarpit pattern "
            "designed to waste scanner time. Treat these 'open' ports and any "
            "service banners with suspicion and corroborate before acting on them."
        )
        return verdict

    # 4) Packet-filtering firewall — many dropped (filtered) ports and almost no
    #    RSTs. This is the classic internal-engagement blind spot.
    if (
        filtered_count >= _MIN_FILTERED_FOR_FIREWALL
        and filtered_count >= max(1, closed_count) * _FILTERED_TO_CLOSED_RATIO
    ):
        ratio = filtered_count / max(1, probed)
        verdict.posture = POSTURE_FIREWALL
        verdict.detected = True
        verdict.confidence = min(0.95, 0.5 + ratio * 0.5)
        verdict.indicators = [
            f"{filtered_count} filtered vs {closed_count} closed port(s): the "
            "perimeter is silently dropping probes rather than refusing them "
            "(a stateful firewall's default-drop signature)."
        ]
        verdict.recommendation = (
            "A packet-filtering firewall is dropping probes to most ports. Re-run "
            "with evasion (`heaven scan --evade`, or `--stealth stealth`) — HEAVEN "
            "fragments packets, pads them, and sources from a trusted port (53) to "
            "slip probes past simple filters — and scan from an in-scope segment "
            "closer to the target. Confirm the intended allowed ports with the "
            "firewall owner. HEAVEN's adaptive re-probe already retried the "
            "high-value ports with these techniques."
        )
        return verdict

    # Otherwise: a normal host (unopened ports came back closed/RST) — no defence
    # inferred, no finding emitted.
    verdict.recommendation = "No perimeter filtering inferred (unopened ports refused normally)."
    return verdict


# ── Finding synthesis ─────────────────────────────────────────────────────────
def build_scan_completeness_findings(net_data: dict) -> list[dict]:
    """Emit an honest, informational finding when the network sweep was cut short.

    ``scan_network`` returns ``hosts_timed_out`` — the number of hosts still in
    flight when the deep-scan deadline fired (their ports were NOT fully
    enumerated). Left unsurfaced, this is exactly the "I toggled a full-port scan
    but only got a few ports" symptom: the scan silently returned partial results.
    Turning it into a visible observation means the operator always knows the port
    list is incomplete and how to get a complete one — never a silent truncation.
    """
    if not isinstance(net_data, dict):
        return []
    timed_out = int(net_data.get("hosts_timed_out") or 0)
    if timed_out <= 0:
        return []
    total = int(net_data.get("total_hosts") or 0) + timed_out
    return [{
        "target": "network scan",
        "vuln_type": "scan_incomplete",
        "severity": "info",
        "title": f"Network scan incomplete — {timed_out} host(s) not fully enumerated",
        "description": (
            f"The deep port scan reached its time budget with {timed_out} of "
            f"{total} host(s) still in flight, so their port lists are PARTIAL — "
            "only the ports found before the deadline are reported. This is why a "
            "scan can come back with fewer open ports than expected. To get a "
            "complete enumeration, scan fewer hosts at once, narrow the port range "
            "to the ports you care about, or re-run this scan on its own (HEAVEN "
            "gives an explicit full-range or UDP scan a larger deadline, and a "
            "slower stealth level more time still)."
        ),
        "confidence": 1.0,
        # A statement about scan conditions, not an exploitable weakness — resolves
        # to "Informational" and is ignored by the confirmed-only Overall Risk.
        "observation": True,
        "evidence": {
            "hosts_timed_out": timed_out,
            "hosts_completed": int(net_data.get("total_hosts") or 0),
        },
    }]


def build_perimeter_findings(net_data: dict) -> list[dict]:
    """Turn the ``perimeter`` block of a :func:`scan_network` result into
    informational findings (one per host where a defence was detected).

    Read-only: consumes the verdicts the scanner already computed. Returns [] when
    no perimeter defence was detected, so a clean scan adds nothing.
    """
    if not isinstance(net_data, dict):
        return []
    perimeter = net_data.get("perimeter") or {}
    hosts = perimeter.get("hosts") or {}
    findings: list[dict] = []
    for host, v in hosts.items():
        if not isinstance(v, dict) or not v.get("detected"):
            continue
        label = v.get("label") or v.get("posture", "perimeter defense")
        indicators = v.get("indicators") or []
        rec = v.get("recommendation") or ""
        desc = " ".join(indicators)
        if rec:
            desc = f"{desc}\n\nWhat this means for the assessment: {rec}"
        findings.append({
            "target": str(host),
            "vuln_type": "perimeter_defense",
            "severity": "info",
            "title": f"Perimeter Defense Detected: {label}",
            "description": desc.strip(),
            "confidence": float(v.get("confidence") or 0.0),
            # An observation about scan conditions, not an exploitable weakness —
            # confirmation_status resolves this to "Informational", and the
            # confirmed-only Overall Risk ignores it.
            "observation": True,
            "evidence": {
                "posture": v.get("posture"),
                "indicators": indicators,
                "recommendation": rec,
                **(v.get("evidence") or {}),
            },
        })
    return findings
