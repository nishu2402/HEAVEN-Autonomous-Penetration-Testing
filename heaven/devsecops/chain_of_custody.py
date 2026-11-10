"""
HEAVEN — Evidence integrity & chain of custody.

A penetration-test report is a defensible document. When a client's auditor,
insurer or legal team reviews it, evidence that cannot be shown to be untampered
is weak evidence. This module gives every finding a verifiable integrity record:

* a **SHA-256 digest** over the finding's proof content (the request, response,
  payload, technique and observed evidence that prove the issue),
* the **UTC collection time**,
* the **collecting tool and version** (``HEAVEN`` + its release), and
* the **collection method** (the detector/technique that produced the proof).

The digest is computed at collection time and stored under
``evidence.chain_of_custody``. Because it covers the exact proof content, any
later alteration of that content makes :func:`verify_finding_integrity` fail, so
a reader can confirm the evidence shown is the evidence captured. The record is
JSON-serialisable and renders into the Markdown/HTML/PDF report as an evidence
manifest without further enrichment.

Everything here is read-only and deterministic: stamping never contacts a
target, and re-hashing the same proof content always yields the same digest, so
the same finding seen on a re-test correlates by digest.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from heaven.utils.logger import get_logger

logger = get_logger("devsecops.chain_of_custody")

# The algorithm label stored alongside the digest. Kept explicit so a future
# migration to a stronger hash is self-describing in old reports.
_ALGORITHM = "sha256"

# The evidence key the custody record lives under. Excluded from the digest so a
# finding can be stamped and then re-verified without the record changing its own
# hash (the digest covers the PROOF, never the stamp).
_RECORD_KEY = "chain_of_custody"


def _tool_version() -> str:
    """The running HEAVEN release, for the ``tool_version`` field."""
    try:
        from heaven import __version__
        return str(__version__)
    except Exception:  # noqa: BLE001 — version lookup must never break stamping
        return "unknown"


def _canonical_proof(finding: dict[str, Any]) -> dict[str, Any]:
    """Build the stable proof view that the digest is computed over.

    Pulls the core identity fields plus the full ``evidence`` dict (minus the
    custody record itself, which must not hash itself). Values that are not
    JSON-native are coerced to strings so the serialisation never raises on an
    exotic evidence payload.
    """
    ev = finding.get("evidence")
    if not isinstance(ev, dict):
        ev = {}
    proof_evidence = {k: v for k, v in ev.items() if k != _RECORD_KEY}
    return {
        "target": finding.get("target") or finding.get("url") or finding.get("host") or "",
        "vuln_type": finding.get("vuln_type") or finding.get("type") or "",
        "cve_id": finding.get("cve_id") or finding.get("cve") or "",
        "cwe": finding.get("cwe") or finding.get("cwe_id") or "",
        "method": finding.get("method") or ev.get("method") or "",
        "request_url": finding.get("request_url") or ev.get("request_url") or ev.get("url") or "",
        "payload": finding.get("payload") or ev.get("payload") or "",
        "technique": ev.get("technique") or "",
        "response_status": ev.get("status") or finding.get("response_status") or 0,
        "evidence": proof_evidence,
    }


def evidence_digest(finding: dict[str, Any]) -> str:
    """Return the SHA-256 hex digest of a finding's proof content.

    Deterministic: the proof view is serialised with sorted keys and a stable
    separator, so the same proof always hashes to the same value. Non-serialisable
    values are stringified rather than raising.
    """
    canonical = _canonical_proof(finding)
    blob = json.dumps(canonical, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


def collection_method(finding: dict[str, Any]) -> str:
    """A short, human-readable label for HOW the proof was collected.

    Prefers the probe technique, then an active-verification technique, then the
    detector source, then a generic scan label — so the manifest always names the
    mechanism that produced the evidence.
    """
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    technique = str(ev.get("technique") or "").strip()
    if technique:
        return technique
    av = ev.get("active_verification")
    if isinstance(av, dict) and av.get("technique"):
        return f"active_verification:{av['technique']}"
    source = str(finding.get("source") or ev.get("source")
                 or ev.get("detection_source") or "").strip()
    if source:
        return source
    return "heaven-scan"


def custody_record(finding: dict[str, Any], *,
                   collected_at: Optional[str] = None,
                   tool_version: Optional[str] = None) -> dict[str, Any]:
    """Build (but do not attach) the chain-of-custody record for a finding.

    ``collected_at`` defaults to the current UTC time; pass the scan's capture
    time to record when the evidence was actually gathered rather than when it is
    rendered.
    """
    return {
        "sha256": evidence_digest(finding),
        "algorithm": _ALGORITHM,
        "collected_at": collected_at or datetime.now(timezone.utc).isoformat(),
        "tool": "HEAVEN",
        "tool_version": tool_version or _tool_version(),
        "collection_method": collection_method(finding),
    }


def stamp_finding(finding: dict[str, Any], *, collected_at: Optional[str] = None,
                  tool_version: Optional[str] = None, force: bool = False) -> bool:
    """Attach a chain-of-custody record to one finding, in place.

    Idempotent: a finding that already carries a record is left untouched unless
    ``force=True`` (which re-stamps, e.g. after a deliberate re-hash). Returns
    True when a record was written. Never raises — evidence stamping must never
    break a scan or a report render.
    """
    if not isinstance(finding, dict):
        return False
    try:
        ev = finding.get("evidence")
        if not isinstance(ev, dict):
            ev = {}
            finding["evidence"] = ev
        if ev.get(_RECORD_KEY) and not force:
            return False
        ev[_RECORD_KEY] = custody_record(
            finding, collected_at=collected_at, tool_version=tool_version)
        return True
    except Exception:  # noqa: BLE001 — never let integrity stamping abort a run
        logger.debug("chain-of-custody stamp failed for a finding", exc_info=True)
        return False


def stamp_all(findings: Iterable[dict[str, Any]], *,
              collected_at: Optional[str] = None,
              tool_version: Optional[str] = None, force: bool = False) -> int:
    """Stamp every finding in a stream. Returns the count newly stamped.

    A single ``collected_at`` (the scan's finalisation time) is shared across the
    batch so one report's findings carry one consistent collection time.
    """
    stamp_time = collected_at or datetime.now(timezone.utc).isoformat()
    version = tool_version or _tool_version()
    return sum(
        1 for f in findings
        if stamp_finding(f, collected_at=stamp_time, tool_version=version, force=force)
    )


def get_record(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a finding's stored custody record, or an empty dict."""
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    rec = ev.get(_RECORD_KEY)
    return rec if isinstance(rec, dict) else {}


def verify_finding_integrity(finding: dict[str, Any]) -> Optional[bool]:
    """Recompute the proof digest and compare it to the stored record.

    Returns True when the evidence is intact, False when it has been altered
    since collection, and None when the finding carries no custody record (so
    there is nothing to verify against). Useful for re-test correlation and for a
    reviewer auditing a delivered report.
    """
    rec = get_record(finding)
    stored = str(rec.get("sha256") or "")
    if not stored:
        return None
    return evidence_digest(finding) == stored


def manifest(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build the evidence-integrity manifest rows for a set of findings.

    Each row carries the finding's id, target, type, the stored (or freshly
    computed) digest, the collection time and the method. Findings without a
    stored record get a computed digest so the manifest is always complete.
    """
    rows: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        rec = get_record(f)
        digest = str(rec.get("sha256") or "") or evidence_digest(f)
        rows.append({
            "id": f.get("id") or "",
            "target": f.get("target") or f.get("url") or f.get("host") or "",
            "vuln_type": f.get("vuln_type") or f.get("type") or "",
            "sha256": digest,
            "collected_at": rec.get("collected_at") or "",
            "tool_version": rec.get("tool_version") or _tool_version(),
            "collection_method": rec.get("collection_method") or collection_method(f),
        })
    return rows


def render_manifest_markdown(findings: Iterable[dict[str, Any]]) -> str:
    """Render the evidence-integrity manifest as a Markdown section, or ''.

    The section states plainly what the digest is and how to use it, then lists
    one row per finding (short digest for readability, full digest is in the
    stored record and the API). Returns '' when there are no findings.
    """
    rows = manifest(findings)
    if not rows:
        return ""
    out = [
        "## Evidence integrity manifest",
        "",
        "_Each finding's proof (request, response, payload and observed evidence) "
        "is hashed with SHA-256 at collection time and recorded below. The digest "
        "lets a reviewer confirm the evidence in this report is exactly what "
        "HEAVEN captured: re-hashing an altered proof will not match._",
        "",
        "| # | Target | Type | Collected (UTC) | Method | SHA-256 |",
        "|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rows, 1):
        short = (r["sha256"][:16] + "…") if len(r["sha256"]) > 16 else r["sha256"]
        target = str(r["target"]).replace("|", "/")[:60]
        vt = str(r["vuln_type"]).replace("|", "/")[:40]
        method = str(r["collection_method"]).replace("|", "/")[:40]
        collected = str(r["collected_at"])[:19] or "n/a"
        out.append(f"| {i} | {target} | {vt} | {collected} | {method} | `{short}` |")
    out.append("")
    out.append(f"_Tool: HEAVEN v{rows[0]['tool_version']} · "
               f"algorithm: SHA-256 · {len(rows)} artifact(s)._")
    out.append("")
    return "\n".join(out)
