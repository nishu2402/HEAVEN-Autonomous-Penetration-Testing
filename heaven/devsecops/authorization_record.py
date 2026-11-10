"""
HEAVEN — Chain of authorization.

A penetration test is run under written authorization. HEAVEN already refuses to
scan without an explicit acknowledgement (``--i-have-authorization`` /
``HEAVEN_AUTHORIZED_SCOPE`` / an interactive confirm); this module captures that
authorization as a durable record on the engagement and in the report, the
counterpart to the per-finding chain of custody:

* **who** acknowledged authorization (operator identity),
* **when** (UTC),
* **how** the acknowledgement was given (flag / env / interactive),
* **which targets** were authorized, and
* **which intrusive capabilities** were enabled for the run (active
  verification, exploit proof, post-exploitation, active exploitation).

Recording the intrusive capabilities matters for OPSEC and for the audit trail:
a reader can see at a glance whether a run was read-only reconnaissance or an
authorized exploitation engagement, and under whose acknowledgement. The record
is built once at scan start and travels in the scan summary into the report.
"""

from __future__ import annotations

import getpass
import os
from datetime import datetime, timezone
from typing import Any, Optional


def _operator() -> str:
    """Best-effort operator identity, without shelling out.

    ``HEAVEN_OPERATOR`` wins (an engagement can set the named, accountable
    tester); otherwise common CI/git author env vars, then the OS login. Never
    raises — an unknown operator is recorded as ``"unknown"`` rather than failing.
    """
    for var in ("HEAVEN_OPERATOR", "GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
        val = str(os.environ.get(var) or "").strip()
        if val:
            return val
    try:
        return getpass.getuser() or "unknown"
    except Exception:  # noqa: BLE001 — getuser can raise with no passwd entry
        return "unknown"


def _tool_version() -> str:
    try:
        from heaven import __version__
        return str(__version__)
    except Exception:  # noqa: BLE001
        return "unknown"


def _all_targets(targets: dict[str, Any]) -> list[str]:
    """Flatten every scannable target the gate authorized, order-preserving."""
    out: list[str] = []
    for key in ("ips", "urls", "repositories", "cloud_providers"):
        for t in targets.get(key, []) or []:
            if t and str(t) not in out:
                out.append(str(t))
    ad = targets.get("ad_domain")
    if ad and str(ad) not in out:
        out.append(str(ad))
    return out


def build_record(targets: dict[str, Any], *, method: str = "flag",
                 operator: Optional[str] = None,
                 tool_version: Optional[str] = None) -> dict[str, Any]:
    """Build the authorization record for a run.

    ``method`` is how authorization was acknowledged: ``"flag"``
    (``--i-have-authorization``), ``"env"`` (``HEAVEN_AUTHORIZED_SCOPE``) or
    ``"interactive"`` (TTY confirm). The ``intrusive`` block records which
    capabilities were enabled, from the same ``targets`` dict the orchestrator
    uses to gate them, so the record cannot drift from what actually ran.
    """
    return {
        "operator": operator or _operator(),
        "authorized_at": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "targets": _all_targets(targets),
        "intrusive": {
            "active_verification": bool(targets.get("verify")),
            "exploit_proof": bool(targets.get("auto_prove")),
            "post_exploitation": bool(targets.get("autonomous")),
            "active_exploitation": bool(targets.get("active_exploit")),
        },
        "stealth_level": targets.get("stealth_level") or "",
        "tool": "HEAVEN",
        "tool_version": tool_version or _tool_version(),
    }


def infer_method(ack_flag: bool) -> str:
    """Infer how the gate was satisfied, matching ``_verify_authorization``'s
    priority order: the explicit flag, then the scope env var, then interactive."""
    if ack_flag:
        return "flag"
    if str(os.environ.get("HEAVEN_AUTHORIZED_SCOPE") or "").strip():
        return "env"
    return "interactive"


def _intrusive_summary(record: dict[str, Any]) -> str:
    """A one-line human summary of the intrusive capabilities, for the report."""
    intr = record.get("intrusive") or {}
    enabled = [name.replace("_", " ") for name, on in intr.items() if on]
    if not enabled:
        return "read-only (no active exploitation enabled)"
    return ", ".join(enabled)


def render_markdown(record: Optional[dict[str, Any]]) -> str:
    """Render the authorization record as a Markdown block, or '' when absent."""
    if not record:
        return ""
    targets = record.get("targets") or []
    method_label = {"flag": "explicit --i-have-authorization flag",
                    "env": "HEAVEN_AUTHORIZED_SCOPE allow-list",
                    "interactive": "interactive operator confirmation"}.get(
        str(record.get("method")), str(record.get("method") or "unknown"))
    out = [
        "## Authorization",
        "",
        f"- **Operator:** {record.get('operator', 'unknown')}",
        f"- **Authorized (UTC):** {str(record.get('authorized_at', ''))[:19]}",
        f"- **Acknowledgement:** {method_label}",
        f"- **Authorized targets:** {len(targets)}",
        f"- **Intrusive testing:** {_intrusive_summary(record)}",
        f"- **Stealth level:** {record.get('stealth_level') or 'n/a'}",
        "",
    ]
    return "\n".join(out)
