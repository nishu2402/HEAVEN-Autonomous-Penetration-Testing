"""
HEAVEN — SAST (static application security testing) via Semgrep

What this does:
  - Runs `semgrep` against a source-code path
  - Uses our curated ruleset (heaven/vulnscan/sast_rules/) by default;
    callers can layer Semgrep registry rules (`p/python`, `p/owasp-top-ten`)
    on top with --extra-config
  - Parses Semgrep's JSON output and converts it to HEAVEN finding dicts
  - Persists into the engagement DB through the existing upsert pipeline
    (so SAST findings live alongside DAST findings in one report)

Why Semgrep:
  - Free, fast, multi-language (Python / JS / TS / Go / Java / Ruby / PHP /
    C# / Kotlin / Scala)
  - Pattern-based + dataflow taint analysis
  - Real, actively-maintained rules — better than rolling our own
  - Apache 2.0 licensed, no telemetry by default with --metrics=off

What this does NOT do:
  - Run without `semgrep` on PATH. Operator installs it: `pip install semgrep`
  - Auto-fix code. Semgrep has --autofix but we don't enable it.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.sast")


_RULES_DIR = Path(__file__).parent / "sast_rules"


@dataclass
class SastFinding:
    """One Semgrep result, normalised to HEAVEN's finding shape."""
    rule_id: str
    severity: str           # critical | high | medium | low | info
    title: str
    description: str = ""
    file_path: str = ""
    line: int = 0
    column: int = 0
    code_excerpt: str = ""
    cwe: str = ""
    owasp: str = ""
    confidence: float = 0.7
    metadata: dict = field(default_factory=dict)

    def to_heaven_finding(self) -> dict[str, Any]:
        """Return a dict shaped for EngagementStore.upsert_finding()."""
        # Use file path as target so the engagement view groups all SAST
        # findings per file. Param = rule_id so multiple rule hits per file
        # produce distinct deduped findings.
        return {
            "target": f"file://{self.file_path}",
            "vuln_type": f"sast_{_normalise_vuln_type(self.rule_id)}",
            "title": self.title or self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "cve_id": "",
            "param": f"{self.rule_id}:{self.line}",
            "endpoint": self.file_path,
            "evidence": {
                "rule_id": self.rule_id,
                "file_path": self.file_path,
                "line": self.line,
                "column": self.column,
                "code_excerpt": self.code_excerpt,
                "cwe": self.cwe,
                "owasp": self.owasp,
                "description": self.description,
                "source": "semgrep",
                "metadata": self.metadata,
            },
        }


@dataclass
class SastRunResult:
    success: bool
    findings: list[SastFinding] = field(default_factory=list)
    files_scanned: int = 0
    duration_s: float = 0.0
    semgrep_version: str = ""
    error: str = ""

    @property
    def severity_breakdown(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "findings_count": len(self.findings),
            "files_scanned": self.files_scanned,
            "duration_s": round(self.duration_s, 2),
            "semgrep_version": self.semgrep_version,
            "severity_breakdown": self.severity_breakdown,
            "error": self.error,
            "findings": [f.__dict__ for f in self.findings[:200]],
        }


# ═══════════════════════════════════════════
# SEMGREP RUNNER
# ═══════════════════════════════════════════


def has_semgrep() -> bool:
    return shutil.which("semgrep") is not None


async def run_sast(
    source_path: str,
    *,
    extra_configs: Optional[list[str]] = None,
    use_builtin_rules: bool = True,
    timeout_s: int = 300,
) -> SastRunResult:
    """Run Semgrep against `source_path` and return parsed findings.

    Args:
      source_path: Path to a file or directory to scan.
      extra_configs: Additional Semgrep config refs (e.g. ["p/owasp-top-ten",
                     "p/python", "/path/to/rules.yml"]).
      use_builtin_rules: When True, includes HEAVEN's curated rule pack at
                         heaven/vulnscan/sast_rules/.
      timeout_s: Hard cap on Semgrep subprocess runtime.
    """
    import time
    t0 = time.time()
    result = SastRunResult(success=False)

    src = Path(source_path).resolve()
    if not src.exists():
        result.error = f"path not found: {source_path}"
        return result
    if not has_semgrep():
        result.error = "semgrep not installed; pip install semgrep"
        return result

    cmd: list[str] = [
        "semgrep", "--json", "--quiet",
        "--metrics=off",                        # no phone-home
        "--timeout", str(min(timeout_s, 60)),   # per-rule timeout
        "--timeout-threshold", "3",             # skip rule if it times out 3+ times
    ]
    configs_added = False
    if use_builtin_rules and _RULES_DIR.exists():
        cmd.extend(["--config", str(_RULES_DIR)])
        configs_added = True
    for c in extra_configs or []:
        cmd.extend(["--config", c])
        configs_added = True
    if not configs_added:
        cmd.extend(["--config", "auto"])
    cmd.append(str(src))

    logger.info(f"sast: running {' '.join(cmd[:6])} … {src}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            result.error = f"semgrep timed out after {timeout_s}s"
            result.duration_s = time.time() - t0
            return result
    except FileNotFoundError:
        result.error = "semgrep binary not found at runtime"
        result.duration_s = time.time() - t0
        return result

    result.duration_s = time.time() - t0

    if proc.returncode not in (0, 1):
        # Semgrep returns 1 when findings present — that's success for us
        result.error = f"semgrep exit {proc.returncode}: {stderr.decode('utf-8', 'ignore')[:500]}"
        return result

    try:
        data = json.loads(stdout.decode("utf-8", "ignore") or "{}")
    except json.JSONDecodeError as e:
        result.error = f"semgrep produced invalid JSON: {e}"
        return result

    # Parse results
    for entry in data.get("results", []):
        try:
            result.findings.append(_parse_semgrep_result(entry))
        except Exception as e:
            logger.warning(f"could not parse semgrep result: {e}")

    paths_meta = data.get("paths", {}) or {}
    scanned = paths_meta.get("scanned") or []
    result.files_scanned = len(scanned) if isinstance(scanned, list) else 0
    result.semgrep_version = (data.get("version") or "").strip()
    result.success = True

    logger.info(
        f"sast: {len(result.findings)} finding(s) across "
        f"{result.files_scanned} file(s) in {result.duration_s:.1f}s"
    )
    return result


# ═══════════════════════════════════════════
# RESULT PARSING
# ═══════════════════════════════════════════


_SEMGREP_SEV_MAP = {
    "ERROR": "high", "WARNING": "medium", "INFO": "low",
    # newer Semgrep also emits these
    "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
    "CRITICAL": "critical",
}


def _parse_semgrep_result(entry: dict[str, Any]) -> SastFinding:
    """Convert one Semgrep result dict → SastFinding."""
    sev_raw = (entry.get("extra", {}).get("severity") or "WARNING").upper()
    metadata = entry.get("extra", {}).get("metadata", {}) or {}
    severity = _SEMGREP_SEV_MAP.get(sev_raw, "medium")

    # CWE / OWASP from metadata when present
    cwe = ""
    owasp = ""
    cwes = metadata.get("cwe") or []
    if isinstance(cwes, list) and cwes:
        cwe = str(cwes[0])
    elif isinstance(cwes, str):
        cwe = cwes
    owasps = metadata.get("owasp") or []
    if isinstance(owasps, list) and owasps:
        owasp = str(owasps[0])
    elif isinstance(owasps, str):
        owasp = owasps

    # Confidence — use metadata.confidence if present, else heuristic
    confidence_raw = (metadata.get("confidence") or "").upper()
    confidence = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(confidence_raw, 0.7)

    return SastFinding(
        rule_id=entry.get("check_id", "unknown") or "unknown",
        severity=severity,
        title=entry.get("extra", {}).get("message", "").split("\n")[0][:200] or
              entry.get("check_id", "Semgrep finding"),
        description=entry.get("extra", {}).get("message", ""),
        file_path=entry.get("path", "") or "",
        line=int(entry.get("start", {}).get("line", 0) or 0),
        column=int(entry.get("start", {}).get("col", 0) or 0),
        code_excerpt=entry.get("extra", {}).get("lines", "")[:500],
        cwe=cwe, owasp=owasp,
        confidence=confidence,
        metadata=metadata,
    )


def _normalise_vuln_type(rule_id: str) -> str:
    """Shorten Semgrep rule ID like
    'heaven.python.sqli-string-formatting' → 'sqli'
    for the engagement-DB `vuln_type` column.
    """
    tail = rule_id.rsplit(".", 1)[-1].lower()
    for cat in ("sqli", "xss", "ssrf", "xxe", "csrf", "lfi", "rfi",
                "cmdi", "rce", "ssti", "open_redirect", "deserialization",
                "weak_crypto", "weak_random", "hardcoded_secret",
                "path_traversal", "idor"):
        if cat in tail.replace("-", "_"):
            return cat
    return "code_quality"


# ═══════════════════════════════════════════
# ENGAGEMENT-DB INTEGRATION
# ═══════════════════════════════════════════


def persist_findings(
    engagement_store, scan_id: str, result: SastRunResult,
) -> int:
    """Push every SAST finding into the engagement DB. Returns insert count."""
    count = 0
    for f in result.findings:
        try:
            engagement_store.upsert_finding(scan_id, f.to_heaven_finding())
            count += 1
        except Exception as e:
            logger.debug(f"could not persist sast finding {f.rule_id}: {e}")
    return count
