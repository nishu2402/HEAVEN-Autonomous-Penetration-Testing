"""
HEAVEN — sqlmap Integration
Runs sqlmap against confirmed SQLi candidates and parses results.
Only invoked when a finding with vuln_type='sqli' and severity critical/high is confirmed.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Optional
import logging
logger = logging.getLogger(__name__)



async def run_sqlmap(
    url: str,
    param: str = "",
    data: str = "",
    level: int = 1,
    risk: int = 1,
    output_dir: Optional[Path] = None,
    timeout: int = 180,
) -> dict:
    """Invoke sqlmap for a single URL. Returns parsed findings dict."""
    if not shutil.which("sqlmap"):
        return {"error": "sqlmap not found in PATH", "url": url, "findings": []}

    work_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="heaven_sqlmap_"))

    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",
        "--level", str(level),
        "--risk", str(risk),
        "--output-dir", str(work_dir),
        "--no-cast",
        "--threads", "3",
    ]
    if data:
        cmd += ["--data", data]
    if param:
        cmd += ["-p", param]
    else:
        cmd += ["--forms"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode(errors="replace")
        return _parse_sqlmap_output(output, url, work_dir)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
        return {"error": "timeout", "url": url, "findings": []}
    except Exception as exc:
        return {"error": str(exc), "url": url, "findings": []}


# sqlmap prints the word "injectable" almost exclusively in its NEGATIVE verdict
# ("all tested parameters do not appear to be injectable"), so a bare
# "parameter ... injectable" substring test inverts a clean result into a
# confirmed critical. The only unambiguous positive markers sqlmap emits on
# success are a per-parameter "is vulnerable" line and the summary header
# "sqlmap identified the following injection point(s)". These never appear on a
# negative run, and both are present on a positive one, so keying on them keeps
# recall while removing the inversion. We also drop any line that carries an
# explicit negation, for defence in depth.
_SQLMAP_NEGATIVE = (
    "do not appear", "does not appear", "do not seem", "does not seem",
    "not vulnerable", "might not be injectable", "unable to",
)
_SQLMAP_POSITIVE = ("is vulnerable", "identified the following injection point")


def _parse_sqlmap_output(output: str, url: str, work_dir: Path) -> dict:
    findings = []
    injectable_params: list[str] = []
    dbms = ""
    current_db = ""

    for line in output.splitlines():
        line_clean = line.strip()
        line_lower = line_clean.lower()
        negated = any(n in line_lower for n in _SQLMAP_NEGATIVE)
        if not negated and any(p in line_lower for p in _SQLMAP_POSITIVE):
            injectable_params.append(line_clean)
        if "back-end dbms:" in line_lower:
            dbms = line_clean.split("back-end DBMS:")[-1].strip()
        if "current database:" in line_lower:
            current_db = line_clean.split(":")[-1].strip().strip("'")

    if injectable_params:
        findings.append({
            "vuln_type": "sqli_confirmed",
            "title": "SQL Injection (sqlmap confirmed)",
            "severity": "critical",
            "target": url,
            "confidence": 1.0,
            "evidence": {
                "injectable_params": injectable_params[:5],
                "dbms": dbms,
                "current_db": current_db,
            },
        })

    # Also check session files written by sqlmap
    for log_file in work_dir.rglob("*.log"):
        try:
            text = log_file.read_text(errors="replace")
            tl = text.lower()
            # Same precision rule as the stdout parse: the definitive positive
            # markers only, never a bare "injectable" substring (which also
            # matches sqlmap's "...do not appear to be injectable" negative).
            if ("identified the following injection point" in tl
                    or ("is vulnerable" in tl and "not vulnerable" not in tl)):
                if not findings:
                    findings.append({
                        "vuln_type": "sqli_confirmed",
                        "title": "SQL Injection (sqlmap confirmed)",
                        "severity": "critical",
                        "target": url,
                        "confidence": 1.0,
                        "evidence": {"log": text[:500]},
                    })
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)

    return {
        "url": url,
        "dbms": dbms,
        "injectable_params": injectable_params,
        "findings": findings,
        "raw_lines": len(output.splitlines()),
    }


async def run_sqlmap_on_findings(sqli_targets: list[dict], timeout_per: int = 180) -> dict:
    """Run sqlmap against a list of SQLi candidate findings. Returns aggregated results."""
    all_findings: list[dict] = []
    errors: list[str] = []

    seen_urls: set[str] = set()
    tasks = []
    for finding in sqli_targets:
        url = finding.get("target", "")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        param = finding.get("evidence", {}).get("param", "") if isinstance(finding.get("evidence"), dict) else ""
        tasks.append(run_sqlmap(url, param=param, timeout=timeout_per))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            errors.append(str(r))
        elif isinstance(r, dict):
            all_findings.extend(r.get("findings", []))
            if r.get("error"):
                errors.append(r["error"])

    return {
        "findings": all_findings,
        "urls_tested": list(seen_urls),
        "errors": errors,
    }
