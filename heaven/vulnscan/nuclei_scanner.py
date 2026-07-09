"""
HEAVEN — Nuclei Integration Wrapper
Executes Nuclei for massive vulnerability and misconfiguration scanning.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.nuclei")


# Nuclei ships parameter-wordlist / fuzzing-helper templates that emit a "match"
# carrying no actual vulnerability — they exist to feed *other* templates. The
# classic offender is ``top-xss-params``, which surfaces as
# "Top 38 Parameters - Cross-Site Scripting". Reporting these inflates the
# findings list with empty-type, non-actionable noise, so drop them at parse
# time.
_NUCLEI_NOISE_TEMPLATE_IDS = {
    "top-xss-params", "top-42-params", "top-38-params", "params-fuzzing",
}
_NUCLEI_NOISE_NAME_RE = re.compile(r"^\s*top[\s\-]*\d+\s+param", re.IGNORECASE)


def _is_noise_template(template_id: str, name: str) -> bool:
    """True for Nuclei wordlist/parameter-list helper templates that are payload
    lists rather than real findings (so they should never be reported)."""
    if (template_id or "").strip().lower() in _NUCLEI_NOISE_TEMPLATE_IDS:
        return True
    return bool(_NUCLEI_NOISE_NAME_RE.match(name or ""))


def _parse_nuclei_output(stdout: bytes) -> list[dict[str, Any]]:
    """Parse Nuclei ``-jsonl`` stdout into findings, tolerant of malformed lines.

    Nuclei normally emits one JSON object per line, but a stray non-object line
    (string/array/number) or a ``null`` ``info`` block must not abort the whole
    scan — those lines are skipped rather than raising. Wordlist/parameter-list
    helper templates (:data:`_NUCLEI_NOISE_TEMPLATE_IDS`) are also skipped: they
    are payload lists, not vulnerabilities.
    """
    findings: list[dict[str, Any]] = []
    for line in stdout.decode(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        info = data.get("info")
        if not isinstance(info, dict):
            info = {}
        template_id = data.get("template-id", "")
        name = info.get("name", "Nuclei Finding")
        if _is_noise_template(template_id, name):
            continue

        # Nuclei templates carry their own classification (cwe-id, cvss-metrics,
        # cve-id, cvss-score). Lift it onto the finding so the report's taxonomy
        # columns reflect the template's real metadata instead of going blank —
        # per-finding data wins over the generic KB fallback in enrich_finding().
        classification = info.get("classification") or {}
        if not isinstance(classification, dict):
            classification = {}

        def _first(val):
            if isinstance(val, (list, tuple)):
                return val[0] if val else None
            return val

        finding: dict[str, Any] = {
            "target": data.get("host", ""),
            "type": "nuclei",
            # Set vuln_type explicitly so this never resolves to an empty type
            # downstream (the report/persist path reads vuln_type directly).
            "vuln_type": "nuclei",
            "severity": info.get("severity", "info"),
            "title": name,
            "description": info.get("description", ""),
            "confidence": 0.9,  # Nuclei is generally high confidence
            "evidence": {
                "template": template_id,
                "matched": data.get("matched-at", ""),
                "extracted": data.get("extracted-results", []),
                "tags": info.get("tags") or [],
            },
        }

        cwe_id = _first(classification.get("cwe-id"))
        if isinstance(cwe_id, str) and cwe_id.strip():
            # Normalise "cwe-79" / "CWE-79" → "CWE-79"
            finding["cwe"] = cwe_id.strip().upper()
        cvss_vec = classification.get("cvss-metrics")
        if isinstance(cvss_vec, str) and cvss_vec.strip():
            finding["cvss_vector"] = cvss_vec.strip()
        cvss_score = classification.get("cvss-score")
        if isinstance(cvss_score, (int, float)) and cvss_score:
            finding["predicted_cvss_score"] = float(cvss_score)
            finding["evidence"]["cvss_score"] = float(cvss_score)
        cve_id = _first(classification.get("cve-id"))
        if isinstance(cve_id, str) and cve_id.strip():
            finding["cve"] = cve_id.strip().upper()
            finding["evidence"]["cve"] = cve_id.strip().upper()

        findings.append(finding)
    return findings


async def scan_nuclei(targets: list[str], severity: str = "low,medium,high,critical", timeout: float = 600.0, stealth_level: str = "normal") -> dict[str, Any]:
    """Run Nuclei against a list of targets and parse the JSONL output."""
    if not targets:
        return {"findings": [], "total": 0}

    # Nuclei is an external binary — skip gracefully if it isn't installed
    # instead of letting FileNotFoundError abort the whole scan pipeline.
    import shutil
    if shutil.which("nuclei") is None:
        logger.warning(
            "Nuclei binary not found on PATH — skipping Nuclei scan. "
            "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
        return {"findings": [], "total": 0, "skipped": "nuclei not installed"}

    findings = []
    
    # We write targets to a temporary file to pass to nuclei
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        for t in targets:
            f.write(f"{t}\n")
        target_file = f.name

    try:
        rate_configs = {
            "aggressive": ["-rate-limit", "1000", "-timeout", "5"],
            "normal":     ["-rate-limit", "150",  "-timeout", "10"],
            "stealth":    ["-rate-limit", "20",   "-timeout", "30",
                           "-header", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],
            "paranoid":   ["-rate-limit", "5",    "-timeout", "60",
                           "-no-interactsh", "-header", "User-Agent: Mozilla/5.0"],
        }
        extra_args = rate_configs.get(stealth_level, rate_configs["normal"])

        cmd = [
            "nuclei",
            "-l", target_file,
            "-silent",
            "-jsonl",
            "-severity", severity,
            "-etags", "fuzz",
            "-c", "50",
            "-stats",
        ] + extra_args
        
        logger.info(f"Starting Nuclei scan on {len(targets)} targets...")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            stdout, stderr = await proc.communicate()
            logger.warning("Nuclei scan timed out")

        if stdout:
            findings.extend(_parse_nuclei_output(stdout))
                    
        logger.info(f"Nuclei scan complete: {len(findings)} findings.")
    finally:
        os.remove(target_file)
        
    return {"findings": findings, "total": len(findings)}
