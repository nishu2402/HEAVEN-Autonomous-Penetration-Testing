"""
HEAVEN — Nuclei Integration Wrapper
Executes Nuclei for massive vulnerability and misconfiguration scanning.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.nuclei")


def _parse_nuclei_output(stdout: bytes) -> list[dict[str, Any]]:
    """Parse Nuclei ``-jsonl`` stdout into findings, tolerant of malformed lines.

    Nuclei normally emits one JSON object per line, but a stray non-object line
    (string/array/number) or a ``null`` ``info`` block must not abort the whole
    scan — those lines are skipped rather than raising.
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
        findings.append({
            "target": data.get("host", ""),
            "type": "nuclei",
            "severity": info.get("severity", "info"),
            "title": info.get("name", "Nuclei Finding"),
            "description": info.get("description", ""),
            "confidence": 0.9,  # Nuclei is generally high confidence
            "evidence": {
                "template": data.get("template-id", ""),
                "matched": data.get("matched-at", ""),
                "extracted": data.get("extracted-results", []),
            },
        })
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
