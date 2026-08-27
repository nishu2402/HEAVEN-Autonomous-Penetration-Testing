"""
HEAVEN — unrestricted file-upload detection (CWE-434, OWASP A06).

Actively but SAFELY tests file-upload forms for missing type/extension
validation, the flaw that turns an upload into remote code execution when a
server-executable file (``.php``, ``.jsp``, ``.asp``) is accepted and stored in
a web-reachable path.

Safety
------
The probe uploads a tiny, INERT marker file. Its only payload is a static
``echo`` of a random token — the same safe class as HEAVEN's command-injection
canaries (``id``/``echo``/``sleep``), with no filesystem, network, or shell
access. If the server executes it, only the token prints, which is exactly what
proves the upload is executable. The probe is gated behind ``authorized=True``
because it writes a file to the target.

Detection is layered so a finding always rests on observed behaviour:
  * acceptance — the response confirms the dangerous-extension file was stored
    (a success message and/or the stored path echoed back);
  * retrieval — the stored file is fetched back and the marker is present;
  * execution — the retrieved marker comes back WITHOUT its ``<?php`` wrapper,
    proving the server ran it (unrestricted upload → RCE, critical).
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    HAS_AIOHTTP = False

from heaven.recon.auth_session import aiohttp_session_kwargs
from heaven.utils.logger import get_logger
from heaven.vulnscan import proof_capture

logger = get_logger("vulnscan.upload")

# Server-executable extensions worth trying, most impactful first. A single
# accepted entry is enough to prove the flaw, so the probe stops at the first.
_EXEC_EXTS = (".php", ".phtml", ".php5", ".jsp", ".asp", ".aspx")

_ACCEPT_SIGNALS = (
    "succesfully uploaded",   # DVWA's (misspelled) success string
    "successfully uploaded",
    "upload complete", "file uploaded", "has been uploaded", "uploaded successfully",
)
_REJECT_SIGNALS = (
    "not allowed", "invalid file", "only images", "were not uploaded",
    "your image was not uploaded", "file type", "extension", "forbidden",
)


def _upload_forms(endpoints: list[dict]) -> list[dict]:
    """Extract POST forms that carry a file input from crawler endpoints.

    Returns one dict per (action, file field): ``{"action", "file_param",
    "others"}`` where ``others`` are the form's non-file fields with benign
    default values (submit buttons included — many handlers gate on
    ``isset($_POST['Upload'])``)."""
    forms: dict[str, dict] = {}
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        for iv in ep.get("input_vectors", []):
            if not isinstance(iv, dict):
                continue
            if (iv.get("method") or "GET").upper() != "POST":
                continue
            action = (iv.get("url") or ep.get("url") or "").split("#", 1)[0]
            name = iv.get("param") or ""
            itype = (iv.get("input_type") or iv.get("type") or "text").lower()
            if not action or not name:
                continue
            form = forms.setdefault(action, {"file_params": set(), "others": {}})
            if itype == "file":
                form["file_params"].add(name)
            elif name.lower() == "max_file_size":
                # PHP enforces a MAX_FILE_SIZE form field as a byte cap and
                # silently rejects anything larger, so a "1" placeholder would
                # block the probe. Give it plenty of headroom.
                form["others"].setdefault(name, "20000000")
            else:
                # A submit button must be present but its value is only checked
                # for existence; other fields get a harmless placeholder.
                form["others"].setdefault(name, name if itype == "submit" else "1")

    out: list[dict] = []
    for action, form in forms.items():
        for fp in sorted(form["file_params"]):
            out.append({"action": action, "file_param": fp, "others": dict(form["others"])})
    return out


def _stored_url(action: str, body: str, filename: str) -> str | None:
    """Best-effort resolve where an accepted upload landed, from the response.

    Finds a path token ending in our filename (e.g. DVWA echoes
    ``../../hackable/uploads/<file>``) and resolves it against the form action.
    """
    m = re.search(r"[\w./~+-]*" + re.escape(filename), body)
    if not m:
        return None
    return urljoin(action, m.group(0))


async def _probe_form(session: "aiohttp.ClientSession", form: dict,
                      timeout: float) -> dict | None:
    action = form["action"]
    file_param = form["file_param"]
    marker = "HEAVEN_UPLOAD_" + secrets.token_hex(5)
    # Inert: a static echo of the marker, nothing else. If executed it prints the
    # marker and nothing more; if merely stored, the raw text is served back.
    content = f'<?php echo "{marker}"; ?>'

    for ext in _EXEC_EXTS:
        filename = f"heaven_probe_{secrets.token_hex(3)}{ext}"
        data = aiohttp.FormData()
        for k, v in form["others"].items():
            data.add_field(k, str(v))
        data.add_field(file_param, content, filename=filename,
                       content_type="application/octet-stream")
        try:
            async with session.post(action, data=data,
                                    timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                body = await resp.text()
                proof_capture.record(action, resp.status, body)
        except Exception as e:  # noqa: BLE001
            logger.debug("upload probe failed for %s (%s): %s", action, ext, e)
            continue

        low = body.lower()
        accepted = (any(s in low for s in _ACCEPT_SIGNALS)
                    or filename.lower() in low)
        rejected = any(s in low for s in _REJECT_SIGNALS)
        if not accepted or (rejected and filename.lower() not in low):
            continue   # this extension was blocked — the secure behaviour; try next

        # Confirm storage/execution by fetching the file back.
        executed = stored = False
        stored_at = _stored_url(action, body, filename)
        if stored_at:
            try:
                async with session.get(stored_at,
                                       timeout=aiohttp.ClientTimeout(total=timeout)) as r2:
                    fetched = await r2.text()
                if marker in fetched:
                    stored = True
                    executed = "<?php" not in fetched   # ran, so the wrapper is gone
            except Exception:  # noqa: BLE001
                logger.debug("upload retrieval failed for %s", stored_at, exc_info=True)

        if executed:
            severity, confidence = "critical", 0.95
            detail = ("the file was executed by the server (the marker returned "
                      "without its PHP wrapper), so this upload yields remote code "
                      "execution")
        elif stored:
            severity, confidence = "high", 0.85
            detail = ("the file is stored and served back verbatim from a "
                      "web-reachable path")
        else:
            severity, confidence = "high", 0.7
            detail = "the server reported the upload as accepted"

        return {
            "target": action,
            "vuln_type": "file_upload",
            "title": f"Unrestricted file upload via '{file_param}'",
            "severity": severity,
            "confidence": confidence,
            "description": (
                f"The upload form accepted a server-executable '{ext}' file with "
                f"no type or extension validation; {detail}."
            ),
            "evidence": {
                "param": file_param,
                "filename": filename,
                "extension": ext,
                "stored_url": stored_at or "",
                "stored": stored,
                "executed": executed,
                "marker": marker,
            },
            "remediation": (
                "Validate uploads by content, not just extension: allow-list safe "
                "types, store files outside the web root or on a separate domain, "
                "randomise stored names, and never serve uploads as executable."
            ),
            "cwe": "CWE-434",
            "source": "upload_scanner",
        }
    return None


async def scan_upload_forms(endpoints: list[dict], *, authorized: bool = False,
                            timeout: float = 12.0) -> dict:
    """Probe every file-upload form discovered by the crawl.

    Gated on ``authorized`` because it writes a (benign, inert) file to the
    target. Returns ``{"findings": [...], "forms_tested": int}``.
    """
    if not HAS_AIOHTTP:
        return {"findings": [], "forms_tested": 0, "error": "aiohttp not installed"}
    if not authorized:
        return {"skipped": True, "reason": "file-upload probe requires authorization"}

    forms = _upload_forms(endpoints)
    if not forms:
        return {"skipped": True, "reason": "no file-upload forms discovered"}

    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    findings: list[dict] = []
    async with aiohttp.ClientSession(connector=connector, **aiohttp_session_kwargs()) as session:
        for form in forms:
            try:
                f = await _probe_form(session, form, timeout)
            except Exception:  # noqa: BLE001
                logger.debug("upload form probe error for %s", form.get("action"),
                             exc_info=True)
                f = None
            if f is not None:
                findings.append(f)

    return {"findings": findings, "forms_tested": len(forms),
            "vulnerabilities": findings, "total": len(findings)}
