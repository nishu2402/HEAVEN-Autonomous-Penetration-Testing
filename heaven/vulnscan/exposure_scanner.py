"""HEAVEN — exposed-file & secret discovery (content-verified, FP-safe).

Cheap, high-accuracy findings that a payload-fuzzing scanner misses: a
world-readable ``.git`` directory, a leaked ``.env``, a published JavaScript
source map that hands an attacker your original source, an editor/backup copy of
a server-side file. These are *disclosure* bugs — no injection, no callback — so
the discipline that keeps them false-positive free is **content verification**:
a probe is only a finding when the response body actually *is* the sensitive
artefact (a git config, a dotenv file, a JSON source map), never merely because
the server answered ``200``.

To survive soft-404 servers (SPAs that return ``200`` + the app shell for every
path), the scanner first calibrates against a random nonexistent path and then
requires each hit to (a) not resemble that soft-404 body and (b) match a strict
content signature for its artefact type. All requests are read-only GETs.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from heaven.recon.evasion_engine import EvasionEngine, profile_for
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.exposure")

# Static exposed-artefact probes: (path, artefact-id, verifier-name).
_STATIC_PROBES: tuple[tuple[str, str, str], ...] = (
    (".git/HEAD", "git", "git_head"),
    (".git/config", "git", "git_config"),
    (".env", "dotenv", "dotenv"),
    (".env.local", "dotenv", "dotenv"),
    (".env.production", "dotenv", "dotenv"),
    (".DS_Store", "ds_store", "ds_store"),
    ("wp-config.php.bak", "backup", "source"),
    ("config.php.bak", "backup", "source"),
    (".htpasswd", "htpasswd", "htpasswd"),
    ("phpinfo.php", "phpinfo", "phpinfo"),
)

# Backup/editor suffixes appended to a *discovered* page to find its stray copy.
_BACKUP_SUFFIXES = (".bak", ".old", ".orig", "~", ".save", ".swp", ".txt")

_SERVER_SRC_MARKERS = ("<?php", "<%", "#!/", "import ", "require(", "package ",
                       "using System", "def ", "func ", "<?=")


@dataclass
class _Resp:
    status: int
    body: str
    ctype: str


# ── content verifiers — each returns True only for the genuine artefact ──────

def _v_git_head(r: _Resp) -> bool:
    b = r.body.strip()
    return bool(re.match(r"^ref:\s+refs/", b) or re.match(r"^[0-9a-f]{40}$", b))


def _v_git_config(r: _Resp) -> bool:
    return "[core]" in r.body and "repositoryformatversion" in r.body


def _v_dotenv(r: _Resp) -> bool:
    low = r.body.lstrip()[:64].lower()
    if low.startswith(("<!doctype", "<html", "<?xml")):
        return False
    # At least two KEY=VALUE lines (dotenv shape), tolerant of comments/blanks.
    kv = re.findall(r"(?m)^[ \t]*[A-Z][A-Z0-9_]{2,}=", r.body)
    return len(kv) >= 2


def _v_ds_store(r: _Resp) -> bool:
    # DS_Store magic: bytes 4..8 are "Bud1". We decoded latin-1-ish via replace,
    # so match the marker near the start.
    return "Bud1" in r.body[:16]


def _v_source(r: _Resp) -> bool:
    if "text/html" in r.ctype.lower():
        return False
    return any(m in r.body for m in _SERVER_SRC_MARKERS)


def _v_htpasswd(r: _Resp) -> bool:
    # user:$apr1$… / user:$2y$… / user:{SHA}…
    return bool(re.search(r"(?m)^[^:\s]+:\$(apr1|2[aby]|1|5|6)\$", r.body) or
                re.search(r"(?m)^[^:\s]+:\{SHA\}", r.body))


def _v_phpinfo(r: _Resp) -> bool:
    return "phpinfo()" in r.body or "PHP Version" in r.body and "<title>phpinfo" in r.body.lower()


_VERIFIERS = {
    "git_head": _v_git_head,
    "git_config": _v_git_config,
    "dotenv": _v_dotenv,
    "ds_store": _v_ds_store,
    "source": _v_source,
    "htpasswd": _v_htpasswd,
    "phpinfo": _v_phpinfo,
}

# Per-artefact reporting metadata.
_ARTEFACT_META: dict[str, dict[str, Any]] = {
    "git": {"vuln_type": "sensitive_file_exposure", "severity": "high",
            "title": "Exposed .git repository",
            "desc": "The .git directory is web-accessible. An attacker can "
                    "reconstruct your full source tree (and any secrets committed "
                    "to history) from it."},
    "dotenv": {"vuln_type": "secret_exposure", "severity": "high",
               "title": "Exposed .env file",
               "desc": "A dotenv file with application secrets (keys, DB "
                       "credentials, tokens) is served to the public."},
    "ds_store": {"vuln_type": "sensitive_file_exposure", "severity": "low",
                 "title": "Exposed .DS_Store",
                 "desc": "A macOS .DS_Store discloses directory and file names, "
                         "aiding further content discovery."},
    "backup": {"vuln_type": "sensitive_file_exposure", "severity": "medium",
               "title": "Exposed backup / source file",
               "desc": "A backup or editor copy of a server-side file is served "
                       "as text, disclosing source code and possibly secrets."},
    "htpasswd": {"vuln_type": "secret_exposure", "severity": "high",
                 "title": "Exposed .htpasswd",
                 "desc": "An Apache .htpasswd with password hashes is web-"
                         "accessible and can be cracked offline."},
    "phpinfo": {"vuln_type": "info_disclosure", "severity": "medium",
                "title": "Exposed phpinfo()",
                "desc": "A phpinfo() page leaks environment variables, paths and "
                        "the full PHP/module configuration."},
    "sourcemap": {"vuln_type": "info_disclosure", "severity": "low",
                  "title": "JavaScript source map exposed",
                  "desc": "A .map file republishes the original, unminified "
                          "front-end source (and sometimes comments/paths)."},
}


async def _get(session: Any, url: str, timeout: float) -> _Resp:
    import aiohttp
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False, ssl=False,
        ) as resp:
            body = await resp.text(errors="replace")
            return _Resp(resp.status, body, resp.headers.get("Content-Type", ""))
    except Exception:
        return _Resp(0, "", "")


def _norm(body: str) -> str:
    return re.sub(r"\s+", " ", body).strip()[:2000]


def _finding(url: str, meta: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    ev = dict(evidence)
    ev["url"] = url
    ev["verification"] = "content-verified"
    return {
        "target": url,
        "vuln_type": meta["vuln_type"],
        "type": meta["vuln_type"],
        "severity": meta["severity"],
        "title": meta["title"],
        "description": meta["desc"],
        "confidence": 0.9,
        "proved": True,
        "cve_id": "",
        "evidence": ev,
        "source": "exposure_scanner",
    }


async def _scan_base(session: Any, base: str, timeout: float) -> list[dict[str, Any]]:
    # Soft-404 calibration: a random path that cannot exist.
    junk = await _get(session, urljoin(base + "/", f"heaven-{secrets.token_hex(6)}.nope"), timeout)
    junk_norm = _norm(junk.body) if junk.status == 200 else ""

    findings: list[dict[str, Any]] = []
    for path, artefact, verifier in _STATIC_PROBES:
        r = await _get(session, urljoin(base + "/", path), timeout)
        if r.status != 200 or not r.body:
            continue
        # Reject anything that mirrors the soft-404 body.
        if junk_norm and _norm(r.body) == junk_norm:
            continue
        if _VERIFIERS[verifier](r):
            meta = _ARTEFACT_META.get(artefact) or _ARTEFACT_META["backup"]
            findings.append(_finding(
                urljoin(base + "/", path), meta,
                {"status": r.status, "signature": verifier,
                 "excerpt": r.body[:180]}))
    return findings


async def _scan_sourcemaps(session: Any, js_files: list[str], timeout: float) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for js in js_files:
        if not js or not js.endswith(".js") or js in seen:
            continue
        seen.add(js)
        map_url = js + ".map"
        r = await _get(session, map_url, timeout)
        if r.status != 200 or not r.body:
            continue
        try:
            doc = json.loads(r.body)
        except (ValueError, TypeError):
            continue
        if isinstance(doc, dict) and "version" in doc and (
            "sources" in doc or "mappings" in doc
        ):
            findings.append(_finding(
                map_url, _ARTEFACT_META["sourcemap"],
                {"status": r.status, "sources": len(doc.get("sources", []) or []),
                 "has_sources_content": bool(doc.get("sourcesContent"))}))
    return findings


async def _scan_backups(session: Any, page_urls: list[str], timeout: float,
                        limit: int = 20) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    count = 0
    for page in page_urls:
        p = urlparse(page)
        # Only pages with a filename that has an extension are worth backup-probing.
        name = p.path.rsplit("/", 1)[-1]
        if "." not in name or not name:
            continue
        base_no_q = page.split("?", 1)[0]
        for suf in _BACKUP_SUFFIXES:
            cand = base_no_q + suf
            if cand in seen:
                continue
            seen.add(cand)
            count += 1
            if count > limit:
                return findings
            r = await _get(session, cand, timeout)
            if r.status == 200 and r.body and _v_source(r):
                findings.append(_finding(
                    cand, _ARTEFACT_META["backup"],
                    {"status": r.status, "of_page": base_no_q, "excerpt": r.body[:180]}))
    return findings


async def scan_exposures(
    base_urls: list[str], *, js_files: Optional[list[str]] = None,
    page_urls: Optional[list[str]] = None, stealth_level: str = "normal",
    timeout: float = 8.0, max_bases: int = 10,
) -> dict[str, Any]:
    """Probe for exposed sensitive files, secrets and source maps.

    ``base_urls`` are scheme+host roots; ``js_files`` feed source-map discovery;
    ``page_urls`` feed backup-copy discovery. Every finding is content-verified.
    """
    try:
        import aiohttp
    except ImportError:
        return {"findings": [], "skipped": "aiohttp missing"}

    # Distinct scheme+host roots.
    roots: list[str] = []
    seen: set[str] = set()
    for u in base_urls:
        p = urlparse(u)
        if not p.scheme.startswith("http"):
            continue
        root = f"{p.scheme}://{p.netloc}"
        if root not in seen:
            seen.add(root)
            roots.append(root)
        if len(roots) >= max_bases:
            break

    profile = profile_for(stealth_level)
    engine = EvasionEngine(profile)
    headers = engine.get_http_headers()

    findings: list[dict[str, Any]] = []
    connector = aiohttp.TCPConnector(ssl=False, limit=max(1, min(10, profile.max_concurrent)))
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        for root in roots:
            await engine.apply_evasion_delay()
            findings.extend(await _scan_base(session, root, timeout))
        if js_files:
            findings.extend(await _scan_sourcemaps(session, js_files, timeout))
        if page_urls:
            findings.extend(await _scan_backups(session, page_urls, timeout))

    if findings:
        logger.info("exposure scan: %d finding(s) across %d root(s)", len(findings), len(roots))
    return {"findings": findings, "vulnerabilities": findings, "total": len(findings)}
