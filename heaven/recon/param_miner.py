"""HEAVEN — Hidden parameter mining (Arjun-style).

A web app only executes the code path behind a parameter it actually *reads*,
and many high-value parameters are never linked anywhere in the HTML the crawler
sees — ``?debug=``, ``?redirect=``, ``?file=``, ``?admin=``, ``?callback=`` …
Because the injection/anomaly scanners can only fuzz inputs the crawler handed
them, an unlinked parameter is a blind spot: a real SQLi/SSRF/LFI sitting behind
``?template=`` is simply never tested.

This module discovers those parameters by *observing the target's own reaction*:

  1. Establish a **baseline** for the URL and calibrate the response **noise band**
     (two identical control requests + a guaranteed-nonexistent junk param).
  2. Send candidate names from a compact, high-signal wordlist in **buckets**,
     each candidate carrying a unique canary value. A bucket that provokes no
     reflection and no out-of-band length change is discarded in a single request
     (this is what keeps mining fast).
  3. A parameter is only reported when its effect is **reproduced** with a second,
     different canary AND a control junk parameter does *not* reproduce the same
     effect. That two-gate confirmation is what makes the result false-positive
     free — a name that merely rides response jitter never survives.

Everything here is **read-only** (GET requests with benign canary values). The
output is shaped exactly like a crawler endpoint (``input_vectors``) so the
orchestrator's injection-discovery task consumes the mined parameters with no
extra wiring — every mined parameter is then fuzzed for SQLi/XSS/LFI/SSTI and
actively confirmed downstream, so discovery never inflates a finding on its own.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from heaven.recon.evasion_engine import EvasionEngine, profile_for
from heaven.utils.logger import get_logger

logger = get_logger("recon.param_miner")


# A compact, high-signal wordlist. These are the parameter names that most often
# gate a *vulnerable* code path (redirects, file reads, template rendering, debug
# switches, access control). Kept deliberately small so mining stays fast — the
# operator can pass a larger list via ``wordlist=``.
DEFAULT_PARAM_WORDLIST: tuple[str, ...] = (
    # identifiers / access control
    "id", "user", "user_id", "uid", "account", "admin", "role", "is_admin",
    "debug", "test", "preview", "draft", "internal", "access", "auth", "token",
    # file / path (LFI / traversal / RFI)
    "file", "filename", "path", "dir", "folder", "document", "doc", "page",
    "template", "tpl", "view", "include", "load", "read", "download", "attachment",
    # url / redirect / SSRF
    "url", "uri", "link", "redirect", "redirect_url", "return", "return_url",
    "returnurl", "next", "continue", "dest", "destination", "callback", "cb",
    "target", "out", "domain", "host", "site", "feed", "image_url", "img",
    # command / eval
    "cmd", "exec", "command", "run", "query", "q", "search", "s", "keyword",
    "filter", "sort", "order", "order_by", "column", "field", "data", "input",
    # rendering / format
    "format", "type", "output", "lang", "language", "locale", "theme", "style",
    "content", "body", "message", "text", "name", "title", "value", "key",
    # api / misc
    "api", "action", "method", "func", "function", "module", "class", "object",
    "ref", "source", "src", "from", "to", "email", "mail", "code", "hash",
)

# How many candidate names ride in one bucket. Small enough that a length change
# is attributable, large enough to keep the request count low on clean targets.
_BUCKET_SIZE = 24
_CANARY_PREFIX = "hvnp"


@dataclass
class MinedParam:
    """One confirmed hidden parameter discovered on a URL."""

    url: str
    param: str
    method: str = "GET"
    signal: str = ""          # "reflection" | "length" | "status"
    confidence: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)


def _canary() -> str:
    return _CANARY_PREFIX + secrets.token_hex(4)


def _with_params(url: str, extra: dict[str, str]) -> str:
    """Return ``url`` with ``extra`` merged into its query string."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    merged: dict[str, Any] = {k: v for k, v in qs.items()}
    for k, v in extra.items():
        merged[k] = [v]
    return urlunparse(parsed._replace(query=urlencode(merged, doseq=True)))


def _norm_len(body: str) -> int:
    """Length with per-request canaries stripped so reflected canaries don't
    themselves count as a length change."""
    import re
    return len(re.sub(_CANARY_PREFIX + r"[0-9a-f]{8}", "", body))


async def _get(session: Any, url: str, timeout: float) -> tuple[int, str]:
    import aiohttp
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False, ssl=False,
        ) as resp:
            return resp.status, await resp.text(errors="replace")
    except Exception:
        return 0, ""


async def _mine_one_url(
    session: Any, url: str, wordlist: tuple[str, ...],
    engine: EvasionEngine, timeout: float,
) -> list[MinedParam]:
    """Discover hidden parameters on a single URL. Read-only."""
    # ── 1. Baseline + noise calibration ──────────────────────────────────────
    status0, body0 = await _get(session, url, timeout)
    if status0 == 0:
        return []
    base_len = _norm_len(body0)

    # Two controls with a guaranteed-nonexistent junk param tell us (a) whether
    # the app reflects arbitrary param names — which would make reflection a
    # useless signal — and (b) how much the response length jitters on its own.
    reflects_any = False
    noise = 0
    control_lens: list[int] = []
    for _ in range(2):
        jc = _canary()
        st, body = await _get(session, _with_params(url, {"hvnjunk_" + secrets.token_hex(3): jc}), timeout)
        if jc in body:
            reflects_any = True
        control_lens.append(_norm_len(body))
    # Noise band = the spread we saw from the app itself, floored generously so a
    # couple of bytes of jitter (timestamps, CSRF tokens) never trips a signal.
    noise = max(48, (max(control_lens) - min(control_lens)) * 2 + abs(max(control_lens) - base_len))

    # ── 2. Bucketed sweep ────────────────────────────────────────────────────
    candidates = [w for w in wordlist if w.lower() not in
                  {k.lower() for k in parse_qs(urlparse(url).query)}]
    suspects: list[tuple[str, str]] = []  # (param, signal)

    for i in range(0, len(candidates), _BUCKET_SIZE):
        bucket = candidates[i:i + _BUCKET_SIZE]
        canaries = {name: _canary() for name in bucket}
        await engine.apply_evasion_delay()
        st, body = await _get(session, _with_params(url, canaries), timeout)
        if st == 0:
            continue

        # Reflection signal: which canaries came back? (only trustworthy when the
        # app does NOT reflect arbitrary names).
        if not reflects_any:
            for name, canary in canaries.items():
                if canary in body:
                    suspects.append((name, "reflection"))

        # Length/status signal: bucket moved the response out of the noise band —
        # binary-split to find which name(s) did it.
        moved_len = abs(_norm_len(body) - base_len) > noise
        moved_status = st != status0
        if moved_len or moved_status:
            already = {n for n, _ in suspects}
            drill = [n for n in bucket if n not in already]
            found = await _isolate(session, url, drill, base_len, status0,
                                   noise, engine, timeout)
            suspects.extend(found)

    # ── 3. Two-gate confirmation ─────────────────────────────────────────────
    confirmed: list[MinedParam] = []
    seen: set[str] = set()
    for name, signal in suspects:
        if name in seen:
            continue
        seen.add(name)
        mp = await _confirm(session, url, name, signal, base_len, status0,
                            noise, reflects_any, engine, timeout)
        if mp is not None:
            confirmed.append(mp)
    if confirmed:
        logger.info("param-miner: %d hidden parameter(s) on %s: %s",
                    len(confirmed), url, ", ".join(m.param for m in confirmed))
    return confirmed


async def _isolate(
    session: Any, url: str, names: list[str], base_len: int, status0: int,
    noise: int, engine: EvasionEngine, timeout: float,
) -> list[tuple[str, str]]:
    """Binary-split a bucket that showed a length/status signal down to the
    individual parameter(s) responsible."""
    if not names:
        return []
    if len(names) == 1:
        name = names[0]
        canaries = {name: _canary()}
        st, body = await _get(session, _with_params(url, canaries), timeout)
        if st == 0:
            return []
        if abs(_norm_len(body) - base_len) > noise:
            return [(name, "length")]
        if st != status0:
            return [(name, "status")]
        return []
    mid = len(names) // 2
    out: list[tuple[str, str]] = []
    for half in (names[:mid], names[mid:]):
        canaries = {n: _canary() for n in half}
        await engine.apply_evasion_delay()
        st, body = await _get(session, _with_params(url, canaries), timeout)
        if st == 0:
            continue
        if abs(_norm_len(body) - base_len) > noise or st != status0:
            out.extend(await _isolate(session, url, half, base_len, status0,
                                      noise, engine, timeout))
    return out


async def _confirm(
    session: Any, url: str, name: str, signal: str, base_len: int, status0: int,
    noise: int, reflects_any: bool, engine: EvasionEngine, timeout: float,
) -> Optional[MinedParam]:
    """Confirm a suspected parameter with a fresh canary AND prove a control junk
    name does NOT reproduce the effect. Both gates must pass."""
    canary = _canary()
    st, body = await _get(session, _with_params(url, {name: canary}), timeout)
    if st == 0:
        return None

    if signal == "reflection":
        if reflects_any or canary not in body:
            return None
        # Control: a junk name of similar shape must NOT reflect (it wouldn't,
        # since reflects_any is False — but re-checking closes the loop).
        jc = _canary()
        _, jbody = await _get(session, _with_params(url, {"hvnjunk_" + secrets.token_hex(3): jc}), timeout)
        if jc in jbody:
            return None
        return MinedParam(url=url, param=name, method="GET", signal="reflection",
                          confidence=0.85,
                          evidence={"canary": canary, "note": "value reflected in response"})

    # length / status signal
    moved = abs(_norm_len(body) - base_len) > noise or st != status0
    if not moved:
        return None
    # Control gate: a random nonexistent name must NOT move the response the same
    # way. If it does, the app reacts to *any* extra param → not a real discovery.
    jc = _canary()
    jst, jbody = await _get(session, _with_params(url, {"hvnjunk_" + secrets.token_hex(3): jc}), timeout)
    if jst != 0 and (abs(_norm_len(jbody) - base_len) > noise or jst != status0):
        return None
    return MinedParam(
        url=url, param=name, method="GET", signal=signal, confidence=0.6,
        evidence={
            "note": f"parameter changed the response ({signal}); "
                    "verify the behaviour it gates",
            "delta_len": abs(_norm_len(body) - base_len),
            "status": st,
        },
    )


async def mine_parameters(
    urls: list[str], stealth_level: str = "normal", max_urls: int = 25,
    wordlist: Optional[tuple[str, ...]] = None, timeout: float = 8.0,
) -> dict[str, Any]:
    """Mine hidden GET parameters across ``urls``.

    Returns a dict shaped like a crawler result so the orchestrator's injection
    task consumes the discovered parameters transparently::

        {"endpoints": [{"url": U, "input_vectors": [{param, url, method, type}]}],
         "mined_params": N}
    """
    try:
        import aiohttp
    except ImportError:
        return {"endpoints": [], "mined_params": 0, "skipped": "aiohttp missing"}

    # Only mine distinct base URLs (path-level); dedupe on scheme+netloc+path so
    # we don't re-mine the same endpoint carrying different query strings.
    seen_paths: set[str] = set()
    picked: list[str] = []
    for u in urls:
        p = urlparse(u)
        key = f"{p.scheme}://{p.netloc}{p.path}"
        if key not in seen_paths:
            seen_paths.add(key)
            picked.append(u)
        if len(picked) >= max_urls:
            break
    if not picked:
        return {"endpoints": [], "mined_params": 0}

    words = wordlist or DEFAULT_PARAM_WORDLIST
    profile = profile_for(stealth_level)
    engine = EvasionEngine(profile)

    # Honour an active authenticated session so mining sees the post-login surface.
    try:
        from heaven.recon.auth_session import aiohttp_session_kwargs
        sess_kwargs = aiohttp_session_kwargs()
    except Exception:
        sess_kwargs = {}

    endpoints: list[dict[str, Any]] = []
    total = 0
    connector = aiohttp.TCPConnector(ssl=False, limit=max(1, profile.max_concurrent))
    async with aiohttp.ClientSession(
        headers=engine.get_http_headers(),
        connector=connector,
        **sess_kwargs,
    ) as session:
        sem = asyncio.Semaphore(max(1, min(8, profile.max_concurrent)))

        async def _run(u: str) -> list[MinedParam]:
            async with sem:
                try:
                    return await _mine_one_url(session, u, words, engine, timeout)
                except Exception as e:  # noqa: BLE001 — one URL must never abort the sweep
                    logger.debug("param-miner error on %s: %s", u, e)
                    return []

        results = await asyncio.gather(*[_run(u) for u in picked])

    for mined in results:
        if not mined:
            continue
        by_url: dict[str, dict[str, Any]] = {}
        for m in mined:
            ep = by_url.setdefault(m.url, {"url": m.url, "input_vectors": []})
            ep["input_vectors"].append({
                "type": "mined_param", "url": m.url, "method": m.method,
                "param": m.param, "signal": m.signal, "confidence": m.confidence,
                "evidence": m.evidence,
            })
            total += 1
        endpoints.extend(by_url.values())

    logger.info("param-miner: %d hidden parameter(s) across %d URL(s)", total, len(picked))
    return {"endpoints": endpoints, "mined_params": total}
