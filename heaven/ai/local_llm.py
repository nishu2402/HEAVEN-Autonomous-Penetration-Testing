"""HEAVEN — local LLM runtime helpers (Ollama).

Thin, offline-safe utilities the CLI (`heaven ai …`), the API
(`GET /api/ai/local/status`), `heaven doctor` and the runtime-capabilities probe
share so they never drift on "is a local model available?". Everything degrades
to a clear status when Ollama is absent or the server is down — nothing here ever
raises into a caller.

Why Ollama: it's the one-command, cross-platform local runtime, and it exposes an
OpenAI-compatible API (`/v1/chat/completions`) that :mod:`heaven.ai.llm_gateway`
talks to directly over ``httpx`` — so the whole AI layer runs on a private,
rate-limit-free local model with no new Python dependencies.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 -- runs the vetted `ollama` CLI, fixed argv, no shell
import sys
from typing import Callable, Optional

from heaven.ai.llm_gateway import DEFAULT_OLLAMA_HOST
from heaven.utils.logger import get_logger

logger = get_logger("ai.local")

# The default HEAVEN pulls/pins for a ~16 GB machine: a fast 7B that follows
# instructions and emits clean JSON (what the structured AI layers need).
DEFAULT_OLLAMA_MODEL = "qwen2.5:7b"

# Curated, hardware-tiered suggestions surfaced by `heaven ai setup` / the UI.
# Ordered small→large; each is a real Ollama tag.
RECOMMENDED_MODELS: tuple[dict[str, str], ...] = (
    {"model": "llama3.2:3b", "tier": "~8 GB RAM", "note": "fast, lightweight"},
    {"model": "qwen2.5:7b", "tier": "~16 GB RAM", "note": "balanced default — strong JSON"},
    {"model": "llama3.1:8b", "tier": "~16 GB RAM", "note": "great general reasoning"},
    {"model": "qwen2.5:14b", "tier": "32 GB+ / GPU", "note": "deeper reasoning, slower on CPU"},
)


def ollama_host() -> str:
    """Base Ollama host (no ``/v1`` suffix, no trailing slash)."""
    import os
    return (os.environ.get("HEAVEN_OLLAMA_HOST") or DEFAULT_OLLAMA_HOST).strip().rstrip("/")


def is_ollama_installed() -> bool:
    """Whether the ``ollama`` CLI is on PATH."""
    return shutil.which("ollama") is not None


def ollama_reachable(timeout: float = 2.0) -> bool:
    """Whether the Ollama server answers on its host (read-only GET /api/tags)."""
    return _tags(timeout) is not None


def list_models(timeout: float = 3.0) -> list[str]:
    """Installed model tags, or ``[]`` when the server is unreachable."""
    tags = _tags(timeout)
    if not tags:
        return []
    out: list[str] = []
    for m in tags.get("models", []) or []:
        name = m.get("name") or m.get("model")
        if name:
            out.append(str(name))
    return out


def _tags(timeout: float) -> Optional[dict]:
    """Raw ``/api/tags`` payload, or ``None`` on any error (offline-safe)."""
    try:
        import httpx
        r = httpx.get(f"{ollama_host()}/api/tags", timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, dict) else {"models": data}
    except Exception:  # noqa: BLE001 — offline / server down / bad JSON → "unavailable"
        logger.debug("ollama /api/tags probe failed", exc_info=True)
        return None


def endpoint_reachable(base_url: str, timeout: float = 2.0) -> bool:
    """Whether a generic OpenAI-compatible endpoint answers on ``/models``."""
    base = (base_url or "").strip().rstrip("/")
    if not base:
        return False
    try:
        import httpx
        r = httpx.get(f"{base}/models", timeout=timeout)
        return r.status_code < 500
    except Exception:  # noqa: BLE001
        logger.debug("local endpoint /models probe failed", exc_info=True)
        return False


def install_hint() -> str:
    """Platform-appropriate one-liner for installing Ollama."""
    if sys.platform == "darwin":
        return "brew install ollama   (or download from https://ollama.com/download)"
    if sys.platform.startswith("win") or sys.platform == "cygwin":
        return "winget install Ollama.Ollama   (or download from https://ollama.com/download)"
    if sys.platform.startswith("linux"):
        return "curl -fsSL https://ollama.com/install.sh | sh"
    return "See https://ollama.com/download"


def install_command() -> Optional[list[str]]:
    """The argv HEAVEN would run to install Ollama, or ``None`` if we can't
    determine a package manager (caller should fall back to :func:`install_hint`).
    Callers must confirm before running — this is a heavyweight action."""
    if sys.platform == "darwin" and shutil.which("brew"):
        return ["brew", "install", "ollama"]
    if (sys.platform.startswith("win") or sys.platform == "cygwin"):
        if shutil.which("winget"):
            return ["winget", "install", "--id", "Ollama.Ollama", "-e", "--source", "winget"]
        if shutil.which("scoop"):
            return ["scoop", "install", "ollama"]
    return None


def pull_model(model: str, on_output: Optional[Callable[[str], None]] = None,
               timeout: int = 3600) -> bool:
    """Pull an Ollama model (`ollama pull <model>`), streaming progress lines to
    ``on_output``. Returns True on success. Never raises — logs and returns False
    when the CLI is missing or the pull fails."""
    model = (model or "").strip()
    if not model:
        return False
    if not is_ollama_installed():
        if on_output:
            on_output(f"ollama not installed — {install_hint()}")
        return False
    try:
        proc = subprocess.Popen(  # nosec B603 B607 -- fixed argv, vetted tool, no shell
            ["ollama", "pull", model],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, bufsize=1,
        )
    except (OSError, ValueError) as e:
        logger.warning("ollama pull failed to start: %s", e)
        if on_output:
            on_output(f"failed to start ollama pull: {e}")
        return False
    try:
        assert proc.stdout is not None  # nosec B101 -- PIPE guarantees a stream
        for line in proc.stdout:
            line = line.rstrip()
            if line and on_output:
                on_output(line)
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        logger.warning("ollama pull timed out for %s", model)
        return False
    return rc == 0


def pull_progress_frame(data: dict) -> dict:
    """Normalize one Ollama ``/api/pull`` streaming line into a compact UI frame.

    Ollama streams newline-delimited JSON while pulling; a line looks like
    ``{"status":"pulling <digest>","completed":123,"total":456}`` for a layer
    download, ``{"status":"verifying sha256 digest"}`` for a phase, or
    ``{"status":"success"}`` at the end. Errors arrive as ``{"error":"..."}``.
    This turns any of those into ``{status, completed, total, percent, done,
    error}`` so the web progress bar and the CLI share one interpretation.

    Pure and total-safe — never raises, so it can run inside the WS relay.
    """
    if not isinstance(data, dict):
        return {"status": "", "completed": 0, "total": 0, "percent": None,
                "done": False, "error": ""}
    err = str(data.get("error") or "").strip()
    status = str(data.get("status") or ("error" if err else "")).strip()
    try:
        completed = int(data.get("completed") or 0)
    except (TypeError, ValueError):
        completed = 0
    try:
        total = int(data.get("total") or 0)
    except (TypeError, ValueError):
        total = 0
    percent = round(completed * 100.0 / total, 1) if total > 0 else None
    done = bool(err) or status.lower() in {"success", "error"}
    return {"status": status, "completed": completed, "total": total,
            "percent": percent, "done": done, "error": err}


def local_status(provider: str = "ollama", base_url: str = "") -> dict:
    """One dict describing local-LLM availability, for the API / doctor / Health.

    Never raises. For ``ollama`` it reports install + reachability + model list;
    for a generic ``local`` endpoint it reports reachability of ``base_url``.
    """
    if provider == "local":
        reachable = endpoint_reachable(base_url)
        return {
            "provider": "local", "installed": None, "reachable": reachable,
            "host": (base_url or "").strip(), "models": [],
            "default_model": "", "recommended": [dict(m) for m in RECOMMENDED_MODELS],
        }
    installed = is_ollama_installed()
    models = list_models() if installed else []
    return {
        "provider": "ollama",
        "installed": installed,
        "reachable": bool(models) or ollama_reachable(),
        "host": ollama_host(),
        "models": models,
        "default_model": DEFAULT_OLLAMA_MODEL,
        "recommended": [dict(m) for m in RECOMMENDED_MODELS],
    }
