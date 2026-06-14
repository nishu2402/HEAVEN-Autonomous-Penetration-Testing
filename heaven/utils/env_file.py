"""Surgical, in-place updates to a `.env` file.

Used by the Web-UI change-password flow so a password set in the browser
persists across server restarts. The AuthManager is in-memory only; `.env` is
the source of truth that `heaven serve` re-reads on boot (see
`heaven/cli/__init__.py`). Writing the new value back here is what makes a
password change "stick".

The writer preserves every other line and comment, replacing only the target
key's line (or appending it if absent), and best-effort tightens the file
permissions to 0600 since it holds secrets.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Union


def _quote(value: str) -> str:
    """Quote a value for .env if it contains characters that would otherwise
    break shell-style parsing. Mirrors the quoting used by `heaven init`."""
    if not value:
        return ""
    if any(c in value for c in (" ", "#", "$", '"', "'", "\t")):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def resolve_env_path() -> Path:
    """Locate the `.env` to persist to: the file python-dotenv would discover
    from the current working directory, else `./.env`."""
    try:
        from dotenv import find_dotenv
        found = find_dotenv(usecwd=True)
        if found:
            return Path(found)
    except ImportError:
        pass
    return Path.cwd() / ".env"


def set_env_var(path: Union[str, Path], key: str, value: str) -> Path:
    """Set ``KEY=value`` in the .env file at ``path``.

    - Replaces an existing, non-commented ``KEY=...`` line in place.
    - Otherwise appends the line.
    - Creates the file (and parent dirs) if it doesn't exist.
    - Tightens perms to 0600 on a best-effort basis.

    Returns the resolved path written to.
    """
    p = Path(path)
    new_line = f"{key}={_quote(value)}"
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")

    lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    out: list[str] = []
    replaced = False
    for raw in lines:
        if not replaced and pattern.match(raw) and not raw.lstrip().startswith("#"):
            out.append(new_line)
            replaced = True
        else:
            out.append(raw)
    if not replaced:
        out.append(new_line)

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass  # non-POSIX FS or insufficient perms — value is still persisted
    return p


def unset_env_var(path: Union[str, Path], key: str) -> Path:
    """Remove the (non-commented) ``KEY=...`` line from the .env file at ``path``.

    No-op if the file or the key is absent. Preserves every other line and
    keeps perms at 0600. Returns the resolved path.
    """
    p = Path(path)
    if not p.exists():
        return p
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    kept = [
        raw for raw in p.read_text(encoding="utf-8").splitlines()
        if not (pattern.match(raw) and not raw.lstrip().startswith("#"))
    ]
    p.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return p
