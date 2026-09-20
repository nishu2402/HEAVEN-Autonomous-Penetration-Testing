"""Surgical, in-place updates to a `.env` file.

Used by the Web-UI change-password flow so a password set in the browser
persists across server restarts. The AuthManager is in-memory only; `.env` is
the source of truth that `heaven serve` re-reads on boot (see
`heaven/cli/__init__.py`). Writing the new value back here is what makes a
password change "stick".

The writer preserves every other line and comment, replacing only the target
key's line (or appending it if absent), and writes atomically with owner-only
(0600) permissions since it holds secrets (see :func:`write_private_file`).
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Union


# A .env value is one physical line: KEY=value. A raw newline or carriage
# return in the value would split it into a second line, and a caller that
# persists a user-influenced value (the Settings API, the change-password flow)
# could smuggle in an out-of-catalog key such as HEAVEN_DISABLE_AUTH=1 — a
# persistent, tool-wide auth bypass that survives the next restart (CWE-93, .env
# line injection). NUL can't appear in a text file or an os.environ value at all.
# None of these ever occur in a legitimate API key, host, URL or password, so we
# reject them outright rather than trying to escape them.
_FORBIDDEN_VALUE_CHARS = ("\n", "\r", "\x00")

# Keys are constants/allow-listed by every caller, but a malformed key would also
# corrupt the file, so pin the shape of a POSIX-style env name defensively.
_VALID_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _quote(value: str) -> str:
    """Quote a value for .env if it contains characters that would otherwise
    break shell-style parsing. Mirrors the quoting used by `heaven init`.

    Callers must reject control characters first (see :func:`set_env_var`); this
    only handles the shell-parsing set."""
    if not value:
        return ""
    if any(c in value for c in (" ", "#", "$", '"', "'", "\t")):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def write_private_file(path: Union[str, Path], text: str) -> Path:
    """Write ``text`` to ``path`` atomically and owner-readable only (0600).

    ``.env`` holds the admin password, the DB password and API keys, so it must
    never be even briefly world-readable and must never be left truncated:

    - A plain ``Path.write_text`` creates a fresh file under the process umask
      (typically 0644 = world-readable) and only a *follow-up* ``chmod`` narrows
      it, leaving a window where a local user can read the secrets (CWE-276,
      incorrect default permissions).
    - ``write_text`` also truncates before it writes, so a crash mid-write can
      leave an existing ``.env`` empty — the admin password and every API key
      gone, and the next boot generating a fresh random admin password.

    ``tempfile.mkstemp`` creates the scratch file 0600 from the start, in the
    SAME directory so ``os.replace`` is an atomic rename on one filesystem. A
    concurrent reader therefore sees either the old file or the fully-written new
    one, never a partial or a wide-open one. Returns the resolved path.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".env-", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass  # scratch file already gone or never created
        raise
    return p


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
    - Writes atomically with owner-only 0600 perms (see :func:`write_private_file`).

    Returns the resolved path written to.

    Raises ``ValueError`` if ``key`` is not a valid env name or ``value`` holds a
    newline, carriage return or NUL — the characters that would let a value break
    out of its own ``KEY=value`` line and inject another (CWE-93).
    """
    if not _VALID_KEY_RE.match(key):
        raise ValueError(f"invalid env var name: {key!r}")
    bad = [c for c in _FORBIDDEN_VALUE_CHARS if c in value]
    if bad:
        raise ValueError(
            "env value may not contain control characters "
            f"({', '.join(repr(c) for c in bad)})"
        )
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

    return write_private_file(p, "\n".join(out) + "\n")


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
    return write_private_file(p, "\n".join(kept) + ("\n" if kept else ""))
