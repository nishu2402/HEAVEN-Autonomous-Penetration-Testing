"""Crash-safe ``asyncssh`` helpers.

**Why this module exists.** ``asyncssh`` ships an *optional* UMAC message-auth
implementation (``asyncssh/crypto/umac.py``) that is an **untyped ctypes binding
to the native Nettle library**. On some platforms that binding is
ABI-incompatible with the installed ``libnettle`` and **segfaults the instant a
MAC is computed** — reproduced here on Apple Silicon + CPython 3.14 + Homebrew
``nettle`` 9 (``nettle_umac64_digest`` → ``SIGSEGV``). A segfault is a *native*
crash, not a Python exception, so it cannot be caught: it takes down the whole
interpreter — the API server or CLI process — aborting any in-flight scan with
the OS "Python quit unexpectedly" dialog.

The trigger is entirely ordinary: HEAVEN opens an SSH connection to a target
(credential validation, lateral movement, loot, post-ex enumeration) and the SSH
handshake negotiates a ``umac-64@openssh.com`` / ``umac-128@openssh.com`` MAC —
which OpenSSH offers by default. Metasploitable-2's OpenSSH is one such server.

**The fix.** ``asyncssh`` is explicitly designed to run *without* UMAC: it only
registers those MACs when the Nettle binding imports, and negotiates
HMAC-SHA2 MACs otherwise — which every SSH server supports. So we simply remove
the UMAC MACs from ``asyncssh``'s negotiation lists before any connection is
made. :func:`connect` is a drop-in replacement for ``asyncssh.connect`` that
guarantees this; :func:`harden_asyncssh` can also be called once at process
startup as belt-and-suspenders.

Everything here is dependency-optional (no-op without ``asyncssh``) and
idempotent.
"""

from __future__ import annotations

import contextlib
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("utils.ssh_safe")

# The four MACs implemented by the crash-prone native Nettle binding all start
# with this prefix (``umac-64``/``umac-128``, in both ``@openssh.com`` and
# ``-etm@openssh.com`` variants). Matching on the prefix is robust to any future
# UMAC variant asyncssh might add.
_UMAC_PREFIX = b"umac"

_hardened = False
_crash_dumps_enabled = False


def harden_asyncssh() -> list[str]:
    """Remove ``asyncssh``'s crash-prone native UMAC MACs from negotiation.

    Mutates ``asyncssh.mac``'s live algorithm lists in place so that no SSH
    connection can negotiate a UMAC MAC (and thus never calls the segfaulting
    Nettle binding). HMAC-SHA2 MACs remain and are what every server uses.

    Idempotent and dependency-optional: a no-op if ``asyncssh`` is not installed
    or UMAC was already stripped. Returns the algorithm names that were removed
    (empty on subsequent calls).
    """
    global _hardened
    if _hardened:
        return []
    try:
        from asyncssh import mac as _mac  # type: ignore[import-not-found]
    except Exception:  # asyncssh missing / import failure — nothing to harden
        _hardened = True
        return []

    removed: set[str] = set()

    def _is_umac(name: Any) -> bool:
        return isinstance(name, (bytes, bytearray)) and bytes(name).startswith(_UMAC_PREFIX)

    # Drop from the offered + default algorithm lists (mutated in place so any
    # reference already captured by asyncssh sees the change too).
    for list_name in ("_mac_algs", "_default_mac_algs"):
        algs = getattr(_mac, list_name, None)
        if isinstance(algs, list):
            for alg in [a for a in algs if _is_umac(a)]:
                algs.remove(alg)
                removed.add(bytes(alg).decode("ascii", "replace"))

    # And from the handler/param registries so the MAC cannot be constructed
    # even if some code path references it by name.
    for dict_name in ("_mac_handler", "_mac_params"):
        registry = getattr(_mac, dict_name, None)
        if isinstance(registry, dict):
            for key in [k for k in registry if _is_umac(k)]:
                registry.pop(key, None)

    # Flag UMAC unavailable so any later (re-)registration path skips it.
    with contextlib.suppress(Exception):  # pragma: no cover - attr always present
        _mac._umac_available = False

    _hardened = True
    if removed:
        logger.debug(
            "Disabled crash-prone asyncssh UMAC/Nettle MACs (native ctypes "
            "segfault workaround): %s",
            ", ".join(sorted(removed)),
        )
    return sorted(removed)


def connect(*args: Any, **kwargs: Any) -> Any:
    """Drop-in replacement for ``asyncssh.connect`` that first strips unsafe MACs.

    Returns the object ``asyncssh.connect`` returns, unchanged — so it works with
    both ``await`` and ``async with`` exactly like the original.
    """
    harden_asyncssh()
    import asyncssh  # local import: asyncssh is an optional dependency

    return asyncssh.connect(*args, **kwargs)


def enable_crash_dumps() -> bool:
    """Enable :mod:`faulthandler` so a *native* crash prints a Python traceback.

    This is a safety net, not a fix: it does not prevent a segfault, but if any
    C extension ever faults again it will dump the offending Python stack to
    stderr instead of dying silently — turning "Python quit unexpectedly" into a
    diagnosable stack trace. Idempotent; never raises.
    """
    global _crash_dumps_enabled
    if _crash_dumps_enabled:
        return True
    try:
        import faulthandler

        if not faulthandler.is_enabled():
            faulthandler.enable()
        _crash_dumps_enabled = True
        return True
    except Exception:  # pragma: no cover - faulthandler is always importable
        return False
