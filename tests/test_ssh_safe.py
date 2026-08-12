"""Tests for the asyncssh UMAC/Nettle crash-safety shim (heaven.utils.ssh_safe).

Regression guard for a native SIGSEGV: asyncssh's optional UMAC MACs are an
untyped ctypes binding to libnettle that segfaults the whole process the instant
a MAC is computed on some platforms (Apple Silicon + CPython 3.14 + Homebrew
nettle 9). Because HEAVEN scans SSH targets in-process, that crash killed the
API server. The fix strips UMAC from asyncssh's negotiation so it is never
selected; HMAC-SHA2 MACs (which every SSH server supports) remain.
"""

from __future__ import annotations

import pytest


def test_harden_removes_umac_and_keeps_hmac():
    asyncssh_mac = pytest.importorskip("asyncssh.mac")
    from heaven.utils import ssh_safe

    ssh_safe.harden_asyncssh()

    offered = asyncssh_mac.get_mac_algs()
    default = asyncssh_mac.get_default_mac_algs()
    # No UMAC MAC can be negotiated any more (the crash path is unreachable).
    assert not any(bytes(a).startswith(b"umac") for a in offered)
    assert not any(bytes(a).startswith(b"umac") for a in default)
    # HMAC-SHA2 remains, so SSH connections still work with standard MACs.
    assert any(bytes(a).startswith(b"hmac-sha2-256") for a in offered)
    # And the handler/param registries carry no UMAC entries either.
    assert not any(bytes(k).startswith(b"umac") for k in asyncssh_mac._mac_handler)
    assert not any(bytes(k).startswith(b"umac") for k in asyncssh_mac._mac_params)


def test_harden_is_idempotent():
    pytest.importorskip("asyncssh.mac")
    from heaven.utils import ssh_safe

    ssh_safe.harden_asyncssh()
    # A second call is a no-op: nothing left to remove.
    assert ssh_safe.harden_asyncssh() == []


def test_harden_actually_strips_a_reinserted_umac():
    """Deterministically exercise the removal path from a 'fresh' state."""
    asyncssh_mac = pytest.importorskip("asyncssh.mac")
    from heaven.utils import ssh_safe

    fake = b"umac-64@openssh.com"
    if fake not in asyncssh_mac._mac_algs:
        asyncssh_mac._mac_algs.append(fake)
    if fake not in asyncssh_mac._default_mac_algs:
        asyncssh_mac._default_mac_algs.append(fake)

    ssh_safe._hardened = False  # force a re-run as if freshly imported
    removed = ssh_safe.harden_asyncssh()

    assert fake.decode() in removed
    assert fake not in asyncssh_mac._mac_algs
    assert fake not in asyncssh_mac._default_mac_algs


def test_connect_hardens_then_delegates(monkeypatch):
    pytest.importorskip("asyncssh")
    import asyncssh

    from heaven.utils import ssh_safe

    captured: dict = {}

    class _Dummy:
        pass

    def fake_connect(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _Dummy()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    ssh_safe._hardened = False  # ensure connect() triggers hardening

    result = ssh_safe.connect("10.0.0.1", port=22, username="msfadmin")

    # Delegates transparently to asyncssh.connect with the same args…
    assert isinstance(result, _Dummy)
    assert captured["args"] == ("10.0.0.1",)
    assert captured["kwargs"] == {"port": 22, "username": "msfadmin"}
    # …and hardening ran as a side effect.
    from asyncssh import mac as _mac
    assert not any(bytes(a).startswith(b"umac") for a in _mac.get_mac_algs())


def test_enable_crash_dumps():
    import faulthandler

    from heaven.utils import ssh_safe

    assert ssh_safe.enable_crash_dumps() is True
    assert faulthandler.is_enabled()
