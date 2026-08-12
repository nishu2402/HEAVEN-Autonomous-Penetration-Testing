"""Regression tests for the SSH default-credential false positive.

The defect: ``CredentialSprayer.spray_ssh`` reported ``"SSH Default Credentials:
<user>:<pass>"`` whenever ``asyncssh.connect`` succeeded — but ``asyncssh`` does
not restrict itself to the password we spray. By default it also offers the
*operator's* SSH agent keys, their default identity files, and a GSSAPI/Kerberos
ticket, and it will happily authenticate against a server that permits SSH
``none`` auth. In every one of those cases the sprayed *password* was never
accepted, yet a critical "default credentials" finding was emitted — e.g. against
the auditor's own ``localhost:22``.

These tests stand up real, in-process ``asyncssh`` servers on ``127.0.0.1`` (no
network, ephemeral ports) and pin the fix:

  * a server that accepts SSH ``none`` auth is reported ONCE, honestly, as
    "accepts unauthenticated access" — never as a specific default password;
  * a public-key-only server yields NO password finding (the agent/key path can
    no longer masquerade as a password hit);
  * a password server that rejects every sprayed pair yields nothing;
  * a genuinely weak server (``user:user`` really works) is still caught — the
    true positive is preserved.
"""
from __future__ import annotations

import asyncio

import pytest

asyncssh = pytest.importorskip("asyncssh")

from heaven.vulnscan.advanced_attacks import CredentialSprayer  # noqa: E402

HOST = "127.0.0.1"


class _NoneAuth(asyncssh.SSHServer):
    """Authorizes the connection with no credentials at all (SSH 'none' auth)."""
    def begin_auth(self, username: str) -> bool:
        return False


class _PasswordOnlyAllWrong(asyncssh.SSHServer):
    """Requires a password; only a credential we never spray is valid."""
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == "realuser" and password == "S3cret-not-sprayed!"


class _PublicKeyOnly(asyncssh.SSHServer):
    """Accepts any offered public key; refuses passwords outright."""
    def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return False


class _RealDefaultCred(asyncssh.SSHServer):
    """A genuinely weak server: the sprayed 'user:user' really authenticates."""
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == "user" and password == "user"


async def _spray_against(handler_cls):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        handler_cls, HOST, 0, server_host_keys=[host_key],
    )
    try:
        port = server.get_port()
        return await CredentialSprayer.spray_ssh(HOST, port)
    finally:
        server.close()
        await server.wait_closed()


def test_none_auth_reported_honestly_not_as_default_password():
    findings = asyncio.run(_spray_against(_NoneAuth))
    assert len(findings) == 1
    f = findings[0]
    # NOT a fabricated "root:root" default-credential claim.
    assert f.vuln_type == "missing_authentication"
    assert "unauthenticated" in f.title.lower()
    assert "Default Credentials" not in f.title


def test_publickey_only_server_yields_no_password_finding():
    # asyncssh must not authenticate via the operator's key/agent and then
    # claim a password worked. Password auth is refused → nothing to report.
    findings = asyncio.run(_spray_against(_PublicKeyOnly))
    assert findings == []


def test_password_server_rejecting_all_sprayed_creds_is_clean():
    findings = asyncio.run(_spray_against(_PasswordOnlyAllWrong))
    assert findings == []


def test_genuine_default_credentials_still_detected():
    findings = asyncio.run(_spray_against(_RealDefaultCred))
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "default_credentials"
    assert "user:user" in f.title
    assert f.evidence["username"] == "user" and f.evidence["password"] == "user"
