"""P2 — Authorized credentialed network testing (SMB / WinRM).

HEAVEN's credential-reuse validator already covered SSH + HTTP. P2 adds real
SMB (impacket) and WinRM (pywinrm, optional) handlers so a discovered credential
is reused across Windows services too. Everything is authorization-gated and
tests *known* credentials — never guesses.

The blocking impacket / pywinrm calls are exercised through mock modules so the
suite stays offline and deterministic.
"""
from __future__ import annotations

import asyncio
import sys
import types

from heaven.postex.cred_validator import CredentialValidator


# ── mock impacket ────────────────────────────────────────────────────────────

def _install_mock_impacket(monkeypatch, *, valid: tuple[str, str] | None):
    class SessionError(Exception):
        pass

    class SMBConnection:
        def __init__(self, remoteName, remoteHost, sess_port=445, timeout=5):
            self.host = remoteHost
            self.port = sess_port

        def login(self, user, pwd, domain=""):
            if valid is None or (user, pwd) != valid:
                raise SessionError("STATUS_LOGON_FAILURE")

        def listShares(self):  # noqa: N802 — mirrors impacket's API name
            return [{"shi1_netname": "ADMIN$\x00"}, {"shi1_netname": "C$\x00"}]

        def logoff(self):
            return None

    mod = types.ModuleType("impacket.smbconnection")
    mod.SMBConnection = SMBConnection
    mod.SessionError = SessionError
    pkg = types.ModuleType("impacket")
    pkg.smbconnection = mod
    monkeypatch.setitem(sys.modules, "impacket", pkg)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", mod)


def _validate(creds, targets):
    v = CredentialValidator(authorized=True, per_attempt_timeout=2.0)
    return asyncio.run(v.validate(creds, targets))


def test_smb_valid_credential_is_a_hit(monkeypatch):
    _install_mock_impacket(monkeypatch, valid=("admin", "Passw0rd!"))
    summary = _validate([("admin", "Passw0rd!")], [("10.0.0.5", 445, "smb")])
    assert len(summary.hits) == 1
    hit = summary.hits[0]
    assert hit.service == "smb" and hit.username == "admin"
    assert "ADMIN$" in hit.evidence["shares"]


def test_smb_wrong_password_no_hit(monkeypatch):
    _install_mock_impacket(monkeypatch, valid=("admin", "Passw0rd!"))
    summary = _validate([("admin", "wrong")], [("10.0.0.5", 445, "smb")])
    assert summary.hits == []
    assert summary.attempted == 1


def test_smb_domain_credential_is_split(monkeypatch):
    # DOMAIN\user must authenticate as user in DOMAIN.
    _install_mock_impacket(monkeypatch, valid=("svc", "s3cr3t"))
    summary = _validate([("CORP\\svc", "s3cr3t")], [("dc01", 445, "smb")])
    assert len(summary.hits) == 1
    assert summary.hits[0].evidence["domain"] == "CORP"


# ── WinRM (optional dep) ─────────────────────────────────────────────────────

def _install_mock_winrm(monkeypatch, *, valid: tuple[str, str] | None):
    class _Result:
        def __init__(self, ok):
            self.status_code = 0 if ok else 1
            self.std_out = b"corp\\svc\r\n" if ok else b""
            self.std_err = b""

    class Session:
        def __init__(self, endpoint, auth=None, transport="ntlm",
                     server_cert_validation="ignore"):
            self._ok = auth == valid

        def run_cmd(self, cmd):
            return _Result(self._ok)

    mod = types.ModuleType("winrm")
    mod.Session = Session
    monkeypatch.setitem(sys.modules, "winrm", mod)


def test_winrm_valid_credential_is_a_hit(monkeypatch):
    _install_mock_winrm(monkeypatch, valid=("svc", "s3cr3t"))
    summary = _validate([("svc", "s3cr3t")], [("10.0.0.9", 5985, "winrm")])
    assert len(summary.hits) == 1
    assert summary.hits[0].service == "winrm"
    assert "corp" in summary.hits[0].evidence["whoami"].lower()


def test_winrm_wrong_password_no_hit(monkeypatch):
    _install_mock_winrm(monkeypatch, valid=("svc", "s3cr3t"))
    summary = _validate([("svc", "nope")], [("10.0.0.9", 5985, "winrm")])
    assert summary.hits == []


def test_winrm_missing_library_is_recorded_not_faked(monkeypatch):
    # No pywinrm installed → an honest error, never a silent/fabricated pass.
    monkeypatch.setitem(sys.modules, "winrm", None)
    summary = _validate([("svc", "s3cr3t")], [("10.0.0.9", 5985, "winrm")])
    assert summary.hits == []
    assert any("pywinrm" in e for e in summary.errors)


# ── dispatch + authorization ─────────────────────────────────────────────────

def test_unauthorized_validator_refuses():
    v = CredentialValidator(authorized=False)
    summary = asyncio.run(v.validate([("a", "b")], [("h", 445, "smb")]))
    assert summary.hits == [] and any("not authorized" in e for e in summary.errors)


def test_unknown_service_recorded():
    summary = _validate([("a", "b")], [("h", 9999, "gopher")])
    assert any("unsupported service" in e for e in summary.errors)


# ── LDAP simple bind (ldap3) ─────────────────────────────────────────────────

def _install_mock_ldap3(monkeypatch, *, valid: tuple[str, str] | None):
    class _Std:
        def __init__(self, ok):
            self._ok = ok

        def who_am_i(self):  # noqa: N802 — mirrors ldap3's extend API name
            return "u:CORP\\svc" if self._ok else None

    class _Extend:
        def __init__(self, ok):
            self.standard = _Std(ok)

    class Server:
        def __init__(self, host, port=389, use_ssl=False, get_info=None,
                     connect_timeout=5):
            self.host = host

    class Connection:
        def __init__(self, server, user=None, password=None, authentication=None,
                     auto_bind=False, receive_timeout=5):
            self._ok = valid is not None and (user, password) == valid
            self.extend = _Extend(self._ok)

        def bind(self):
            return self._ok

        def unbind(self):
            return None

    mod = types.ModuleType("ldap3")
    mod.Server = Server
    mod.Connection = Connection
    mod.SIMPLE = "SIMPLE"
    mod.NONE = "NO_INFO"
    monkeypatch.setitem(sys.modules, "ldap3", mod)


def test_ldap_valid_credential_is_a_hit(monkeypatch):
    _install_mock_ldap3(monkeypatch, valid=("CORP\\svc", "s3cr3t"))
    summary = _validate([("CORP\\svc", "s3cr3t")], [("dc01", 389, "ldap")])
    assert len(summary.hits) == 1
    hit = summary.hits[0]
    assert hit.service == "ldap"
    assert "CORP" in hit.evidence["bound_as"]


def test_ldap_wrong_password_no_hit(monkeypatch):
    _install_mock_ldap3(monkeypatch, valid=("CORP\\svc", "s3cr3t"))
    summary = _validate([("CORP\\svc", "wrong")], [("dc01", 389, "ldap")])
    assert summary.hits == []
    assert summary.attempted == 1


def test_ldap_empty_password_never_overclaims(monkeypatch):
    # RFC 4513 unauthenticated-bind guard: an empty password must never count as
    # a success even if the mock server would "bind".
    _install_mock_ldap3(monkeypatch, valid=("CORP\\svc", ""))
    summary = _validate([("CORP\\svc", "")], [("dc01", 636, "ldaps")])
    assert summary.hits == []


# ── Kerberos AS-REQ pre-auth (impacket) ──────────────────────────────────────

def _install_mock_kerberos(monkeypatch, *, valid: tuple[str, str] | None):
    # impacket is a base dependency, so reuse its real KerberosError / constants
    # and only fake the network call `getKerberosTGT`.
    import impacket.krb5.kerberosv5 as k5
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import KerberosError

    def fake_getKerberosTGT(clientName, password, domain, lmhash, nthash,  # noqa: N802,N803
                            aesKey="", kdcHost=None, **kw):
        user = (clientName.components[0]
                if getattr(clientName, "components", None) else str(clientName))
        if valid is not None and (user, password) == valid:
            return (b"TGT", None, None, None)
        raise KerberosError(error=constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value)

    monkeypatch.setattr(k5, "getKerberosTGT", fake_getKerberosTGT)


def test_kerberos_valid_credential_is_a_hit(monkeypatch):
    _install_mock_kerberos(monkeypatch, valid=("svc", "s3cr3t"))
    summary = _validate([("CORP\\svc", "s3cr3t")], [("dc01", 88, "kerberos")])
    assert len(summary.hits) == 1
    hit = summary.hits[0]
    assert hit.service == "kerberos"
    assert hit.evidence["realm"] == "CORP" and hit.evidence["principal"] == "svc"


def test_kerberos_wrong_password_no_hit(monkeypatch):
    _install_mock_kerberos(monkeypatch, valid=("svc", "s3cr3t"))
    summary = _validate([("CORP\\svc", "wrong")], [("dc01", 88, "kerberos")])
    assert summary.hits == []
    assert summary.attempted == 1


def test_kerberos_without_realm_is_recorded_not_guessed(monkeypatch):
    # No domain in the username → we can't know the realm, so record an honest
    # error rather than silently pass or guess.
    _install_mock_kerberos(monkeypatch, valid=("svc", "s3cr3t"))
    summary = _validate([("svc", "s3cr3t")], [("dc01", 88, "kerberos")])
    assert summary.hits == []
    assert any("realm" in e for e in summary.errors)
