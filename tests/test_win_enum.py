"""Tests for the self-contained Windows post-exploitation enum engine.

All tests drive the pure parser :func:`parse_windows_enumeration` with canned
command output — no live host, no SSH.
"""

from __future__ import annotations

import json

from heaven.postex import (
    PostExSession,
    WindowsEnumEngine,
    WinEnumResult,
    parse_windows_enumeration,
)

WHOAMI_STD = r"""
USER INFORMATION
----------------
User Name     SID
============= ==============================================
web01\svcapp  S-1-5-21-1111111111-2222222222-3333333333-1013

GROUP INFORMATION
-----------------
Group Name                             Type             SID
====================================== ================ ============
BUILTIN\Users                          Alias            S-1-5-32-545
NT AUTHORITY\SERVICE                    Well-known group S-1-5-6
Mandatory Label\Medium Mandatory Level  Label           S-1-16-8192

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                      State
============================= ================================ ========
SeImpersonatePrivilege        Impersonate a client after auth  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeBackupPrivilege             Back up files and directories    Disabled
"""

WHOAMI_ADMIN = WHOAMI_STD.replace("BUILTIN\\Users", "BUILTIN\\Administrators").replace(
    "Medium Mandatory Level", "High Mandatory Level")

SYSINFO = ("OS Name:                   Microsoft Windows Server 2019 Standard\n"
           "OS Version:                10.0.17763 N/A Build 17763\n")

SERVICES = "\n".join([
    r'GoodSvc|"C:\Program Files\App\app.exe" -k|Auto|LocalSystem',   # quoted → safe
    r"VulnSvc|C:\Program Files\Sub Dir\service.exe|Auto|LocalSystem",  # unquoted+space
    r"WritableSvc|C:\ProgramData\vendor\svc.exe|Auto|LocalSystem",    # writable loc
    r"UserSvc|C:\Windows\System32\safe.exe|Auto|NT AUTHORITY\LocalService",  # safe
])

AIE = "    AlwaysInstallElevated    REG_DWORD    0x1\n"
AUTOLOGON = ("    AutoAdminLogon    REG_SZ    1\n"
             "    DefaultUserName    REG_SZ    Administrator\n"
             "    DefaultPassword    REG_SZ    Sup3rSecret\n")
UAC_OFF = "    EnableLUA    REG_DWORD    0x0\n"
CMDKEY = "    Target: Domain:interactive=WEB01\\Administrator\n"
UNATTEND = r"UNATTEND_FILE:C:\Windows\Panther\Unattend.xml"
NETLISTEN = ("  TCP    0.0.0.0:3389   0.0.0.0:0   LISTENING   123\n"
             "  TCP    0.0.0.0:445    0.0.0.0:0   LISTENING   4\n")


def _full_outputs() -> dict[str, str]:
    return {
        "whoami": WHOAMI_STD, "sysinfo": SYSINFO, "services": SERVICES,
        "aie_hklm": AIE, "aie_hkcu": AIE, "autologon": AUTOLOGON, "uac": UAC_OFF,
        "cmdkey": CMDKEY, "unattend": UNATTEND, "net_listen": NETLISTEN,
    }


def test_facts_parsed_from_whoami_and_sysinfo():
    res = parse_windows_enumeration("web01", "svcapp", _full_outputs())
    assert res.success
    assert res.facts.username == r"web01\svcapp"
    assert res.facts.is_admin is False
    assert res.facts.integrity == "Medium"
    assert "Windows Server 2019" in res.facts.os
    assert res.facts.build.startswith("10.0.17763")
    assert res.facts.listening_ports == [445, 3389]
    # Only the *enabled* dangerous privilege is captured.
    assert res.facts.privileges == ["SeImpersonatePrivilege"]


def test_always_install_elevated_requires_both_hives():
    both = parse_windows_enumeration("h", "u", {"aie_hklm": AIE, "aie_hkcu": AIE,
                                                "whoami": WHOAMI_STD})
    titles = [v["title"] for v in both.vectors]
    assert any("AlwaysInstallElevated" in t for t in titles)
    # Only one hive set → not a finding.
    one = parse_windows_enumeration("h", "u", {"aie_hklm": AIE, "aie_hkcu": "",
                                               "whoami": WHOAMI_STD})
    assert not any("AlwaysInstallElevated" in v["title"] for v in one.vectors)


def test_unquoted_service_flagged_but_quoted_and_nospace_are_not():
    res = parse_windows_enumeration("h", "u", {"services": SERVICES,
                                               "whoami": WHOAMI_STD})
    titles = [v["title"] for v in res.vectors]
    assert "Unquoted service path: VulnSvc" in titles
    assert "Unquoted service path: GoodSvc" not in titles  # quoted
    assert "Unquoted service path: UserSvc" not in titles  # no space
    assert "Service binary in a user-writable path: WritableSvc" in titles


def test_dangerous_privilege_and_credential_vectors():
    res = parse_windows_enumeration("web01", "svcapp", _full_outputs())
    titles = [v["title"] for v in res.vectors]
    assert "Dangerous privilege held: SeImpersonatePrivilege" in titles
    assert "Autologon credential stored in the registry" in titles
    assert "UAC is disabled (EnableLUA = 0)" in titles
    assert "Unattended-install answer file present" in titles
    assert any("Saved credentials in the vault" in t for t in titles)


def test_autologon_password_value_never_leaks():
    res = parse_windows_enumeration("web01", "svcapp", _full_outputs())
    blob = json.dumps(res.to_dict()) + json.dumps(res.to_findings())
    assert "Sup3rSecret" not in blob  # the plaintext password must be redacted


def test_already_admin_skips_privesc_but_keeps_config_findings():
    res = parse_windows_enumeration("web01", "admin", {
        "whoami": WHOAMI_ADMIN, "services": SERVICES, "aie_hklm": AIE,
        "aie_hkcu": AIE, "autologon": AUTOLOGON,
    })
    assert res.facts.is_admin is True
    titles = [v["title"] for v in res.vectors]
    # No token/service escalation vectors when already elevated…
    assert not any(t.startswith("Dangerous privilege") for t in titles)
    assert not any(t.startswith("Unquoted service") for t in titles)
    # …but config-level findings (AIE, autologon creds) are still reported.
    assert any("AlwaysInstallElevated" in t for t in titles)
    assert any("Autologon" in t for t in titles)


def test_findings_are_mitre_tagged_privesc():
    res = parse_windows_enumeration("web01", "svcapp", _full_outputs())
    findings = res.to_findings()
    assert findings and all(f["vuln_type"] == "privesc" for f in findings)
    for f in findings:
        assert f["evidence"]["platform"] == "windows"
        assert "mitre" in f and f["mitre"]["techniques"]


def test_engine_authorization_gate_and_result_type():
    import asyncio
    res = asyncio.run(WindowsEnumEngine(authorized=False).enumerate("h", "u"))
    assert isinstance(res, WinEnumResult)
    assert res.success is False
    assert "not authorized" in res.error


def test_session_target_os_attribute_and_auth_gate():
    import asyncio
    s = PostExSession("h", "u", authorized=False, target_os="windows")
    assert s.target_os == "windows"
    rep = asyncio.run(s.run_full_postex())
    assert rep.success is False and "not authorized" in rep.error
