"""Active Directory scanner depth — the fixes that make an AD scan of a bare DC
IP produce real findings instead of skipping: domain auto-derivation, pre-auth
SMB findings (signing/relay, SMBv1, null session), machine-account-quota, and
taxonomy on AD findings."""
from __future__ import annotations

import asyncio

from heaven.recon.ad_scanner import (
    ADScanner, ADAttackType, derive_domain_from_dn, scan_active_directory,
)
from heaven.devsecops.vuln_kb import enrich_finding


def test_derive_domain_from_dn():
    assert derive_domain_from_dn("DC=corp,DC=example,DC=com") == "corp.example.com"
    assert derive_domain_from_dn("dc=lab,dc=local") == "lab.local"
    assert derive_domain_from_dn("") == ""
    assert derive_domain_from_dn("CN=x,OU=y") == ""


def test_empty_domain_does_not_build_bogus_base_dn():
    s = ADScanner(domain="", dc_host="10.0.0.1")
    assert s.domain_dn == ""     # was "DC=" before the fix


def test_smb_findings_from_synthetic_enum():
    s = ADScanner(domain="lab.local", dc_host="10.0.0.10")
    s._smb_findings({
        "signing_required": False,        # → relay exposure (high)
        "smbv1": True,                    # → EternalBlue exposure (high)
        "null_session": True,
        "shares": ["ADMIN$", "C$", "SYSVOL"],   # → null-session enum (medium)
        "server_os": "Windows Server 2019",
    })
    types = {f.attack_type for f in s._findings}
    assert ADAttackType.SMB_SIGNING_DISABLED in types
    assert ADAttackType.SMBV1_ENABLED in types
    assert ADAttackType.NULL_SESSION in types
    # SMB signing REQUIRED (True) must NOT raise the relay finding
    s2 = ADScanner(domain="lab.local", dc_host="10.0.0.11")
    s2._smb_findings({"signing_required": True, "smbv1": False})
    assert ADAttackType.SMB_SIGNING_DISABLED not in {f.attack_type for f in s2._findings}


def test_ntlmv1_finding_only_on_positive_signal():
    # ntlmv1=True (server cleared extended session security) → finding.
    s = ADScanner(domain="lab.local", dc_host="10.0.0.10")
    s._smb_findings({"ntlmv1": True})
    ntlm = [f for f in s._findings if f.attack_type == ADAttackType.NTLMV1_SUPPORTED]
    assert len(ntlm) == 1
    assert ntlm[0].severity == "high"
    assert ntlm[0].evidence.get("extended_session_security") is False

    # ntlmv1 False (ESS enforced) or None (undetermined) → NO finding, no FP.
    for val in (False, None):
        s2 = ADScanner(domain="lab.local", dc_host="10.0.0.11")
        s2._smb_findings({"ntlmv1": val})
        assert ADAttackType.NTLMV1_SUPPORTED not in {f.attack_type for f in s2._findings}


def test_detect_ntlmv1_reads_server_challenge_ess_bit(monkeypatch):
    # Prove the ESS-bit interpretation against a captured challenge, without a
    # live host: patch impacket so login() drives NTLMAuthChallenge with a
    # server challenge whose ESS flag is cleared (→ NTLMv1 negotiated).
    from impacket import ntlm as _ntlm

    class _FakeConn:
        def __init__(self, *a, **k):
            pass

        def login(self, *a, **k):
            # Impacket parses the server's type-2 here; emulate that call.
            _ntlm.NTLMAuthChallenge()  # goes through whatever is currently bound
            raise RuntimeError("STATUS_LOGON_FAILURE (expected)")

        def close(self):
            pass

    import heaven.recon.ad_scanner as adm
    monkeypatch.setattr("impacket.smbconnection.SMBConnection", _FakeConn)

    # ESS cleared → NTLMv1.
    def _mk(flags):
        def _factory(*a, **k):
            return {"flags": flags}
        monkeypatch.setattr(_ntlm, "NTLMAuthChallenge", _factory)
        return adm.ADScanner._detect_ntlmv1("10.0.0.10")

    ess = _ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    assert _mk(0x00008201) is True            # ESS bit not set → NTLMv1
    assert _mk(0x00008201 | ess) is False     # ESS enforced → not NTLMv1


def test_ad_finding_dict_mirrors_vuln_type_and_enriches():
    s = ADScanner(domain="lab.local", dc_host="10.0.0.10")
    s._smb_findings({"signing_required": False})
    d = s._findings[0].to_dict()
    # vuln_type mirrors attack_type so the store + KB taxonomy key on it
    assert d["vuln_type"] == d["attack_type"] == "smb_signing_not_required"
    e = enrich_finding(d)
    assert e.get("cwe") and e.get("owasp") and e.get("cvss_vector")


def test_scan_skips_only_when_no_dc_and_no_domain():
    async def go():
        res = await scan_active_directory()   # nothing supplied
        assert res.get("skipped") is True
    asyncio.run(go())


def test_scan_with_dc_host_does_not_skip_offline():
    # Against an unreachable DC it must still return a real summary (not a skip),
    # because the pre-auth layer runs regardless of an authenticated bind.
    async def go():
        res = await asyncio.wait_for(
            scan_active_directory(dc_host="127.0.0.1"), timeout=40)
        assert res.get("skipped") is not True
        assert "findings" in res and "domain_info" in res
    asyncio.run(go())


def test_summary_exposes_domain_context_fields():
    s = ADScanner(domain="lab.local", dc_host="dc01")
    s._domain_info.forest = "lab.local"
    s._domain_info.functional_level = "Windows Server 2016+"
    out = s.summary()
    assert out["domain_info"]["forest"] == "lab.local"
    assert out["domain_info"]["functional_level"] == "Windows Server 2016+"
