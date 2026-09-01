"""Tests for the AD CS (Active Directory Certificate Services) audit
(heaven.recon.adcs_scanner). The ESC classification is pure logic exercised
against synthetic template dicts; enumeration is driven by a fake ldap3
connection so no directory is needed.
"""
from __future__ import annotations

from heaven.recon import adcs_scanner as a


# ── ESC classification ──────────────────────────────────────────────────────────

def _tmpl(**over) -> dict:
    base = {
        "name": "T", "enabled": True, "enrollee_supplies_subject": False,
        "requires_manager_approval": False, "authorized_signatures": 0,
        "ekus": [], "low_priv_can_enroll": True, "low_priv_can_write": False,
    }
    base.update(over)
    return base


def _escs(hits: list[dict]) -> set[str]:
    return {h["esc"] for h in hits}


def test_esc1_confirmed_is_critical():
    hits = a.classify_template(_tmpl(
        enrollee_supplies_subject=True, ekus=[a.EKU_CLIENT_AUTH],
        low_priv_can_enroll=True))
    assert "ESC1" in _escs(hits)
    esc1 = next(h for h in hits if h["esc"] == "ESC1")
    assert esc1["severity"] == "critical" and esc1["confirmed"] is True


def test_esc1_unconfirmed_rights_is_potential_high():
    hits = a.classify_template(_tmpl(
        enrollee_supplies_subject=True, ekus=[a.EKU_CLIENT_AUTH],
        low_priv_can_enroll=None))
    esc1 = next(h for h in hits if h["esc"] == "ESC1")
    assert esc1["severity"] == "high" and esc1["confirmed"] is False


def test_esc2_any_purpose_template():
    hits = a.classify_template(_tmpl(ekus=[a.EKU_ANY_PURPOSE]))
    assert "ESC2" in _escs(hits)


def test_esc2_no_eku_subca_template():
    hits = a.classify_template(_tmpl(ekus=[]))
    assert "ESC2" in _escs(hits)


def test_esc3_enrollment_agent_template():
    hits = a.classify_template(_tmpl(ekus=[a.EKU_CERT_REQUEST_AGENT]))
    assert "ESC3" in _escs(hits)


def test_esc4_writable_template():
    hits = a.classify_template(_tmpl(
        ekus=[a.EKU_SERVER_AUTH], requires_manager_approval=True,
        low_priv_can_write=True))
    assert _escs(hits) == {"ESC4"}


def test_manager_approval_blocks_escalation():
    hits = a.classify_template(_tmpl(
        enrollee_supplies_subject=True, ekus=[a.EKU_CLIENT_AUTH],
        requires_manager_approval=True))
    assert "ESC1" not in _escs(hits) and "ESC2" not in _escs(hits)


def test_ra_signature_blocks_escalation():
    hits = a.classify_template(_tmpl(
        enrollee_supplies_subject=True, ekus=[a.EKU_CLIENT_AUTH],
        authorized_signatures=1))
    assert "ESC1" not in _escs(hits)


def test_disabled_template_yields_nothing():
    hits = a.classify_template(_tmpl(
        enabled=False, enrollee_supplies_subject=True, ekus=[a.EKU_CLIENT_AUTH]))
    assert hits == []


def test_server_auth_only_template_is_safe():
    hits = a.classify_template(_tmpl(ekus=[a.EKU_SERVER_AUTH]))
    assert hits == []


# ── EKU helpers ─────────────────────────────────────────────────────────────────

def test_authentication_eku_detection():
    assert a._has_authentication_eku([a.EKU_CLIENT_AUTH])
    assert a._has_authentication_eku([a.EKU_SMARTCARD_LOGON])
    assert a._has_authentication_eku([])          # no EKU = unrestricted
    assert a._has_authentication_eku([a.EKU_ANY_PURPOSE])
    assert not a._has_authentication_eku([a.EKU_SERVER_AUTH])


# ── low-privileged SID detection ────────────────────────────────────────────────

def test_low_priv_sids():
    assert a._sid_is_low_priv("S-1-5-11")                      # Authenticated Users
    assert a._sid_is_low_priv("S-1-1-0")                       # Everyone
    assert a._sid_is_low_priv("S-1-5-21-1-2-3-513")            # Domain Users
    assert a._sid_is_low_priv("S-1-5-21-1-2-3-515")            # Domain Computers
    assert not a._sid_is_low_priv("S-1-5-21-1-2-3-512")        # Domain Admins
    assert not a._sid_is_low_priv("S-1-5-21-1-2-3-1104")       # a normal user RID


# ── LDAP enumeration with a fake connection ─────────────────────────────────────

class _FakeEntry:
    def __init__(self, **attrs):
        object.__setattr__(self, "_d", attrs)

    def __getattr__(self, name):
        d = object.__getattribute__(self, "_d")
        if name in d:
            return d[name]
        raise AttributeError(name)


class _FakeConn:
    def __init__(self, cas, templates):
        self._cas, self._templates = cas, templates
        self.entries = []

    def search(self, base, filt, attributes=None, **kw):
        if "pKIEnrollmentService" in filt:
            self.entries = self._cas
        elif "pKICertificateTemplate" in filt:
            self.entries = self._templates
        else:
            self.entries = []
        return True


def test_enumerate_adcs_flags_published_esc1():
    ca = _FakeEntry(cn="CORP-CA", dNSHostName="ca.corp.local",
                    certificateTemplates=["VulnUser", "WebServer"])
    vuln = _FakeEntry(**{
        "cn": "VulnUser", "name": "VulnUser",
        "msPKI-Certificate-Name-Flag": a.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        "msPKI-Enrollment-Flag": 0, "msPKI-RA-Signature": 0,
        "pKIExtendedKeyUsage": [a.EKU_CLIENT_AUTH],
        "nTSecurityDescriptor": b"",   # unparseable → potential
    })
    safe = _FakeEntry(**{
        "cn": "WebServer", "name": "WebServer",
        "msPKI-Certificate-Name-Flag": 0, "msPKI-Enrollment-Flag": 0,
        "msPKI-RA-Signature": 0, "pKIExtendedKeyUsage": [a.EKU_SERVER_AUTH],
        "nTSecurityDescriptor": b"",
    })
    conn = _FakeConn([ca], [vuln, safe])
    findings = a.enumerate_adcs(conn, "CN=Configuration,DC=corp,DC=local")
    vtypes = {f["vuln_type"] for f in findings}
    assert "adcs_ca_discovered" in vtypes
    assert "adcs_esc1" in vtypes
    # The unparseable SD means the ESC1 is reported as potential (unconfirmed).
    esc1 = next(f for f in findings if f["vuln_type"] == "adcs_esc1")
    assert esc1["evidence"]["confirmed"] is False


def test_enumerate_adcs_skips_unpublished_template():
    ca = _FakeEntry(cn="CORP-CA", dNSHostName="ca.corp.local",
                    certificateTemplates=["OnlyThis"])
    unpublished = _FakeEntry(**{
        "cn": "NotPublished", "name": "NotPublished",
        "msPKI-Certificate-Name-Flag": a.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        "msPKI-Enrollment-Flag": 0, "msPKI-RA-Signature": 0,
        "pKIExtendedKeyUsage": [a.EKU_CLIENT_AUTH], "nTSecurityDescriptor": b"",
    })
    conn = _FakeConn([ca], [unpublished])
    findings = a.enumerate_adcs(conn, "CN=Configuration,DC=corp,DC=local")
    assert not any(f["vuln_type"].startswith("adcs_esc") for f in findings)


def test_enumerate_adcs_esc8_from_web_map():
    ca = _FakeEntry(cn="CORP-CA", dNSHostName="ca.corp.local",
                    certificateTemplates=[])
    conn = _FakeConn([ca], [])
    findings = a.enumerate_adcs(
        conn, "CN=Configuration,DC=corp,DC=local",
        web_reachable_cas={"ca.corp.local": ["http://ca.corp.local/certsrv/"]})
    assert any(f["vuln_type"] == "adcs_esc8" for f in findings)


def test_enumerate_adcs_no_ca_returns_empty():
    conn = _FakeConn([], [])
    assert a.enumerate_adcs(conn, "CN=Configuration,DC=corp,DC=local") == []
