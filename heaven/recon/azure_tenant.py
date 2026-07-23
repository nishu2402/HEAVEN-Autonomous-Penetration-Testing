"""HEAVEN — credential-free Azure AD / Microsoft 365 tenant reconnaissance.

A black-box engagement against a company that runs Microsoft 365 / Entra ID can
learn a great deal about the target's identity plane **without any credentials**,
using only Microsoft's own public, unauthenticated discovery endpoints. This is
standard external-recon tradecraft (the technique behind tools like AADInternals
and o365creeper) and it maps the "Cloud identity" surface that HEAVEN's
bucket/metadata cloud checks do not touch:

  1. **User-realm discovery** — ``getuserrealm.srf`` reports whether a domain is
     backed by Entra ID at all and, if so, whether authentication is **Managed**
     (cloud-only — the org authenticates directly against Entra, so an external
     password-spray surface exists) or **Federated** (delegated to an on-prem /
     third-party STS whose URL — e.g. an ADFS host — is disclosed).

  2. **OpenID-Connect metadata** — the tenant's ``.well-known/openid-configuration``
     yields the **tenant GUID** and region, confirming the tenant exists.

Everything here is a plain HTTPS ``GET`` against a Microsoft-operated endpoint;
no target credentials are used or guessed and nothing is written. The finding is
raised at **informational** severity — it is external attack-surface recon, not
a vulnerability — and only when Microsoft *positively confirms* a tenant, so it
can never false-positive on a domain that isn't an Entra customer.

The parsers are pure and unit-tested against canned responses; the network layer
degrades gracefully without ``aiohttp`` (returns no findings, never raises).
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Optional
from urllib.parse import urlparse

from heaven.utils.logger import get_logger

logger = get_logger("recon.azure_tenant")

_LOGIN_HOST = "login.microsoftonline.com"
# Neutral, non-identifying local-part — getuserrealm keys only on the domain.
_PROBE_LOCALPART = "info"

_GUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


def is_queryable_domain(domain: str) -> bool:
    """True for a real registrable domain (has a dot, is not an IP/localhost).

    Azure-tenant discovery is meaningless for a bare IP, ``localhost`` or a
    single-label host, so those are skipped rather than queried.
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d or "." not in d:
        return False
    if d in ("localhost", "localhost.localdomain"):
        return False
    try:
        ipaddress.ip_address(d)
        return False  # it's an IP literal, not a domain
    except ValueError:
        return True


def userrealm_url(domain: str) -> str:
    return (f"https://{_LOGIN_HOST}/getuserrealm.srf"
            f"?login={_PROBE_LOCALPART}@{domain}&json=1")


def openid_config_url(domain: str) -> str:
    return f"https://{_LOGIN_HOST}/{domain}/v2.0/.well-known/openid-configuration"


def parse_userrealm(text: str) -> dict[str, Any]:
    """Parse a ``getuserrealm.srf?...&json=1`` body.

    Returns ``{}`` when the body isn't JSON or the domain is not an Entra tenant
    (``NameSpaceType`` of ``Unknown``/absent). Otherwise returns the normalized
    realm facts, always including ``is_tenant: True``.
    """
    try:
        data = json.loads(text or "")
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    ns = str(data.get("NameSpaceType", "")).strip()
    # "Managed" / "Federated" prove an Entra tenant; "Unknown" means Microsoft
    # doesn't recognize the domain — not a tenant, so no finding.
    if ns not in ("Managed", "Federated"):
        return {}
    out: dict[str, Any] = {
        "is_tenant": True,
        "namespace_type": ns,
        "domain_name": str(data.get("DomainName", "") or ""),
        "cloud_instance": str(data.get("CloudInstanceName", "") or ""),
        "is_federated": ns == "Federated",
    }
    brand = str(data.get("FederationBrandName", "") or "")
    auth_url = str(data.get("AuthURL", "") or "")
    if brand:
        out["federation_brand"] = brand
    if auth_url:
        out["federation_auth_url"] = auth_url
    return out


def parse_openid_config(text: str) -> dict[str, Any]:
    """Parse a tenant's OpenID-Connect metadata for the tenant GUID + region.

    Returns ``{}`` when the body isn't JSON, carries an AAD error (e.g. the
    ``AADSTS90002`` "tenant not found"), or contains no discernible tenant GUID.
    """
    try:
        data = json.loads(text or "")
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict) or data.get("error"):
        return {}
    issuer = str(data.get("issuer", "") or "")
    token_ep = str(data.get("token_endpoint", "") or "")
    auth_ep = str(data.get("authorization_endpoint", "") or "")
    m = (_GUID_RE.search(issuer) or _GUID_RE.search(token_ep)
         or _GUID_RE.search(auth_ep))
    if not m:
        return {}
    out: dict[str, Any] = {"tenant_id": m.group(0).lower(), "issuer": issuer}
    region = str(data.get("tenant_region_scope", "") or "")
    if region:
        out["tenant_region"] = region
    return out


# ── Federation / ADFS reachability (only for a *federated* tenant) ────────────
#
# When ``getuserrealm`` reports ``NameSpaceType = Federated`` it also discloses
# the ``AuthURL`` of the target's Security Token Service (typically an on-prem
# ADFS host). Two further *read-only* GETs against that STS turn "the domain is
# federated" into concrete, actionable posture:
#
#   • ``FederationMetadata.xml`` — public-by-design WS-Fed/SAML metadata that
#     names the STS entity id, its endpoints and the token-signing certificate;
#     confirms an internet-facing on-prem identity component (a pivot / phishing-
#     infrastructure target). Reported at INFO — recon, not a flaw.
#   • ``/adfs/ls/idpinitiatedsignon.aspx`` — the ADFS IdP-initiated sign-on page.
#     Microsoft recommends disabling it; when reachable it is an unauthenticated
#     password-spray target and a username-enumeration oracle. Reported at MEDIUM.
#
# Both fire only from positive evidence (metadata actually parsed / the sign-on
# page actually served with ADFS markers), so a hardened or non-ADFS STS yields
# nothing rather than a guess.


def _host_of(url: str) -> str:
    """Lowercase hostname from a URL (or bare host); ``''`` when none."""
    try:
        ref = url if "://" in (url or "") else f"//{url}"
        return (urlparse(ref, scheme="https").hostname or "").lower()
    except ValueError:
        return ""


def _federation_base(auth_url: str) -> str:
    """``https://<sts-host>`` for a realm AuthURL, or ``''`` if not a real host."""
    host = _host_of(auth_url)
    if not host or "." not in host or host in ("localhost", "localhost.localdomain"):
        return ""
    try:
        ipaddress.ip_address(host)
        return ""  # an IP literal is never a federation STS worth probing
    except ValueError:
        return f"https://{host}"


def federation_metadata_url(auth_url: str) -> str:
    base = _federation_base(auth_url)
    return f"{base}/FederationMetadata/2007-06/FederationMetadata.xml" if base else ""


def idpinit_signon_url(auth_url: str) -> str:
    base = _federation_base(auth_url)
    return f"{base}/adfs/ls/idpinitiatedsignon.aspx" if base else ""


def parse_federation_metadata(text: str) -> dict[str, Any]:
    """Parse a WS-Federation / SAML ``FederationMetadata.xml`` document.

    Returns ``{}`` unless the body is genuine federation metadata (an
    ``EntityDescriptor`` carrying an ``entityID``). Otherwise returns the
    disclosed STS identity: entity id and host, whether it fingerprints as ADFS,
    whether a token-signing certificate is embedded, and the advertised roles.
    """
    if not text or "EntityDescriptor" not in text:
        return {}
    m = re.search(r'entityID="([^"]+)"', text)
    if not m:
        return {}
    entity_id = m.group(1).strip()
    low = text.lower()
    out: dict[str, Any] = {
        "entity_id": entity_id,
        "is_adfs": ("/adfs/services/trust" in low or "/adfs/ls" in low
                    or "http://docs.oasis-open.org/wsfed/federation/200706" in low),
        "token_signing_cert": "x509certificate" in low,
    }
    host = _host_of(entity_id)
    if host:
        out["sts_host"] = host
    roles = [r for r in ("IDPSSODescriptor", "SPSSODescriptor", "RoleDescriptor")
             if r in text]
    if roles:
        out["roles"] = roles
    return out


def detect_idpinit_signon(status: int, html: str) -> bool:
    """True when an HTTP 200 body is an ADFS IdP-initiated sign-on form.

    Requires two independent ADFS-specific markers so a generic login page can't
    be mistaken for one: the ``userNameInput`` / ``passwordInput`` element ids,
    the ``idpinitiatedsignon`` reference, and the ``/adfs/portal/`` asset path /
    ``MSISConfig`` bootstrap are each unique to the ADFS sign-in page.
    """
    if status != 200 or not html:
        return False
    low = html.lower()
    markers = 0
    if "usernameinput" in low:
        markers += 1
    if "passwordinput" in low:
        markers += 1
    if "idpinitiatedsignon" in low:
        markers += 1
    if "/adfs/portal/" in low or "msisconfig" in low:
        markers += 1
    return markers >= 2


def federation_findings(domain: str, realm: dict[str, Any],
                        meta: dict[str, Any],
                        idpinit_enabled: bool) -> list[dict[str, Any]]:
    """Findings for a federated tenant's on-prem STS (read-only, confirmed only).

    Built purely from positive evidence — ``idpinit_enabled`` proves the sign-on
    page is reachable, and ``meta`` is non-empty only when real metadata parsed.
    """
    out: list[dict[str, Any]] = []
    auth_url = str(realm.get("federation_auth_url", "") or "")
    sts_host = str(meta.get("sts_host") or _host_of(auth_url) or "")
    is_adfs = bool(meta.get("is_adfs") or "/adfs/" in auth_url.lower())
    tech = "ADFS" if is_adfs else "federation STS"

    if idpinit_enabled:
        out.append({
            "target": sts_host or domain,
            "vuln_type": "adfs_idp_signon_enabled",
            "title": ("ADFS IdP-initiated sign-on page enabled"
                      + (f" on {sts_host}" if sts_host else "")),
            "severity": "medium",
            "confidence": 0.85,
            "description": (
                f"The federation service for {domain} exposes the ADFS "
                f"IdP-initiated sign-on page (/adfs/ls/idpinitiatedsignon.aspx) "
                f"to the internet. It serves an unauthenticated username/password "
                f"form that Microsoft recommends disabling: it is a ready-made "
                f"password-spray target and a username-enumeration oracle, since "
                f"valid and invalid users elicit different responses."),
            "remediation": (
                "Disable the IdP-initiated sign-on page — "
                "`Set-AdfsProperties -EnableIdpInitiatedSignonPage $false` — "
                "publish ADFS only through the Web Application Proxy, and enforce "
                "MFA plus extranet smart-lockout to blunt password spraying."),
            "evidence": {
                "source": "recon.azure_tenant",
                "domain": domain,
                "sts_host": sts_host,
                "idpinit_url": idpinit_signon_url(auth_url),
                "federation_auth_url": auth_url,
            },
        })

    if meta.get("entity_id"):
        ev: dict[str, Any] = {
            "source": "recon.azure_tenant",
            "domain": domain,
            "federation_metadata_url": federation_metadata_url(auth_url),
            "entity_id": meta["entity_id"],
        }
        for k in ("sts_host", "is_adfs", "token_signing_cert", "roles"):
            if meta.get(k) not in (None, "", []):
                ev[k] = meta[k]
        out.append({
            "target": sts_host or domain,
            "vuln_type": "federation_sts_exposed",
            "title": (f"On-prem federation STS disclosed for {domain}"
                      + (f" ({sts_host})" if sts_host else "")),
            "severity": "info",
            "confidence": 0.9,
            "description": (
                f"{domain} federates authentication to an on-prem / third-party "
                f"{tech}. Its federation metadata is publicly reachable and "
                f"discloses the STS entity id, endpoint URLs"
                + (" and the token-signing certificate"
                   if meta.get("token_signing_cert") else "")
                + ". This maps an internet-facing identity component as a pivot "
                "and phishing-infrastructure target. The metadata is public by "
                "design — reported as attack-surface recon, not a flaw."),
            "remediation": (
                "Where the relying-party set is known, restrict access to the "
                "ADFS/STS federation endpoints; keep the STS fully patched and "
                "monitored; and consider migrating to Entra-managed "
                "authentication to shrink the on-prem attack surface."),
            "evidence": ev,
        })
    return out


def tenant_finding(domain: str, realm: dict[str, Any],
                   oidc: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Build the informational recon finding, or ``None`` if unconfirmed.

    A finding is emitted only when Microsoft positively confirmed the tenant —
    either a realm namespace of Managed/Federated or a resolved tenant GUID.
    """
    if not (realm.get("is_tenant") or oidc.get("tenant_id")):
        return None
    ns = realm.get("namespace_type", "")
    tenant_id = oidc.get("tenant_id", "")
    bits = ["Microsoft 365 / Entra ID tenant confirmed for the target domain"]
    if ns == "Managed":
        bits.append("cloud-managed authentication (external sign-in surface)")
    elif ns == "Federated":
        fed = realm.get("federation_auth_url") or realm.get("federation_brand")
        bits.append(f"federated authentication{f' via {fed}' if fed else ''}")
    evidence: dict[str, Any] = {
        "source": "recon.azure_tenant",
        "domain": domain,
        "userrealm_url": userrealm_url(domain),
        "openid_config_url": openid_config_url(domain),
    }
    for k in ("namespace_type", "cloud_instance", "is_federated",
              "federation_brand", "federation_auth_url"):
        if realm.get(k) not in (None, ""):
            evidence[k] = realm[k]
    for k in ("tenant_id", "tenant_region", "issuer"):
        if oidc.get(k):
            evidence[k] = oidc[k]
    return {
        "target": domain,
        "vuln_type": "azure_ad_tenant_exposed",
        "title": (f"Azure AD / M365 tenant exposed via public discovery"
                  f"{f' (tenant {tenant_id})' if tenant_id else ''}"),
        "severity": "info",
        "confidence": 0.9,
        "description": " — ".join(bits) + (
            ". Microsoft's unauthenticated discovery endpoints reveal the "
            "tenant's existence, authentication model and identifiers to any "
            "external party, seeding targeted phishing and password-spray "
            "campaigns. This is attack-surface intelligence, not a flaw in the "
            "target's own systems."),
        "remediation": (
            "Tenant discovery cannot be disabled (it is a function of Microsoft's "
            "identity platform), so treat the external sign-in surface as exposed: "
            "enforce phishing-resistant MFA and Conditional Access, enable "
            "password-spray/smart-lockout protection, and monitor Entra sign-in "
            "logs for spraying against the confirmed tenant."),
        "evidence": evidence,
    }


async def recon_azure_tenant(domain: str, timeout: float = 8.0) -> dict[str, Any]:
    """Query Microsoft's public discovery endpoints for one domain (read-only)."""
    result: dict[str, Any] = {"domain": domain, "is_tenant": False,
                              "findings": []}
    if not is_queryable_domain(domain):
        return result
    try:
        import aiohttp  # type: ignore[import-not-found]
    except ImportError:
        result["error"] = "aiohttp not installed"
        return result

    ct = aiohttp.ClientTimeout(total=timeout)

    async def _get_status(session: Any, url: str) -> tuple[int, str]:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                return resp.status, await resp.text(errors="replace")
        except Exception as e:  # network error — treat as "no data", never raise
            logger.debug("azure recon GET %s failed: %s", url, e)
            return 0, ""

    async def _get(session: Any, url: str) -> str:
        return (await _get_status(session, url))[1]

    fed_findings: list[dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession(timeout=ct) as session:
            realm = parse_userrealm(await _get(session, userrealm_url(domain)))
            oidc = parse_openid_config(
                await _get(session, openid_config_url(domain)))

            # For a *federated* realm, probe the disclosed STS (read-only). The
            # STS is a different host from Microsoft's login endpoint; the same
            # session handles both fine.
            auth_url = str(realm.get("federation_auth_url", "") or "")
            if realm.get("is_federated") and _federation_base(auth_url):
                meta = parse_federation_metadata(
                    await _get(session, federation_metadata_url(auth_url)))
                status, body = await _get_status(
                    session, idpinit_signon_url(auth_url))
                fed_findings = federation_findings(
                    domain, realm, meta, detect_idpinit_signon(status, body))
    except Exception as e:
        logger.debug("azure recon for %s failed: %s", domain, e)
        return result

    findings: list[dict[str, Any]] = []
    finding = tenant_finding(domain, realm, oidc)
    if finding:
        result["is_tenant"] = True
        result["tenant_id"] = oidc.get("tenant_id", "")
        result["namespace_type"] = realm.get("namespace_type", "")
        findings.append(finding)
        logger.info("azure tenant confirmed for %s (tenant=%s, ns=%s)",
                    domain, oidc.get("tenant_id", "?"),
                    realm.get("namespace_type", "?"))
    if fed_findings:
        findings.extend(fed_findings)
        result["federation_findings"] = len(fed_findings)
        logger.info("azure federation recon for %s produced %d finding(s)",
                    domain, len(fed_findings))
    result["findings"] = findings
    return result


async def recon_azure_tenants(domains: list[str]) -> dict[str, Any]:
    """Orchestrator entry — dedup queryable domains, probe each, aggregate."""
    import asyncio

    seen: list[str] = []
    for d in domains or []:
        dl = (d or "").strip().lower().rstrip(".")
        if is_queryable_domain(dl) and dl not in seen:
            seen.append(dl)
    if not seen:
        return {"domains_checked": 0, "tenants_found": 0, "findings": []}

    results = await asyncio.gather(*[recon_azure_tenant(d) for d in seen],
                                   return_exceptions=True)
    findings: list[dict[str, Any]] = []
    tenants = 0
    for r in results:
        if isinstance(r, dict):
            findings.extend(r.get("findings", []))
            if r.get("is_tenant"):
                tenants += 1
    return {"domains_checked": len(seen), "tenants_found": tenants,
            "findings": findings}


__all__ = [
    "is_queryable_domain", "userrealm_url", "openid_config_url",
    "parse_userrealm", "parse_openid_config", "tenant_finding",
    "federation_metadata_url", "idpinit_signon_url",
    "parse_federation_metadata", "detect_idpinit_signon", "federation_findings",
    "recon_azure_tenant", "recon_azure_tenants",
]
