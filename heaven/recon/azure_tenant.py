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

    async def _get(session: Any, url: str) -> str:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                return await resp.text(errors="replace")
        except Exception as e:  # network error — treat as "no data", never raise
            logger.debug("azure recon GET %s failed: %s", url, e)
            return ""

    try:
        async with aiohttp.ClientSession(timeout=ct) as session:
            realm = parse_userrealm(await _get(session, userrealm_url(domain)))
            oidc = parse_openid_config(
                await _get(session, openid_config_url(domain)))
    except Exception as e:
        logger.debug("azure recon for %s failed: %s", domain, e)
        return result

    finding = tenant_finding(domain, realm, oidc)
    if finding:
        result["is_tenant"] = True
        result["tenant_id"] = oidc.get("tenant_id", "")
        result["namespace_type"] = realm.get("namespace_type", "")
        result["findings"] = [finding]
        logger.info("azure tenant confirmed for %s (tenant=%s, ns=%s)",
                    domain, oidc.get("tenant_id", "?"),
                    realm.get("namespace_type", "?"))
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
    "recon_azure_tenant", "recon_azure_tenants",
]
