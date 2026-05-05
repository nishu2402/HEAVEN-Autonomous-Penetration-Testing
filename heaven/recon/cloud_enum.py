"""
HEAVEN — Cloud Asset Enumeration
API-driven modules to enumerate AWS, GCP, and Azure assets.
Detects public exposure, overpermissioned IAM, and misconfigurations.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("recon.cloud")


@dataclass
class CloudAsset:
    provider: str
    asset_type: str
    arn_or_id: str
    name: str = ""
    region: str = ""
    public: bool = False
    metadata: dict = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)


async def enumerate_aws() -> list[CloudAsset]:
    """Enumerate AWS assets using boto3."""
    assets: list[CloudAsset] = []
    try:
        import boto3
        loop = asyncio.get_running_loop()

        # EC2 instances
        async def _enum_ec2():
            ec2 = boto3.client("ec2")
            result = await loop.run_in_executor(None, lambda: ec2.describe_instances())
            for res in result.get("Reservations", []):
                for inst in res.get("Instances", []):
                    a = CloudAsset(
                        provider="aws", asset_type="ec2",
                        arn_or_id=inst["InstanceId"],
                        name=next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), ""),
                        region=inst.get("Placement", {}).get("AvailabilityZone", ""),
                        public=bool(inst.get("PublicIpAddress")),
                        metadata={"ip": inst.get("PublicIpAddress"), "state": inst["State"]["Name"],
                                  "type": inst["InstanceType"], "vpc": inst.get("VpcId")},
                    )
                    if a.public:
                        a.issues.append("Instance has public IP address")
                    assets.append(a)

        # S3 buckets
        async def _enum_s3():
            s3 = boto3.client("s3")
            buckets = await loop.run_in_executor(None, lambda: s3.list_buckets())
            for b in buckets.get("Buckets", []):
                name = b["Name"]
                a = CloudAsset(provider="aws", asset_type="s3", arn_or_id=f"arn:aws:s3:::{name}", name=name)
                try:
                    acl = await loop.run_in_executor(None, lambda: s3.get_bucket_acl(Bucket=name))
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                            a.public = True
                            a.issues.append(f"Public ACL: {grant.get('Permission')}")
                except Exception:
                    pass
                assets.append(a)

        # IAM analysis
        async def _enum_iam():
            iam = boto3.client("iam")
            users = await loop.run_in_executor(None, lambda: iam.list_users())
            for u in users.get("Users", []):
                a = CloudAsset(provider="aws", asset_type="iam_user", arn_or_id=u["Arn"], name=u["UserName"])
                try:
                    policies = await loop.run_in_executor(
                        None, lambda: iam.list_attached_user_policies(UserName=u["UserName"]))
                    for p in policies.get("AttachedPolicies", []):
                        if "AdministratorAccess" in p["PolicyName"]:
                            a.issues.append("Has AdministratorAccess policy")
                        if "FullAccess" in p["PolicyName"]:
                            a.issues.append(f"Has full access: {p['PolicyName']}")
                    a.metadata["policies"] = [p["PolicyName"] for p in policies.get("AttachedPolicies", [])]
                except Exception:
                    pass
                assets.append(a)

        await asyncio.gather(_enum_ec2(), _enum_s3(), _enum_iam(), return_exceptions=True)

    except ImportError:
        logger.warning("boto3 not available — skipping AWS enumeration")
    except Exception as e:
        logger.error(f"AWS enumeration error: {e}")

    return assets


async def enumerate_gcp() -> list[CloudAsset]:
    """Enumerate GCP assets (requires google-cloud SDKs)."""
    assets: list[CloudAsset] = []
    try:
        from google.cloud import compute_v1, storage  # noqa: F401
        loop = asyncio.get_running_loop()

        # GCP Compute instances
        client = compute_v1.InstancesClient()
        agg = await loop.run_in_executor(None, lambda: client.aggregated_list(project="-"))
        for zone, response in agg:
            for inst in response.instances or []:
                public_ip = ""
                for iface in inst.network_interfaces or []:
                    for ac in iface.access_configs or []:
                        if ac.nat_i_p:
                            public_ip = ac.nat_i_p
                a = CloudAsset(
                    provider="gcp", asset_type="compute", arn_or_id=str(inst.id),
                    name=inst.name, region=zone, public=bool(public_ip),
                    metadata={"ip": public_ip, "status": inst.status, "machine_type": inst.machine_type},
                )
                assets.append(a)

    except ImportError:
        logger.info("GCP SDKs not available — skipping GCP enumeration")
    except Exception as e:
        logger.error(f"GCP enumeration error: {e}")

    return assets


async def enumerate_azure() -> list[CloudAsset]:
    """Enumerate Azure assets (requires azure-mgmt SDKs)."""
    assets: list[CloudAsset] = []
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.resource import SubscriptionClient

        credential = DefaultAzureCredential()
        sub_client = SubscriptionClient(credential)
        loop = asyncio.get_running_loop()

        subs = await loop.run_in_executor(None, lambda: list(sub_client.subscriptions.list()))
        for sub in subs:
            compute = ComputeManagementClient(credential, sub.subscription_id)
            vms = await loop.run_in_executor(None, lambda: list(compute.virtual_machines.list_all()))
            for vm in vms:
                a = CloudAsset(
                    provider="azure", asset_type="vm", arn_or_id=vm.id,
                    name=vm.name, region=vm.location,
                    metadata={"size": vm.hardware_profile.vm_size, "os": vm.storage_profile.os_disk.os_type},
                )
                assets.append(a)

    except ImportError:
        logger.info("Azure SDKs not available — skipping Azure enumeration")
    except Exception as e:
        logger.error(f"Azure enumeration error: {e}")

    return assets


async def enumerate_cloud(providers: list[str] = None, **kwargs) -> dict[str, Any]:
    """Main entry point for cloud enumeration (called by orchestrator)."""
    if not providers:
        logger.info("No cloud providers specified — skipping cloud enumeration")
        return {"assets": [], "total": 0}

    all_assets: list[CloudAsset] = []
    tasks = []

    provider_map = {"aws": enumerate_aws, "gcp": enumerate_gcp, "azure": enumerate_azure}
    for p in providers:
        func = provider_map.get(p.lower())
        if func:
            tasks.append(func())
        else:
            logger.warning(f"Unknown cloud provider: {p}")

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            all_assets.extend(r)
        elif isinstance(r, Exception):
            logger.error(f"Cloud enum error: {r}")

    public = sum(1 for a in all_assets if a.public)
    issues = sum(len(a.issues) for a in all_assets)
    logger.info(f"Cloud enum: {len(all_assets)} assets, {public} public, {issues} issues")

    return {
        "assets": [
            {"provider": a.provider, "type": a.asset_type, "id": a.arn_or_id,
             "name": a.name, "region": a.region, "public": a.public,
             "issues": a.issues, "metadata": a.metadata}
            for a in all_assets
        ],
        "total": len(all_assets),
        "public_count": public,
        "issue_count": issues,
    }
