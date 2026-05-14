"""
HEAVEN — Container & Kubernetes Security Scanner
Docker socket exposure, K8s API server misconfig, RBAC analysis,
pod security, container escape detection, etcd exposure.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.container")

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


@dataclass
class ContainerFinding:
    target: str
    vuln_type: str
    severity: str
    title: str
    description: str
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    cwe: str = ""
    mitre: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target, "vuln_type": self.vuln_type,
            "severity": self.severity, "title": self.title,
            "description": self.description, "confidence": self.confidence,
            "evidence": self.evidence, "remediation": self.remediation,
            "cwe": self.cwe, "mitre": self.mitre,
        }


class DockerScanner:
    """Docker security scanner."""

    @classmethod
    async def check_docker_socket(cls, host: str = "localhost") -> list[ContainerFinding]:
        """Check for exposed Docker socket (local and remote)."""
        findings = []
        # Local socket
        if os.path.exists("/var/run/docker.sock"):
            findings.append(ContainerFinding(
                target="localhost", vuln_type="docker_socket_exposed",
                severity="critical",
                title="Docker Socket Exposed: /var/run/docker.sock",
                description=(
                    "Docker socket is accessible. Any process with access can control Docker, "
                    "mount host filesystem, and escape the container."
                ),
                confidence=0.95,
                remediation="Restrict Docker socket permissions. Use rootless Docker. Never mount socket in containers.",
                cwe="CWE-269", mitre="T1611",
            ))

        # Remote Docker API (port 2375/2376)
        if HAS_AIOHTTP:
            for port in [2375, 2376]:
                try:
                    async with aiohttp.ClientSession() as session:
                        url = f"http://{host}:{port}/version"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                findings.append(ContainerFinding(
                                    target=host, vuln_type="docker_api_exposed",
                                    severity="critical",
                                    title=f"Docker Remote API Exposed on {host}:{port}",
                                    description=f"Docker API v{data.get('ApiVersion', '?')} accessible without auth.",
                                    confidence=0.95,
                                    evidence={"version": data.get("Version"), "api": data.get("ApiVersion")},
                                    remediation="Enable TLS authentication on Docker API. Use firewall rules.",
                                    cwe="CWE-306", mitre="T1609",
                                ))
                except Exception:
                    pass
        return findings

    @classmethod
    async def check_privileged_containers(cls) -> list[ContainerFinding]:
        """Check for privileged containers (local Docker)."""
        findings = []
        try:
            import docker
            client = docker.from_env()
            for container in client.containers.list():
                if container.attrs.get("HostConfig", {}).get("Privileged"):
                    findings.append(ContainerFinding(
                        target=container.name, vuln_type="privileged_container",
                        severity="critical",
                        title=f"Privileged Container: {container.name}",
                        description="Container running in privileged mode — full host access.",
                        confidence=0.95,
                        evidence={"image": container.image.tags, "status": container.status},
                        remediation="Remove --privileged flag. Use specific capabilities.",
                        cwe="CWE-250", mitre="T1611",
                    ))
                # Check host mounts
                mounts = container.attrs.get("Mounts", [])
                dangerous_mounts = [m for m in mounts if m.get("Source", "").startswith(("/", "/etc", "/var/run"))]
                if dangerous_mounts:
                    mount_paths = [m["Source"] for m in dangerous_mounts[:5]]
                    findings.append(ContainerFinding(
                        target=container.name, vuln_type="dangerous_mount",
                        severity="high",
                        title=f"Dangerous Host Mount: {container.name}",
                        description=f"Container mounts sensitive host paths: {mount_paths}",
                        confidence=0.85,
                        remediation="Minimize host mounts. Use named volumes instead.",
                        cwe="CWE-269", mitre="T1611",
                    ))
        except ImportError:
            logger.debug("docker library not installed — skipping local container checks")
        except Exception as e:
            logger.debug(f"Docker check failed: {e}")
        return findings


class KubernetesScanner:
    """Kubernetes security scanner."""

    @classmethod
    async def check_api_server(cls, host: str = "localhost",
                                 port: int = 6443) -> list[ContainerFinding]:
        """Check Kubernetes API server for misconfigurations."""
        findings: list[ContainerFinding] = []
        if not HAS_AIOHTTP:
            return findings

        async with aiohttp.ClientSession() as session:
            # Check anonymous auth
            for scheme in ["https", "http"]:
                api_url = f"{scheme}://{host}:{port}"
                try:
                    async with session.get(
                        f"{api_url}/api/v1/namespaces",
                        timeout=aiohttp.ClientTimeout(total=5), ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            ns_count = len(data.get("items", []))
                            findings.append(ContainerFinding(
                                target=host, vuln_type="k8s_anon_auth",
                                severity="critical",
                                title=f"K8s API: Anonymous access to {api_url}",
                                description=f"Kubernetes API accessible without auth. {ns_count} namespaces found.",
                                confidence=0.95,
                                evidence={"namespaces": ns_count},
                                remediation="Disable anonymous auth: --anonymous-auth=false",
                                cwe="CWE-306", mitre="T1609",
                            ))

                    # Check for exposed secrets
                    async with session.get(
                        f"{api_url}/api/v1/secrets",
                        timeout=aiohttp.ClientTimeout(total=5), ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            findings.append(ContainerFinding(
                                target=host, vuln_type="k8s_secrets_exposed",
                                severity="critical",
                                title="K8s: Cluster Secrets Accessible",
                                description="All cluster secrets readable without authentication.",
                                confidence=0.95,
                                remediation="Enable RBAC. Restrict secret access. Use external secret managers.",
                                cwe="CWE-200", mitre="T1552",
                            ))
                except Exception:
                    continue

            # Check etcd
            for etcd_port in [2379, 2380]:
                try:
                    async with session.get(
                        f"http://{host}:{etcd_port}/version",
                        timeout=aiohttp.ClientTimeout(total=3),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            findings.append(ContainerFinding(
                                target=host, vuln_type="etcd_exposed",
                                severity="critical",
                                title=f"Etcd Exposed on {host}:{etcd_port}",
                                description=f"Etcd v{data.get('etcdserver', '?')} accessible — contains all cluster state.",
                                confidence=0.95,
                                evidence=data,
                                remediation="Restrict etcd to localhost. Enable TLS client auth.",
                                cwe="CWE-306", mitre="T1552",
                            ))
                except Exception:
                    pass

            # Check kubelet API
            for kubelet_port in [10250, 10255]:
                try:
                    async with session.get(
                        f"https://{host}:{kubelet_port}/pods",
                        timeout=aiohttp.ClientTimeout(total=3), ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            pod_count = len(data.get("items", []))
                            findings.append(ContainerFinding(
                                target=host, vuln_type="kubelet_exposed",
                                severity="high",
                                title=f"Kubelet API Exposed on {host}:{kubelet_port}",
                                description=f"Kubelet API accessible — {pod_count} pods visible.",
                                confidence=0.90,
                                evidence={"pods": pod_count},
                                remediation="Disable anonymous kubelet access. Enable webhook auth.",
                                cwe="CWE-306", mitre="T1609",
                            ))
                except Exception:
                    pass

        return findings

    @classmethod
    async def analyze_rbac(cls, kubeconfig_path: Optional[str] = None) -> list[ContainerFinding]:
        """Analyze Kubernetes RBAC for overprivileged accounts."""
        findings = []
        try:
            from kubernetes import client, config
            if kubeconfig_path:
                config.load_kube_config(kubeconfig_path)
            else:
                config.load_incluster_config()

            rbac_api = client.RbacAuthorizationV1Api()
            # Check for cluster-admin bindings
            bindings = rbac_api.list_cluster_role_binding()
            admin_bindings = []
            for binding in bindings.items:
                if binding.role_ref.name == "cluster-admin":
                    subjects = binding.subjects or []
                    for sub in subjects:
                        if sub.kind == "ServiceAccount":
                            admin_bindings.append(f"{sub.namespace}/{sub.name}")

            if len(admin_bindings) > 3:
                findings.append(ContainerFinding(
                    target="cluster", vuln_type="k8s_rbac_overprivileged",
                    severity="high",
                    title=f"K8s RBAC: {len(admin_bindings)} cluster-admin service accounts",
                    description=f"Excessive cluster-admin bindings: {admin_bindings[:10]}",
                    confidence=0.85,
                    remediation="Apply least-privilege. Create specific roles instead of cluster-admin.",
                    cwe="CWE-269", mitre="T1078",
                ))
        except ImportError:
            logger.debug("kubernetes library not installed")
        except Exception as e:
            logger.debug(f"RBAC analysis failed: {e}")
        return findings


class ContainerScanner:
    """Master container security scanner."""

    def __init__(self):
        self._findings: list[ContainerFinding] = []

    async def scan(self, host: str = "localhost", k8s_port: int = 6443) -> list[ContainerFinding]:
        logger.info(f"🐳 Container Security Scan: {host}")
        self._findings = []

        docker_findings = await DockerScanner.check_docker_socket(host)
        self._findings.extend(docker_findings)

        priv_findings = await DockerScanner.check_privileged_containers()
        self._findings.extend(priv_findings)

        k8s_findings = await KubernetesScanner.check_api_server(host, k8s_port)
        self._findings.extend(k8s_findings)

        rbac_findings = await KubernetesScanner.analyze_rbac()
        self._findings.extend(rbac_findings)

        logger.info(f"Container scan complete: {len(self._findings)} findings")
        return self._findings

    def summary(self) -> dict:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self._findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        return {
            "total_findings": len(self._findings),
            "severity": sev,
            "findings": [f.to_dict() for f in self._findings],
        }


async def scan_containers(hosts: Optional[list[str]] = None, **kwargs) -> dict:
    """Entry point from orchestrator."""
    targets = hosts or kwargs.get("container_hosts", ["localhost"])
    scanner = ContainerScanner()
    all_findings = []
    for host in targets:
        findings = await scanner.scan(host)
        all_findings.extend(findings)
    return {"total": len(all_findings), "findings": [f.to_dict() for f in all_findings]}
