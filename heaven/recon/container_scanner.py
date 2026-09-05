"""
HEAVEN — Container & Kubernetes Security Scanner
Docker socket exposure, K8s API server misconfig, RBAC analysis,
pod security, container escape detection, etcd exposure.
"""

from __future__ import annotations
from heaven.net.egress import client_session as _egress_cs  # egress-routed aiohttp

import os
import socket
from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.container")

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# Host paths whose bind-mount into a container is a genuine escape / host-tamper
# vector. A bind mount of application data (e.g. /srv/app) is not dangerous, so
# the set is the OS-sensitive roots plus the Docker socket — not "any path".
_SENSITIVE_MOUNT_ROOTS = (
    "/etc", "/root", "/proc", "/sys", "/boot", "/dev", "/var/run",
    "/run", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/home",
    "/var/lib/docker", "/var/lib/kubelet",
)


def _is_dangerous_mount(m: dict) -> bool:
    """Whether a container mount is a bind mount of a sensitive host path.

    Only ``bind`` mounts touch the host filesystem; Docker-managed ``volume`` and
    ``tmpfs`` mounts do not, so they are never dangerous. A bind of ``/`` or the
    Docker socket is a full escape; binds of the OS-sensitive roots are host
    tamper vectors. Application-data binds (``/srv/app``, ``/data``) are not.
    """
    if (m.get("Type") or "").lower() != "bind":
        return False
    raw = m.get("Source") or ""
    if not raw:
        return False
    if raw == "/":  # the whole host root filesystem
        return True
    src = raw.rstrip("/")
    if src.endswith("/docker.sock") or src.endswith("/containerd.sock"):
        return True
    return any(src == r or src.startswith(r + "/") for r in _SENSITIVE_MOUNT_ROOTS)


def _is_local_target(host: str) -> bool:
    """True only when the scan target IS the machine HEAVEN runs on.

    The local Docker-socket / privileged-container / RBAC checks inspect the
    *scanner's own host*, so they may only be attributed to the target when the
    target actually is this host. Scanning a remote target must never surface
    the analyst's own `/var/run/docker.sock` as a target finding.
    """
    if not host:
        return False
    h = host.strip().lower()
    if "://" in h:
        from urllib.parse import urlparse
        h = urlparse(h).hostname or h
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"):
        return True
    try:
        if h in (socket.gethostname().lower(), socket.getfqdn().lower()):
            return True
    except Exception:  # noqa: BLE001 — hostname lookup is best-effort
        logger.debug("suppressed non-fatal exception", exc_info=True)
    return False


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
    async def check_docker_socket(cls, host: str = "localhost",
                                  is_local: bool = False) -> list[ContainerFinding]:
        """Check for an exposed Docker socket.

        The local ``/var/run/docker.sock`` check inspects the machine HEAVEN is
        running on, so it only applies when the target IS this host — otherwise
        scanning any remote target from a workstation with Docker installed
        would emit a bogus critical attributed to the remote. The remote Docker
        API probe (2375/2376) is genuinely target-scoped and always runs.
        """
        findings = []
        # Local socket — only meaningful (and only correctly attributed) when
        # the target is this host.
        if is_local and os.path.exists("/var/run/docker.sock"):
            findings.append(ContainerFinding(
                target=host, vuln_type="docker_socket_exposed",
                severity="critical",
                title="Docker Socket Exposed: /var/run/docker.sock",
                description=(
                    "Docker socket is accessible on this host. Any process with access "
                    "can control Docker, mount the host filesystem, and escape the container."
                ),
                confidence=0.95,
                remediation="Restrict Docker socket permissions. Use rootless Docker. Never mount socket in containers.",
                cwe="CWE-269", mitre="T1611",
            ))

        # Remote Docker API (port 2375/2376)
        if HAS_AIOHTTP:
            for port in [2375, 2376]:
                try:
                    async with _egress_cs() as session:
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
                    logger.debug("suppressed non-fatal exception", exc_info=True)
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
                # Check host mounts. Only *bind* mounts of sensitive host paths are
                # dangerous (a container escape / host-tamper vector). Docker-managed
                # named/anonymous volumes (Type=="volume", Source under
                # /var/lib/docker/volumes/…) and tmpfs are NOT host exposure — the old
                # check flagged any Source starting with "/", so every container with a
                # volume got a bogus "dangerous mount" (the remediation even said "use
                # named volumes", which were exactly what tripped it).
                mounts = container.attrs.get("Mounts", [])
                dangerous_mounts = [m for m in mounts if _is_dangerous_mount(m)]
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

        async with _egress_cs() as session:
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
                    logger.debug("suppressed non-fatal exception", exc_info=True)
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
                    logger.debug("suppressed non-fatal exception", exc_info=True)

            # Check kubelet API. 10250 is HTTPS (authenticated in a hardened
            # cluster); 10255 is the plain-HTTP read-only port — using https on
            # it never connected, so that check silently never fired.
            for kubelet_port, kscheme in [(10250, "https"), (10255, "http")]:
                try:
                    async with session.get(
                        f"{kscheme}://{host}:{kubelet_port}/pods",
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
                                evidence={"pods": pod_count, "scheme": kscheme},
                                remediation="Disable anonymous kubelet access. Enable webhook auth. "
                                            "Set --read-only-port=0 to close 10255.",
                                cwe="CWE-306", mitre="T1609",
                            ))
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)

            # Legacy insecure API port (--insecure-port 8080): serves the API with
            # NO authentication or authorization. Removed in k8s >=1.20 but still
            # seen on older/self-managed clusters.
            try:
                async with session.get(
                    f"http://{host}:8080/api/v1/namespaces",
                    timeout=aiohttp.ClientTimeout(total=4),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ns = len(data.get("items", []))
                        findings.append(ContainerFinding(
                            target=host, vuln_type="k8s_insecure_port",
                            severity="critical",
                            title=f"K8s API insecure port open on {host}:8080",
                            description=("The legacy kube-apiserver insecure port (8080) serves the "
                                         f"API with no authentication or authorization — {ns} "
                                         "namespaces readable."),
                            confidence=0.95, evidence={"namespaces": ns},
                            remediation="Set --insecure-port=0 (default on modern k8s). Never expose 8080.",
                            cwe="CWE-306", mitre="T1610",
                        ))
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

            # cAdvisor container-metrics API (port 4194) — discloses running
            # containers, images and host resource layout.
            try:
                async with session.get(
                    f"http://{host}:4194/api/v1.3/subcontainers",
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    ctype = (resp.headers.get("Content-Type") or "").lower()
                    if resp.status == 200 and "json" in ctype:
                        findings.append(ContainerFinding(
                            target=host, vuln_type="cadvisor_exposed",
                            severity="medium",
                            title=f"cAdvisor Exposed on {host}:4194",
                            description=("cAdvisor metrics API is publicly reachable — discloses "
                                         "running containers, images and host resource layout."),
                            confidence=0.85,
                            remediation="Bind cAdvisor to localhost or require auth; do not expose 4194.",
                            cwe="CWE-200", mitre="T1526",
                        ))
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)

            # Open Docker registry (v2 API) — anonymous catalog read / image pull
            # (image poisoning + source-code leakage risk).
            for reg_scheme in ("https", "http"):
                try:
                    async with session.get(
                        f"{reg_scheme}://{host}:5000/v2/_catalog",
                        timeout=aiohttp.ClientTimeout(total=4), ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            repos = data.get("repositories")
                            if isinstance(repos, list):
                                findings.append(ContainerFinding(
                                    target=host, vuln_type="registry_exposed",
                                    severity="high",
                                    title=f"Open Container Registry on {host}:5000",
                                    description=("Docker Registry v2 catalog is readable without "
                                                 f"authentication — {len(repos)} repositories exposed "
                                                 "(image pull / poisoning risk)."),
                                    confidence=0.9, evidence={"repositories": repos[:20]},
                                    remediation="Require registry authentication (htpasswd/token); "
                                                "restrict network access.",
                                    cwe="CWE-306", mitre="T1525",
                                ))
                                break
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)

        return findings

    # Over-broad built-in principals that must NEVER hold cluster-admin. Binding
    # cluster-admin to any of these is a critical, unambiguous misconfiguration:
    #   system:anonymous / system:unauthenticated → unauthenticated callers are
    #     full cluster admins; system:authenticated → EVERY authenticated user is.
    # system:masters is deliberately absent: it is the built-in break-glass admin
    # group that legitimately holds cluster-admin, so flagging it would be a false
    # positive on every healthy cluster.
    _DANGEROUS_ADMIN_PRINCIPALS = frozenset({
        "system:anonymous", "system:unauthenticated", "system:authenticated",
    })

    @staticmethod
    def _assess_cluster_admin_bindings(
        bindings: "list[tuple[str, list[tuple[str, str, str]]]]",
    ) -> "tuple[list[dict], list[str]]":
        """Classify cluster-admin bindings from a normalized view.

        ``bindings`` is ``[(binding_name, [(subject_kind, name, namespace), ...])]``
        for the bindings whose roleRef is ``cluster-admin``. Returns
        ``(dangerous, sa_admins)`` where *dangerous* names each over-broad
        principal (anonymous / unauthenticated / all-authenticated) granted
        cluster-admin, and *sa_admins* is the list of ServiceAccount admins (a
        separate, lower-severity "sprawl" signal). Pure + client-free so it is
        unit-testable without a live cluster."""
        dangerous: list[dict] = []
        sa_admins: list[str] = []
        for binding_name, subjects in bindings:
            for kind, name, namespace in subjects:
                if (kind in ("User", "Group")
                        and name in KubernetesScanner._DANGEROUS_ADMIN_PRINCIPALS):
                    dangerous.append(
                        {"binding": binding_name, "kind": kind, "principal": name})
                elif kind == "ServiceAccount":
                    sa_admins.append(f"{namespace}/{name}")
        return dangerous, sa_admins

    @classmethod
    async def analyze_rbac(cls, kubeconfig_path: Optional[str] = None) -> list[ContainerFinding]:
        """Analyze Kubernetes RBAC for overprivileged accounts."""
        findings: list[ContainerFinding] = []
        try:
            from kubernetes import client, config
            if kubeconfig_path:
                config.load_kube_config(kubeconfig_path)
            else:
                config.load_incluster_config()

            rbac_api = client.RbacAuthorizationV1Api()
            bindings = rbac_api.list_cluster_role_binding()
            normalized: list[tuple[str, list[tuple[str, str, str]]]] = []
            for binding in bindings.items:
                if binding.role_ref.name != "cluster-admin":
                    continue
                subs = [(s.kind, s.name, getattr(s, "namespace", "") or "")
                        for s in (binding.subjects or [])]
                normalized.append((binding.metadata.name, subs))

            dangerous, sa_admins = cls._assess_cluster_admin_bindings(normalized)

            if dangerous:
                who = ", ".join(f"{d['principal']} (via {d['binding']})"
                                for d in dangerous)
                findings.append(ContainerFinding(
                    target="cluster", vuln_type="k8s_rbac_overprivileged",
                    severity="critical",
                    title="K8s RBAC: cluster-admin granted to an "
                          "unauthenticated / all-users principal",
                    description=(
                        "A ClusterRoleBinding grants cluster-admin to an "
                        f"over-broad built-in principal: {who}. This makes "
                        "unauthenticated (or every authenticated) caller a full "
                        "cluster administrator — total cluster compromise."),
                    confidence=0.95,
                    remediation="Delete the binding immediately; never bind "
                                "cluster-admin to system:anonymous, "
                                "system:unauthenticated or system:authenticated.",
                    cwe="CWE-269", mitre="T1078",
                ))

            # Separate, lower-severity signal: cluster-admin ServiceAccount sprawl.
            if len(sa_admins) > 3:
                findings.append(ContainerFinding(
                    target="cluster", vuln_type="k8s_rbac_overprivileged",
                    severity="high",
                    title=f"K8s RBAC: {len(sa_admins)} cluster-admin service accounts",
                    description=f"Excessive cluster-admin bindings: {sa_admins[:10]}",
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
        is_local = _is_local_target(host)

        # Docker socket: local-host check gated to a local target; remote API
        # probe (2375/2376) is target-scoped and always runs.
        self._findings.extend(
            await DockerScanner.check_docker_socket(host, is_local=is_local))

        # These enumerate the LOCAL Docker/K8s daemon, so only run them when the
        # target is this host — never attribute the scanner's own containers /
        # RBAC to a remote target.
        if is_local:
            self._findings.extend(await DockerScanner.check_privileged_containers())
            self._findings.extend(await KubernetesScanner.analyze_rbac())

        # Target-scoped remote probes (K8s API / etcd / kubelet).
        self._findings.extend(
            await KubernetesScanner.check_api_server(host, k8s_port))

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
