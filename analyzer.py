# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""
analyzer.py — YAML parsing and static security checks by Jayden Aung

Static checks are fast, deterministic, and run without the API.
They cover the most common K8s security misconfigurations from:
  - CIS Kubernetes Benchmark
  - NSA/CISA Kubernetes Hardening Guide
  - OWASP Kubernetes Top 10
  
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any


_EXCLUDE_DIRS = {".git", "venv", "node_modules", "__pycache__", ".tox", ".mypy_cache"}


def load_manifests(path: Path) -> List[Dict]:
    """Load and parse YAML manifests from a file or directory."""
    if path.is_dir():
        return _load_from_dir(path)
    return _load_from_file(path)


def load_manifests_from_files(paths: List[Path]) -> List[Dict]:
    """Load and parse YAML manifests from an explicit list of file paths."""
    resources = []
    for p in paths:
        resources.extend(_load_from_file(p))
    return resources


def _load_from_file(path: Path) -> List[Dict]:
    resources = []
    with open(path, "r") as f:
        for doc in yaml.safe_load_all(f):
            if doc is not None:
                doc["_source_file"] = str(path)
                resources.append(doc)
    return resources


def _load_from_dir(path: Path) -> List[Dict]:
    files = set()
    for ext in ("*.yaml", "*.yml"):
        for f in path.rglob(ext):
            if not any(part in _EXCLUDE_DIRS for part in f.parts):
                files.add(f)
    resources = []
    for f in sorted(files):
        resources.extend(_load_from_file(f))
    return resources


def run_static_checks(resources: List[Dict]) -> List[Dict]:
    """Run all static checks across all resources. Returns list of findings."""
    findings = []
    for resource in resources:
        kind = resource.get("kind", "Unknown")
        name = resource.get("metadata", {}).get("name", "unnamed")
        context = f"{kind}/{name}"

        fns = [
            check_privileged_containers,
            check_host_namespace,
            check_root_user,
            check_capabilities,
            check_read_only_root_fs,
            check_resource_limits,
            check_image_tag,
            check_service_account,
            check_host_path_volumes,
            check_network_policy,
            check_secrets_in_env,
            check_liveness_readiness,
            check_security_context,
            check_rbac_wildcard,
            check_apparmor,
            check_default_namespace,
            check_allow_privilege_escalation,
            check_ssh_port,
            check_ingress_tls,
            check_service_loadbalancer,
            check_image_digest,
            check_env_var_secrets,
            check_topology_spread,
            check_drop_all_capabilities,
        ]

        for fn in fns:
            result = fn(resource, context)
            if result:
                if isinstance(result, list):
                    findings.extend(result)
                else:
                    findings.append(result)

    return findings


# ─────────────────────────────────────────────
# Individual check functions
# Each returns None (pass) or a finding dict
# ─────────────────────────────────────────────

def _finding(check_id, severity, context, title, detail, remediation, resource_path=""):
    return {
        "source": "static",
        "check_id": check_id,
        "severity": severity,
        "context": context,
        "title": title,
        "detail": detail,
        "remediation": remediation,
        "resource_path": resource_path,
    }


def _get_containers(resource: Dict) -> List[Dict]:
    """Extract all containers (including initContainers) from a resource."""
    spec = resource.get("spec", {})
    # Handle Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob
    template_spec = spec.get("template", {}).get("spec", spec)
    containers = template_spec.get("containers", [])
    init_containers = template_spec.get("initContainers", [])
    return containers + init_containers


def check_privileged_containers(resource, context):
    findings = []
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        if sc.get("privileged") is True:
            findings.append(_finding(
                "K8S-001", "CRITICAL", context,
                f"Privileged container: {c.get('name')}",
                "Container runs with privileged=true, granting full host access.",
                "Set securityContext.privileged: false or remove the field.",
                f"spec.containers[{c.get('name')}].securityContext.privileged"
            ))
    return findings


def check_host_namespace(resource, context):
    findings = []
    spec = resource.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", spec)
    for field, label in [("hostPID", "hostPID"), ("hostIPC", "hostIPC"), ("hostNetwork", "hostNetwork")]:
        if template_spec.get(field) is True:
            sev = "CRITICAL" if field in ("hostPID", "hostIPC") else "HIGH"
            findings.append(_finding(
                "K8S-002", sev, context,
                f"{label} enabled on pod spec",
                f"{label}: true shares the host's {field.replace('host','')} namespace with the container.",
                f"Set spec.{field}: false or remove it.",
                f"spec.{field}"
            ))
    return findings


def check_root_user(resource, context):
    findings = []
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        run_as = sc.get("runAsUser")
        run_as_non_root = sc.get("runAsNonRoot")
        if run_as == 0:
            findings.append(_finding(
                "K8S-003", "HIGH", context,
                f"Container runs as root (UID 0): {c.get('name')}",
                "runAsUser: 0 explicitly runs the container as root.",
                "Set runAsUser to a non-zero UID (e.g., 1000) and runAsNonRoot: true.",
                f"spec.containers[{c.get('name')}].securityContext.runAsUser"
            ))
        elif run_as_non_root is False:
            findings.append(_finding(
                "K8S-003", "MEDIUM", context,
                f"runAsNonRoot explicitly disabled: {c.get('name')}",
                "runAsNonRoot: false allows the container to run as root.",
                "Set runAsNonRoot: true.",
                f"spec.containers[{c.get('name')}].securityContext.runAsNonRoot"
            ))
    return findings


def check_capabilities(resource, context):
    findings = []
    dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "ALL"}
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        caps = sc.get("capabilities", {})
        added = set(caps.get("add", []))
        dangerous = added & dangerous_caps
        if dangerous:
            findings.append(_finding(
                "K8S-004", "HIGH", context,
                f"Dangerous capabilities added: {c.get('name')}",
                f"Capabilities {dangerous} are added, granting elevated kernel privileges.",
                "Drop all capabilities and only add the minimum required. Use drop: [ALL] and add only what's needed.",
                f"spec.containers[{c.get('name')}].securityContext.capabilities.add"
            ))
        if "ALL" in added:
            findings.append(_finding(
                "K8S-004", "CRITICAL", context,
                f"ALL capabilities added: {c.get('name')}",
                "capabilities.add: [ALL] grants every Linux capability to the container.",
                "Replace with the specific capabilities the application actually needs.",
                f"spec.containers[{c.get('name')}].securityContext.capabilities.add"
            ))
    return findings


def check_read_only_root_fs(resource, context):
    findings = []
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        if sc.get("readOnlyRootFilesystem") is not True:
            findings.append(_finding(
                "K8S-005", "MEDIUM", context,
                f"Writable root filesystem: {c.get('name')}",
                "readOnlyRootFilesystem is not set to true. A writable root FS makes exploitation easier.",
                "Set securityContext.readOnlyRootFilesystem: true. Use emptyDir volumes for writable paths.",
                f"spec.containers[{c.get('name')}].securityContext.readOnlyRootFilesystem"
            ))
    return findings


def check_resource_limits(resource, context):
    findings = []
    for c in _get_containers(resource):
        resources = c.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})
        if not limits.get("cpu") or not limits.get("memory"):
            findings.append(_finding(
                "K8S-006", "MEDIUM", context,
                f"Missing resource limits: {c.get('name')}",
                "CPU and/or memory limits are not set. This enables resource exhaustion (DoS) attacks.",
                "Set resources.limits.cpu and resources.limits.memory for every container.",
                f"spec.containers[{c.get('name')}].resources.limits"
            ))
        if not requests.get("cpu") or not requests.get("memory"):
            findings.append(_finding(
                "K8S-006", "LOW", context,
                f"Missing resource requests: {c.get('name')}",
                "Resource requests not set — Kubernetes scheduler cannot make informed placement decisions.",
                "Set resources.requests.cpu and resources.requests.memory.",
                f"spec.containers[{c.get('name')}].resources.requests"
            ))
    return findings


def check_image_tag(resource, context):
    findings = []
    for c in _get_containers(resource):
        image = c.get("image", "")
        if image.endswith(":latest") or (":" not in image):
            findings.append(_finding(
                "K8S-007", "MEDIUM", context,
                f"Unpinned image tag: {c.get('name')}",
                f"Image '{image}' uses :latest or no tag. This causes unpredictable deployments and supply chain risk.",
                "Pin images to a specific digest (e.g., image@sha256:...) or an immutable semver tag.",
                f"spec.containers[{c.get('name')}].image"
            ))
    return findings


_WORKLOAD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicaSet"}

def check_service_account(resource, context):
    if resource.get("kind") not in _WORKLOAD_KINDS:
        return []
    findings = []
    spec = resource.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", spec)
    if template_spec.get("automountServiceAccountToken") is not False:
        findings.append(_finding(
            "K8S-008", "MEDIUM", context,
            "Service account token auto-mounted",
            "automountServiceAccountToken is not explicitly set to false. "
            "Every pod gets an API token mounted at /var/run/secrets — useful for lateral movement.",
            "Set automountServiceAccountToken: false unless the pod genuinely needs API access.",
            "spec.automountServiceAccountToken"
        ))
    return findings


def check_host_path_volumes(resource, context):
    findings = []
    spec = resource.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", spec)
    for vol in template_spec.get("volumes", []):
        if "hostPath" in vol:
            path = vol["hostPath"].get("path", "")
            sev = "CRITICAL" if path in ("/", "/etc", "/proc", "/sys", "/var/run/docker.sock") else "HIGH"
            findings.append(_finding(
                "K8S-009", sev, context,
                f"hostPath volume mounted: {vol.get('name')}",
                f"Volume mounts host path '{path}'. This can expose sensitive host data or allow container escape.",
                "Avoid hostPath volumes. Use PersistentVolumeClaims or ConfigMaps instead.",
                f"spec.volumes[{vol.get('name')}].hostPath"
            ))
    return findings


def check_network_policy(resource, context):
    # Only flag for Deployments/DaemonSets/StatefulSets — not for NetworkPolicy itself
    if resource.get("kind") in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
        labels = resource.get("metadata", {}).get("labels", {})
        if not labels:
            return _finding(
                "K8S-010", "LOW", context,
                "No labels defined — NetworkPolicy targeting may be impaired",
                "Resources without labels cannot be targeted by NetworkPolicy selectors, "
                "leaving pod-level network isolation undefined.",
                "Add meaningful labels (app, tier, environment) to enable NetworkPolicy targeting.",
                "metadata.labels"
            )
    return None


def check_secrets_in_env(resource, context):
    findings = []
    sensitive_keys = {"password", "secret", "token", "key", "api_key", "apikey", "passwd", "credential"}
    for c in _get_containers(resource):
        for env in c.get("env", []):
            name_lower = env.get("name", "").lower()
            if any(k in name_lower for k in sensitive_keys):
                if "value" in env:  # hardcoded — not using valueFrom
                    findings.append(_finding(
                        "K8S-011", "HIGH", context,
                        f"Hardcoded secret in env var: {env.get('name')}",
                        f"Environment variable '{env.get('name')}' appears to contain a secret hardcoded as plaintext.",
                        "Use secretKeyRef to reference a Kubernetes Secret instead of hardcoding values.",
                        f"spec.containers[{c.get('name')}].env[{env.get('name')}]"
                    ))
    return findings


def check_liveness_readiness(resource, context):
    findings = []
    for c in _get_containers(resource):
        if not c.get("livenessProbe"):
            findings.append(_finding(
                "K8S-012", "LOW", context,
                f"No liveness probe: {c.get('name')}",
                "Without a liveness probe, Kubernetes cannot detect and recover from application deadlocks.",
                "Add a livenessProbe (httpGet, exec, or tcpSocket) to enable automatic pod restart on failure.",
                f"spec.containers[{c.get('name')}].livenessProbe"
            ))
        if not c.get("readinessProbe"):
            findings.append(_finding(
                "K8S-012", "LOW", context,
                f"No readiness probe: {c.get('name')}",
                "Without a readiness probe, a failing container may still receive traffic.",
                "Add a readinessProbe to gate traffic until the container is actually ready.",
                f"spec.containers[{c.get('name')}].readinessProbe"
            ))
    return findings


def check_security_context(resource, context):
    if resource.get("kind") not in _WORKLOAD_KINDS:
        return []
    findings = []
    spec = resource.get("spec", {})
    template_spec = spec.get("template", {}).get("spec", spec)
    pod_sc = template_spec.get("securityContext", {})
    if not pod_sc:
        findings.append(_finding(
            "K8S-013", "MEDIUM", context,
            "No pod-level securityContext defined",
            "Pod-level securityContext is missing. Best practice is to set runAsNonRoot, "
            "runAsUser, fsGroup, and seccompProfile at the pod level.",
            "Add a securityContext block to the pod spec with at minimum runAsNonRoot: true and a seccompProfile.",
            "spec.securityContext"
        ))
    if pod_sc and not pod_sc.get("seccompProfile"):
        findings.append(_finding(
            "K8S-013", "LOW", context,
            "No seccomp profile defined",
            "seccompProfile is not set. Without it, containers can make any syscall the kernel allows.",
            "Set securityContext.seccompProfile.type: RuntimeDefault or a custom profile.",
            "spec.securityContext.seccompProfile"
        ))
    return findings


def check_rbac_wildcard(resource, context):
    findings = []
    if resource.get("kind") in ("ClusterRole", "Role"):
        for rule in resource.get("rules", []):
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            api_groups = rule.get("apiGroups", [])
            if "*" in verbs:
                findings.append(_finding(
                    "K8S-014", "HIGH", context,
                    "Wildcard verb in RBAC rule",
                    f"Rule grants wildcard (*) verbs on resources: {resources}. This is overly permissive.",
                    "Replace wildcard verbs with the minimum required verbs (get, list, watch).",
                    "rules[].verbs"
                ))
            if "*" in resources:
                findings.append(_finding(
                    "K8S-014", "CRITICAL", context,
                    "Wildcard resource in RBAC rule",
                    "Rule grants access to all (*) resources. This effectively grants cluster-admin-like access.",
                    "Enumerate the specific resources the role needs access to.",
                    "rules[].resources"
                ))
    return findings


def check_apparmor(resource, context):
    """K8S-015 — Missing AppArmor annotation."""
    if resource.get("kind") not in ("Pod", "Deployment", "DaemonSet", "StatefulSet"):
        return None
    annotations = resource.get("metadata", {}).get("annotations", {})
    has_apparmor = any("apparmor" in k.lower() for k in annotations)
    if not has_apparmor:
        return _finding(
            "K8S-015", "LOW", context,
            "No AppArmor profile annotation",
            "No AppArmor profile is set. AppArmor restricts the syscalls a container can make, "
            "reducing the impact of a container compromise.",
            "Add annotation: container.apparmor.security.beta.kubernetes.io/<container>: runtime/default",
            "metadata.annotations"
        )
    return None


def check_default_namespace(resource, context):
    """K8S-016 — Workload deployed in the default namespace."""
    if resource.get("kind") not in ("Deployment", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"):
        return None
    ns = resource.get("metadata", {}).get("namespace", "default")
    if ns == "default":
        return _finding(
            "K8S-016", "LOW", context,
            "Workload deployed in default namespace",
            "Deploying workloads in the 'default' namespace makes it harder to apply "
            "namespace-scoped NetworkPolicies and RBAC boundaries.",
            "Create a dedicated namespace for the application and deploy there.",
            "metadata.namespace"
        )
    return None


def check_allow_privilege_escalation(resource, context):
    """K8S-017 — allowPrivilegeEscalation not explicitly false."""
    findings = []
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(_finding(
                "K8S-017", "MEDIUM", context,
                f"allowPrivilegeEscalation not disabled: {c.get('name')}",
                "allowPrivilegeEscalation is not set to false. This allows child processes to "
                "gain more privileges than the parent — a common privilege escalation vector.",
                "Set securityContext.allowPrivilegeEscalation: false on every container.",
                f"spec.containers[{c.get('name')}].securityContext.allowPrivilegeEscalation"
            ))
    return findings


def check_ssh_port(resource, context):
    """K8S-018 — Container exposes port 22 (SSH)."""
    findings = []
    for c in _get_containers(resource):
        for port in c.get("ports", []):
            if port.get("containerPort") == 22:
                findings.append(_finding(
                    "K8S-018", "HIGH", context,
                    f"SSH port 22 exposed: {c.get('name')}",
                    "Container exposes port 22. SSH in containers is an anti-pattern — it bypasses "
                    "Kubernetes audit logging and creates a persistent backdoor if the image is compromised.",
                    "Remove SSH from the container image. Use 'kubectl exec' for debugging instead.",
                    f"spec.containers[{c.get('name')}].ports"
                ))
    return findings


def check_ingress_tls(resource, context):
    """K8S-019 — Ingress missing TLS configuration."""
    if resource.get("kind") != "Ingress":
        return None
    spec = resource.get("spec", {})
    if not spec.get("tls"):
        return _finding(
            "K8S-019", "MEDIUM", context,
            "Ingress has no TLS configuration",
            "This Ingress does not enforce TLS. Traffic between clients and the ingress "
            "controller will be transmitted in plaintext.",
            "Add a spec.tls block with a valid certificate Secret to enforce HTTPS.",
            "spec.tls"
        )
    return None


def check_service_loadbalancer(resource, context):
    """K8S-020 — Service of type LoadBalancer without restriction annotation."""
    if resource.get("kind") != "Service":
        return None
    if resource.get("spec", {}).get("type") != "LoadBalancer":
        return None
    annotations = resource.get("metadata", {}).get("annotations", {})
    has_restriction = any(
        k in annotations for k in [
            "service.beta.kubernetes.io/aws-load-balancer-internal",
            "networking.gke.io/load-balancer-type",
            "service.kubernetes.io/azure-load-balancer-internal",
        ]
    )
    if not has_restriction:
        return _finding(
            "K8S-020", "HIGH", context,
            "LoadBalancer Service may be publicly exposed",
            "Service type is LoadBalancer with no internal-only annotation. "
            "This likely provisions a public cloud load balancer, exposing the service to the internet.",
            "Add an annotation to make the load balancer internal, or change the service type to ClusterIP "
            "and use an Ingress controller for external access.",
            "spec.type"
        )
    return None


def check_image_digest(resource, context):
    """K8S-021 — Image not pinned to a SHA digest."""
    findings = []
    for c in _get_containers(resource):
        image = c.get("image", "")
        if "@sha256:" not in image:
            findings.append(_finding(
                "K8S-021", "LOW", context,
                f"Image not pinned to SHA digest: {c.get('name')}",
                f"Image '{image}' is not pinned to a SHA256 digest. Even immutable tags can be "
                "overwritten in some registries, creating a supply chain risk.",
                "Pin images to their digest: image@sha256:<hash>. Use tools like Renovate to automate digest updates.",
                f"spec.containers[{c.get('name')}].image"
            ))
    return findings


def check_env_var_secrets(resource, context):
    """K8S-022 — Secret referenced via envFrom instead of mounted volume."""
    findings = []
    for c in _get_containers(resource):
        for env_from in c.get("envFrom", []):
            if "secretRef" in env_from:
                findings.append(_finding(
                    "K8S-022", "LOW", context,
                    f"Secret exposed as environment variable via envFrom: {c.get('name')}",
                    "Secrets loaded via envFrom are exposed as environment variables, "
                    "which can leak via crash dumps, /proc, or logging of env vars.",
                    "Mount secrets as files via volumeMounts instead of envFrom where possible.",
                    f"spec.containers[{c.get('name')}].envFrom"
                ))
    return findings


def check_topology_spread(resource, context):
    """K8S-023 — Deployment missing topologySpreadConstraints (single point of failure risk)."""
    if resource.get("kind") != "Deployment":
        return None
    spec = resource.get("spec", {})
    replicas = spec.get("replicas", 1)
    if replicas < 2:
        return None
    template_spec = spec.get("template", {}).get("spec", {})
    if not template_spec.get("topologySpreadConstraints") and not template_spec.get("affinity"):
        return _finding(
            "K8S-023", "LOW", context,
            "Multi-replica Deployment missing spread constraints",
            f"Deployment has {replicas} replicas but no topologySpreadConstraints or affinity rules. "
            "All replicas may be scheduled on the same node, creating a single point of failure.",
            "Add topologySpreadConstraints to distribute replicas across nodes or availability zones.",
            "spec.template.spec.topologySpreadConstraints"
        )
    return None


def check_drop_all_capabilities(resource, context):
    """K8S-024 — Container does not drop ALL capabilities."""
    findings = []
    for c in _get_containers(resource):
        sc = c.get("securityContext", {})
        caps = sc.get("capabilities", {})
        dropped = caps.get("drop", [])
        if "ALL" not in [d.upper() for d in dropped]:
            findings.append(_finding(
                "K8S-024", "MEDIUM", context,
                f"Container does not drop ALL capabilities: {c.get('name')}",
                "Best practice is to drop ALL Linux capabilities and then add back only what is needed. "
                "Without dropping all, the container retains capabilities it may not need.",
                "Add capabilities.drop: [ALL] to the container securityContext, then add back only required capabilities.",
                f"spec.containers[{c.get('name')}].securityContext.capabilities.drop"
            ))
    return findings


# ─────────────────────────────────────────────
# Registry — used by the agent tool layer
# ─────────────────────────────────────────────

CHECK_REGISTRY = {
    "K8S-001": check_privileged_containers,
    "K8S-002": check_host_namespace,
    "K8S-003": check_root_user,
    "K8S-004": check_capabilities,
    "K8S-005": check_read_only_root_fs,
    "K8S-006": check_resource_limits,
    "K8S-007": check_image_tag,
    "K8S-008": check_service_account,
    "K8S-009": check_host_path_volumes,
    "K8S-010": check_network_policy,
    "K8S-011": check_secrets_in_env,
    "K8S-012": check_liveness_readiness,
    "K8S-013": check_security_context,
    "K8S-014": check_rbac_wildcard,
    "K8S-015": check_apparmor,
    "K8S-016": check_default_namespace,
    "K8S-017": check_allow_privilege_escalation,
    "K8S-018": check_ssh_port,
    "K8S-019": check_ingress_tls,
    "K8S-020": check_service_loadbalancer,
    "K8S-021": check_image_digest,
    "K8S-022": check_env_var_secrets,
    "K8S-023": check_topology_spread,
    "K8S-024": check_drop_all_capabilities,
}


def run_check_by_id(check_id: str, resource: Dict) -> List[Dict]:
    """Run a single check (or ALL) on one resource. Returns a list of findings."""
    kind = resource.get("kind", "Unknown")
    name = resource.get("metadata", {}).get("name", "unnamed")
    context = f"{kind}/{name}"

    if check_id == "ALL":
        return run_static_checks([resource])

    fn = CHECK_REGISTRY.get(check_id)
    if fn is None:
        return []

    result = fn(resource, context)
    if result is None:
        return []
    if isinstance(result, list):
        return result
    return [result]
