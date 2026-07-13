"""
Unit tests for analyzer.py static checks.
Run with: pytest tests/
"""

import pytest
from analyzer import (
    check_privileged_containers,
    check_host_namespace,
    check_root_user,
    check_capabilities,
    check_read_only_root_fs,
    check_resource_limits,
    check_image_tag,
    check_service_account,
    check_host_path_volumes,
    check_secrets_in_env,
    check_liveness_readiness,
    check_rbac_wildcard,
    check_host_aliases,
    check_unsafe_sysctls,
    check_fs_group,
    run_check_by_id,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def deployment(containers=None, spec_overrides=None, volumes=None):
    resource = {
        "kind": "Deployment",
        "metadata": {"name": "test"},
        "spec": {
            "template": {
                "spec": {
                    "containers": containers or [],
                    "volumes": volumes or [],
                }
            }
        },
    }
    if spec_overrides:
        resource["spec"]["template"]["spec"].update(spec_overrides)
    return resource


def container(name="app", image="myapp:1.0.0", sc=None, resources=None, env=None,
              liveness=None, readiness=None):
    c = {"name": name, "image": image}
    if sc is not None:
        c["securityContext"] = sc
    if resources is not None:
        c["resources"] = resources
    if env is not None:
        c["env"] = env
    if liveness is not None:
        c["livenessProbe"] = liveness
    if readiness is not None:
        c["readinessProbe"] = readiness
    return c


def severities(findings):
    return [f["severity"] for f in findings]


def check_ids(findings):
    return [f["check_id"] for f in findings]


# ── check_privileged_containers ───────────────────────────────────────────────

def test_privileged_true_is_critical():
    r = deployment([container(sc={"privileged": True})])
    findings = check_privileged_containers(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["check_id"] == "K8S-001"


def test_privileged_false_no_finding():
    r = deployment([container(sc={"privileged": False})])
    assert check_privileged_containers(r, "Deployment/test") == []


def test_privileged_absent_no_finding():
    r = deployment([container()])
    assert check_privileged_containers(r, "Deployment/test") == []


# ── check_host_namespace ──────────────────────────────────────────────────────

@pytest.mark.parametrize("field,expected_severity", [
    ("hostPID",     "CRITICAL"),
    ("hostIPC",     "CRITICAL"),
    ("hostNetwork", "HIGH"),
])
def test_host_namespace_flags(field, expected_severity):
    r = deployment(spec_overrides={field: True})
    findings = check_host_namespace(r, "Deployment/test")
    assert any(f["severity"] == expected_severity for f in findings)


def test_host_namespace_all_false_no_finding():
    r = deployment(spec_overrides={"hostPID": False, "hostIPC": False, "hostNetwork": False})
    assert check_host_namespace(r, "Deployment/test") == []


# ── check_root_user ───────────────────────────────────────────────────────────

def test_run_as_user_zero_is_high():
    r = deployment([container(sc={"runAsUser": 0})])
    findings = check_root_user(r, "Deployment/test")
    assert any(f["severity"] == "HIGH" for f in findings)


def test_run_as_non_root_false_is_medium():
    r = deployment([container(sc={"runAsNonRoot": False})])
    findings = check_root_user(r, "Deployment/test")
    assert any(f["severity"] == "MEDIUM" for f in findings)


def test_run_as_non_root_true_no_finding():
    r = deployment([container(sc={"runAsUser": 1000, "runAsNonRoot": True})])
    assert check_root_user(r, "Deployment/test") == []


# ── check_capabilities ────────────────────────────────────────────────────────

def test_all_capabilities_is_critical():
    r = deployment([container(sc={"capabilities": {"add": ["ALL"]}})])
    findings = check_capabilities(r, "Deployment/test")
    assert any(f["severity"] == "CRITICAL" for f in findings)


def test_sys_admin_is_high():
    r = deployment([container(sc={"capabilities": {"add": ["SYS_ADMIN"]}})])
    findings = check_capabilities(r, "Deployment/test")
    assert any(f["severity"] == "HIGH" for f in findings)


def test_safe_capabilities_no_finding():
    r = deployment([container(sc={"capabilities": {"drop": ["ALL"]}})])
    assert check_capabilities(r, "Deployment/test") == []


# ── check_read_only_root_fs ───────────────────────────────────────────────────

def test_writable_root_fs_is_medium():
    r = deployment([container(sc={"readOnlyRootFilesystem": False})])
    findings = check_read_only_root_fs(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_read_only_root_fs_no_finding():
    r = deployment([container(sc={"readOnlyRootFilesystem": True})])
    assert check_read_only_root_fs(r, "Deployment/test") == []


# ── check_resource_limits ─────────────────────────────────────────────────────

def test_missing_limits_is_medium():
    r = deployment([container(resources={"requests": {"cpu": "100m", "memory": "128Mi"}})])
    findings = check_resource_limits(r, "Deployment/test")
    assert any(f["severity"] == "MEDIUM" for f in findings)


def test_missing_requests_is_low():
    r = deployment([container(resources={"limits": {"cpu": "500m", "memory": "256Mi"}})])
    findings = check_resource_limits(r, "Deployment/test")
    assert any(f["severity"] == "LOW" for f in findings)


def test_full_resources_no_finding():
    r = deployment([container(resources={
        "requests": {"cpu": "100m", "memory": "128Mi"},
        "limits":   {"cpu": "500m", "memory": "256Mi"},
    })])
    assert check_resource_limits(r, "Deployment/test") == []


# ── check_image_tag ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("image", ["nginx:latest", "nginx", "myrepo/app"])
def test_unpinned_image_is_medium(image):
    r = deployment([container(image=image)])
    findings = check_image_tag(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


@pytest.mark.parametrize("image", ["nginx:1.25.3", "myrepo/app:2.0.1", "app@sha256:abc123"])
def test_pinned_image_no_finding(image):
    r = deployment([container(image=image)])
    assert check_image_tag(r, "Deployment/test") == []


# ── check_service_account ─────────────────────────────────────────────────────

def test_auto_mount_not_disabled_is_medium():
    r = deployment()
    findings = check_service_account(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_auto_mount_disabled_no_finding():
    r = deployment(spec_overrides={"automountServiceAccountToken": False})
    assert check_service_account(r, "Deployment/test") == []


# ── check_host_path_volumes ───────────────────────────────────────────────────

def test_host_root_mount_is_critical():
    r = deployment(volumes=[{"name": "host-root", "hostPath": {"path": "/"}}])
    findings = check_host_path_volumes(r, "Deployment/test")
    assert findings[0]["severity"] == "CRITICAL"


def test_host_var_log_mount_is_high():
    r = deployment(volumes=[{"name": "logs", "hostPath": {"path": "/var/log"}}])
    findings = check_host_path_volumes(r, "Deployment/test")
    assert findings[0]["severity"] == "HIGH"


def test_no_host_path_no_finding():
    r = deployment(volumes=[{"name": "tmp", "emptyDir": {}}])
    assert check_host_path_volumes(r, "Deployment/test") == []


# ── check_secrets_in_env ──────────────────────────────────────────────────────

def test_hardcoded_password_is_high():
    r = deployment([container(env=[{"name": "DATABASE_PASSWORD", "value": "s3cr3t"}])])
    findings = check_secrets_in_env(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_secret_ref_no_finding():
    r = deployment([container(env=[{
        "name": "DATABASE_PASSWORD",
        "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}},
    }])])
    assert check_secrets_in_env(r, "Deployment/test") == []


def test_non_sensitive_env_no_finding():
    r = deployment([container(env=[{"name": "LOG_LEVEL", "value": "debug"}])])
    assert check_secrets_in_env(r, "Deployment/test") == []


# ── check_liveness_readiness ──────────────────────────────────────────────────

def test_missing_both_probes_two_findings():
    r = deployment([container()])
    findings = check_liveness_readiness(r, "Deployment/test")
    assert len(findings) == 2


def test_has_both_probes_no_finding():
    probe = {"httpGet": {"path": "/health", "port": 8080}}
    r = deployment([container(liveness=probe, readiness=probe)])
    assert check_liveness_readiness(r, "Deployment/test") == []


# ── check_rbac_wildcard ───────────────────────────────────────────────────────

def test_wildcard_resources_is_critical():
    resource = {
        "kind": "ClusterRole",
        "metadata": {"name": "dangerous"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get"]}],
    }
    findings = check_rbac_wildcard(resource, "ClusterRole/dangerous")
    assert any(f["severity"] == "CRITICAL" for f in findings)


def test_wildcard_verbs_is_high():
    resource = {
        "kind": "ClusterRole",
        "metadata": {"name": "dangerous"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}],
    }
    findings = check_rbac_wildcard(resource, "ClusterRole/dangerous")
    assert any(f["severity"] == "HIGH" for f in findings)


def test_minimal_rbac_no_finding():
    resource = {
        "kind": "ClusterRole",
        "metadata": {"name": "safe"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
    }
    assert check_rbac_wildcard(resource, "ClusterRole/safe") == []


# ── run_check_by_id ───────────────────────────────────────────────────────────

def test_run_check_by_id_single():
    r = deployment([container(sc={"privileged": True})])
    findings = run_check_by_id("K8S-001", r)
    assert len(findings) == 1
    assert findings[0]["check_id"] == "K8S-001"


def test_run_check_by_id_all():
    r = deployment([container(sc={"privileged": True})])
    findings = run_check_by_id("ALL", r)
    assert any(f["check_id"] == "K8S-001" for f in findings)


def test_run_check_by_id_unknown_returns_empty():
    r = deployment()
    assert run_check_by_id("K8S-999", r) == []


# ── check_host_aliases ────────────────────────────────────────────────────────

def test_host_aliases_detected():
    r = deployment(spec_overrides={
        "hostAliases": [{"ip": "1.2.3.4", "hostnames": ["evil.com"]}]
    })
    findings = check_host_aliases(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["check_id"] == "K8S-025"
    assert findings[0]["severity"] == "HIGH"


def test_host_aliases_clean():
    r = deployment()
    findings = check_host_aliases(r, "Deployment/test")
    assert findings == []


def test_host_aliases_multiple_entries():
    r = deployment(spec_overrides={
        "hostAliases": [
            {"ip": "1.2.3.4", "hostnames": ["a.com"]},
            {"ip": "5.6.7.8", "hostnames": ["b.com"]},
        ]
    })
    findings = check_host_aliases(r, "Deployment/test")
    assert len(findings) == 1
    assert "2 hostAlias" in findings[0]["detail"]


# ── check_unsafe_sysctls ──────────────────────────────────────────────────────

def test_unsafe_net_sysctl_detected():
    r = deployment([container(sc={"sysctls": {"net.ipv4.ip_forward": "1"}})])
    findings = check_unsafe_sysctls(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["check_id"] == "K8S-026"
    assert findings[0]["severity"] == "HIGH"


def test_unsafe_pod_level_sysctl_detected():
    r = deployment(spec_overrides={
        "securityContext": {"sysctls": {"net.ipv4.ip_forward": "1"}}
    })
    findings = check_unsafe_sysctls(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["check_id"] == "K8S-026"
    assert "pod" in findings[0]["title"].lower()


def test_unsafe_kernel_sysctl_detected():
    r = deployment([container(sc={"sysctls": {"kernel.shm_rmid_forced": "1"}})])
    findings = check_unsafe_sysctls(r, "Deployment/test")
    assert len(findings) == 1
    assert "kernel.shm_rmid_forced" in findings[0]["title"]


def test_safe_sysctl_no_finding():
    r = deployment([container(sc={"sysctls": {"net.core.somaxconn": "1024"}})])
    # somaxconn is net.* so it IS unsafe
    findings = check_unsafe_sysctls(r, "Deployment/test")
    assert len(findings) == 1


def test_no_sysctls_no_finding():
    r = deployment([container(sc={})])
    findings = check_unsafe_sysctls(r, "Deployment/test")
    assert findings == []


def test_custom_safe_sysctl_no_finding():
    # Custom sysctl with safe prefix (not net/kernel/fs/vm)
    r = deployment([container(sc={"sysctls": {"my.custom.setting": "42"}})])
    findings = check_unsafe_sysctls(r, "Deployment/test")
    assert findings == []


# ── check_fs_group ────────────────────────────────────────────────────────────

def test_missing_fs_group_with_volumes():
    r = deployment(volumes=[{"name": "data", "emptyDir": {}}])
    findings = check_fs_group(r, "Deployment/test")
    assert len(findings) == 1
    assert findings[0]["check_id"] == "K8S-027"
    assert findings[0]["severity"] == "LOW"


def test_fs_group_set_no_finding():
    r = deployment(
        spec_overrides={"securityContext": {"fsGroup": 1000}},
        volumes=[{"name": "data", "emptyDir": {}}],
    )
    findings = check_fs_group(r, "Deployment/test")
    assert findings == []


def test_no_volumes_no_finding():
    r = deployment()
    findings = check_fs_group(r, "Deployment/test")
    assert findings == []


def test_non_workload_kind_no_finding():
    resource = {
        "kind": "Service",
        "metadata": {"name": "test"},
        "spec": {"type": "ClusterIP"},
    }
    findings = check_fs_group(resource, "Service/test")
    assert findings == []
