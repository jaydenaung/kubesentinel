# Copyright 2026 Jayden Aung — Apache 2.0
"""
kubectl_sentinel — KubeSentinel kubectl plugin (pip-installable module)

This module is the authoritative implementation.
The `kubectl-sentinel` script at the repo root is a thin shim that calls main().
"""

import argparse
import base64
import json
import math
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# When running from the repo (not pip-installed), add the repo root so
# `import analyzer` resolves. When pip-installed, analyzer.py is in site-packages
# alongside this file — sys.path already covers it.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

try:
    from analyzer import run_static_checks
except ImportError:
    print("error: could not import analyzer — reinstall with: pip install kubesentinel", file=sys.stderr)
    sys.exit(1)

# ── Kubernetes client (optional — only needed for live cluster scans) ─────────
try:
    from kubernetes import client as _k8s, config as _k8s_cfg
    from kubernetes.client.rest import ApiException
    _HAS_K8S = True
except ImportError:
    _HAS_K8S = False

# ── ANSI colours ──────────────────────────────────────────────────────────────
_NO_COLOR = not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))

def _c(code: str, text: str) -> str:
    return text if _NO_COLOR else f"\033[{code}m{text}\033[0m"

def _sev(sev: str, text: str) -> str:
    codes = {"CRITICAL": "91;1", "HIGH": "33", "MEDIUM": "93", "LOW": "34", "INFO": "90"}
    return _c(codes.get(sev, "0"), text)

_bold   = lambda t: _c("1", t)
_dim    = lambda t: _c("2", t)
_green  = lambda t: _c("32", t)
_cyan   = lambda t: _c("36", t)
_purple = lambda t: _c("35", t)

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── Cluster resource fetcher ──────────────────────────────────────────────────
def _load_kubeconfig(context: Optional[str]) -> None:
    try:
        _k8s_cfg.load_kube_config(context=context)
    except Exception:
        try:
            _k8s_cfg.load_incluster_config()
        except Exception as e:
            print(f"error: cannot load kubeconfig: {e}", file=sys.stderr)
            sys.exit(1)


def _to_dict(api, obj) -> Dict:
    return api.sanitize_for_serialization(obj)


def _fetch_resources(namespace: Optional[str], context: Optional[str]) -> List[Dict]:
    _load_kubeconfig(context)
    api  = _k8s.ApiClient()
    apps = _k8s.AppsV1Api(api)
    core = _k8s.CoreV1Api(api)
    net  = _k8s.NetworkingV1Api(api)
    rbac = _k8s.RbacAuthorizationV1Api(api)

    resources: List[Dict] = []
    ns = namespace

    def collect(fn_ns, fn_all):
        try:
            items = (fn_ns(ns) if ns else fn_all()).items
            resources.extend(_to_dict(api, i) for i in items)
        except ApiException as exc:
            if exc.status not in (403, 404):
                raise

    try:
        collect(apps.list_namespaced_deployment,    apps.list_deployment_for_all_namespaces)
        collect(apps.list_namespaced_daemon_set,     apps.list_daemon_set_for_all_namespaces)
        collect(apps.list_namespaced_stateful_set,   apps.list_stateful_set_for_all_namespaces)
        collect(core.list_namespaced_service,        core.list_service_for_all_namespaces)
        collect(net.list_namespaced_ingress,         net.list_ingress_for_all_namespaces)
        collect(net.list_namespaced_network_policy,  net.list_network_policy_for_all_namespaces)
        collect(rbac.list_namespaced_role,           rbac.list_role_for_all_namespaces)
        try:
            resources.extend(_to_dict(api, i) for i in rbac.list_cluster_role().items)
        except ApiException:
            pass
    except ApiException as exc:
        print(f"error: cluster API returned {exc.status}: {exc.reason}", file=sys.stderr)
        sys.exit(1)

    return resources


def _cluster_name(context: Optional[str]) -> str:
    try:
        ctx = _k8s_cfg.list_kube_config_contexts()[1]
        return ctx.get("context", {}).get("cluster", "unknown")
    except Exception:
        return context or "current context"


# ── Compound risk correlation ─────────────────────────────────────────────────
def _correlate(findings: List[Dict], resources: List[Dict]) -> List[Dict]:
    netpol_ns: set = set()
    for r in resources:
        if r.get("kind") == "NetworkPolicy":
            netpol_ns.add(r.get("metadata", {}).get("namespace", "default"))

    hot_ctx: set = set()
    for f in findings:
        if f.get("severity") in ("CRITICAL", "HIGH"):
            hot_ctx.add(f.get("context", ""))

    compound: List[Dict] = []
    seen: set = set()

    for r in resources:
        kind = r.get("kind", "")
        if kind not in ("Deployment", "DaemonSet", "StatefulSet"):
            continue
        name = r.get("metadata", {}).get("name", "unnamed")
        ns   = r.get("metadata", {}).get("namespace", "default")
        ctx  = f"{kind}/{name}"
        if ctx in seen:
            continue
        seen.add(ctx)

        tspec   = r.get("spec", {}).get("template", {}).get("spec", {})
        sa_name = tspec.get("serviceAccountName", "default")
        auto_sa = tspec.get("automountServiceAccountToken") is not False

        signals, details, chain = [], [], []

        if ctx in hot_ctx:
            signals.append("misconfiguration")
            details.append("Has CRITICAL/HIGH security misconfigurations (privileged, root, hostPID…)")
            chain.append("exploit misconfiguration for container escape / host access")

        if ns not in netpol_ns:
            signals.append("network")
            details.append(f"Namespace '{ns}' has no NetworkPolicy — unrestricted east-west traffic")
            chain.append("reach pod from any namespace (no network isolation)")

        if auto_sa and "misconfiguration" in signals:
            signals.append("rbac")
            details.append(f"SA token '{sa_name}' auto-mounted — accessible to any process in container")
            chain.append("use mounted SA token for API server lateral movement")

        if len(signals) < 2:
            continue

        has_misc = "misconfiguration" in signals
        has_rbac = "rbac" in signals
        sev = "CRITICAL" if (has_misc and has_rbac) or len(signals) >= 3 else "HIGH"
        cid = f"CMP-00{min(len(signals), 4)}"

        compound.append({
            "source":          "compound",
            "check_id":        cid,
            "severity":        sev,
            "context":         ctx,
            "title":           f"Compound risk ({len(signals)} signals): {' + '.join(signals)}",
            "detail":          (
                f"This workload has {len(signals)} correlated risk signals:\n"
                + "\n".join(f"• {d}" for d in details)
            ),
            "remediation":     (
                "1) Fix misconfigurations (privileged:false, runAsNonRoot:true). "
                "2) Set automountServiceAccountToken:false. "
                "3) Add default-deny NetworkPolicy."
            ),
            "attack_scenario": "Attacker chain: " + " → ".join(chain) + ".",
            "resource_path":   "",
        })

    return compound


# ── SA privilege probe ────────────────────────────────────────────────────────
_PROBE_VERBS = [
    ("get",    "secrets"),
    ("list",   "secrets"),
    ("create", "pods"),
    ("delete", "pods"),
    ("get",    "nodes"),
]

def _sa_probe(namespace: Optional[str]) -> List[Dict]:
    findings: List[Dict] = []
    try:
        ns_flag = ["-n", namespace] if namespace else ["-A"]
        r = subprocess.run(
            ["kubectl", "get", "serviceaccounts"] + ns_flag + ["-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return []
        sas = json.loads(r.stdout).get("items", [])
    except Exception:
        return []

    for sa in sas[:12]:
        sa_name = sa["metadata"]["name"]
        sa_ns   = sa["metadata"].get("namespace", "default")
        if sa_name == "default":
            continue

        confirmed: List[str] = []
        for verb, resource in _PROBE_VERBS:
            try:
                result = subprocess.run(
                    ["kubectl", "auth", "can-i", verb, resource,
                     f"--as=system:serviceaccount:{sa_ns}:{sa_name}",
                     "-n", sa_ns],
                    capture_output=True, text=True, timeout=5,
                )
                if result.stdout.strip() == "yes":
                    confirmed.append(f"{verb} {resource}")
            except Exception:
                continue

        if confirmed:
            findings.append({
                "source":        "sa-probe",
                "check_id":      "SA-001",
                "severity":      "HIGH",
                "context":       f"ServiceAccount/{sa_name} ({sa_ns})",
                "title":         f"Over-privileged service account: {sa_name}",
                "detail":        f"Runtime probe confirmed SA '{sa_name}' ({sa_ns}) can: {', '.join(confirmed)}",
                "remediation":   "Apply least-privilege RBAC. Remove broad ClusterRoleBindings.",
                "resource_path": "",
            })

    return findings


# ── Probe: secret analysis ───────────────────────────────────────────────────
#
# Each pattern: (check_id, label, regex, severity, mitre_tags, remediation)
# Ordered CRITICAL → HIGH → MEDIUM so first match wins on overlapping patterns.
#
_SECRET_PATTERNS: List[Tuple] = [
    # ── CRITICAL ─────────────────────────────────────────────────────────────
    ("PRB-S001", "AWS long-term access key",
     r"AKIA[0-9A-Z]{16}",
     "CRITICAL", ["T1552.001"],
     "Rotate immediately. Replace with IAM role + short-lived STS credentials."),

    ("PRB-S002", "Private key material",
     r"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY",
     "CRITICAL", ["T1552.001", "T1588.004"],
     "Rotate key pair. Use Vault PKI or cert-manager for lifecycle management."),

    ("PRB-S003", "GCP service account key",
     r'"type"\s*:\s*"service_account"',
     "CRITICAL", ["T1552.001"],
     "Rotate service account key. Migrate to Workload Identity Federation."),

    ("PRB-S004", "Stripe live secret key",
     r"sk_live_[a-zA-Z0-9]{24,}",
     "CRITICAL", ["T1552.001"],
     "Rotate immediately at dashboard.stripe.com/apikeys."),

    # ── HIGH ─────────────────────────────────────────────────────────────────
    ("PRB-S005", "AWS STS temporary credentials",
     r"ASIA[0-9A-Z]{16}",
     "HIGH", ["T1552.001"],
     "STS tokens stored in Secrets indicate credential leakage from an IAM role."),

    ("PRB-S006", "GitHub Personal Access Token",
     r"(?:ghp|ghs|gho|ghu|ghr)_[a-zA-Z0-9]{32,}",
     "HIGH", ["T1552.001"],
     "Rotate at github.com/settings/tokens. Use OIDC instead of PATs in CI/CD."),

    ("PRB-S007", "GitHub fine-grained PAT",
     r"github_pat_[a-zA-Z0-9_]{82}",
     "HIGH", ["T1552.001"],
     "Rotate at github.com/settings/tokens."),

    ("PRB-S008", "Stripe test key",
     r"sk_test_[a-zA-Z0-9]{24,}",
     "HIGH", ["T1552.001"],
     "Test keys still grant full API access. Inject from CI/CD, not K8s secrets."),

    ("PRB-S009", "Slack bot token",
     r"xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
     "HIGH", ["T1552.001"],
     "Rotate at api.slack.com/apps."),

    ("PRB-S010", "Slack user/app token",
     r"xox[pa]-[0-9]+-[0-9\-a-zA-Z]+",
     "HIGH", ["T1552.001"],
     "Rotate at api.slack.com/apps. User tokens grant broad account access."),

    ("PRB-S011", "SendGrid API key",
     r"SG\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{40,}",
     "HIGH", ["T1552.001"],
     "Rotate at app.sendgrid.com/settings/api_keys."),

    ("PRB-S012", "npm access token",
     r"npm_[a-zA-Z0-9]{32,}",
     "HIGH", ["T1552.001"],
     "Rotate at npmjs.com. Use scoped publish-only tokens."),

    ("PRB-S013", "OpenAI API key",
     r"sk-[a-zA-Z0-9]{48}",
     "HIGH", ["T1552.001"],
     "Rotate at platform.openai.com/api-keys."),

    ("PRB-S014", "HuggingFace token",
     r"hf_[a-zA-Z0-9]{34}",
     "HIGH", ["T1552.001"],
     "Rotate at huggingface.co/settings/tokens."),

    ("PRB-S015", "Twilio API key",
     r"SK[a-f0-9]{32}",
     "HIGH", ["T1552.001"],
     "Rotate at console.twilio.com/project/api-keys."),

    ("PRB-S016", "Datadog API key",
     r"(?i)(?:dd_api_key|datadog.api.key)\s*[=:]\s*[a-f0-9]{32}",
     "HIGH", ["T1552.001"],
     "Rotate at app.datadoghq.com/organization-settings/api-keys."),

    # ── MEDIUM ───────────────────────────────────────────────────────────────
    ("PRB-S017", "Database DSN with embedded password",
     r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|mssql|sqlserver)"
     r"://[^:@\s]{1,64}:[^@\s]{1,256}@",
     "MEDIUM", ["T1552.001"],
     "Move password to a dedicated Secret key. Use IAM auth where supported."),

    ("PRB-S018", "URL with embedded credentials",
     r"https?://[^:@\s]{1,64}:[^@\s]{4,256}@[^@\s]{1,256}",
     "MEDIUM", ["T1552.001"],
     "Extract credentials from URL into separate username/password fields."),

    ("PRB-S019", "JDBC connection string with password",
     r"jdbc:[a-z]+://[^\s]*(?:password|passwd)=[^\s;&]{4,}",
     "MEDIUM", ["T1552.001"],
     "Remove embedded password from JDBC URL."),

    ("PRB-S020", "Docker registry credentials",
     r'"auth"\s*:\s*"[a-zA-Z0-9+/=]{12,}"',
     "MEDIUM", ["T1552.001"],
     "Rotate registry credentials. Use short-lived tokens or OIDC where available."),
]

# Key names that suggest the value is intentionally a credential;
# used to gate the entropy check so we avoid flagging random app config.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|pass(?:wd)?|secret|api[_.\-]?key|auth[_.\-]?token"
    r"|credential|private[_.\-]?key|access[_.\-]?key|client[_.\-]?secret)",
)

# Secret names / key names we skip (system noise, not useful to analyse)
_SKIP_SECRET_PREFIXES = ("sh.helm.release.", "bootstrap-token-")
_SKIP_KEYS = frozenset({"namespace", "ca.crt", "service-ca.crt"})


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _decode_value(raw: str) -> Optional[str]:
    try:
        return base64.b64decode(raw).decode("utf-8")
    except Exception:
        return None


def _redact(value: str, keep: int = 16) -> str:
    if len(value) <= keep:
        return value
    return value[:keep] + "…[redacted]"


def _match_patterns(key: str, value: str) -> List[Dict]:
    hits: List[Dict] = []
    matched_ids: set = set()

    for check_id, label, pattern, severity, mitre, remediation in _SECRET_PATTERNS:
        m = re.search(pattern, value)
        if m:
            matched_ids.add(check_id)
            hits.append({
                "check_id":    check_id,
                "label":       label,
                "severity":    severity,
                "mitre":       mitre,
                "remediation": remediation,
                "matched_key": key,
                "snippet":     _redact(m.group(0)),
            })

    # Entropy fallback: flag high-entropy values in suspiciously-named keys
    # only when no format pattern already matched.
    if not hits and _SENSITIVE_KEY_RE.search(key):
        printable = value.strip()
        entropy = _shannon_entropy(printable)
        if entropy >= 4.0 and 8 <= len(printable) <= 512:
            hits.append({
                "check_id":    "PRB-S021",
                "label":       "High-entropy value in credential-named key",
                "severity":    "MEDIUM",
                "mitre":       ["T1552.001"],
                "remediation": "Review manually — may be a password or secret not matching a known format.",
                "matched_key": key,
                "snippet":     _redact(printable, 12) + f"  [entropy {entropy:.1f}]",
            })

    return hits


def _probe_secrets(
    namespace: Optional[str],
    context:   Optional[str],
    all_ns:    bool,
    show_values: bool,
) -> Tuple[List[Dict], Dict]:
    _load_kubeconfig(context)
    api  = _k8s.ApiClient()
    core = _k8s.CoreV1Api(api)

    try:
        items = (
            core.list_secret_for_all_namespaces().items
            if (all_ns or not namespace)
            else core.list_namespaced_secret(namespace).items
        )
    except ApiException as exc:
        print(f"error: cannot list secrets — {exc.status} {exc.reason}", file=sys.stderr)
        if exc.status == 403:
            print("  hint: your kubeconfig context needs 'get' and 'list' on secrets", file=sys.stderr)
        sys.exit(1)

    findings: List[Dict] = []

    for secret in items:
        name  = secret.metadata.name
        ns    = secret.metadata.namespace
        stype = secret.type or "Opaque"

        if any(name.startswith(p) for p in _SKIP_SECRET_PREFIXES):
            continue

        for key, raw in (secret.data or {}).items():
            if not raw or key in _SKIP_KEYS:
                continue
            decoded = _decode_value(raw)
            if decoded is None:
                continue

            for hit in _match_patterns(key, decoded):
                findings.append({
                    "source":        "probe-secrets",
                    "check_id":      hit["check_id"],
                    "severity":      hit["severity"],
                    "context":       f"Secret/{name} ({ns})",
                    "secret_name":   name,
                    "secret_ns":     ns,
                    "secret_type":   stype,
                    "title":         hit["label"],
                    "secret_key":    hit["matched_key"],
                    "snippet":       decoded if show_values else hit["snippet"],
                    "mitre":         hit["mitre"],
                    "detail":        f"Key '{hit['matched_key']}' — {hit['label']}",
                    "remediation":   hit["remediation"],
                    "resource_path": f"{ns}/{name}",
                })

    findings.sort(key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 4))

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    meta = {
        "cluster":      _cluster_name(context),
        "namespace":    namespace or "all namespaces",
        "secret_count": len(items),
        "counts":       counts,
        "timestamp":    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    return findings, meta


# ── Probe output: table ───────────────────────────────────────────────────────

def _print_secrets_table(findings: List[Dict], meta: Dict) -> None:
    W = 64
    print()
    print(_bold("  KubeSentinel Probe") + " — secret analysis")
    print()
    print(f"  {'Cluster:':<14} {meta.get('cluster', '—')}")
    print(f"  {'Namespace:':<14} {meta.get('namespace', '—')}")
    print(f"  {'Secrets scanned:':<14} {meta.get('secret_count', 0)}")
    print(f"  {'Timestamp:':<14} {meta.get('timestamp', '—')}")
    print()

    if not findings:
        print("  " + _green("✓  No credential patterns detected in any secret."))
        print()
        return

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = [f for f in findings if f.get("severity") == sev]
        if not group:
            continue
        header = f"━━  {sev} ({len(group)})  "
        print("  " + _sev(sev, header) + _dim("━" * max(0, W - len(header))))
        for f in group:
            print()
            cid  = f.get("check_id", "")
            ctx  = f.get("context", "")
            key  = f.get("secret_key", "")
            snip = f.get("snippet", "")
            mitre = "  ".join(f.get("mitre") or [])
            print(f"  {_sev(sev, f'[{sev[:4]}]')}  {_cyan(f'{cid:<10}')}  {ctx}")
            print(f"        {_bold(f.get('title', ''))}")
            print(f"        key: {_dim(key)}  →  {snip}")
            if mitre:
                print(f"        {_dim('MITRE: ' + mitre)}")
            rem = f.get("remediation", "")
            if rem:
                print(f"        {_dim(rem[:88])}")
        print()

    counts = meta.get("counts", {})
    print("  " + _bold("━━  SUMMARY  " + "━" * (W - 12)))
    print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        if n:
            print(f"  {sev + ':':<16} {_sev(sev, str(n))}")
    print(f"  {'Total findings:':<16} {_bold(str(len(findings)))}")
    print()

    if counts.get("CRITICAL", 0):
        print(f"  {_sev('CRITICAL', '✗')}  Rotate CRITICAL credentials immediately.")
    elif counts.get("HIGH", 0):
        print(f"  {_sev('HIGH', '!')}  High-severity credentials detected — rotate promptly.")
    else:
        print(f"  {_green('✓')}  No critical or high credential exposures.")
    print()
    if sys.stdout.isatty():
        print(_dim("  --output json     pipe-friendly JSON"))
        print(_dim("  --output report   markdown for pentest reports"))
        print(_dim("  --show-values     show full credential values"))
        print()


# ── Probe output: markdown report ────────────────────────────────────────────

def _print_secrets_report(findings: List[Dict], meta: Dict) -> None:
    counts = meta.get("counts", {})
    lines  = []

    lines.append("# KubeSentinel Probe — Secret Analysis\n")
    lines.append(f"**Cluster:** {meta.get('cluster', '—')}  ")
    lines.append(f"**Namespace:** {meta.get('namespace', '—')}  ")
    lines.append(f"**Secrets scanned:** {meta.get('secret_count', 0)}  ")
    lines.append(f"**Date:** {meta.get('timestamp', '—')}  \n")

    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"| {sev} | {n} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    if not findings:
        lines.append("No credential patterns detected.\n")
        print("\n".join(lines))
        return

    lines.append("## Findings\n")
    for f in findings:
        sev   = f.get("severity", "")
        cid   = f.get("check_id", "")
        title = f.get("title", "")
        lines.append(f"### [{sev}] {cid} — {title}\n")
        lines.append(f"**Secret:** `{f.get('secret_name', '')}` ({f.get('secret_ns', '')})  ")
        lines.append(f"**Type:** `{f.get('secret_type', '')}` ")
        lines.append(f"**Key:** `{f.get('secret_key', '')}`  ")
        lines.append(f"**Value (truncated):** `{f.get('snippet', '')}`  ")
        mitre = ", ".join(f.get("mitre") or [])
        if mitre:
            lines.append(f"**MITRE ATT&CK:** {mitre}  ")
        lines.append(f"\n**Remediation:** {f.get('remediation', '')}\n")

    lines.append("---")
    lines.append("*Generated by KubeSentinel probe — github.com/jaydenaung/kubesentinel*")
    print("\n".join(lines))


# ── Probe output: JSON ────────────────────────────────────────────────────────

def _print_secrets_json(findings: List[Dict], meta: Dict) -> None:
    print(json.dumps({
        "scanner":   "kubesentinel-probe",
        "probe":     "secrets",
        "cluster":   meta.get("cluster"),
        "namespace": meta.get("namespace"),
        "timestamp": meta.get("timestamp"),
        "summary":   meta.get("counts", {}),
        "findings":  findings,
    }, indent=2))


# ── Output: table ─────────────────────────────────────────────────────────────
def _print_table(findings: List[Dict], meta: Dict) -> None:
    W = 60
    print()
    print(_bold("  KubeSentinel") + " — kubectl static scan")
    print()
    print(f"  {'Cluster:':<12} {meta.get('cluster', '—')}")
    print(f"  {'Namespace:':<12} {meta.get('namespace', 'all namespaces')}")
    print(f"  {'Resources:':<12} {meta.get('resource_count', 0)} scanned")
    print(f"  {'Checks:':<12} 24 static · compound risk · SA probe")
    print()

    if not findings:
        print("  " + _green("✓  No findings — clean scan."))
        print()
        return

    compound = [f for f in findings if f.get("source") == "compound"]
    by_sev: Dict[str, List] = {s: [] for s in SEV_ORDER}
    for f in findings:
        if f.get("source") != "compound":
            by_sev.setdefault(f.get("severity", "INFO"), []).append(f)

    if compound:
        print("  " + _purple("━━  COMPOUND RISK  " + "━" * (W - 18)))
        for f in compound:
            sev = f.get("severity", "HIGH")
            print()
            print(f"  {_sev(sev, f'[{sev}]')}  {_bold(f.get('check_id',''))}  {_cyan(f.get('context',''))}")
            print(f"  {_dim(f.get('title',''))}")
            for line in f.get("detail", "").split("\n"):
                if line.strip():
                    print(f"    {_dim(line)}")
            if f.get("attack_scenario"):
                print(f"    {_purple('⛓  ' + f['attack_scenario'])}")
        print()

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = by_sev.get(sev, [])
        if not group:
            continue
        header = f"━━  {sev} ({len(group)})  "
        print("  " + _sev(sev, header) + _dim("━" * max(0, W - len(header))))
        for f in group:
            print()
            cid = f.get("check_id", "")
            print(f"  {_sev(sev, f'[{sev[:4]}]')}  {_cyan(f'{cid:<10}')}  {f.get('context','')}")
            print(f"        {f.get('title','')}")
            rem = f.get("remediation", "")
            if rem:
                print(f"        {_dim(rem[:90])}")
        print()

    total    = len(findings)
    n_crit   = len(by_sev.get("CRITICAL", []))
    n_high   = len(by_sev.get("HIGH", [])) + len([f for f in compound if f.get("severity") == "HIGH"])
    n_comp_c = len([f for f in compound if f.get("severity") == "CRITICAL"])

    print("  " + _bold("━━  SUMMARY  " + "━" * (W - 12)))
    print()
    if compound:
        print(f"  {'Compound risk:':<18} {_purple(str(len(compound)))}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = len(by_sev.get(sev, []))
        if n:
            print(f"  {sev + ':':<18} {_sev(sev, str(n))}")
    print(f"  {'Total:':<18} {_bold(str(total))}")
    print()

    if n_crit or n_comp_c:
        print(f"  {_sev('CRITICAL', '✗')} Critical findings require immediate action.")
    elif n_high:
        print(f"  {_sev('HIGH', '!')} High-severity findings detected.")
    else:
        print(f"  {_green('✓')} No critical or high findings.")
    print()

    if sys.stdout.isatty():
        print(_dim("  --output json  for CI/CD pipelines"))
        print(_dim("  --output sarif for GitHub Advanced Security"))
        print()


# ── Output: JSON ──────────────────────────────────────────────────────────────
def _print_json(findings: List[Dict], meta: Dict) -> None:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1
    print(json.dumps({
        "scanner":   "kubesentinel",
        "version":   "1.0.0",
        "cluster":   meta.get("cluster"),
        "namespace": meta.get("namespace"),
        "summary": {
            "critical": counts.get("CRITICAL", 0),
            "high":     counts.get("HIGH", 0),
            "medium":   counts.get("MEDIUM", 0),
            "low":      counts.get("LOW", 0),
            "total":    len(findings),
        },
        "findings": findings,
    }, indent=2))


# ── Output: SARIF ─────────────────────────────────────────────────────────────
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

def _print_sarif(findings: List[Dict], meta: Dict) -> None:
    rules: Dict[str, Dict] = {}
    for f in findings:
        cid = f.get("check_id", "UNKNOWN")
        if cid not in rules:
            rules[cid] = {
                "id":               cid,
                "name":             cid.replace("-", ""),
                "shortDescription": {"text": f.get("title", cid)},
                "helpUri":          "https://github.com/jaydenaung/kubesentinel",
                "properties":       {"tags": ["security", "kubernetes"]},
            }
    results = [{
        "ruleId":  f.get("check_id", "UNKNOWN"),
        "level":   _SARIF_LEVEL.get(f.get("severity", "INFO"), "note"),
        "message": {
            "text": " ".join(filter(None, [
                f.get("title", ""),
                f.get("detail", ""),
                f"Remediation: {f.get('remediation')}" if f.get("remediation") else "",
            ]))
        },
        "locations": [{"physicalLocation": {"artifactLocation": {
            "uri": f.get("resource_path") or f.get("context", "cluster"),
        }}}],
    } for f in findings]
    print(json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name":           "KubeSentinel",
            "version":        "0.1.0",
            "informationUri": "https://github.com/jaydenaung/kubesentinel",
            "rules":          list(rules.values()),
        }}, "results": results}],
    }, indent=2))


# ── CLI ───────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="kubectl-sentinel",
        description="KubeSentinel — static Kubernetes security scanner (no API key required)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  kubectl sentinel scan
  kubectl sentinel scan -n production
  kubectl sentinel scan --output json | jq '.findings[] | select(.severity=="CRITICAL")'
  kubectl sentinel scan --fail-on CRITICAL && kubectl apply -f .
  kubectl sentinel scan --output sarif > results.sarif
  kubectl sentinel scan --file deployment.yaml
        """,
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version", help="Print version and exit")

    # ── probe subcommand ──────────────────────────────────────────────────
    prob = sub.add_parser(
        "probe",
        help="Active security probes — enumerate exposed credentials, RBAC blast radius, and more",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
probes:
  secrets   Enumerate Kubernetes secrets and detect exposed credentials,
            API keys, passwords, and private key material.

examples:
  kubectl sentinel probe secrets -n production
  kubectl sentinel probe secrets -A --output json | jq '.findings[] | select(.severity=="CRITICAL")'
  kubectl sentinel probe secrets -n staging --output report > findings.md
  kubectl sentinel probe secrets -n production --show-values
        """,
    )
    prob_sub = prob.add_subparsers(dest="probe_command")

    ps = prob_sub.add_parser("secrets", help="Detect exposed credentials in Kubernetes secrets")
    ps.add_argument("-n", "--namespace", metavar="NS",
                    help="Namespace to probe (default: current namespace)")
    ps.add_argument("-A", "--all-namespaces", action="store_true", dest="all_namespaces",
                    help="Probe all namespaces")
    ps.add_argument("--context", metavar="CTX",
                    help="kubeconfig context (default: current context)")
    ps.add_argument("--output", "-o", choices=["table", "json", "report"], default="table",
                    help="Output format (default: table)")
    ps.add_argument("--show-values", action="store_true", dest="show_values",
                    help="Show full credential values — caution: sensitive output")
    ps.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    metavar="SEV", dest="fail_on",
                    help="Exit 1 if any finding at or above this severity is found")

    # ── scan subcommand ───────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="Scan a live cluster or a local manifest file")
    sp.add_argument("-n", "--namespace", metavar="NS",
                    help="Namespace to scan (default: all namespaces)")
    sp.add_argument("--context",         metavar="CTX",
                    help="kubeconfig context (default: current context)")
    sp.add_argument("--output", "-o",    choices=["table", "json", "sarif"], default="table")
    sp.add_argument("--fail-on",         choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    metavar="SEV", dest="fail_on",
                    help="Exit 1 if any finding at or above this severity is found")
    sp.add_argument("--file", "-f",      metavar="FILE",
                    help="Scan a local YAML manifest instead of a live cluster")
    sp.add_argument("--no-probe",        action="store_true",
                    help="Skip SA privilege probe")
    sp.add_argument("--no-compound",     action="store_true",
                    help="Skip compound risk correlation")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        print("kubectl-sentinel 1.1.0")
        sys.exit(0)

    # ── probe dispatch ─────────────────────────────────────────────────────
    if args.command == "probe":
        if not getattr(args, "probe_command", None):
            prob.print_help()
            sys.exit(0)

        if args.probe_command == "secrets":
            if not _HAS_K8S:
                print("error: 'kubernetes' package not installed. Run: pip install kubernetes",
                      file=sys.stderr)
                sys.exit(1)
            if args.output == "table":
                hint = f" ({args.context})" if args.context else ""
                print(_dim(f"  Probing secrets{hint}…"), end="\r", flush=True)

            findings, meta = _probe_secrets(
                namespace    = args.namespace,
                context      = args.context,
                all_ns       = args.all_namespaces,
                show_values  = args.show_values,
            )

            if args.output == "table":
                _print_secrets_table(findings, meta)
            elif args.output == "json":
                _print_secrets_json(findings, meta)
            elif args.output == "report":
                _print_secrets_report(findings, meta)

            if args.fail_on:
                threshold = SEV_ORDER[args.fail_on]
                if any(SEV_ORDER.get(f.get("severity", "INFO"), 4) <= threshold for f in findings):
                    sys.exit(1)
            sys.exit(0)

    # ── Fetch resources ────────────────────────────────────────────────────
    if args.file:
        import yaml as _yaml
        path = Path(args.file)
        if not path.exists():
            print(f"error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        if path.stat().st_size > 50 * 1024 * 1024:
            print("error: file exceeds 50MB limit", file=sys.stderr)
            sys.exit(1)
        with open(path) as fh:
            resources = [d for d in _yaml.safe_load_all(fh) if d]
        meta = {"cluster": args.file, "namespace": "—", "resource_count": len(resources)}
    else:
        if not _HAS_K8S:
            print("error: 'kubernetes' package not installed. Run: pip install kubernetes", file=sys.stderr)
            sys.exit(1)
        if args.output == "table":
            hint = f" ({args.context})" if args.context else ""
            print(_dim(f"  Connecting to cluster{hint}…"), end="\r", flush=True)
        resources = _fetch_resources(args.namespace, args.context)
        meta = {
            "cluster":        _cluster_name(args.context),
            "namespace":      args.namespace or "all namespaces",
            "resource_count": len(resources),
        }

    # ── Run checks ────────────────────────────────────────────────────────
    findings: List[Dict] = run_static_checks(resources)

    if not args.file and not args.no_probe:
        findings.extend(_sa_probe(args.namespace))

    if not args.no_compound:
        findings = _correlate(findings, resources) + findings

    findings.sort(key=lambda f: (
        0 if f.get("source") == "compound" else 1,
        SEV_ORDER.get(f.get("severity", "INFO"), 4),
    ))

    # ── Emit ──────────────────────────────────────────────────────────────
    if args.output == "table":
        _print_table(findings, meta)
    elif args.output == "json":
        _print_json(findings, meta)
    elif args.output == "sarif":
        _print_sarif(findings, meta)

    # ── CI exit code ──────────────────────────────────────────────────────
    if args.fail_on:
        threshold = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER.get(f.get("severity", "INFO"), 4) <= threshold for f in findings):
            sys.exit(1)


if __name__ == "__main__":
    main()
