# Security Policy

## Supported Versions

Only the latest release receives security fixes. We do not backport patches to older versions.

| Version | Supported |
|---|---|
| 1.0.x (latest) | ✅ |
| < 1.0.0 | ❌ — do not use |

All images and packages below v1.0.0 have been removed from Docker Hub, GHCR, and PyPI.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately by email:

**jaydenaung@gmail.com**

Use the subject line: `[KubeSentinel Security] <brief description>`

### What to include

- Description of the vulnerability and its potential impact
- Steps to reproduce (environment, version, exact commands)
- Any proof-of-concept code or screenshots
- Your suggested severity (Critical / High / Medium / Low)

### What to expect

| Timeline | Commitment |
|---|---|
| **48 hours** | Acknowledgement of your report |
| **7 days** | Initial assessment and severity rating |
| **30 days** | Fix released for Critical and High findings |
| **90 days** | Fix released for Medium and Low findings |

We will keep you informed throughout the process and credit you in the release notes unless you prefer to remain anonymous.

---

## Scope

### In scope

- The KubeSentinel web dashboard (`server.py`, `web/`)
- The kubectl plugin (`kubectl-sentinel`, `kubectl_sentinel.py`)
- The static analysis engine (`analyzer.py`)
- The Docker images (`jaydenaung17/kubesentinel`, `ghcr.io/jaydenaung/kubesentinel`)
- The PyPI package (`kubesentinel`)
- Authentication and session management
- RBAC and access control between users
- Any vulnerability that could compromise a connected Kubernetes cluster

### Out of scope

- Vulnerabilities in third-party dependencies (report these to the upstream project directly; we track them via `pip-audit` and Dependabot)
- Findings against demo or test instances
- Social engineering
- Denial of service that requires authentication and cluster access
- Issues in versions below v1.0.0 (no longer supported)

---

## Security Design

### What KubeSentinel does NOT do

- **Never modifies your cluster** — all operations are read-only (`kubectl get`, `kubectl auth can-i`)
- **Never stores credentials in the image** — kubeconfigs and API keys live in the mounted volume only
- **Never phones home** — no telemetry, no analytics, no data leaves your environment unless you configure a SIEM webhook
- **Never exposes AI provider identity** at runtime — the underlying AI provider is not disclosed in the UI or API

### Protections in v1.0.0

- CSRF protection (Origin header + synchronizer token) on all state-changing endpoints
- SSRF prevention on webhook URLs (RFC-1918, link-local, and metadata service blocked)
- Path traversal sanitisation on all file uploads
- Login rate limiting (10 attempts per 5-minute window per IP)
- Object-level authorisation — users can only access their own clusters and manifests
- Security response headers on every response (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- Session cookie: `SameSite=Strict`, `HttpOnly`, 1-hour expiry
- HTTPS support via `--ssl-certfile` / `--ssl-keyfile` with `HTTPS_ONLY=true`
- Non-root container user (`kubesentinel`, UID 999)
- All subprocess calls use list form — no shell injection risk
- Safe YAML parsing (`yaml.safe_load`) — no arbitrary code execution from manifests

### Known limitations (open items)

The following items are known and being tracked for a future release:

- Sensitive settings (webhook token) are stored in plaintext in the SQLite database
- No encryption at rest for kubeconfig files on disk
- No structured audit log for authentication events
- No Vault / KMS integration for secret management
- Session is not invalidated server-side on user deactivation
- SQLite WAL mode not explicitly enabled

---

## Security Test Benchmark

A documented set of security tests with exact reproduction steps is maintained at [`tmp/security_tests.md`](tmp/security_tests.md). Third-party assessors should use this as the baseline for their engagement.

---

## Disclosure Policy

KubeSentinel follows **coordinated disclosure**:

1. Researcher reports privately
2. We confirm and assess within 7 days
3. We develop and test a fix
4. Fix is released, researcher is credited
5. Public disclosure after 30 days (Critical/High) or 90 days (Medium/Low), or earlier by mutual agreement

We will not pursue legal action against researchers who act in good faith and follow this policy.

---

## PGP

PGP signing is not yet set up. If you need to send sensitive information encrypted before we have this in place, mention it in your initial email and we will arrange a secure channel.
