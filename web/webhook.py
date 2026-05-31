# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/webhook.py — SIEM webhook dispatcher

Fires a POST after every completed scan to a configurable endpoint.
Supports generic JSON (Elastic, Datadog, custom) and Splunk HEC format.

Configuration (env vars):
  WEBHOOK_URL     — endpoint to POST to (required to enable)
  WEBHOOK_TOKEN   — auth token; sent as "Bearer <token>" or "Splunk <token>"
  WEBHOOK_FORMAT  — "json" (default) or "splunk"

Errors are silently logged — a broken webhook never affects scan results.
"""

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional
from urllib.parse import urlparse

from web.database import Finding, Scan, get_db

_SUPPORTED_FORMATS = ("json", "splunk")
_ALLOWED_SCHEMES   = {"http", "https"}

# Private/reserved ranges that must never be webhook targets (SSRF prevention)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _validate_webhook_url(url: str) -> bool:
    """Return True only if the URL is safe to POST to (blocks SSRF targets)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False

    host = parsed.hostname or ""
    if not host:
        return False

    # If host is an IP address, check against blocked ranges
    try:
        addr = ipaddress.ip_address(host)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                return False
        return True
    except ValueError:
        pass  # hostname — DNS resolution not checked here; rely on scheme + blocked-range checks

    # Block obvious loopback/internal hostnames
    blocked_hosts = {"localhost", "metadata.google.internal", "169.254.169.254"}
    if host.lower() in blocked_hosts:
        return False

    return True


def _build_payload(scan: Scan, findings: list) -> Dict:
    return {
        "source":       "kubesentinel",
        "scan_id":      scan.id,
        "scan_type":    scan.scan_type,
        "target":       scan.target_name,
        "scan_mode":    scan.scan_mode,
        "triggered_by": scan.triggered_by,
        "status":       scan.status,
        "started_at":   scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "summary": {
            "critical": scan.critical_count or 0,
            "high":     scan.high_count or 0,
            "medium":   scan.medium_count or 0,
            "low":      scan.low_count or 0,
            "total":    (scan.critical_count or 0) + (scan.high_count or 0)
                        + (scan.medium_count or 0) + (scan.low_count or 0),
        },
        "findings": [
            {
                "check_id":       f.check_id,
                "severity":       f.severity,
                "source":         f.source,
                "context":        f.context,
                "title":          f.title,
                "detail":         f.detail,
                "remediation":    f.remediation,
                "resource_path":  f.resource_path,
                "attack_scenario": f.attack_scenario,
            }
            for f in findings
        ],
    }


def _cfg(db_key: str, env_key: str, default: str = "") -> str:
    """Read a config value from the DB settings table, falling back to env var."""
    from web.database import get_setting
    val = get_setting(db_key)
    return val if val else os.environ.get(env_key, default)


def dispatch(scan_id: int) -> None:
    """POST scan results to the configured webhook. No-op if WEBHOOK_URL is unset."""
    url = _cfg("webhook_url", "WEBHOOK_URL").strip()
    if not url:
        return
    if not _validate_webhook_url(url):
        print(f"[webhook] blocked unsafe URL: {url}")
        return

    token  = _cfg("webhook_token", "WEBHOOK_TOKEN").strip()
    fmt    = _cfg("webhook_format", "WEBHOOK_FORMAT", "json").lower()
    if fmt not in _SUPPORTED_FORMATS:
        fmt = "json"

    try:
        with get_db() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            payload = _build_payload(scan, findings)
            db.expunge_all()

        if fmt == "splunk":
            body       = json.dumps({"time": int(time.time()), "sourcetype": "kubesentinel:scan", "event": payload})
            auth_value = f"Splunk {token}" if token else None
        else:
            body       = json.dumps(payload)
            auth_value = f"Bearer {token}" if token else None

        req = urllib.request.Request(
            url,
            data=body.encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if auth_value:
            req.add_header("Authorization", auth_value)

        with urllib.request.urlopen(req, timeout=10) as resp:
            _ = resp.read()

    except Exception as exc:
        print(f"[webhook] dispatch failed for scan {scan_id}: {exc}")
