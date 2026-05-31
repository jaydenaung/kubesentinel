# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/routes/compliance.py — CIS compliance routes.

GET  /compliance                       List clusters with their latest CIS score.
POST /compliance/clusters/<id>/scan    Trigger a CIS scan against a cluster.
GET  /compliance/scans/<id>            View per-control results for a scan.
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import RedirectResponse
from web.secure_templates import SecureTemplates

from web.auth import check_login
from web.cis_scanner import DEFAULT_FRAMEWORK, run_cis_scan
from web.database import Cluster, ComplianceResult, Scan, get_db

router = APIRouter()
templates = SecureTemplates(directory="web/templates")


_STATUS_ORDER = {"FAIL": 0, "ERROR": 1, "MANUAL": 2, "SKIP": 3, "PASS": 4}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, None: 5}


def _score_band(score: int | None) -> str:
    if score is None:
        return "unknown"
    if score >= 90:
        return "good"
    if score >= 70:
        return "ok"
    return "bad"


@router.get("/compliance")
async def compliance_list(request: Request):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        clusters = db.query(Cluster).order_by(Cluster.name).all()
        rows = []
        for c in clusters:
            latest = (
                db.query(Scan)
                .filter(Scan.scan_type == "cluster",
                        Scan.target_id == c.id,
                        Scan.framework.isnot(None))
                .order_by(Scan.id.desc())
                .first()
            )
            rows.append({
                "cluster": c,
                "latest_scan": latest,
                "score_band": _score_band(latest.compliance_score if latest else None),
            })
        db.expunge_all()

    return templates.TemplateResponse(request, "compliance_list.html", context={
        "user":    user,
        "rows":    rows,
        "default_framework": DEFAULT_FRAMEWORK,
    })


@router.post("/compliance/clusters/{cluster_id}/scan")
async def trigger_compliance_scan(
    request: Request,
    cluster_id: int,
    background_tasks: BackgroundTasks,
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        cluster = db.query(Cluster).filter(Cluster.id == cluster_id).first()
        if not cluster:
            return RedirectResponse("/compliance", status_code=302)

        scan = Scan(
            scan_type="cluster",
            target_id=cluster.id,
            target_name=cluster.name,
            scan_mode="cis",
            framework=DEFAULT_FRAMEWORK,
            triggered_by=user.username,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    background_tasks.add_task(run_cis_scan, scan_id)
    return RedirectResponse(f"/compliance/scans/{scan_id}", status_code=302)


@router.get("/compliance/scans/{scan_id}")
async def compliance_scan_detail(request: Request, scan_id: int):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.framework is None:
            return RedirectResponse("/compliance", status_code=302)

        results = (
            db.query(ComplianceResult)
            .filter(ComplianceResult.scan_id == scan_id)
            .all()
        )

        # Group by section, sort by (status priority, severity) within each section.
        sections: dict = {}
        for r in results:
            sections.setdefault(r.section or "Other", []).append(r)
        for section in sections.values():
            section.sort(key=lambda r: (
                _STATUS_ORDER.get(r.status, 99),
                _SEVERITY_ORDER.get(r.severity, 99),
                r.control_id,
            ))
        sections_ordered = sorted(sections.items(), key=lambda kv: kv[0])

        cluster = db.query(Cluster).filter(Cluster.id == scan.target_id).first()
        db.expunge_all()

    return templates.TemplateResponse(request, "compliance_detail.html", context={
        "user":     user,
        "scan":     scan,
        "cluster":  cluster,
        "sections": sections_ordered,
        "score_band": _score_band(scan.compliance_score),
        "total":    len(results),
    })
