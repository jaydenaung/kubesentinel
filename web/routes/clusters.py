# Copyright 2026 Jayden Aung — Apache 2.0
import os
import shutil
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy import or_

from web.auth import check_login
from web.database import Cluster, Finding, Scan, get_db
from web.scanner import run_scan
from web.scheduler import remove_cluster_schedule, upsert_cluster_schedule
from web.secure_templates import SecureTemplates

router    = APIRouter()
templates = SecureTemplates(directory="web/templates")
KUBECONFIG_DIR = Path("data/kubeconfigs")
MAX_KUBECONFIG_BYTES = 1 * 1024 * 1024  # 1 MB — kubeconfigs are small

SCHEDULE_OPTIONS = [
    (0,   "Off (manual only)"),
    (6,   "Every 6 hours"),
    (12,  "Every 12 hours"),
    (24,  "Every 24 hours"),
    (48,  "Every 48 hours"),
    (168, "Weekly"),
]


@router.get("/clusters")
async def clusters_list(request: Request):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        query = db.query(Cluster)
        if not user.is_admin:
            query = query.filter(Cluster.added_by == user.id)
        clusters = query.order_by(Cluster.added_at.desc()).all()
        cluster_data = []
        for c in clusters:
            latest = (
                db.query(Scan)
                .filter(Scan.scan_type == "cluster", Scan.target_id == c.id)
                .order_by(Scan.id.desc())
                .first()
            )
            cluster_data.append({"cluster": c, "latest_scan": latest})
        db.expunge_all()

    return templates.TemplateResponse(request, "clusters.html", context={
        "user":         user,
        "cluster_data": cluster_data,
    })


@router.post("/clusters/onboard")
async def onboard_cluster(
    request: Request,
    name: str = Form(...),
    file: UploadFile = File(...),
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    cluster_name = name.strip()[:128]

    with get_db() as db:
        existing = db.query(Cluster).filter(Cluster.name == cluster_name).first()
        if existing:
            return RedirectResponse("/clusters?error=name_taken", status_code=302)

        cluster = Cluster(
            name=cluster_name,
            kubeconfig_path="",
            added_by=user.id,
            added_by_name=user.username,
        )
        db.add(cluster)
        db.commit()
        db.refresh(cluster)

        dest = KUBECONFIG_DIR / f"{cluster.id}.yaml"
        written = 0
        with open(dest, "wb") as fout:
            while chunk := await file.read(65536):
                written += len(chunk)
                if written > MAX_KUBECONFIG_BYTES:
                    fout.close()
                    dest.unlink(missing_ok=True)
                    db.delete(cluster)
                    db.commit()
                    return RedirectResponse("/clusters?error=kubeconfig_too_large", status_code=302)
                fout.write(chunk)

        os.chmod(dest, 0o600)
        cluster.kubeconfig_path = str(dest)
        db.commit()
        cluster_id = cluster.id

    return RedirectResponse(f"/clusters/{cluster_id}", status_code=302)


def _owns_cluster(db, cluster_id: int, user) -> "Cluster | None":
    """Return the cluster if the user owns it or is an admin, else None."""
    query = db.query(Cluster).filter(Cluster.id == cluster_id)
    if not user.is_admin:
        query = query.filter(Cluster.added_by == user.id)
    return query.first()


@router.get("/clusters/{cluster_id}")
async def cluster_detail(request: Request, cluster_id: int):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        cluster = _owns_cluster(db, cluster_id, user)
        if not cluster:
            return RedirectResponse("/clusters", status_code=302)

        scans = (
            db.query(Scan)
            .filter(Scan.scan_type == "cluster", Scan.target_id == cluster_id)
            .order_by(Scan.id.desc())
            .limit(20)
            .all()
        )
        latest_scan = scans[0] if scans else None
        findings = []
        if latest_scan and latest_scan.status == "done":
            findings = (
                db.query(Finding)
                .filter(Finding.scan_id == latest_scan.id)
                .order_by(Finding.severity)
                .all()
            )
        db.expunge_all()

    return templates.TemplateResponse(request, "cluster_detail.html", context={
        "user":          user,
        "cluster":       cluster,
        "scans":         scans,
        "latest_scan":   latest_scan,
        "findings":      findings,
        "schedule_opts": SCHEDULE_OPTIONS,
    })


@router.post("/clusters/{cluster_id}/scan")
async def trigger_cluster_scan(
    request: Request,
    cluster_id: int,
    background_tasks: BackgroundTasks,
    scan_mode: Literal["static", "ai", "cis"] = Form(...),
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        cluster = _owns_cluster(db, cluster_id, user)
        if not cluster:
            return RedirectResponse("/clusters", status_code=302)
        scan = Scan(
            scan_type="cluster",
            target_id=cluster.id,
            target_name=cluster.name,
            scan_mode=scan_mode,
            triggered_by=user.username,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    background_tasks.add_task(run_scan, scan_id)
    return RedirectResponse(f"/clusters/{cluster_id}", status_code=302)


@router.post("/clusters/{cluster_id}/schedule")
async def update_schedule(
    request: Request,
    cluster_id: int,
    schedule_hours: int = Form(...),
    scan_mode: Literal["static", "ai", "cis"] = Form(...),
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        cluster = _owns_cluster(db, cluster_id, user)
        if not cluster:
            return RedirectResponse("/clusters", status_code=302)
        cluster.schedule_hours = schedule_hours
        db.commit()
        cluster_name = cluster.name

    upsert_cluster_schedule(cluster_id, cluster_name, schedule_hours, scan_mode)
    return RedirectResponse(f"/clusters/{cluster_id}", status_code=302)


@router.post("/clusters/{cluster_id}/delete")
async def delete_cluster(request: Request, cluster_id: int):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result
    if not user.is_admin:
        return RedirectResponse("/clusters", status_code=302)

    with get_db() as db:
        cluster = db.query(Cluster).filter(Cluster.id == cluster_id).first()
        if cluster:
            remove_cluster_schedule(cluster_id)
            try:
                Path(cluster.kubeconfig_path).unlink(missing_ok=True)
            except Exception:
                pass
            db.delete(cluster)
            db.commit()

    return RedirectResponse("/clusters", status_code=302)
