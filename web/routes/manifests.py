# Copyright 2026 Jayden Aung — Apache 2.0
import re
import shutil
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse

from web.auth import check_login
from web.database import Finding, Manifest, Scan, get_db
from web.scanner import run_scan
from web.secure_templates import SecureTemplates

router    = APIRouter()
templates = SecureTemplates(directory="web/templates")
UPLOAD_DIR    = Path("data/uploads/manifests")
MAX_UPLOAD_MB = 10
MAX_BYTES     = MAX_UPLOAD_MB * 1024 * 1024


def _safe_filename(raw: str) -> str:
    """Strip path components and replace unsafe characters."""
    name = Path(raw).name                          # drop any directory traversal
    name = re.sub(r"[^\w\-.]", "_", name)         # allow only word chars, hyphens, dots
    return name[:128] or "upload"                  # cap length, never empty


@router.get("/manifests")
async def manifests_list(request: Request):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        query = db.query(Manifest)
        if not user.is_admin:
            query = query.filter(Manifest.uploaded_by == user.id)
        manifests = query.order_by(Manifest.uploaded_at.desc()).all()
        manifest_data = []
        for m in manifests:
            latest = (
                db.query(Scan)
                .filter(Scan.scan_type == "manifest", Scan.target_id == m.id)
                .order_by(Scan.id.desc())
                .first()
            )
            manifest_data.append({"manifest": m, "latest_scan": latest})
        db.expunge_all()

    return templates.TemplateResponse(request, "manifests.html", context={
        "user":          user,
        "manifest_data": manifest_data,
    })


@router.post("/manifests/upload")
async def upload_manifest(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    scan_mode: Literal["static", "ai"] = Form(...),
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    raw_name = file.filename or "upload.yaml"
    if not raw_name.endswith((".yaml", ".yml")):
        return RedirectResponse("/manifests?error=not_yaml", status_code=302)

    safe_name = _safe_filename(raw_name)

    with get_db() as db:
        manifest = Manifest(
            filename=safe_name,
            file_path="",
            uploaded_by=user.id,
            uploaded_by_name=user.username,
        )
        db.add(manifest)
        db.commit()
        db.refresh(manifest)

        dest = UPLOAD_DIR / f"{manifest.id}_{safe_name}"
        # Enforce size limit while streaming to disk
        written = 0
        with open(dest, "wb") as fout:
            while chunk := await file.read(65536):
                written += len(chunk)
                if written > MAX_BYTES:
                    fout.close()
                    dest.unlink(missing_ok=True)
                    db.delete(manifest)
                    db.commit()
                    return RedirectResponse(
                        f"/manifests?error=too_large&max={MAX_UPLOAD_MB}mb",
                        status_code=302,
                    )
                fout.write(chunk)

        # Verify resolved path stays inside UPLOAD_DIR (defense-in-depth)
        if not dest.resolve().is_relative_to(UPLOAD_DIR.resolve()):
            dest.unlink(missing_ok=True)
            db.delete(manifest)
            db.commit()
            return RedirectResponse("/manifests?error=invalid_path", status_code=302)

        manifest.file_path = str(dest)
        scan = Scan(
            scan_type="manifest",
            target_id=manifest.id,
            target_name=safe_name,
            scan_mode=scan_mode,
            triggered_by=user.username,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id    = scan.id
        manifest_id = manifest.id

    background_tasks.add_task(run_scan, scan_id)
    return RedirectResponse(f"/manifests/{manifest_id}", status_code=302)


@router.get("/manifests/{manifest_id}")
async def manifest_detail(request: Request, manifest_id: int):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        query = db.query(Manifest).filter(Manifest.id == manifest_id)
        if not user.is_admin:
            query = query.filter(Manifest.uploaded_by == user.id)
        manifest = query.first()
        if not manifest:
            return RedirectResponse("/manifests", status_code=302)

        scans = (
            db.query(Scan)
            .filter(Scan.scan_type == "manifest", Scan.target_id == manifest_id)
            .order_by(Scan.id.desc())
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

    return templates.TemplateResponse(request, "manifest_detail.html", context={
        "user":        user,
        "manifest":    manifest,
        "scans":       scans,
        "latest_scan": latest_scan,
        "findings":    findings,
    })


@router.post("/manifests/{manifest_id}/scan")
async def rescan_manifest(
    request: Request,
    manifest_id: int,
    background_tasks: BackgroundTasks,
    scan_mode: Literal["static", "ai"] = Form(...),
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        query = db.query(Manifest).filter(Manifest.id == manifest_id)
        if not user.is_admin:
            query = query.filter(Manifest.uploaded_by == user.id)
        manifest = query.first()
        if not manifest:
            return RedirectResponse("/manifests", status_code=302)

        scan = Scan(
            scan_type="manifest",
            target_id=manifest.id,
            target_name=manifest.filename,
            scan_mode=scan_mode,
            triggered_by=user.username,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    background_tasks.add_task(run_scan, scan_id)
    return RedirectResponse(f"/manifests/{manifest_id}", status_code=302)
