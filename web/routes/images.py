import json

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from web.secure_templates import SecureTemplates

from web.auth import check_login
from web.database import Image, Scan, get_db

router = APIRouter()
templates = SecureTemplates(directory="web/templates")


@router.get("/images")
async def images_list(request: Request):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        # Deduplicate by image_ref, show worst CVE counts seen
        rows = db.query(Image).order_by(Image.critical_cves.desc(), Image.scanned_at.desc()).all()
        seen: dict = {}
        for img in rows:
            if img.image_ref not in seen:
                seen[img.image_ref] = img
            else:
                existing = seen[img.image_ref]
                if img.critical_cves > existing.critical_cves:
                    seen[img.image_ref] = img
        images = list(seen.values())

        # Attach scan target name for context
        scan_map = {}
        scan_ids = {img.scan_id for img in rows}
        for sid in scan_ids:
            s = db.query(Scan).filter(Scan.id == sid).first()
            if s:
                scan_map[sid] = s.target_name
        db.expunge_all()

    SEVERITIES = ["critical", "high", "medium", "low"]
    details_map: dict = {}
    for img in images:
        if img.cve_details:
            try:
                raw = json.loads(img.cve_details)
                if isinstance(raw, dict):
                    # New format: {critical: [...], high: [...], ...}
                    details_map[img.image_ref] = {
                        sev: raw.get(sev, []) for sev in SEVERITIES if raw.get(sev)
                    }
                elif isinstance(raw, list) and raw:
                    # Legacy format: flat list of critical CVEs
                    details_map[img.image_ref] = {"critical": raw}
            except Exception:
                pass

    return templates.TemplateResponse(request, "images.html", context={
        "user":        user,
        "images":      images,
        "scan_map":    scan_map,
        "details_map": details_map,
    })
