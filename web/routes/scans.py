from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Query, Request
from fastapi.responses import RedirectResponse
from web.secure_templates import SecureTemplates

from web.auth import check_login
from web.database import Finding, Scan, get_db
from web.scanner import run_ai_enrichment, run_patch_generation

router = APIRouter()
templates = SecureTemplates(directory="web/templates")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _fingerprint(f: Finding) -> tuple:
    if f.check_id:
        return (f.check_id, f.context or "")
    return ("__title__", f.title or "")


def _compute_diff(baseline: list, current: list) -> dict:
    base_map = {_fingerprint(f): f for f in baseline}
    curr_map = {_fingerprint(f): f for f in current}

    new_findings, fixed_findings, worsened, improved, unchanged = [], [], [], [], []

    for fp, f in curr_map.items():
        if fp not in base_map:
            new_findings.append(f)
        else:
            b = base_map[fp]
            cs = SEVERITY_ORDER.get(f.severity or "INFO", 4)
            bs = SEVERITY_ORDER.get(b.severity or "INFO", 4)
            if cs < bs:
                worsened.append({"before": b, "after": f})
            elif cs > bs:
                improved.append({"before": b, "after": f})
            else:
                unchanged.append(f)

    for fp, f in base_map.items():
        if fp not in curr_map:
            fixed_findings.append(f)

    srt = lambda lst: sorted(lst, key=lambda f: SEVERITY_ORDER.get(f.severity or "INFO", 99))
    return {
        "new":       srt(new_findings),
        "fixed":     srt(fixed_findings),
        "worsened":  worsened,
        "improved":  improved,
        "unchanged": srt(unchanged),
    }


@router.get("/scans/{scan_id}/diff")
async def scan_diff(
    request: Request,
    scan_id: int,
    compare_to: Optional[int] = Query(default=None),
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status != "done":
            return RedirectResponse(f"/scans/{scan_id}", status_code=302)

        if compare_to:
            baseline = db.query(Scan).filter(Scan.id == compare_to, Scan.status == "done").first()
        else:
            baseline = (
                db.query(Scan)
                .filter(
                    Scan.scan_type == scan.scan_type,
                    Scan.target_id == scan.target_id,
                    Scan.id < scan_id,
                    Scan.status == "done",
                )
                .order_by(Scan.id.desc())
                .first()
            )

        # Sibling scans for the baseline picker
        siblings = (
            db.query(Scan)
            .filter(
                Scan.scan_type == scan.scan_type,
                Scan.target_id == scan.target_id,
                Scan.id != scan_id,
                Scan.status == "done",
            )
            .order_by(Scan.id.desc())
            .all()
        )

        current_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        baseline_findings = db.query(Finding).filter(Finding.scan_id == baseline.id).all() if baseline else []

        db.expunge_all()

    diff = _compute_diff(baseline_findings, current_findings)

    return templates.TemplateResponse(request, "scan_diff.html", context={
        "user":     user,
        "scan":     scan,
        "baseline": baseline,
        "siblings": siblings,
        "diff":     diff,
    })


@router.get("/scans/{scan_id}")
async def scan_detail(request: Request, scan_id: int):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return RedirectResponse("/", status_code=302)
        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .all()
        )
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity or "INFO", 99))

        # Previous completed scan of same target (for diff button)
        prev_scan = (
            db.query(Scan)
            .filter(
                Scan.scan_type == scan.scan_type,
                Scan.target_id == scan.target_id,
                Scan.id < scan_id,
                Scan.status == "done",
            )
            .order_by(Scan.id.desc())
            .first()
        ) if scan.status == "done" else None

        db.expunge_all()

    return templates.TemplateResponse(request, "scan_detail.html", context={
        "user":      user,
        "scan":      scan,
        "findings":  findings,
        "prev_scan": prev_scan,
    })


@router.post("/scans/{scan_id}/patches")
async def generate_patches(
    request: Request,
    scan_id: int,
    background_tasks: BackgroundTasks,
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status != "done":
            return RedirectResponse(f"/scans/{scan_id}", status_code=302)
        if scan.patches_status in ("generating", "done"):
            return RedirectResponse(f"/scans/{scan_id}", status_code=302)

    background_tasks.add_task(run_patch_generation, scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=302)


@router.post("/scans/{scan_id}/enrich")
async def enrich_with_ai(
    request: Request,
    scan_id: int,
    background_tasks: BackgroundTasks,
):
    result = check_login(request)
    if isinstance(result, RedirectResponse):
        return result

    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status != "done":
            return RedirectResponse(f"/scans/{scan_id}", status_code=302)
        if scan.enrichment_status in ("generating", "done"):
            return RedirectResponse(f"/scans/{scan_id}", status_code=302)

    background_tasks.add_task(run_ai_enrichment, scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=302)
