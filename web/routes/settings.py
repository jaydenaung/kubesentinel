# Copyright 2026 Jayden Aung — Apache 2.0
import json
import time
import urllib.error
import urllib.request

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from web.secure_templates import SecureTemplates

from web.auth import check_admin
from web.database import get_setting, set_setting

router = APIRouter()
templates = SecureTemplates(directory="web/templates")


@router.get("/settings")
async def settings_page(request: Request):
    result = check_admin(request)
    if isinstance(result, RedirectResponse):
        return result
    user = result

    return templates.TemplateResponse(request, "settings.html", context={
        "user":             user,
        "webhook_url":      get_setting("webhook_url"),
        "webhook_token":    get_setting("webhook_token"),
        "webhook_format":   get_setting("webhook_format", "json"),
        "saved":            request.query_params.get("saved"),
        "test_result":      request.query_params.get("test_result"),
    })


@router.post("/settings/webhook")
async def save_webhook(
    request: Request,
    webhook_url:    str = Form(default=""),
    webhook_token:  str = Form(default=""),
    webhook_format: str = Form(default="json"),
):
    result = check_admin(request)
    if isinstance(result, RedirectResponse):
        return result

    set_setting("webhook_url",    webhook_url.strip())
    set_setting("webhook_token",  webhook_token.strip())
    set_setting("webhook_format", webhook_format if webhook_format in ("json", "splunk") else "json")

    return RedirectResponse("/settings?saved=1", status_code=302)


@router.post("/settings/webhook/test")
async def test_webhook(request: Request):
    result = check_admin(request)
    if isinstance(result, RedirectResponse):
        return result

    url    = get_setting("webhook_url").strip()
    token  = get_setting("webhook_token").strip()
    fmt    = get_setting("webhook_format", "json").lower()

    if not url:
        return RedirectResponse("/settings?test_result=no_url", status_code=302)

    from web.webhook import _validate_webhook_url
    if not _validate_webhook_url(url):
        return RedirectResponse("/settings?test_result=error&msg=URL+blocked+SSRF+check", status_code=302)

    test_payload = {
        "source":   "kubesentinel",
        "event":    "test",
        "message":  "KubeSentinel webhook test — connection verified",
        "timestamp": time.time(),
    }

    try:
        if fmt == "splunk":
            body       = json.dumps({"time": int(time.time()), "sourcetype": "kubesentinel:test", "event": test_payload})
            auth_value = f"Splunk {token}" if token else None
        else:
            body       = json.dumps(test_payload)
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
            status = resp.status

        return RedirectResponse(f"/settings?test_result=ok&status={status}", status_code=302)

    except urllib.error.HTTPError as exc:
        return RedirectResponse(f"/settings?test_result=http_error&status={exc.code}", status_code=302)
    except Exception as exc:
        msg = str(exc)[:80].replace("&", "").replace("?", "").replace("=", "")
        return RedirectResponse(f"/settings?test_result=error&msg={msg}", status_code=302)
