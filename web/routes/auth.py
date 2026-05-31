# Copyright 2026 Jayden Aung — Apache 2.0
import time
from collections import defaultdict

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from web.auth import get_current_user, verify_password
from web.database import User, get_db, has_users
from web.secure_templates import SecureTemplates

router    = APIRouter()
templates = SecureTemplates(directory="web/templates")

# ── Login rate limiting (in-memory, per IP) ────────────────────────────────────
_WINDOW      = 300   # 5-minute window
_MAX_ATTEMPTS = 10   # max failures per window
_attempts: dict = defaultdict(list)


def _rate_limited(ip: str) -> bool:
    now = time.monotonic()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < _WINDOW]
    if len(_attempts[ip]) >= _MAX_ATTEMPTS:
        return True
    _attempts[ip].append(now)
    return False


def _clear_attempts(ip: str) -> None:
    _attempts.pop(ip, None)


@router.get("/login")
async def login_page(request: Request):
    if not has_users():
        return RedirectResponse("/setup", status_code=302)
    if get_current_user(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", context={"error": None})


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ip = request.client.host if request.client else "unknown"

    if _rate_limited(ip):
        return templates.TemplateResponse(
            request, "login.html",
            context={"error": "Too many failed attempts. Try again in 5 minutes."},
            status_code=429,
        )

    with get_db() as db:
        user = db.query(User).filter(
            User.username == username.strip(),
            User.is_active == True,
        ).first()

    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request, "login.html",
            context={"error": "Invalid username or password."},
        )

    _clear_attempts(ip)
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=302)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)
