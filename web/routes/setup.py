from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from web.auth import hash_password
from web.database import User, get_db, has_users
from web.secure_templates import SecureTemplates

router    = APIRouter()
templates = SecureTemplates(directory="web/templates")
_MIN_PASSWORD_LEN = 12


@router.get("/setup")
async def setup_page(request: Request):
    if has_users():
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "setup.html", context={"error": None})


@router.post("/setup")
async def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    if has_users():
        return RedirectResponse("/", status_code=302)

    error = None
    if len(username) < 3:
        error = "Username must be at least 3 characters."
    elif len(password) < _MIN_PASSWORD_LEN:
        error = f"Password must be at least {_MIN_PASSWORD_LEN} characters."
    elif password != confirm:
        error = "Passwords do not match."

    if error:
        return templates.TemplateResponse(request, "setup.html", context={"error": error})

    with get_db() as db:
        user = User(
            username=username.strip(),
            hashed_password=hash_password(password),
            is_admin=True,
            is_active=True,
        )
        db.add(user)
        db.commit()

    return RedirectResponse("/login", status_code=302)
