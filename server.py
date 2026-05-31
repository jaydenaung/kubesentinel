# Copyright 2026 Jayden Aung — Apache 2.0
"""
server.py — KubeSentinel web server

Usage:
    python server.py                                         # HTTP, 0.0.0.0:8000
    python server.py --port 8080
    python server.py --ssl-certfile cert.pem --ssl-keyfile key.pem   # HTTPS

Environment:
    HTTPS_ONLY=true   — set Secure flag on session cookie (required when behind TLS)
"""

import argparse
import os
import secrets
from pathlib import Path
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from web import csrf as _csrf
from web.database import has_users, init_db
from web.routes import api, auth, clusters, compliance, dashboard, images, manifests, scans, settings, setup, users
from web.scheduler import restore_schedules, scheduler


def _get_secret_key() -> str:
    key_file = Path("data/.secret_key")
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    key_file.chmod(0o600)
    return key


# ── Security middleware ────────────────────────────────────────────────────────
_CSRF_SAFE   = {"GET", "HEAD", "OPTIONS", "TRACE"}
_CSRF_EXEMPT = "/api/"   # API routes use Bearer/token auth, not session cookies


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection (Origin header + synchronizer token) and security headers.
    Runs after SessionMiddleware so request.session is available.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method not in _CSRF_SAFE:
            if not request.url.path.startswith(_CSRF_EXEMPT):
                err = await self._csrf_check(request)
                if err:
                    return HTMLResponse(
                        f"<h1>403 Forbidden</h1><p>{err}</p>"
                        "<p><a href='javascript:history.back()'>Go back</a></p>",
                        status_code=403,
                    )

        response = await call_next(request)

        h = response.headers
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault("X-XSS-Protection", "1; mode=block")
        h.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # unsafe-inline required by current inline scripts/styles; tighten when templates adopt nonces
        h.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'",
        )
        return response

    async def _csrf_check(self, request: Request) -> str:
        host    = request.url.netloc
        origin  = request.headers.get("origin", "")
        referer = request.headers.get("referer", "")

        # Layer 1: Origin/Referer validation (covers multipart file uploads too)
        if origin:
            if urlparse(origin).netloc != host:
                return "CSRF: origin mismatch"
        elif referer:
            if urlparse(referer).netloc != host:
                return "CSRF: referer mismatch"

        # Layer 2: synchronizer token for URL-encoded form bodies
        ct = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in ct:
            from urllib.parse import parse_qs
            body   = await request.body()   # Starlette caches _body; downstream handlers unaffected
            fields = parse_qs(body.decode("utf-8", errors="ignore"))
            token  = (fields.get("_csrf") or [""])[0]
            if not _csrf.validate(request, token):
                return "CSRF token missing or invalid"

        return ""


# ── Application ────────────────────────────────────────────────────────────────
app = FastAPI(title="KubeSentinel", docs_url=None, redoc_url=None)

app.add_middleware(
    SessionMiddleware,
    secret_key=_get_secret_key(),
    session_cookie="ks_session",
    max_age=3600,           # 1-hour session expiry
    same_site="strict",     # prevents CSRF via cross-site cookie sending
    https_only=os.environ.get("HTTPS_ONLY", "false").lower() == "true",
)
app.add_middleware(SecurityMiddleware)

app.include_router(setup.router)
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(manifests.router)
app.include_router(clusters.router)
app.include_router(images.router)
app.include_router(scans.router)
app.include_router(compliance.router)
app.include_router(users.router)
app.include_router(settings.router)
app.include_router(api.router)


@app.middleware("http")
async def setup_guard(request: Request, call_next):
    """Redirect everything except /setup to /setup when no users exist."""
    if not request.url.path.startswith("/setup") and not has_users():
        return RedirectResponse("/setup")
    return await call_next(request)


@app.on_event("startup")
async def startup():
    init_db()
    scheduler.start()
    restore_schedules()


@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown(wait=False)


if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="KubeSentinel web server")
    parser.add_argument("--host",         default="0.0.0.0")
    parser.add_argument("--port",         type=int, default=8000)
    parser.add_argument("--ssl-certfile", dest="ssl_certfile", default=None,
                        help="TLS certificate file — enables HTTPS")
    parser.add_argument("--ssl-keyfile",  dest="ssl_keyfile",  default=None,
                        help="TLS private key file")
    args = parser.parse_args()

    scheme = "https" if args.ssl_certfile else "http"
    print(f"\n  🛡  KubeSentinel — AI-powered Kubernetes Security")
    print(f"  Dashboard: {scheme}://{args.host}:{args.port}")
    if args.ssl_certfile:
        print(f"  TLS cert:  {args.ssl_certfile}")
    print()

    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        reload=False,
        ssl_certfile=args.ssl_certfile or None,
        ssl_keyfile=args.ssl_keyfile or None,
    )
