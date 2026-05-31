# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/csrf.py — Synchronizer-token CSRF protection

Tokens are stored in the signed session cookie (never in the DB).
Use SecureTemplates to auto-inject `csrf_token` into every template context.
"""

import hmac
import secrets

from starlette.requests import Request

_SESSION_KEY = "_csrf_token"


def get_token(request: Request) -> str:
    """Return the CSRF token for this session, creating one if absent."""
    token = request.session.get(_SESSION_KEY)
    if not token:
        token = secrets.token_hex(32)
        request.session[_SESSION_KEY] = token
    return token


def validate(request: Request, submitted: str) -> bool:
    """Constant-time comparison of the session token vs. the submitted token."""
    stored = request.session.get(_SESSION_KEY, "")
    if not stored or not submitted:
        return False
    return hmac.compare_digest(stored.encode(), submitted.encode())
