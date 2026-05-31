# Copyright 2026 Jayden Aung — Apache 2.0
"""
web/secure_templates.py — Drop-in Jinja2Templates that auto-injects csrf_token.

Replace every `Jinja2Templates(directory=...)` with `SecureTemplates(directory=...)`.
Every TemplateResponse call then gets `csrf_token` in context automatically —
no changes needed at individual route level.
"""

from fastapi.templating import Jinja2Templates
from web import csrf


class SecureTemplates(Jinja2Templates):
    def TemplateResponse(self, request, name, context=None, **kwargs):
        ctx = dict(context or {})
        ctx.setdefault("csrf_token", csrf.get_token(request))
        return super().TemplateResponse(request, name, context=ctx, **kwargs)
