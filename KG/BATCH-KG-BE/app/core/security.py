"""AuthN/AuthZ — API-key guard.

If ``API_KEY`` is set in the environment every protected endpoint requires
the caller to pass it in the ``X-API-Key`` request header.

When ``API_KEY`` is *unset* (default) the dependency is a no-op so local
development requires no configuration changes.

Usage
-----
Add ``_: None = Depends(require_auth)`` to any route that should be
protected.  Example::

    @router.post("")
    async def chat(req: ChatRequest, _: None = Depends(require_auth)):
        ...
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from config.settings import get_settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_auth(api_key: str | None = Security(_api_key_header)) -> None:
    """FastAPI dependency — raises 401 when the API key is invalid.

    Bypassed transparently when ``settings.api_key`` is ``None``.
    """
    settings = get_settings()
    configured = settings.api_key
    if configured is None:
        # Auth disabled — dev / testing mode
        return
    if not api_key or api_key != configured:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
