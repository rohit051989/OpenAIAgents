"""Correlation ID middleware.

Attaches a unique ``X-Correlation-ID`` to every request/response pair and
injects it into the Python logging context so all log lines emitted during a
request carry the same identifier — essential for tracing distributed calls.

Header precedence:
  1. Caller supplies ``X-Correlation-ID`` in the request   → reuse it
  2. No header supplied                                     → generate UUID4

The ID is exposed via :func:`get_correlation_id` which is called by the
logging filter in ``app.core.logging_config``.
"""
from __future__ import annotations

import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Module-level context var — one value per async task (= per HTTP request)
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")


def get_correlation_id() -> str:
    """Return the correlation ID for the current request context."""
    return _correlation_id.get()


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that stamps every request with a correlation ID."""

    async def dispatch(self, request: Request, call_next) -> Response:
        cid = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        token = _correlation_id.set(cid)
        try:
            response: Response = await call_next(request)
            response.headers["X-Correlation-ID"] = cid
            return response
        finally:
            _correlation_id.reset(token)
