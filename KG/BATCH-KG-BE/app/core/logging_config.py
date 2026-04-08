"""Structured logging configuration.

In ``development`` mode (``APP_ENV=development``) logs are emitted as
human-readable text.  In any other environment they are emitted as
single-line JSON, compatible with ELK, CloudWatch, and Grafana Loki.

Every log record is enriched with a ``correlation_id`` field taken from the
current request context (see :mod:`app.middleware.correlation`).
"""
from __future__ import annotations

import json
import logging
import sys
import traceback

from config.settings import get_settings


# ---------------------------------------------------------------------------
# Correlation ID filter
# ---------------------------------------------------------------------------

class _CorrelationFilter(logging.Filter):
    """Inject ``correlation_id`` from the async context into every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            from app.middleware.correlation import get_correlation_id
            record.correlation_id = get_correlation_id()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            record.correlation_id = "-"  # type: ignore[attr-defined]
        return True


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class _JSONFormatter(logging.Formatter):
    """One-liner JSON log suitable for log aggregation pipelines."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "cid": getattr(record, "correlation_id", "-"),
        }
        if record.exc_info:
            payload["exc"] = "".join(traceback.format_exception(*record.exc_info))
        return json.dumps(payload)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def configure_logging() -> None:
    """Configure the root logger based on the current settings.

    Call once at application startup (before :mod:`app.api.router` is imported).
    """
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    use_json = settings.app_env != "development"

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_CorrelationFilter())

    if use_json:
        handler.setFormatter(_JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s [%(correlation_id)s] - %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)

    # Silence noisy third-party loggers
    for noisy in ("httpx", "httpcore", "hpack", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
