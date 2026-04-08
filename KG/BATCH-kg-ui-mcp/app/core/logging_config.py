"""Centralised logging configuration.

Call ``configure_logging()`` once at application startup, before any
logger is used.  All subsequent ``logging.getLogger(__name__)`` calls
will pick up the configured handlers automatically.
"""

import logging
import sys

from config.settings import get_settings


def configure_logging(level: str | None = None) -> None:
    """Configure root logger with a consistent format.

    Args:
        level: Override log level (uses ``LOG_LEVEL`` from settings if omitted).
    """
    settings = get_settings()
    resolved_level = level or settings.log_level

    logging.basicConfig(
        level=getattr(logging, resolved_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    # Suppress overly verbose third-party loggers
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
