"""MCP resource: kg://schema

Exposes the full Knowledge Graph schema — node labels, properties,
relationship types, and live relationship patterns — as an MCP resource.

This module is intentionally thin: it only handles MCP registration and
delegates all logic to ``schema_service``.
"""

import logging

from app.core.database import get_driver
from app.mcp.server import mcp
from app.services import schema_service

logger = logging.getLogger(__name__)


@mcp.resource("kg://schema")
async def resource_kg_schema() -> dict:
    """Knowledge Graph schema with node definitions, properties, and relationship patterns."""
    logger.info("MCP resource kg://schema requested")
    driver = await get_driver()
    return await schema_service.get_kg_schema(driver)
