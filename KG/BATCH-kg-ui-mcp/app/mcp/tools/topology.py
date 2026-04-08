"""MCP tool: get_job_topology

Returns the structural definition of a Spring Batch Job including steps,
blocks, SLAs, calendars, required resources, listeners, tags, and
schedule contexts.

This module is intentionally thin: only MCP registration lives here.
All logic is in ``topology_service``.
"""

import logging

from app.core.database import get_driver
from app.mcp.server import mcp
from app.services import topology_service

logger = logging.getLogger(__name__)


@mcp.tool(name="get_job_topology")
async def tool_get_job_topology(job_id: str) -> dict:
    """Retrieve the topology of a specific job.

    Returns the job structure including steps, blocks, entry point, SLAs,
    allowed/blocked calendars, required resources, listeners, tags, and
    associated schedule contexts.

    Args:
        job_id: The unique ``id`` property value of the target Job node.

    Returns:
        Dictionary with ``job_topology`` (full structural data) and ``job_id``.
    """
    logger.info("MCP tool get_job_topology job_id=%s", job_id)
    driver = await get_driver()
    return await topology_service.get_job_topology(job_id, driver)
