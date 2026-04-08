"""MCP tools: execution history and monitoring.

Registers the following MCP tools:
  - get_failed_jobs
  - get_common_errors
  - get_execution_timeline
  - get_job_execution_history
  - get_all_active_jobs

This module is intentionally thin: only MCP registration lives here.
All logic is in ``execution_service``.
"""

import logging

from app.core.database import get_driver
from app.mcp.server import mcp
from app.services import execution_service

logger = logging.getLogger(__name__)


@mcp.tool(name="get_failed_jobs")
async def tool_get_failed_jobs(days: int = 7, limit: int = 10) -> dict:
    """Retrieve jobs that have failed within a specified time range.

    Args:
        days: Number of past days to search (default 7).
        limit: Maximum number of failed jobs to return (default 10).

    Returns:
        ``{"failed_jobs": [...], "count": N, "time_range_days": days}``
    """
    logger.info("MCP tool get_failed_jobs days=%s limit=%s", days, limit)
    driver = await get_driver()
    return await execution_service.get_failed_jobs(driver, days=days, limit=limit)


@mcp.tool(name="get_common_errors")
async def tool_get_common_errors(days: int = 30, limit: int = 10) -> dict:
    """Retrieve the most common error messages from failed job executions.

    Args:
        days: Number of past days to search (default 30).
        limit: Maximum number of error messages to return (default 10).

    Returns:
        ``{"common_errors": [...], "count": N, "time_range_days": days}``
    """
    logger.info("MCP tool get_common_errors days=%s limit=%s", days, limit)
    driver = await get_driver()
    return await execution_service.get_common_errors(driver, days=days, limit=limit)


@mcp.tool(name="get_execution_timeline")
async def tool_get_execution_timeline(days: int = 30) -> dict:
    """Retrieve daily execution statistics for all jobs.

    Args:
        days: Number of past days to include (default 30).

    Returns:
        ``{"timeline": [...], "count": N, "time_range_days": days}``
        Each entry has ``execution_date``, ``total_executions``,
        ``completed``, ``failed``, ``failure_rate``.
    """
    logger.info("MCP tool get_execution_timeline days=%s", days)
    driver = await get_driver()
    return await execution_service.get_execution_timeline(driver, days=days)


@mcp.tool(name="get_job_execution_history")
async def tool_get_job_execution_history(
    job_id: str,
    days: int = 30,
    limit: int = 50,
) -> dict:
    """Retrieve the complete execution history for a specific job.

    Args:
        job_id: The unique ``id`` property of the target Job node.
        days: Number of past days to include (default 30).
        limit: Maximum number of records to return (default 50).

    Returns:
        ``{"job_id": ..., "execution_history": [...], "count": N, "time_range_days": days}``
    """
    logger.info("MCP tool get_job_execution_history job_id=%s days=%s limit=%s", job_id, days, limit)
    driver = await get_driver()
    return await execution_service.get_job_execution_history(driver, job_id=job_id, days=days, limit=limit)


@mcp.tool(name="get_all_active_jobs")
async def tool_get_all_active_jobs(days: int = 30) -> dict:
    """Retrieve all jobs that have had at least one execution recently.

    Args:
        days: Number of past days to search (default 30).

    Returns:
        ``{"active_jobs": [...], "count": N, "time_range_days": days}``
        Each entry has ``job_id``, ``job_name``, ``execution_count``,
        ``last_execution``.
    """
    logger.info("MCP tool get_all_active_jobs days=%s", days)
    driver = await get_driver()
    return await execution_service.get_all_active_jobs(driver, days=days)
