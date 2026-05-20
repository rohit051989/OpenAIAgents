"""MCP tools: performance analysis.

Registers the following MCP tools:
  - get_job_performance
  - get_slow_jobs
  - get_step_failure_analysis
  - compare_jobs
  - get_sla_execution_breach
  - predict_sla_impact
"""

import logging

from app.core.database import get_driver
from app.mcp.server import mcp
from app.services import performance_service

logger = logging.getLogger(__name__)


@mcp.tool(name="get_job_performance")
async def tool_get_job_performance(job_id: str, days: int = 30) -> dict:
    """Retrieve aggregate performance metrics for a specific job.

    Args:
        job_id: The unique ``id`` property of the target Job node.
        days: Number of past days to include (default 30).

    Returns:
        Dictionary with ``job_name``, ``avg_duration_seconds``,
        ``min_duration_seconds``, ``max_duration_seconds``,
        ``execution_count``, ``success_count``, ``failure_count``.
    """
    logger.info("MCP tool get_job_performance job_id=%s days=%s", job_id, days)
    driver = await get_driver()
    return await performance_service.get_job_performance(driver, job_id=job_id, days=days)


@mcp.tool(name="get_slow_jobs")
async def tool_get_slow_jobs(
    threshold_minutes: int = 10,
    days: int = 7,
    limit: int = 10,
) -> dict:
    """Retrieve jobs that exceeded a specified execution time threshold.

    Args:
        threshold_minutes: Execution time threshold in minutes (default 10).
        days: Number of past days to search (default 7).
        limit: Maximum number of records to return (default 10).

    Returns:
        ``{"slow_jobs": [...], "count": N, "threshold_minutes": T, "time_range_days": days}``
    """
    logger.info(
        "MCP tool get_slow_jobs threshold_minutes=%s days=%s limit=%s",
        threshold_minutes, days, limit,
    )
    driver = await get_driver()
    return await performance_service.get_slow_jobs(
        driver, threshold_minutes=threshold_minutes, days=days, limit=limit
    )


@mcp.tool(name="get_step_failure_analysis")
async def tool_get_step_failure_analysis(job_id: str, days: int = 30) -> dict:
    """Retrieve step-level failure analysis for a specific job.

    Args:
        job_id: The unique ``id`` property of the target Job node.
        days: Number of past days to include (default 30).

    Returns:
        ``{"job_id": ..., "step_analysis": [...], "count": N, "time_range_days": days}``
        Each entry has ``step_id``, ``total_executions``, ``failures``,
        ``failure_rate_pct``, ``avg_duration_seconds``.
    """
    logger.info("MCP tool get_step_failure_analysis job_id=%s days=%s", job_id, days)
    driver = await get_driver()
    return await performance_service.get_step_failure_analysis(driver, job_id=job_id, days=days)


@mcp.tool(name="compare_jobs")
async def tool_compare_jobs(job_ids: list[str], days: int = 30) -> dict:
    """Compare performance metrics across multiple jobs side by side.

    Args:
        job_ids: List of Job ``id`` property values to compare.
        days: Number of past days to include (default 30).

    Returns:
        ``{"job_comparison": [...], "jobs_compared": job_ids, "count": N, "time_range_days": days}``
        Each entry has ``job_name``, ``executions``, ``failures``,
        ``failure_rate``, ``avg_duration_seconds``, ``avg_duration_minutes``.
    """
    logger.info("MCP tool compare_jobs job_ids=%s days=%s", job_ids, days)
    driver = await get_driver()
    return await performance_service.compare_jobs(driver, job_ids=job_ids, days=days)


@mcp.tool(name="get_sla_execution_breach")
async def tool_get_sla_execution_breach(
    business_date: str,
    region: str = "ALL",
) -> dict:
    """Return SLA breach status for a day from execution history only.

    Args:
        business_date: ISO date (YYYY-MM-DD) to evaluate.
        region: Region used for eligibility evaluation.

    Returns:
        Execution-only SLA status for eligible SICs on the given date.
    """
    logger.info(
        "MCP tool get_sla_execution_breach business_date=%s region=%s",
        business_date,
        region,
    )
    driver = await get_driver()
    return await performance_service.get_sla_execution_breach(
        driver,
        business_date=business_date,
        region=region,
    )


@mcp.tool(name="predict_sla_impact")
async def tool_predict_sla_impact(
    source_type: str,
    source_id: str,
    delay_minutes: int,
    days: int = 30,
    business_date: str | None = None,
    region: str = "ALL",
) -> dict:
    """Predict SLA impact for delay scenarios.

    Args:
        source_type: Dependency type: ``resource``, ``job``, ``sic``, ``job_group``.
        source_id: Source identifier (id/name/elementId).
        delay_minutes: Simulated delay to inject.
        days: Historical window used for average duration computation.
        business_date: Optional date for today/future eligible-graph prediction.
        region: Region used for eligibility evaluation when business_date is set.

    Returns:
        Predicted SLA impact payload with critical-path and buffer-aware fields.
    """
    logger.info(
        "MCP tool predict_sla_impact source_type=%s source_id=%s delay_minutes=%s days=%s business_date=%s region=%s",
        source_type,
        source_id,
        delay_minutes,
        days,
        business_date,
        region,
    )
    driver = await get_driver()
    return await performance_service.predict_sla_impact(
        driver,
        source_type=source_type,
        source_id=source_id,
        delay_minutes=delay_minutes,
        days=days,
        business_date=business_date,
        region=region,
    )
