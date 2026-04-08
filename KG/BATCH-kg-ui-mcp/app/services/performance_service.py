"""Performance service — job performance metrics and analysis.

Covers:
  - Per-job duration statistics (avg / min / max)
  - Jobs that exceeded an execution time threshold
  - Step-level failure rate analysis for a job
  - Side-by-side comparison of multiple jobs
"""

import logging
from datetime import datetime, timedelta
from typing import Any

from neo4j import AsyncDriver

from app.core.database import kg_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_Q_JOB_PERFORMANCE = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE j.id = $job_id
  AND e.startTime >= datetime($start_date)
  AND e.durationMs IS NOT NULL
WITH j.name AS job_name,
     e.durationMs / 1000.0 AS duration_seconds
RETURN
    job_name,
    avg(duration_seconds)   AS avg_duration_seconds,
    min(duration_seconds)   AS min_duration_seconds,
    max(duration_seconds)   AS max_duration_seconds,
    count(*)                AS execution_count,
    sum(CASE WHEN e.status = 'COMPLETED' THEN 1 ELSE 0 END) AS success_count,
    sum(CASE WHEN e.status = 'FAILED'    THEN 1 ELSE 0 END) AS failure_count
"""

_Q_SLOW_JOBS = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE e.startTime >= datetime($start_date)
  AND e.durationMs IS NOT NULL
  AND e.durationMs > $threshold_ms
RETURN
    j.name                      AS job_name,
    e.id                        AS execution_id,
    toString(e.startTime)       AS start_time,
    toString(e.endTime)         AS end_time,
    e.status                    AS status,
    e.durationMs / 1000         AS duration_seconds,
    round(e.durationMs / 60000.0, 2) AS duration_minutes
ORDER BY e.durationMs DESC
LIMIT $limit
"""

_Q_STEP_FAILURE_ANALYSIS = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE j.id = $job_id
  AND e.startTime >= datetime($start_date)
MATCH (se:StepExecution)-[:FOR_RUN]->(e)
WITH
    se.stepId                                                           AS step_id,
    count(se)                                                           AS total_executions,
    sum(CASE WHEN se.status = 'FAILED'    THEN 1 ELSE 0 END)           AS failures,
    avg(se.durationMs)                                                  AS avg_duration_ms
WHERE total_executions > 0
RETURN
    step_id,
    total_executions,
    failures,
    round(100.0 * failures / total_executions, 2) AS failure_rate_pct,
    round(avg_duration_ms / 1000.0, 2)            AS avg_duration_seconds
ORDER BY failure_rate_pct DESC, failures DESC
"""

_Q_COMPARE_JOBS = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE j.id IN $job_ids
  AND e.startTime >= datetime($start_date)
  AND e.durationMs IS NOT NULL
WITH j.name AS job_name,
     avg(e.durationMs / 1000.0) AS avg_duration_seconds,
     count(e)                   AS executions,
     sum(CASE WHEN e.status = 'FAILED' THEN 1 ELSE 0 END) AS failures
WHERE executions > 0
RETURN
    job_name,
    executions,
    failures,
    round(100.0 * failures / executions, 2) AS failure_rate,
    round(avg_duration_seconds, 2)          AS avg_duration_seconds,
    round(avg_duration_seconds / 60.0, 2)  AS avg_duration_minutes
ORDER BY failure_rate DESC, avg_duration_seconds DESC
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _start_date(days: int) -> str:
    return (datetime.now() - timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

async def get_job_performance(
    driver: AsyncDriver,
    job_id: str,
    days: int = 30,
) -> dict[str, Any]:
    """Return aggregate duration and success/failure counts for a job.

    Args:
        driver: Shared Neo4j async driver.
        job_id: The ``id`` property of the target ``Job`` node.
        days: How many days back to include.

    Returns:
        Dictionary with ``job_name``, ``avg/min/max_duration_seconds``,
        ``execution_count``, ``success_count``, ``failure_count``.
    """
    logger.info("get_job_performance job_id=%s days=%s", job_id, days)
    async with kg_session(driver) as session:
        result = await session.run(
            _Q_JOB_PERFORMANCE, job_id=job_id, start_date=_start_date(days)
        )
        record = await result.single()
    return dict(record) if record else {}


async def get_slow_jobs(
    driver: AsyncDriver,
    threshold_minutes: int = 10,
    days: int = 7,
    limit: int = 10,
) -> dict[str, Any]:
    """Return executions that exceeded *threshold_minutes*.

    Args:
        driver: Shared Neo4j async driver.
        threshold_minutes: Minimum execution time to qualify as 'slow'.
        days: How many days back to search.
        limit: Maximum number of records to return.

    Returns:
        ``{"slow_jobs": [...], "count": N, "threshold_minutes": T, "time_range_days": days}``
    """
    logger.info(
        "get_slow_jobs threshold_minutes=%s days=%s limit=%s",
        threshold_minutes, days, limit,
    )
    threshold_ms = threshold_minutes * 60_000
    async with kg_session(driver) as session:
        result = await session.run(
            _Q_SLOW_JOBS,
            start_date=_start_date(days),
            threshold_ms=threshold_ms,
            limit=limit,
        )
        records = await result.data()
    return {
        "slow_jobs": records,
        "count": len(records),
        "threshold_minutes": threshold_minutes,
        "time_range_days": days,
    }


async def get_step_failure_analysis(
    driver: AsyncDriver,
    job_id: str,
    days: int = 30,
) -> dict[str, Any]:
    """Return step-level failure rates for a specific job.

    Args:
        driver: Shared Neo4j async driver.
        job_id: The ``id`` property of the target ``Job`` node.
        days: How many days back to include.

    Returns:
        ``{"job_id": job_id, "step_analysis": [...], "count": N, "time_range_days": days}``
    """
    logger.info("get_step_failure_analysis job_id=%s days=%s", job_id, days)
    async with kg_session(driver) as session:
        result = await session.run(
            _Q_STEP_FAILURE_ANALYSIS, job_id=job_id, start_date=_start_date(days)
        )
        records = await result.data()
    return {
        "job_id": job_id,
        "step_analysis": records,
        "count": len(records),
        "time_range_days": days,
    }


async def compare_jobs(
    driver: AsyncDriver,
    job_ids: list[str],
    days: int = 30,
) -> dict[str, Any]:
    """Compare performance metrics across multiple jobs side by side.

    Args:
        driver: Shared Neo4j async driver.
        job_ids: List of ``id`` property values of ``Job`` nodes.
        days: How many days back to include.

    Returns:
        ``{"job_comparison": [...], "jobs_compared": job_ids, "count": N, "time_range_days": days}``
    """
    logger.info("compare_jobs job_ids=%s days=%s", job_ids, days)
    async with kg_session(driver) as session:
        result = await session.run(
            _Q_COMPARE_JOBS, job_ids=job_ids, start_date=_start_date(days)
        )
        records = await result.data()
    return {
        "job_comparison": records,
        "jobs_compared": job_ids,
        "count": len(records),
        "time_range_days": days,
    }
