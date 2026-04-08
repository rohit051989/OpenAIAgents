"""Execution service — queries job and step execution history.

Covers:
  - Failed jobs
  - Common error messages
  - Daily execution timeline
  - Full execution history per job
  - All recently-active jobs
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

_Q_FAILED_JOBS = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE e.status = 'FAILED'
  AND e.startTime >= datetime($start_date)
OPTIONAL MATCH (se:StepExecution)-[:FOR_RUN]->(e)
WHERE se.status = 'FAILED'
WITH j, e, collect(DISTINCT se.stepId) AS failed_steps
RETURN
    j.name              AS job_name,
    e.id                AS execution_id,
    toString(e.startTime) AS start_time,
    toString(e.endTime)   AS end_time,
    e.exitMessage         AS error_message,
    failed_steps
ORDER BY e.startTime DESC
LIMIT $limit
"""

_Q_COMMON_ERRORS = """
MATCH (e:JobContextExecution)
WHERE e.status = 'FAILED'
  AND e.exitMessage IS NOT NULL
  AND e.startTime >= datetime($start_date)
WITH e.exitMessage AS error, count(*) AS occurrences
ORDER BY occurrences DESC
LIMIT $limit
RETURN error, occurrences
"""

_Q_EXECUTION_TIMELINE = """
MATCH (e:JobContextExecution)
WHERE e.startTime >= datetime($start_date)
WITH date(e.startTime) AS execution_date,
     count(e)                                                           AS total_executions,
     sum(CASE WHEN e.status = 'COMPLETED' THEN 1 ELSE 0 END)           AS completed,
     sum(CASE WHEN e.status = 'FAILED'    THEN 1 ELSE 0 END)           AS failed
RETURN
    toString(execution_date) AS execution_date,
    total_executions,
    completed,
    failed,
    round(100.0 * failed / total_executions, 2) AS failure_rate
ORDER BY execution_date DESC
"""

_Q_JOB_EXECUTION_HISTORY = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE j.id = $job_id
  AND e.startTime >= datetime($start_date)
RETURN
    e.id                  AS execution_id,
    toString(e.startTime) AS start_time,
    toString(e.endTime)   AS end_time,
    e.status              AS status,
    e.durationMs          AS duration_ms,
    e.exitMessage         AS error_message
ORDER BY e.startTime DESC
LIMIT $limit
"""

_Q_ALL_ACTIVE_JOBS = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE e.startTime >= datetime($start_date)
WITH j.id AS job_id, j.name AS job_name,
     count(e) AS execution_count,
     max(e.startTime) AS last_execution
RETURN
    job_id,
    job_name,
    execution_count,
    toString(last_execution) AS last_execution
ORDER BY last_execution DESC
"""


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def _start_date(days: int) -> str:
    return (datetime.now() - timedelta(days=days)).isoformat()


async def get_failed_jobs(
    driver: AsyncDriver,
    days: int = 7,
    limit: int = 10,
) -> dict[str, Any]:
    """Return failed job executions within the recent *days* window.

    Args:
        driver: Shared Neo4j async driver.
        days: How many days back to search.
        limit: Maximum number of records to return.

    Returns:
        ``{"failed_jobs": [...], "count": N, "time_range_days": days}``
    """
    logger.info("get_failed_jobs days=%s limit=%s", days, limit)
    async with kg_session(driver) as session:
        result = await session.run(_Q_FAILED_JOBS, start_date=_start_date(days), limit=limit)
        records = await result.data()
    return {"failed_jobs": records, "count": len(records), "time_range_days": days}


async def get_common_errors(
    driver: AsyncDriver,
    days: int = 30,
    limit: int = 10,
) -> dict[str, Any]:
    """Return the most frequent error messages from failed executions.

    Args:
        driver: Shared Neo4j async driver.
        days: How many days back to search.
        limit: Maximum number of error messages to return.

    Returns:
        ``{"common_errors": [...], "count": N, "time_range_days": days}``
    """
    logger.info("get_common_errors days=%s limit=%s", days, limit)
    async with kg_session(driver) as session:
        result = await session.run(_Q_COMMON_ERRORS, start_date=_start_date(days), limit=limit)
        records = await result.data()
    return {"common_errors": records, "count": len(records), "time_range_days": days}


async def get_execution_timeline(
    driver: AsyncDriver,
    days: int = 30,
) -> dict[str, Any]:
    """Return daily execution statistics across all jobs.

    Args:
        driver: Shared Neo4j async driver.
        days: How many days back to include.

    Returns:
        ``{"timeline": [...], "count": N, "time_range_days": days}``
    """
    logger.info("get_execution_timeline days=%s", days)
    async with kg_session(driver) as session:
        result = await session.run(_Q_EXECUTION_TIMELINE, start_date=_start_date(days))
        records = await result.data()
    return {"timeline": records, "count": len(records), "time_range_days": days}


async def get_job_execution_history(
    driver: AsyncDriver,
    job_id: str,
    days: int = 30,
    limit: int = 50,
) -> dict[str, Any]:
    """Return execution history for a specific job.

    Args:
        driver: Shared Neo4j async driver.
        job_id: The ``id`` property of the target ``Job`` node.
        days: How many days back to include.
        limit: Maximum number of records to return.

    Returns:
        ``{"job_id": job_id, "execution_history": [...], "count": N, "time_range_days": days}``
    """
    logger.info("get_job_execution_history job_id=%s days=%s limit=%s", job_id, days, limit)
    async with kg_session(driver) as session:
        result = await session.run(
            _Q_JOB_EXECUTION_HISTORY,
            job_id=job_id,
            start_date=_start_date(days),
            limit=limit,
        )
        records = await result.data()
    return {
        "job_id": job_id,
        "execution_history": records,
        "count": len(records),
        "time_range_days": days,
    }


async def get_all_active_jobs(
    driver: AsyncDriver,
    days: int = 30,
) -> dict[str, Any]:
    """Return all jobs that have executed within the recent *days* window.

    Args:
        driver: Shared Neo4j async driver.
        days: How many days back to search.

    Returns:
        ``{"active_jobs": [...], "count": N, "time_range_days": days}``
    """
    logger.info("get_all_active_jobs days=%s", days)
    async with kg_session(driver) as session:
        result = await session.run(_Q_ALL_ACTIVE_JOBS, start_date=_start_date(days))
        records = await result.data()
    return {"active_jobs": records, "count": len(records), "time_range_days": days}
