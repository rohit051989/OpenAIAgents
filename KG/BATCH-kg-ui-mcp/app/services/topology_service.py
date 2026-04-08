"""Topology service — queries the structural definition of a Job.

Retrieves steps, blocks, entry point, SLAs, calendars, required resources,
listeners, tags, and schedule contexts for a given job.
"""

import logging
from typing import Any

from neo4j import AsyncDriver

from app.core.database import kg_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher
# ---------------------------------------------------------------------------

_Q_JOB_TOPOLOGY = """
MATCH (j:Job {id: $job_id})

// Steps
OPTIONAL MATCH (j)-[:CONTAINS]->(s:Step)
WITH j, collect(DISTINCT {
    name: s.name, id: s.id, stepKind: s.stepKind,
    className: s.className, implBean: s.implBean
}) AS steps

// Blocks
OPTIONAL MATCH (j)-[:CONTAINS]->(b:Block)
WITH j, steps, collect(DISTINCT {name: b.name, id: b.id, type: b.type}) AS blocks

// Entry point
OPTIONAL MATCH (j)-[:ENTRY]->(entry)
WITH j, steps, blocks, entry.name AS entry_point

// SLAs
OPTIONAL MATCH (j)-[:HAS_SLA]->(sla:SLA)
WITH j, steps, blocks, entry_point, collect(DISTINCT {
    name: sla.name, id: sla.id, type: sla.type,
    policy: sla.policy, severity: sla.severity,
    time: sla.time, durationMs: sla.durationMs
}) AS slas

// Allowed calendars
OPTIONAL MATCH (j)-[:CAN_EXECUTE_ON]->(cal_allow:Calendar)
WITH j, steps, blocks, entry_point, slas,
     collect(DISTINCT cal_allow.name) AS calendars_allowed

// Blocked calendars
OPTIONAL MATCH (j)-[:CANNOT_EXECUTE_ON]->(cal_block:Calendar)
WITH j, steps, blocks, entry_point, slas, calendars_allowed,
     collect(DISTINCT cal_block.name) AS calendars_blocked

// Required resources
OPTIONAL MATCH (j)-[:Require_Resource]->(res:Resource)
WITH j, steps, blocks, entry_point, slas, calendars_allowed, calendars_blocked,
     collect(DISTINCT res.name) AS required_resources

// Listeners
OPTIONAL MATCH (j)-[:HAS_LISTENER]->(listener:Listener)
WITH j, steps, blocks, entry_point, slas, calendars_allowed, calendars_blocked,
     required_resources, collect(DISTINCT listener.name) AS listeners

// Tags
OPTIONAL MATCH (j)-[:HAS_TAG]->(tag:Tag)
WITH j, steps, blocks, entry_point, slas, calendars_allowed, calendars_blocked,
     required_resources, listeners, collect(DISTINCT tag.name) AS tags

// Schedule contexts
OPTIONAL MATCH (ctx:ScheduleInstanceContext)-[:FOR_JOB]->(j)

RETURN
    j.name            AS job_name,
    j.id              AS job_id,
    j.sourceFile      AS source_file,
    j.enabled         AS enabled,
    steps,
    blocks,
    entry_point,
    slas,
    calendars_allowed,
    calendars_blocked,
    required_resources,
    listeners,
    tags,
    collect(DISTINCT ctx.id) AS schedule_contexts
"""


# ---------------------------------------------------------------------------
# Public service function
# ---------------------------------------------------------------------------

async def get_job_topology(job_id: str, driver: AsyncDriver) -> dict[str, Any]:
    """Return the structural topology of a Job.

    Args:
        job_id: The ``id`` property value of the target ``Job`` node.
        driver: Shared Neo4j async driver.

    Returns:
        Dictionary with a ``job_topology`` key containing all structural data
        and a ``job_id`` key echoing the request parameter.
    """
    logger.info("get_job_topology job_id=%s", job_id)
    async with kg_session(driver) as session:
        result = await session.run(_Q_JOB_TOPOLOGY, job_id=job_id)
        records = await result.data()
    return {
        "job_topology": records[0] if records else {},
        "job_id": job_id,
    }
