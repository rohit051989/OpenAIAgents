"""Topology service — queries the structural definition of a Job.

Retrieves steps, blocks, entry point, SLAs, business calendar allow/deny rules,
required resources, listeners, tags, and schedule contexts for a given job.

Supports both job types:
- ``spring_xml_config_job``: has Steps, Blocks, CONTAINS/ENTRY/PRECEDES structure,
  HAS_LISTENER relationships, and a sourceFile from Spring XML.
- ``dynamic_job``: may have no steps/blocks; structure comes from the scheduling
  system rather than Spring XML.
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
MATCH (j:Job {name: $job_id})

// Steps (present for spring_xml_config_job; may be absent for dynamic_job)
OPTIONAL MATCH (j)-[:CONTAINS]->(s:Step)
WITH j, collect(DISTINCT {
    name:          s.name,
    id:            s.id,
    stepKind:      s.stepKind,
    className:     s.className,
    implBean:      s.implBean,
    readerBean:    s.readerBean,
    writerBean:    s.writerBean,
    processorBean: s.processorBean
}) AS steps

// Blocks (FLOW / PARALLEL — spring_xml_config_job only)
OPTIONAL MATCH (j)-[:CONTAINS]->(b:Block)
WITH j, steps, collect(DISTINCT {id: b.id, blockType: b.blockType}) AS blocks

// Entry point
OPTIONAL MATCH (j)-[:ENTRY]->(entry)
WITH j, steps, blocks, coalesce(entry.name, entry.id) AS entry_point

// SLAs
OPTIONAL MATCH (j)-[:HAS_SLA]->(sla:SLA)
WITH j, steps, blocks, entry_point, collect(DISTINCT {
    name: sla.name, id: sla.id, type: sla.type,
    severity: sla.severity,
    time: sla.time, durationMs: sla.durationMs
}) AS slas

// Business Calendar allow/deny rules via ScheduleInstanceContext (per-job scope)
OPTIONAL MATCH (sic:ScheduleInstanceContext)-[:FOR_JOB]->(j)
OPTIONAL MATCH (sic)-[sic_rel:ALLOWS|DENIES]->(sic_bc:BusinessCalendar)-[:USES_PATTERN]->(sic_cp:CalendarPattern)
WITH j, steps, blocks, entry_point, slas,
     collect(DISTINCT CASE WHEN sic_rel IS NOT NULL AND type(sic_rel) = 'ALLOWS' THEN {
         ruleId: sic_bc.ruleId, name: sic_bc.name, region: sic_bc.region,
         pattern: sic_cp.name, evaluatorFn: sic_cp.evaluatorFn, scope: 'JOB_CONTEXT'
     } END) AS _sic_allows_raw,
     collect(DISTINCT CASE WHEN sic_rel IS NOT NULL AND type(sic_rel) = 'DENIES' THEN {
         ruleId: sic_bc.ruleId, name: sic_bc.name, region: sic_bc.region,
         pattern: sic_cp.name, evaluatorFn: sic_cp.evaluatorFn, scope: 'JOB_CONTEXT',
         action: sic_rel.action
     } END) AS _sic_denies_raw

// Business Calendar allow/deny rules via JobGroup (group scope)
OPTIONAL MATCH (jg:JobGroup)-[:HAS_JOB]->(j)
OPTIONAL MATCH (jg)-[jg_rel:ALLOWS|DENIES]->(jg_bc:BusinessCalendar)-[:USES_PATTERN]->(jg_cp:CalendarPattern)
WITH j, steps, blocks, entry_point, slas, _sic_allows_raw, _sic_denies_raw,
     collect(DISTINCT CASE WHEN jg_rel IS NOT NULL AND type(jg_rel) = 'ALLOWS' THEN {
         ruleId: jg_bc.ruleId, name: jg_bc.name, region: jg_bc.region,
         pattern: jg_cp.name, evaluatorFn: jg_cp.evaluatorFn, scope: 'JOB_GROUP'
     } END) AS _jg_allows_raw,
     collect(DISTINCT CASE WHEN jg_rel IS NOT NULL AND type(jg_rel) = 'DENIES' THEN {
         ruleId: jg_bc.ruleId, name: jg_bc.name, region: jg_bc.region,
         pattern: jg_cp.name, evaluatorFn: jg_cp.evaluatorFn, scope: 'JOB_GROUP',
         action: jg_rel.action
     } END) AS _jg_denies_raw

// Merge SIC-level and group-level rules into final allow/deny lists
WITH j, steps, blocks, entry_point, slas,
     [x IN _sic_allows_raw WHERE x IS NOT NULL] +
     [x IN _jg_allows_raw  WHERE x IS NOT NULL] AS allow_rules,
     [x IN _sic_denies_raw WHERE x IS NOT NULL] +
     [x IN _jg_denies_raw  WHERE x IS NOT NULL] AS deny_rules

// Required resources
OPTIONAL MATCH (j)-[:Require_Resource]->(res:Resource)
WITH j, steps, blocks, entry_point, slas, allow_rules, deny_rules,
     collect(DISTINCT {name: res.name, type: res.type}) AS required_resources

// Listeners
OPTIONAL MATCH (j)-[:HAS_LISTENER]->(listener:Listener)
WITH j, steps, blocks, entry_point, slas, allow_rules, deny_rules,
     required_resources, collect(DISTINCT listener.name) AS listeners

// Tags
OPTIONAL MATCH (j)-[:HAS_TAG]->(tag:Tag)
WITH j, steps, blocks, entry_point, slas, allow_rules, deny_rules,
     required_resources, listeners, collect(DISTINCT tag.name) AS tags

// Schedule contexts
OPTIONAL MATCH (ctx:ScheduleInstanceContext)-[:FOR_JOB]->(j)

RETURN
    j.name            AS job_name,
    j.id              AS job_id,
    j.type            AS job_type,
    j.sourceFile      AS source_file,
    j.enabled         AS enabled,
    steps,
    blocks,
    entry_point,
    slas,
    allow_rules,
    deny_rules,
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
        job_id: The ``name`` property value of the target ``Job`` node.
        driver: Shared Neo4j async driver.

    Returns:
        Dictionary with a ``job_topology`` key containing all structural data
        (including ``job_type``, ``allow_rules``, ``deny_rules``) and a
        ``job_id`` key echoing the request parameter.
    """
    logger.info("get_job_topology job_id=%s", job_id)
    async with kg_session(driver) as session:
        result = await session.run(_Q_JOB_TOPOLOGY, job_id=job_id)
        records = await result.data()
    return {
        "job_topology": records[0] if records else {},
        "job_id": job_id,
    }
