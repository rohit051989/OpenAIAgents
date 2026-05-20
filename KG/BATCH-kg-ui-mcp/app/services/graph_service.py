"""Graph visualization service — entity subgraph and node expansion queries.

Provides two operations:
  - ``get_entity_graph``  — subgraph centered on a KG entity (Job, Step, etc.)
  - ``expand_node``       — immediate neighbours of a single node, excluding
                           nodes the caller already has

Both return the standard ``GraphData`` shape:
    ``{"nodes": [{id, labels, properties}], "relationships": [{id, type, startNodeId, endNodeId, properties}]}``
"""

import logging
from datetime import date, datetime
from typing import Any

from neo4j import AsyncDriver

from app.core.database import kg_session
from app.services.anomalies_service import _build_sic_map, _evaluate_sic

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher helpers
# ---------------------------------------------------------------------------

# Look up a center node by its application id property or Neo4j element ID,
# then collect all nodes and relationships reachable within `depth` hops.
_Q_ENTITY_GRAPH = """
MATCH (center)
WHERE center.id = $entity_id OR elementId(center) = $entity_id OR center.name = $entity_id
CALL {
    WITH center
    OPTIONAL MATCH (center)-[r]-(neighbor)
    WITH center, collect(DISTINCT neighbor) AS neighbors, collect(DISTINCT r) AS rels
    RETURN neighbors, rels
}
WITH [center] + neighbors AS allNodes, rels
UNWIND allNodes AS n
WITH collect(DISTINCT {
    id:         coalesce(n.id, elementId(n)),
    elementId:  elementId(n),
    labels:     labels(n),
    properties: {
        id:          n.id,
        name:        n.name,
        description: n.description,
        type:        n.type,
        enabled:     n.enabled,
        status:      n.status
    }
}) AS nodes, rels
UNWIND rels AS r
RETURN nodes, collect(DISTINCT {
    id:          elementId(r),
    type:        type(r),
    startNodeId: coalesce(startNode(r).id, elementId(startNode(r))),
    endNodeId:   coalesce(endNode(r).id,   elementId(endNode(r))),
    properties:  properties(r)
}) AS relationships
"""

_Q_EXPAND_NODE = """
MATCH (n)
WHERE n.id = $node_id OR elementId(n) = $node_id
OPTIONAL MATCH (n)-[r]-(neighbor)
WHERE NOT (coalesce(neighbor.id, elementId(neighbor))) IN $existing_node_ids
WITH collect(DISTINCT {
    id:         coalesce(neighbor.id, elementId(neighbor)),
    elementId:  elementId(neighbor),
    labels:     labels(neighbor),
    properties: {
        id:          neighbor.id,
        name:        neighbor.name,
        description: neighbor.description,
        type:        neighbor.type,
        enabled:     neighbor.enabled,
        status:      neighbor.status
    }
}) AS nodes,
collect(DISTINCT {
    id:          elementId(r),
    type:        type(r),
    startNodeId: coalesce(startNode(r).id, elementId(startNode(r))),
    endNodeId:   coalesce(endNode(r).id,   elementId(endNode(r))),
    properties:  properties(r)
}) AS relationships
RETURN nodes, relationships
"""

# Fetch all SICs optionally scoped to a JobGroup.
# Returns the same column set as _Q_ALL_SICS in anomalies_service so the
# shared _build_sic_map / _evaluate_sic helpers work unchanged.
_Q_ELIGIBLE_SICS = """
MATCH (sic:ScheduleInstanceContext)-[:FOR_GROUP]->(jg:JobGroup)
MATCH (sic)-[:FOR_JOB]->(job:Job)
WHERE ($job_group IS NULL OR jg.id = $job_group OR jg.name = $job_group OR elementId(jg) = $job_group)
RETURN
  elementId(sic) AS sic_eid,
  sic.id         AS sic_id,
  sic.enabled    AS sic_enabled,
  job.name       AS job_name,
  elementId(job) AS job_eid,
  elementId(jg)  AS jg_eid,
  jg.name        AS jg_name
"""

# JobGroup-level ALLOWS/DENIES rules restricted to the JGs in the scope set.
_Q_JG_RULES_FILTERED = """
MATCH (jg:JobGroup)-[rel:ALLOWS|DENIES]->(jr:BusinessCalendar)-[:USES_PATTERN]->(cp:CalendarPattern)
WHERE elementId(jg) IN $jg_eids
OPTIONAL MATCH (cp)-[hr:IS_HOLIDAY_ON]->(h:Day)
WITH jg, rel, jr, cp,
     collect(DISTINCT CASE WHEN h IS NOT NULL THEN {
       region: hr.region,
       date:   toString(h.date),
       name:   hr.name
     } END) AS holidays
RETURN
  elementId(jg)  AS target_eid,
  type(rel)      AS rule_type,
  jr.ruleId      AS rule_id,
  cp.evaluatorFn AS evaluatorFn,
  jr.params      AS params,
  holidays
"""

# SIC-level ALLOWS/DENIES rules restricted to the SICs in the scope set.
_Q_SIC_RULES_FILTERED = """
MATCH (sic:ScheduleInstanceContext)-[rel:ALLOWS|DENIES]->(jr:BusinessCalendar)-[:USES_PATTERN]->(cp:CalendarPattern)
WHERE elementId(sic) IN $sic_eids
OPTIONAL MATCH (cp)-[hr:IS_HOLIDAY_ON]->(h:Day)
WITH sic, rel, jr, cp,
     collect(DISTINCT CASE WHEN h IS NOT NULL THEN {
       region: hr.region,
       date:   toString(h.date),
       name:   hr.name
     } END) AS holidays
RETURN
  elementId(sic) AS target_eid,
  type(rel)      AS rule_type,
  jr.ruleId      AS rule_id,
  cp.evaluatorFn AS evaluatorFn,
  jr.params      AS params,
  holidays
"""

_Q_SCOPED_ACTUAL_CONTEXTS_BY_DATE = """
MATCH (jge:JobGroupExecution)
WHERE jge.businessDate = date($business_date)
     OR toString(jge.businessDate) = $business_date
MATCH (jge)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(sic:ScheduleInstanceContext)
MATCH (sic)-[:FOR_GROUP]->(jg:JobGroup)
MATCH (sic)-[:FOR_JOB]->(job:Job)
WHERE ($job_group IS NULL OR jg.id = $job_group OR jg.name = $job_group OR elementId(jg) = $job_group)
WITH sic, job, jg, jce
ORDER BY jce.startTime DESC
WITH sic, job, jg, collect(jce)[0] AS latest
RETURN DISTINCT
    elementId(sic) AS sic_element_id,
    sic.id AS sic_id,
    sic.name AS sic_name,
    elementId(job) AS job_element_id,
    job.id AS job_id,
    job.name AS job_name,
    elementId(jg) AS job_group_element_id,
    jg.id AS job_group_id,
    jg.name AS job_group_name,
    latest.id AS execution_id,
    latest.status AS execution_status,
    toString(latest.startTime) AS start_time,
    toString(latest.endTime) AS end_time,
    latest.durationMs AS duration_ms
"""

_Q_PRECEDES_BETWEEN_CONTEXTS = """
UNWIND $sic_element_ids AS source_sic_id
MATCH (src:ScheduleInstanceContext)
WHERE elementId(src) = source_sic_id
MATCH (src)-[r:PRECEDES]->(dst:ScheduleInstanceContext)
WHERE elementId(dst) IN $sic_element_ids
RETURN DISTINCT
    elementId(r) AS relationship_id,
    elementId(src) AS start_sic_element_id,
    elementId(dst) AS end_sic_element_id
"""


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------

def _clean_properties(props: dict[str, Any]) -> dict[str, Any]:
    """Remove None-valued keys from a properties dict."""
    return {k: v for k, v in props.items() if v is not None}


def _normalise_row(row: dict[str, Any]) -> dict[str, Any]:
    nodes = [
        {
            "id": n["id"],
            "labels": n.get("labels", []),
            "properties": _clean_properties(n.get("properties", {})),
        }
        for n in (row.get("nodes") or [])
        if n and n.get("id")
    ]
    relationships = [
        {
            "id": str(r["id"]),
            "type": r.get("type", ""),
            "startNodeId": r.get("startNodeId", ""),
            "endNodeId": r.get("endNodeId", ""),
            "properties": _clean_properties(r.get("properties", {})),
        }
        for r in (row.get("relationships") or [])
        if r and r.get("id") and r.get("startNodeId") and r.get("endNodeId")
    ]
    return {"nodes": nodes, "relationships": relationships}


async def get_entity_graph(
    driver: AsyncDriver,
    entity_id: str,
) -> dict[str, Any]:
    """Return a 1-hop subgraph centered on the given entity.

    Args:
        driver: Shared Neo4j async driver.
        entity_id: The ``id`` property, ``name``, or Neo4j element ID of the
            target node.

    Returns:
        ``{"nodes": [...], "relationships": [...]}``
    """
    logger.info("get_entity_graph entity_id=%s", entity_id)
    async with kg_session(driver) as session:
        result = await session.run(_Q_ENTITY_GRAPH, entity_id=entity_id)
        rows = await result.data()

    if not rows:
        logger.warning("No graph data found for entity_id=%s", entity_id)
        return {"nodes": [], "relationships": []}

    return _normalise_row(rows[0])


async def expand_node(
    driver: AsyncDriver,
    node_id: str,
    existing_node_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Return immediate neighbours of *node_id* not already in the graph.

    Args:
        driver: Shared Neo4j async driver.
        node_id: The ``id`` property or Neo4j element ID of the node to expand.
        existing_node_ids: Node IDs already rendered by the frontend.  These
            are excluded from the response to avoid duplicating data.

    Returns:
        ``{"nodes": [...], "relationships": [...]}`` containing only new nodes
        and any relationships connecting them (including back to existing nodes).
    """
    logger.info("expand_node node_id=%s existing=%s", node_id, len(existing_node_ids or []))
    async with kg_session(driver) as session:
        result = await session.run(
            _Q_EXPAND_NODE,
            node_id=node_id,
            existing_node_ids=existing_node_ids or [],
        )
        rows = await result.data()

    if not rows:
        return {"nodes": [], "relationships": []}

    return _normalise_row(rows[0])


def _parse_iso_business_date(business_date: str) -> date:
    try:
        return datetime.fromisoformat(business_date).date()
    except ValueError as exc:
        raise ValueError("business_date must be ISO format YYYY-MM-DD") from exc


def _build_job_graph_node(
    row: dict[str, Any],
    *,
    mode: str,
    planned: bool | None,
    has_actual: bool,
) -> dict[str, Any]:
    # Normalise field names — rows from eligibility queries use sic_eid/job_eid;
    # rows from the actual-execution query use sic_element_id/job_element_id.
    node_id = row.get("sic_element_id") or row.get("sic_eid") or ""
    props = {
        "sic_id":          row.get("sic_id"),
        "job_id":          row.get("job_id"),
        "job_name":        row.get("job_name"),
        "job_group_id":    row.get("job_group_id") or row.get("jg_eid"),
        "job_group_name":  row.get("job_group_name") or row.get("jg_name"),
        "mode":            mode,
        "planned":         planned,
        "has_actual_execution": has_actual,
        "execution_id":    row.get("execution_id"),
        "execution_status": row.get("execution_status"),
        "start_time":      row.get("start_time"),
        "end_time":        row.get("end_time"),
        "duration_ms":     row.get("duration_ms"),
    }
    return {
        "id":     node_id,
        "labels": ["ScheduleInstanceContext"],
        "properties": _clean_properties(props),
    }


async def _get_precedes_relationships(
    driver: AsyncDriver,
    sic_element_ids: list[str],
) -> list[dict[str, Any]]:
    if not sic_element_ids:
        return []

    async with kg_session(driver) as session:
        result = await session.run(
            _Q_PRECEDES_BETWEEN_CONTEXTS,
            sic_element_ids=sic_element_ids,
        )
        rows = await result.data()

    return [
        {
            "id": row["relationship_id"],
            "type": "PRECEDES",
            "startNodeId": row["start_sic_element_id"],
            "endNodeId": row["end_sic_element_id"],
            "properties": {},
        }
        for row in rows
        if row.get("relationship_id") and row.get("start_sic_element_id") and row.get("end_sic_element_id")
    ]


async def get_job_graph_for_date(
    driver: AsyncDriver,
    business_date: str,
    region: str = "ALL",
    job_group: str | None = None,
) -> dict[str, Any]:
    """Return a date-aware job graph with proper calendar-based eligibility.

    Algorithm
    ---------
    1. Fetch all SICs (optionally scoped by job_group).
       If job_group is NOT provided, fetch ALL SICs in the KG.
    2. Fetch their JG-level and SIC-level ALLOWS/DENIES rules.
    3. Apply calendar evaluation for business_date / region.
       Only SICs passing rule evaluation are marked ``planned=true``.
       SICs with no rules are excluded from the plan.
    4. For past dates:   ``schedule_vs_actual`` mode
       - Show eligible SICs + which ones actually ran
       - Show wrongly_executed (executed but not eligible)
    5. For current date: ``actual`` mode
       - Show ALL eligible SICs + which ones are currently executing
       - Show wrongly_executed (running but not eligible)
    6. For future dates: ``schedule`` mode
       - Show only eligible SICs
    7. Build graph nodes and fetch PRECEDES edges between them.

    Date modes
    ----------
    - past date    -> ``schedule_vs_actual``  (eligible vs what actually ran + wrongly_executed)
    - current date -> ``actual``              (eligible vs currently executing + wrongly_executed)
    - future date  -> ``schedule``            (eligible SICs only)
    """
    d = _parse_iso_business_date(business_date)
    today = date.today()
    if d < today:
        mode = "schedule_vs_actual"
    elif d == today:
        mode = "actual"
    else:
        mode = "schedule"

    logger.info(
        "get_job_graph_for_date date=%s region=%s mode=%s job_group=%s",
        business_date, region, mode, job_group,
    )

    # ── Step 1: fetch scoped SICs + their rules ───────────────────────────────
    async with kg_session(driver) as session:
        r_sics = await (
            await session.run(
                _Q_ELIGIBLE_SICS,
                job_group=job_group,
            )
        ).fetch(5000)
        all_sics = [dict(r) for r in r_sics]

        jg_eids  = list({s["jg_eid"]  for s in all_sics if s.get("jg_eid")})
        sic_eids = [s["sic_eid"] for s in all_sics if s.get("sic_eid")]

        r_jg_rules = await (
            await session.run(_Q_JG_RULES_FILTERED, jg_eids=jg_eids)
        ).fetch(5000)
        r_sic_rules = await (
            await session.run(_Q_SIC_RULES_FILTERED, sic_eids=sic_eids)
        ).fetch(5000)

        actual_rows: list[dict[str, Any]] = []
        if mode in {"schedule_vs_actual", "actual"}:
            r_exec = await (
                await session.run(
                    _Q_SCOPED_ACTUAL_CONTEXTS_BY_DATE,
                    business_date=business_date,
                    job_group=job_group,
                )
            ).fetch(5000)
            actual_rows = [dict(r) for r in r_exec]

    jg_rules  = [dict(r) for r in r_jg_rules]
    sic_rules = [dict(r) for r in r_sic_rules]

    logger.info(
        "Scoped: %d SICs | %d JG rules | %d SIC rules | %d actual executions",
        len(all_sics), len(jg_rules), len(sic_rules), len(actual_rows),
    )

    # ── Step 2: calendar evaluation → eligible (planned) SIC set ─────────────
    # _build_sic_map fans JG rules to every SIC of that JG and returns only
    # SICs that have at least one rule.  _evaluate_sic applies ALLOW/DENY logic.
    sic_map = _build_sic_map(all_sics, jg_rules, sic_rules)

    eligible_eids: set[str] = set()
    for sic_eid, sic_entry in sic_map.items():
        should_run, _ = _evaluate_sic(sic_entry, d, region)
        if should_run:
            eligible_eids.add(sic_eid)

    # SICs without any rules are excluded from the planned set (no rules = not scheduled)
    sics_by_eid = {s["sic_eid"]: s for s in all_sics if s.get("sic_eid")}
    actual_by_eid = {r["sic_element_id"]: r for r in actual_rows if r.get("sic_element_id")}

    logger.info("Eligible SICs: %d | Actual executions: %d", len(eligible_eids), len(actual_rows))

    # ── Step 3: build graph nodes ─────────────────────────────────────────────
    nodes: list[dict[str, Any]] = []
    seen_eids: set[str] = set()

    if mode == "schedule_vs_actual":
        # Eligible SICs — show whether they actually ran
        for sic_eid in eligible_eids:
            row = actual_by_eid.get(sic_eid) or sics_by_eid.get(sic_eid) or {}
            if not row:
                continue
            # Merge sic_eid key naming so _build_job_graph_node can find it
            row = {**row, "sic_element_id": sic_eid, "sic_eid": sic_eid}
            nodes.append(_build_job_graph_node(row, mode=mode, planned=True,
                                               has_actual=sic_eid in actual_by_eid))
            seen_eids.add(sic_eid)

        # Actual-only contexts (ran but were not eligible = anomaly jobs)
        for sic_eid, row in actual_by_eid.items():
            if sic_eid in seen_eids:
                continue
            nodes.append(_build_job_graph_node(
                {**row, "sic_eid": sic_eid},
                mode=mode, planned=False, has_actual=True,
            ))

    elif mode == "actual":
        # Current date — show all eligible SICs + which ones actually executed.
        # First show eligible SICs (whether executed or not),
        # then show wrongly_executed (executed but not eligible).
        for sic_eid in eligible_eids:
            row = actual_by_eid.get(sic_eid) or sics_by_eid.get(sic_eid) or {}
            if not row:
                continue
            row = {**row, "sic_element_id": sic_eid, "sic_eid": sic_eid}
            nodes.append(_build_job_graph_node(
                row, mode=mode, planned=True, has_actual=sic_eid in actual_by_eid
            ))
            seen_eids.add(sic_eid)

        # Wrongly executed: ran but were not eligible (anomaly jobs on today's date)
        for sic_eid, row in actual_by_eid.items():
            if sic_eid in seen_eids:
                continue
            nodes.append(_build_job_graph_node(
                {**row, "sic_eid": sic_eid},
                mode=mode, planned=False, has_actual=True,
            ))

    else:  # future — schedule only
        for sic_eid in eligible_eids:
            row = sics_by_eid.get(sic_eid, {})
            nodes.append(_build_job_graph_node(
                {**row, "sic_element_id": sic_eid, "sic_eid": sic_eid},
                mode=mode, planned=True, has_actual=False,
            ))

    # ── Step 4: fetch PRECEDES edges between the selected nodes ───────────────
    node_ids = [n["id"] for n in nodes if n.get("id")]
    relationships = await _get_precedes_relationships(driver, node_ids)

    return {
        "graph_mode": mode,
        "business_date": business_date,
        "region": region,
        "filters": {
            "job_group": job_group,
        },
        "nodes": nodes,
        "relationships": relationships,
        "summary": _clean_properties({
            "mode":              mode,
            "business_date":     business_date,
            "region":            region,
            "job_group_filter":  job_group,
            "total_sics_in_scope": len(all_sics),
            "eligible_count":    len(eligible_eids),
            "actual_count":      len(actual_rows),
            "node_count":        len(nodes),
            "relationship_count": len(relationships),
        }),
    }
