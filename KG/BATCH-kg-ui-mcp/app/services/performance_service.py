"""Performance service — job performance metrics and analysis.

Covers:
  - Per-job duration statistics (avg / min / max)
  - Jobs that exceeded an execution time threshold
  - Step-level failure rate analysis for a job
  - Side-by-side comparison of multiple jobs
"""

import logging
from datetime import date, datetime, time, timedelta
from typing import Any

from neo4j import AsyncDriver

from app.core.database import kg_session
from app.services.anomalies_service import _build_sic_map, _evaluate_sic

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

_Q_SCOPED_SICS = """
MATCH (sic:ScheduleInstanceContext)-[:FOR_GROUP]->(jg:JobGroup)
MATCH (sic)-[:FOR_JOB]->(job:Job)
WHERE ($job_group IS NULL OR jg.id = $job_group OR jg.name = $job_group OR elementId(jg) = $job_group)
RETURN
    elementId(sic) AS sic_eid,
    sic.id         AS sic_id,
    sic.name       AS sic_name,
    sic.enabled    AS sic_enabled,
    job.id         AS job_id,
    job.name       AS job_name,
    elementId(job) AS job_eid,
    jg.id          AS jg_id,
    elementId(jg)  AS jg_eid,
    jg.name        AS jg_name
"""

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

_Q_EXECUTION_SICS_BY_DATE = """
MATCH (jge:JobGroupExecution)
WHERE jge.businessDate = date($business_date)
     OR toString(jge.businessDate) = $business_date
MATCH (jge)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(sic:ScheduleInstanceContext)
MATCH (sic)-[:FOR_GROUP]->(jg:JobGroup)
OPTIONAL MATCH (sic)-[:FOR_JOB]->(job:Job)
WITH sic, jg, job, jce
ORDER BY jce.startTime DESC
WITH sic, jg, job, collect(jce)[0] AS latest
RETURN DISTINCT
        elementId(sic)              AS sic_eid,
        sic.id                      AS sic_id,
        sic.name                    AS sic_name,
        elementId(jg)               AS jg_eid,
        jg.id                       AS jg_id,
        jg.name                     AS jg_name,
        elementId(job)              AS job_eid,
        job.id                      AS job_id,
        job.name                    AS job_name,
        latest.id                   AS execution_id,
        latest.status               AS execution_status,
        toString(latest.startTime)  AS start_time,
        toString(latest.endTime)    AS end_time,
        latest.durationMs           AS duration_ms
"""

_Q_EXECUTION_SICS_FOR_SET_BY_DATE = """
UNWIND $sic_eids AS sic_eid
MATCH (sic:ScheduleInstanceContext)
WHERE elementId(sic) = sic_eid
OPTIONAL MATCH (jge:JobGroupExecution)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(sic)
WHERE jge.businessDate = date($business_date)
   OR toString(jge.businessDate) = $business_date
WITH sic, jce
ORDER BY jce.startTime DESC
WITH sic, collect(jce)[0] AS latest
RETURN
    elementId(sic)              AS sic_eid,
    latest.id                   AS execution_id,
    latest.status               AS execution_status,
    toString(latest.startTime)  AS start_time,
    toString(latest.endTime)    AS end_time,
    latest.durationMs           AS duration_ms
"""

_Q_AVG_DURATION_FOR_SICS = """
UNWIND $sic_eids AS sic_eid
MATCH (sic:ScheduleInstanceContext)
WHERE elementId(sic) = sic_eid
OPTIONAL MATCH (jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(sic)
WHERE jce.startTime >= datetime($start_date)
  AND jce.durationMs IS NOT NULL
RETURN
    sic_eid,
    avg(jce.durationMs) AS avg_duration_ms,
    count(jce) AS sample_size
"""

_Q_PRECEDES_BETWEEN_CONTEXTS = """
UNWIND $sic_eids AS source_sic_id
MATCH (src:ScheduleInstanceContext)
WHERE elementId(src) = source_sic_id
MATCH (src)-[r:PRECEDES]->(dst:ScheduleInstanceContext)
WHERE elementId(dst) IN $sic_eids
RETURN DISTINCT
    elementId(r) AS relationship_id,
    elementId(src) AS start_sic_eid,
    elementId(dst) AS end_sic_eid
"""

_Q_ROOT_SICS_BY_RESOURCE = """
MATCH (r:Resource)
WHERE r.id = $source_id OR r.name = $source_id OR elementId(r) = $source_id
OPTIONAL MATCH (sic1:ScheduleInstanceContext)-[:Require_Resource]->(r)
OPTIONAL MATCH (jg:JobGroup)-[:Require_Resource]->(r)
OPTIONAL MATCH (sic2:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
WITH r, collect(DISTINCT sic1) + collect(DISTINCT sic2) AS candidates
UNWIND candidates AS sic
WITH DISTINCT r, sic
WHERE sic IS NOT NULL
RETURN elementId(sic) AS sic_eid,
             sic.id         AS sic_id,
             sic.name       AS sic_name,
             r.id           AS source_entity_id,
             r.name         AS source_entity_name
"""

_Q_ROOT_SICS_BY_JOB = """
MATCH (j:Job)
WHERE j.id = $source_id OR j.name = $source_id OR elementId(j) = $source_id
MATCH (sic:ScheduleInstanceContext)-[:FOR_JOB]->(j)
RETURN elementId(sic) AS sic_eid,
             sic.id         AS sic_id,
             sic.name       AS sic_name,
             j.id           AS source_entity_id,
             j.name         AS source_entity_name
"""

_Q_ROOT_SICS_BY_SIC = """
MATCH (sic:ScheduleInstanceContext)
WHERE sic.id = $source_id OR sic.name = $source_id OR elementId(sic) = $source_id
RETURN elementId(sic) AS sic_eid,
             sic.id         AS sic_id,
             sic.name       AS sic_name,
             sic.id         AS source_entity_id,
             sic.name       AS source_entity_name
"""

_Q_ROOT_SICS_BY_JOB_GROUP = """
MATCH (jg:JobGroup)
WHERE jg.id = $source_id OR jg.name = $source_id OR elementId(jg) = $source_id
MATCH (sic:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
RETURN elementId(sic) AS sic_eid,
             sic.id         AS sic_id,
             sic.name       AS sic_name,
             jg.id          AS source_entity_id,
             jg.name        AS source_entity_name
"""

_Q_IMPACTED_SICS = """
UNWIND $root_sic_eids AS root_eid
MATCH (root:ScheduleInstanceContext)
WHERE elementId(root) = root_eid
MATCH p = (root)-[:PRECEDES*0..50]->(sic:ScheduleInstanceContext)
WITH collect(DISTINCT sic) AS impacted
UNWIND impacted AS sic
WITH DISTINCT sic
MATCH (sic)-[:FOR_GROUP]->(jg:JobGroup)
OPTIONAL MATCH (sic)-[:FOR_JOB]->(job:Job)
OPTIONAL MATCH (jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(sic)
WHERE jce.startTime >= datetime($start_date)
    AND jce.durationMs IS NOT NULL
WITH sic, jg, job,
         avg(jce.durationMs) AS avg_duration_ms
RETURN DISTINCT
    elementId(sic)            AS sic_eid,
    sic.id                    AS sic_id,
    sic.name                  AS sic_name,
    elementId(jg)             AS jg_eid,
    jg.id                     AS jg_id,
    jg.name                   AS jg_name,
    elementId(job)            AS job_eid,
    job.id                    AS job_id,
    job.name                  AS job_name,
    sic.estimatedDurationMs   AS estimated_duration_ms,
    avg_duration_ms
"""

_Q_IMPACTED_SICS_IN_SCOPE = """
UNWIND $root_sic_eids AS root_eid
MATCH (root:ScheduleInstanceContext)
WHERE elementId(root) = root_eid
    AND elementId(root) IN $scope_sic_eids
MATCH p = (root)-[:PRECEDES*0..50]->(sic:ScheduleInstanceContext)
WHERE elementId(sic) IN $scope_sic_eids
    AND all(n IN nodes(p) WHERE elementId(n) IN $scope_sic_eids)
WITH collect(DISTINCT sic) AS impacted
UNWIND impacted AS sic
WITH DISTINCT sic
MATCH (sic)-[:FOR_GROUP]->(jg:JobGroup)
OPTIONAL MATCH (sic)-[:FOR_JOB]->(job:Job)
OPTIONAL MATCH (jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(sic)
WHERE jce.startTime >= datetime($start_date)
        AND jce.durationMs IS NOT NULL
WITH sic, jg, job,
         avg(jce.durationMs) AS avg_duration_ms
RETURN DISTINCT
        elementId(sic)            AS sic_eid,
        sic.id                    AS sic_id,
        sic.name                  AS sic_name,
        elementId(jg)             AS jg_eid,
        jg.id                     AS jg_id,
        jg.name                   AS jg_name,
        elementId(job)            AS job_eid,
        job.id                    AS job_id,
        job.name                  AS job_name,
        sic.estimatedDurationMs   AS estimated_duration_ms,
        avg_duration_ms
"""

_Q_IMPACTED_SICS_IN_SCOPE_BASE = """
UNWIND $root_sic_eids AS root_eid
MATCH (root:ScheduleInstanceContext)
WHERE elementId(root) = root_eid
    AND elementId(root) IN $scope_sic_eids
MATCH p = (root)-[:PRECEDES*0..50]->(sic:ScheduleInstanceContext)
WHERE elementId(sic) IN $scope_sic_eids
    AND all(n IN nodes(p) WHERE elementId(n) IN $scope_sic_eids)
WITH collect(DISTINCT sic) AS impacted
UNWIND impacted AS sic
WITH DISTINCT sic
MATCH (sic)-[:FOR_GROUP]->(jg:JobGroup)
OPTIONAL MATCH (sic)-[:FOR_JOB]->(job:Job)
RETURN DISTINCT
        elementId(sic)            AS sic_eid,
        sic.id                    AS sic_id,
        sic.name                  AS sic_name,
        elementId(jg)             AS jg_eid,
        jg.id                     AS jg_id,
        jg.name                   AS jg_name,
        elementId(job)            AS job_eid,
        job.id                    AS job_id,
        job.name                  AS job_name
"""

_Q_SLA_ROWS_FOR_SICS = """
UNWIND $sic_eids AS sic_eid
MATCH (sic:ScheduleInstanceContext)
WHERE elementId(sic) = sic_eid
MATCH (sic)-[:FOR_GROUP]->(jg:JobGroup)
CALL {
        WITH sic, jg
        OPTIONAL MATCH (sic)-[:HAS_SLA]->(sic_sla:SLA)
        WHERE coalesce(sic_sla.enabled, true) = true
        OPTIONAL MATCH (jg)-[:HAS_SLA]->(jg_sla:SLA)
        WHERE coalesce(jg_sla.enabled, true) = true
        OPTIONAL MATCH (sic)-[:Require_Resource]->(sr:Resource)-[:HAS_SLA]->(sr_sla:SLA)
        WHERE coalesce(sr_sla.enabled, true) = true
        OPTIONAL MATCH (jg)-[:Require_Resource]->(gr:Resource)-[:HAS_SLA]->(gr_sla:SLA)
        WHERE coalesce(gr_sla.enabled, true) = true
        WITH sic, jg,
                 collect(DISTINCT {sla: sic_sla, owner_type: 'SIC', owner_id: sic.id, owner_name: sic.name}) +
                 collect(DISTINCT {sla: jg_sla, owner_type: 'JOB_GROUP', owner_id: jg.id, owner_name: jg.name}) +
                 collect(DISTINCT {sla: sr_sla, owner_type: 'RESOURCE', owner_id: sr.id, owner_name: sr.name}) +
                 collect(DISTINCT {sla: gr_sla, owner_type: 'RESOURCE', owner_id: gr.id, owner_name: gr.name})
                 AS rows
        UNWIND rows AS row
        WITH row
        WHERE row.sla IS NOT NULL
        RETURN DISTINCT row
}
OPTIONAL MATCH (row.sla)-[:RELATIVE_TO_RESOURCE|RELATIVE_TO]->(relative_res:Resource)
RETURN DISTINCT
    sic_eid,
    row.owner_type          AS owner_type,
    row.owner_id            AS owner_id,
    row.owner_name          AS owner_name,
    row.sla.id              AS sla_id,
    row.sla.name            AS sla_name,
    row.sla.type            AS sla_type,
    row.sla.policy          AS sla_policy,
    row.sla.severity        AS sla_severity,
    row.sla.durationMs      AS sla_duration_ms,
    row.sla.time            AS sla_time,
    row.sla.tz              AS sla_tz,
    relative_res.id         AS relative_resource_id,
    relative_res.name       AS relative_resource_name
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _start_date(days: int) -> str:
    return (datetime.now() - timedelta(days=days)).isoformat()


def _today_business_date() -> str:
    return date.today().isoformat()


def _parse_iso_business_date(business_date: str) -> date:
    try:
        return datetime.fromisoformat(business_date).date()
    except ValueError as exc:
        raise ValueError("business_date must be ISO format YYYY-MM-DD") from exc


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _parse_sla_clock(value: str | None) -> time | None:
    if not value:
        return None
    try:
        return time.fromisoformat(value)
    except ValueError:
        return None


def _normalise_source_type(source_type: str | None) -> str | None:
    if source_type is None:
        return None
    normalized = source_type.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "resource": "resource",
        "job": "job",
        "sic": "sic",
        "jobgroup": "job_group",
        "job_group": "job_group",
    }
    return aliases.get(normalized)


async def _get_eligible_sic_scope(
    session: Any,
    business_date: str,
    region: str,
    job_group: str | None = None,
) -> tuple[list[dict[str, Any]], set[str]]:
    business_day = _parse_iso_business_date(business_date)

    all_sics = await (await session.run(_Q_SCOPED_SICS, job_group=job_group)).data()
    jg_eids = list({row["jg_eid"] for row in all_sics if row.get("jg_eid")})
    sic_eids = [row["sic_eid"] for row in all_sics if row.get("sic_eid")]

    jg_rules = []
    sic_rules = []
    if jg_eids:
        jg_rules = await (await session.run(_Q_JG_RULES_FILTERED, jg_eids=jg_eids)).data()
    if sic_eids:
        sic_rules = await (await session.run(_Q_SIC_RULES_FILTERED, sic_eids=sic_eids)).data()

    sic_map = _build_sic_map(all_sics, jg_rules, sic_rules)
    eligible_eids: set[str] = set()
    for sic_eid, sic_entry in sic_map.items():
        should_run, _ = _evaluate_sic(sic_entry, business_day, region)
        if should_run:
            eligible_eids.add(sic_eid)

    eligible_rows = [row for row in all_sics if row.get("sic_eid") in eligible_eids]
    return eligible_rows, eligible_eids


def _build_missing_sla_rows(
    scope_rows: dict[str, dict[str, Any]],
    covered_sic_eids: set[str],
) -> list[dict[str, Any]]:
    missing_rows: list[dict[str, Any]] = []
    for sic_eid, row in scope_rows.items():
        if sic_eid in covered_sic_eids:
            continue
        missing_rows.append({
            "sic_eid": sic_eid,
            "sic_id": row.get("sic_id"),
            "sic_name": row.get("sic_name"),
            "job_id": row.get("job_id"),
            "job_name": row.get("job_name"),
            "job_group_id": row.get("jg_id"),
            "job_group_name": row.get("jg_name"),
            "planned_for_date": row.get("planned_for_date"),
            "has_actual_execution": row.get("has_actual_execution"),
            "execution_id": row.get("execution_id"),
            "execution_status": row.get("execution_status"),
            "coverage_status": "missing_sla",
        })
    return missing_rows


def _ms_since_midnight(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    return (
        dt.hour * 3_600_000
        + dt.minute * 60_000
        + dt.second * 1000
        + int(dt.microsecond / 1000)
    )


def _clock_to_ms(value: str | None) -> int | None:
    clock = _parse_sla_clock(value)
    if clock is None:
        return None
    return (
        clock.hour * 3_600_000
        + clock.minute * 60_000
        + clock.second * 1000
        + int(clock.microsecond / 1000)
    )


def _topological_order(nodes: set[str], edges: list[tuple[str, str]]) -> list[str]:
    indegree: dict[str, int] = {n: 0 for n in nodes}
    outgoing: dict[str, list[str]] = {n: [] for n in nodes}
    for src, dst in edges:
        if src not in nodes or dst not in nodes:
            continue
        outgoing[src].append(dst)
        indegree[dst] += 1

    queue: list[str] = [n for n in nodes if indegree[n] == 0]
    ordered: list[str] = []
    idx = 0
    while idx < len(queue):
        node = queue[idx]
        idx += 1
        ordered.append(node)
        for nxt in outgoing.get(node, []):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)

    if len(ordered) != len(nodes):
        # Fallback for unexpected cycles: append remaining nodes to keep analysis usable.
        for node in nodes:
            if node not in ordered:
                ordered.append(node)
    return ordered


def _compute_downstream_after_ms(
    nodes: set[str],
    edges: list[tuple[str, str]],
    duration_ms: dict[str, int | None],
) -> dict[str, int | None]:
    outgoing: dict[str, list[str]] = {n: [] for n in nodes}
    for src, dst in edges:
        if src in nodes and dst in nodes:
            outgoing[src].append(dst)

    order = _topological_order(nodes, edges)
    tail_including_self: dict[str, int | None] = {}

    for node in reversed(order):
        node_dur = duration_ms.get(node)
        succ_vals = [tail_including_self.get(succ) for succ in outgoing.get(node, [])]
        succ_vals_known = [v for v in succ_vals if v is not None]
        best_succ = max(succ_vals_known) if succ_vals_known else 0
        if node_dur is None:
            tail_including_self[node] = None
        else:
            tail_including_self[node] = node_dur + best_succ

    downstream_after: dict[str, int | None] = {}
    for node in nodes:
        total = tail_including_self.get(node)
        node_dur = duration_ms.get(node)
        if total is None or node_dur is None:
            downstream_after[node] = None
        else:
            downstream_after[node] = max(0, total - node_dur)
    return downstream_after


def _build_delay_and_finish_projection(
    nodes: set[str],
    edges: list[tuple[str, str]],
    root_nodes: set[str],
    delay_ms: int,
    duration_ms: dict[str, int | None],
    executed_ms: dict[str, int | None],
    anchor_ms: int,
) -> tuple[dict[str, int], dict[str, int | None], dict[str, int | None]]:
    preds: dict[str, list[str]] = {n: [] for n in nodes}
    for src, dst in edges:
        if src in nodes and dst in nodes:
            preds[dst].append(src)

    order = _topological_order(nodes, edges)
    propagated_delay: dict[str, int] = {n: 0 for n in nodes}
    baseline_finish: dict[str, int | None] = {n: None for n in nodes}
    projected_finish: dict[str, int | None] = {n: None for n in nodes}

    for node in order:
        node_dur = duration_ms.get(node)
        pred_baseline = [baseline_finish.get(p) for p in preds.get(node, []) if baseline_finish.get(p) is not None]
        pred_projected = [projected_finish.get(p) for p in preds.get(node, []) if projected_finish.get(p) is not None]
        baseline_start = max([anchor_ms] + pred_baseline) if pred_baseline else anchor_ms
        projected_start = max([anchor_ms] + pred_projected) if pred_projected else anchor_ms

        if executed_ms.get(node) is not None:
            # Already executed on the target date; freeze its finish and avoid delay carry-in.
            propagated_delay[node] = 0
            baseline_finish[node] = executed_ms[node]
            projected_finish[node] = executed_ms[node]
            continue

        inherited_delay = max((propagated_delay.get(p, 0) for p in preds.get(node, [])), default=0)
        own_delay = delay_ms if node in root_nodes else 0
        propagated_delay[node] = max(own_delay, inherited_delay)

        if node_dur is None:
            baseline_finish[node] = None
            projected_finish[node] = None
            continue

        baseline_finish[node] = baseline_start + node_dur
        projected_finish[node] = projected_start + node_dur + propagated_delay[node]

    return propagated_delay, baseline_finish, projected_finish


def _evaluate_observed_sla(
    sic_row: dict[str, Any],
    sla_row: dict[str, Any],
) -> dict[str, Any]:
    actual_duration_ms = int(sic_row.get("duration_ms") or 0)
    threshold_ms = int(sla_row.get("sla_duration_ms") or 0)
    has_duration_threshold = threshold_ms > 0
    duration_breach = has_duration_threshold and actual_duration_ms > threshold_ms

    end_dt = _parse_iso_datetime(sic_row.get("end_time"))
    sla_clock = _parse_sla_clock(sla_row.get("sla_time"))
    end_clock = end_dt.timetz().replace(tzinfo=None) if end_dt else None
    absolute_time_breach = bool(end_clock and sla_clock and end_clock > sla_clock)

    breached = bool(duration_breach or absolute_time_breach)
    computable = bool(has_duration_threshold or (end_dt and sla_clock))
    if duration_breach and absolute_time_breach:
        breach_reason = "duration_and_absolute_time_breach"
    elif duration_breach:
        breach_reason = "duration_threshold_breach"
    elif absolute_time_breach:
        breach_reason = "absolute_time_breach"
    elif computable:
        breach_reason = "within_sla"
    else:
        breach_reason = "no_computable_threshold"

    return {
        "sic_eid": sic_row.get("sic_eid"),
        "sic_id": sic_row.get("sic_id"),
        "sic_name": sic_row.get("sic_name"),
        "job_id": sic_row.get("job_id"),
        "job_name": sic_row.get("job_name"),
        "job_group_id": sic_row.get("jg_id"),
        "job_group_name": sic_row.get("jg_name"),
        "planned_for_date": sic_row.get("planned_for_date"),
        "has_actual_execution": sic_row.get("has_actual_execution"),
        "execution_id": sic_row.get("execution_id"),
        "execution_status": sic_row.get("execution_status"),
        "start_time": sic_row.get("start_time"),
        "end_time": sic_row.get("end_time"),
        "actual_duration_ms": actual_duration_ms,
        "owner_type": sla_row.get("owner_type"),
        "owner_id": sla_row.get("owner_id"),
        "owner_name": sla_row.get("owner_name"),
        "sla_id": sla_row.get("sla_id"),
        "sla_name": sla_row.get("sla_name"),
        "sla_type": sla_row.get("sla_type"),
        "sla_policy": sla_row.get("sla_policy"),
        "sla_severity": sla_row.get("sla_severity"),
        "sla_duration_ms": threshold_ms if has_duration_threshold else None,
        "sla_time": sla_row.get("sla_time"),
        "sla_tz": sla_row.get("sla_tz"),
        "relative_resource_id": sla_row.get("relative_resource_id"),
        "relative_resource_name": sla_row.get("relative_resource_name"),
        "meets_sla": computable and not breached,
        "breached": breached,
        "breach_reason": breach_reason,
        "breach_by_ms": max(0, actual_duration_ms - threshold_ms) if duration_breach else 0,
    }


def _evaluate_projected_sla(
    sic_row: dict[str, Any],
    sla_row: dict[str, Any],
    delay_ms: int,
) -> dict[str, Any]:
    baseline_ms = sic_row.get("avg_duration_ms")
    if baseline_ms is None:
        baseline_ms = None

    baseline_ms_int = int(baseline_ms) if baseline_ms is not None else None
    projected_ms = (baseline_ms_int + delay_ms) if baseline_ms_int is not None else None
    threshold_ms = int(sla_row.get("sla_duration_ms") or 0)
    has_duration_threshold = threshold_ms > 0
    projected_breach = bool(
        has_duration_threshold and projected_ms is not None and projected_ms > threshold_ms
    )
    headroom_ms = (
        threshold_ms - baseline_ms_int
        if has_duration_threshold and baseline_ms_int is not None
        else None
    )
    breach_by_ms = (
        projected_ms - threshold_ms
        if projected_breach and projected_ms is not None
        else 0
    )

    absolute_time_only = (
        (sla_row.get("sla_type") or "").upper() == "ABSOLUTE"
        and bool(sla_row.get("sla_time"))
        and not has_duration_threshold
    )
    at_risk = bool(projected_breach or (absolute_time_only and delay_ms > 0))

    return {
        "sic_eid": sic_row.get("sic_eid"),
        "sic_id": sic_row.get("sic_id"),
        "sic_name": sic_row.get("sic_name"),
        "job_id": sic_row.get("job_id"),
        "job_name": sic_row.get("job_name"),
        "job_group_id": sic_row.get("jg_id"),
        "job_group_name": sic_row.get("jg_name"),
        "owner_type": sla_row.get("owner_type"),
        "owner_id": sla_row.get("owner_id"),
        "owner_name": sla_row.get("owner_name"),
        "sla_id": sla_row.get("sla_id"),
        "sla_name": sla_row.get("sla_name"),
        "sla_type": sla_row.get("sla_type"),
        "sla_policy": sla_row.get("sla_policy"),
        "sla_severity": sla_row.get("sla_severity"),
        "sla_duration_ms": threshold_ms if has_duration_threshold else None,
        "sla_time": sla_row.get("sla_time"),
        "sla_tz": sla_row.get("sla_tz"),
        "relative_resource_id": sla_row.get("relative_resource_id"),
        "relative_resource_name": sla_row.get("relative_resource_name"),
        "baseline_duration_ms": baseline_ms_int,
        "projected_duration_ms": projected_ms,
        "injected_delay_ms": delay_ms,
        "headroom_ms": headroom_ms,
        "projected_breach": projected_breach,
        "breach_by_ms": breach_by_ms,
        "at_risk": at_risk,
        "risk_reason": (
            "duration_threshold_breach" if projected_breach
            else "absolute_time_with_delay" if absolute_time_only and delay_ms > 0
            else "within_duration_threshold" if has_duration_threshold
            else "no_computable_threshold"
        ),
    }


def _evaluate_date_projection_sla(
    *,
    sic_row: dict[str, Any],
    sla_row: dict[str, Any],
    duration_ms: int | None,
    duration_source: str,
    propagated_delay_ms: int,
    baseline_finish_ms: int | None,
    projected_finish_ms: int | None,
    downstream_after_ms: int | None,
) -> dict[str, Any]:
    owner_type = (sla_row.get("owner_type") or "").upper()
    base_deadline_ms = _clock_to_ms(sla_row.get("sla_time"))
    effective_deadline_ms = base_deadline_ms
    if base_deadline_ms is not None and owner_type == "JOB_GROUP" and downstream_after_ms is not None:
        effective_deadline_ms = max(0, base_deadline_ms - downstream_after_ms)

    threshold_ms = int(sla_row.get("sla_duration_ms") or 0)
    has_duration_threshold = threshold_ms > 0
    duration_breach = bool(
        has_duration_threshold and duration_ms is not None and duration_ms > threshold_ms
    )

    absolute_breach = bool(
        effective_deadline_ms is not None
        and projected_finish_ms is not None
        and projected_finish_ms > effective_deadline_ms
    )

    projected_breach = bool(duration_breach or absolute_breach)
    buffer_ms = (
        effective_deadline_ms - baseline_finish_ms
        if effective_deadline_ms is not None and baseline_finish_ms is not None
        else None
    )

    if projected_breach and absolute_breach and duration_breach:
        risk_reason = "absolute_and_duration_breach"
    elif projected_breach and absolute_breach:
        risk_reason = "absolute_time_breach"
    elif projected_breach and duration_breach:
        risk_reason = "duration_threshold_breach"
    elif buffer_ms is not None:
        risk_reason = "within_buffer"
    elif has_duration_threshold:
        risk_reason = "within_duration_threshold"
    else:
        risk_reason = "no_computable_threshold"

    breach_by_ms = (
        max(0, (projected_finish_ms or 0) - effective_deadline_ms)
        if absolute_breach and effective_deadline_ms is not None
        else 0
    )

    return {
        "sic_eid": sic_row.get("sic_eid"),
        "sic_id": sic_row.get("sic_id"),
        "sic_name": sic_row.get("sic_name"),
        "job_id": sic_row.get("job_id"),
        "job_name": sic_row.get("job_name"),
        "job_group_id": sic_row.get("jg_id"),
        "job_group_name": sic_row.get("jg_name"),
        "owner_type": sla_row.get("owner_type"),
        "owner_id": sla_row.get("owner_id"),
        "owner_name": sla_row.get("owner_name"),
        "sla_id": sla_row.get("sla_id"),
        "sla_name": sla_row.get("sla_name"),
        "sla_type": sla_row.get("sla_type"),
        "sla_policy": sla_row.get("sla_policy"),
        "sla_severity": sla_row.get("sla_severity"),
        "sla_duration_ms": threshold_ms if has_duration_threshold else None,
        "sla_time": sla_row.get("sla_time"),
        "sla_tz": sla_row.get("sla_tz"),
        "relative_resource_id": sla_row.get("relative_resource_id"),
        "relative_resource_name": sla_row.get("relative_resource_name"),
        "duration_source": duration_source,
        "effective_duration_ms": duration_ms,
        "propagated_delay_ms": propagated_delay_ms,
        "baseline_finish_ms": baseline_finish_ms,
        "projected_finish_ms": projected_finish_ms,
        "base_deadline_ms": base_deadline_ms,
        "effective_deadline_ms": effective_deadline_ms,
        "downstream_after_ms": downstream_after_ms,
        "buffer_ms": buffer_ms,
        "projected_breach": projected_breach,
        "breach_by_ms": breach_by_ms,
        "at_risk": projected_breach,
        "risk_reason": risk_reason,
    }


async def _run_execution_status(
    driver: AsyncDriver,
    business_date: str,
    region: str,
) -> dict[str, Any]:
    business_day = _parse_iso_business_date(business_date)
    if business_day > date.today():
        raise ValueError(
            "execution_status requires today or a past business_date; future dates require prediction inputs"
        )

    async with kg_session(driver) as session:
        eligible_rows, eligible_eids = await _get_eligible_sic_scope(session, business_date, region)
        actual_rows = await (await session.run(
            _Q_EXECUTION_SICS_BY_DATE,
            business_date=business_date,
        )).data()

        actual_by_eid = {
            row["sic_eid"]: {
                **row,
                "planned_for_date": row.get("sic_eid") in eligible_eids,
                "has_actual_execution": True,
            }
            for row in actual_rows
            if row.get("sic_eid")
        }
        scope_rows_by_eid = {
            row["sic_eid"]: {
                **row,
                "planned_for_date": True,
                "has_actual_execution": row.get("sic_eid") in actual_by_eid,
            }
            for row in eligible_rows
            if row.get("sic_eid")
        }
        scope_rows_by_eid.update(actual_by_eid)

        scope_sic_eids = list(scope_rows_by_eid)
        sla_rows: list[dict[str, Any]] = []
        if scope_sic_eids:
            sla_rows = await (await session.run(_Q_SLA_ROWS_FOR_SICS, sic_eids=scope_sic_eids)).data()

    covered_sic_eids = {row["sic_eid"] for row in sla_rows if row.get("sic_eid")}
    missing_sla_coverage = _build_missing_sla_rows(scope_rows_by_eid, covered_sic_eids)

    observed_results: list[dict[str, Any]] = []
    for sla_row in sla_rows:
        sic_eid = sla_row.get("sic_eid")
        sic_row = actual_by_eid.get(sic_eid)
        if not sic_row:
            continue
        observed_results.append(_evaluate_observed_sla(sic_row, sla_row))

    breach_count = sum(1 for row in observed_results if row.get("breached"))
    met_count = sum(1 for row in observed_results if row.get("meets_sla"))

    return {
        "mode": "execution_status",
        "business_date": business_date,
        "region": region,
        "eligible_sic_count": len(eligible_eids),
        "actual_sic_count": len(actual_by_eid),
        "eligible_without_execution_count": len(eligible_eids - set(actual_by_eid)),
        "missing_sla_coverage_count": len(missing_sla_coverage),
        "sla_evaluated_count": len(observed_results),
        "breach_count": breach_count,
        "met_count": met_count,
        "scope_sics": list(scope_rows_by_eid.values()),
        "missing_sla_coverage": missing_sla_coverage,
        "sla_results": observed_results,
    }


async def _run_projected_impact(
    driver: AsyncDriver,
    *,
    resolved_mode: str,
    source_type: str,
    source_id: str,
    delay_minutes: int,
    days: int,
    business_date: str | None,
    region: str,
) -> dict[str, Any]:
    source_type_norm = _normalise_source_type(source_type)
    if source_type_norm not in {"resource", "job", "sic", "job_group"}:
        raise ValueError("source_type must be one of: resource, job, sic, job_group")

    delay_ms = max(0, int(delay_minutes)) * 60_000
    start_date = _start_date(days)
    eligible_eids: set[str] = set()

    root_query = {
        "resource": _Q_ROOT_SICS_BY_RESOURCE,
        "job": _Q_ROOT_SICS_BY_JOB,
        "sic": _Q_ROOT_SICS_BY_SIC,
        "job_group": _Q_ROOT_SICS_BY_JOB_GROUP,
    }[source_type_norm]

    if resolved_mode == "date_projection":
        projection_date = business_date or _today_business_date()
        projection_day = _parse_iso_business_date(projection_date)
        today = date.today()
        if projection_day == today:
            anchor_ms = _ms_since_midnight(datetime.now()) or 0
        elif projection_day > today:
            anchor_ms = 0
        else:
            raise ValueError("date_projection is supported for today or future business_date only")

        async with kg_session(driver) as session:
            _, eligible_eids = await _get_eligible_sic_scope(session, projection_date, region)
            root_rows = await (await session.run(root_query, source_id=source_id)).data()
            root_sic_eids = [
                row["sic_eid"]
                for row in root_rows
                if row.get("sic_eid") and row["sic_eid"] in eligible_eids
            ]

            if not root_sic_eids:
                return {
                    "mode": resolved_mode,
                    "business_date": projection_date,
                    "region": region,
                    "source_type": source_type_norm,
                    "source_id": source_id,
                    "delay_minutes": delay_minutes,
                    "delay_ms": delay_ms,
                    "historical_window_days": days,
                    "eligible_graph_sic_count": len(eligible_eids),
                    "root_sic_count": 0,
                    "impacted_sic_count": 0,
                    "projected_breach_count": 0,
                    "at_risk_count": 0,
                    "impacted_sics": [],
                    "sla_impacts": [],
                }

            impacted_rows = await (
                await session.run(
                    _Q_IMPACTED_SICS_IN_SCOPE_BASE,
                    root_sic_eids=root_sic_eids,
                    scope_sic_eids=list(eligible_eids),
                )
            ).data()
            impacted_sic_eids = [row["sic_eid"] for row in impacted_rows if row.get("sic_eid")]

            if not impacted_sic_eids:
                return {
                    "mode": resolved_mode,
                    "business_date": projection_date,
                    "region": region,
                    "source_type": source_type_norm,
                    "source_id": source_id,
                    "delay_minutes": delay_minutes,
                    "delay_ms": delay_ms,
                    "historical_window_days": days,
                    "eligible_graph_sic_count": len(eligible_eids),
                    "root_sic_count": len(root_sic_eids),
                    "impacted_sic_count": 0,
                    "projected_breach_count": 0,
                    "at_risk_count": 0,
                    "impacted_sics": [],
                    "sla_impacts": [],
                }

            precedes_rows = await (
                await session.run(_Q_PRECEDES_BETWEEN_CONTEXTS, sic_eids=impacted_sic_eids)
            ).data()
            avg_rows = await (
                await session.run(
                    _Q_AVG_DURATION_FOR_SICS,
                    sic_eids=impacted_sic_eids,
                    start_date=start_date,
                )
            ).data()
            actual_rows = await (
                await session.run(
                    _Q_EXECUTION_SICS_FOR_SET_BY_DATE,
                    sic_eids=impacted_sic_eids,
                    business_date=projection_date,
                )
            ).data()
            sla_rows = await (
                await session.run(_Q_SLA_ROWS_FOR_SICS, sic_eids=impacted_sic_eids)
            ).data()

        impacted_by_sic = {row["sic_eid"]: row for row in impacted_rows if row.get("sic_eid")}
        edges = [
            (row["start_sic_eid"], row["end_sic_eid"])
            for row in precedes_rows
            if row.get("start_sic_eid") and row.get("end_sic_eid")
        ]
        node_set = set(impacted_by_sic)

        avg_by_sic: dict[str, int | None] = {}
        for row in avg_rows:
            sic_eid = row.get("sic_eid")
            if not sic_eid:
                continue
            avg_val = row.get("avg_duration_ms")
            avg_by_sic[sic_eid] = int(avg_val) if avg_val is not None else None

        actual_by_sic = {
            row["sic_eid"]: row
            for row in actual_rows
            if row.get("sic_eid")
        }

        duration_ms: dict[str, int | None] = {}
        duration_source: dict[str, str] = {}
        executed_finish_ms: dict[str, int | None] = {}
        for sic_eid in node_set:
            actual = actual_by_sic.get(sic_eid, {})
            actual_duration = actual.get("duration_ms")
            end_dt = _parse_iso_datetime(actual.get("end_time"))
            executed_finish_ms[sic_eid] = _ms_since_midnight(end_dt)

            if actual_duration is not None:
                duration_ms[sic_eid] = int(actual_duration)
                duration_source[sic_eid] = "actual"
            elif avg_by_sic.get(sic_eid) is not None:
                duration_ms[sic_eid] = avg_by_sic[sic_eid]
                duration_source[sic_eid] = "average"
            else:
                duration_ms[sic_eid] = None
                duration_source[sic_eid] = "missing"

        downstream_after_ms = _compute_downstream_after_ms(node_set, edges, duration_ms)
        propagated_delay_ms, baseline_finish_ms, projected_finish_ms = _build_delay_and_finish_projection(
            node_set,
            edges,
            set(root_sic_eids),
            delay_ms,
            duration_ms,
            executed_finish_ms,
            anchor_ms,
        )

        sla_impacts = []
        for sla_row in sla_rows:
            sic_eid = sla_row.get("sic_eid")
            if not sic_eid or sic_eid not in impacted_by_sic:
                continue
            sic_row = impacted_by_sic[sic_eid]
            sla_impacts.append(_evaluate_date_projection_sla(
                sic_row=sic_row,
                sla_row=sla_row,
                duration_ms=duration_ms.get(sic_eid),
                duration_source=duration_source.get(sic_eid, "missing"),
                propagated_delay_ms=propagated_delay_ms.get(sic_eid, 0),
                baseline_finish_ms=baseline_finish_ms.get(sic_eid),
                projected_finish_ms=projected_finish_ms.get(sic_eid),
                downstream_after_ms=downstream_after_ms.get(sic_eid),
            ))

        projected_breach_count = sum(1 for row in sla_impacts if row.get("projected_breach"))
        at_risk_count = sum(1 for row in sla_impacts if row.get("at_risk"))

        impacted_sics_enriched = []
        for sic_eid, sic_row in impacted_by_sic.items():
            impacted_sics_enriched.append({
                **sic_row,
                "duration_source": duration_source.get(sic_eid, "missing"),
                "effective_duration_ms": duration_ms.get(sic_eid),
                "propagated_delay_ms": propagated_delay_ms.get(sic_eid, 0),
                "baseline_finish_ms": baseline_finish_ms.get(sic_eid),
                "projected_finish_ms": projected_finish_ms.get(sic_eid),
                "downstream_after_ms": downstream_after_ms.get(sic_eid),
            })

        return {
            "mode": resolved_mode,
            "business_date": projection_date,
            "region": region,
            "source_type": source_type_norm,
            "source_id": source_id,
            "delay_minutes": delay_minutes,
            "delay_ms": delay_ms,
            "historical_window_days": days,
            "eligible_graph_sic_count": len(eligible_eids),
            "root_sic_count": len(root_sic_eids),
            "impacted_sic_count": len(impacted_rows),
            "sla_evaluated_count": len(sla_impacts),
            "projected_breach_count": projected_breach_count,
            "at_risk_count": at_risk_count,
            "impacted_sics": impacted_sics_enriched,
            "sla_impacts": sla_impacts,
        }

    async with kg_session(driver) as session:
        root_rows = await (await session.run(root_query, source_id=source_id)).data()

        if resolved_mode == "date_projection":
            _, eligible_eids = await _get_eligible_sic_scope(session, business_date or _today_business_date(), region)

        root_sic_eids = [
            row["sic_eid"]
            for row in root_rows
            if row.get("sic_eid") and (not eligible_eids or row["sic_eid"] in eligible_eids)
        ]

        if not root_sic_eids:
            return {
                "mode": resolved_mode,
                "business_date": business_date,
                "region": region,
                "source_type": source_type_norm,
                "source_id": source_id,
                "delay_minutes": delay_minutes,
                "delay_ms": delay_ms,
                "historical_window_days": days,
                "eligible_graph_sic_count": len(eligible_eids) if eligible_eids else None,
                "root_sic_count": 0,
                "impacted_sic_count": 0,
                "projected_breach_count": 0,
                "at_risk_count": 0,
                "impacted_sics": [],
                "sla_impacts": [],
            }

        impacted_query = _Q_IMPACTED_SICS_IN_SCOPE if eligible_eids else _Q_IMPACTED_SICS
        impacted_params: dict[str, Any] = {
            "root_sic_eids": root_sic_eids,
            "start_date": start_date,
        }
        if eligible_eids:
            impacted_params["scope_sic_eids"] = list(eligible_eids)

        impacted_rows = await (await session.run(impacted_query, **impacted_params)).data()
        impacted_sic_eids = [row["sic_eid"] for row in impacted_rows if row.get("sic_eid")]

        sla_rows: list[dict[str, Any]] = []
        if impacted_sic_eids:
            sla_rows = await (await session.run(_Q_SLA_ROWS_FOR_SICS, sic_eids=impacted_sic_eids)).data()

    impacted_by_sic = {row["sic_eid"]: row for row in impacted_rows if row.get("sic_eid")}
    sla_impacts = [
        _evaluate_projected_sla(impacted_by_sic[sla_row["sic_eid"]], sla_row, delay_ms)
        for sla_row in sla_rows
        if sla_row.get("sic_eid") in impacted_by_sic
    ]

    projected_breach_count = sum(1 for row in sla_impacts if row.get("projected_breach"))
    at_risk_count = sum(1 for row in sla_impacts if row.get("at_risk"))

    return {
        "mode": resolved_mode,
        "business_date": business_date,
        "region": region,
        "source_type": source_type_norm,
        "source_id": source_id,
        "delay_minutes": delay_minutes,
        "delay_ms": delay_ms,
        "historical_window_days": days,
        "eligible_graph_sic_count": len(eligible_eids) if eligible_eids else None,
        "root_sic_count": len(root_sic_eids),
        "impacted_sic_count": len(impacted_rows),
        "sla_evaluated_count": len(sla_impacts),
        "projected_breach_count": projected_breach_count,
        "at_risk_count": at_risk_count,
        "impacted_sics": impacted_rows,
        "sla_impacts": sla_impacts,
    }


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


async def get_sla_execution_breach(
    driver: AsyncDriver,
    business_date: str,
    region: str = "ALL",
) -> dict[str, Any]:
    """Return SLA breach status for a given date from execution history only.

    This evaluates only observed execution data (JobContextExecution), scoped to
    SICs eligible for the supplied date and region.
    """
    logger.info(
        "get_sla_execution_breach business_date=%s region=%s",
        business_date,
        region,
    )
    return await _run_execution_status(
        driver,
        business_date=business_date,
        region=region,
    )


async def predict_sla_impact(
    driver: AsyncDriver,
    source_type: str,
    source_id: str,
    delay_minutes: int,
    days: int = 30,
    business_date: str | None = None,
    region: str = "ALL",
) -> dict[str, Any]:
    """Predict SLA impact for delay scenarios with optional date scoping.

    - With ``business_date``: predicts on eligible SIC graph for that date.
    - Without ``business_date``: runs date-agnostic hypothetical projection.
    """
    resolved_mode = "date_projection" if business_date else "hypothetical_projection"
    logger.info(
        "predict_sla_impact source_type=%s source_id=%s delay_minutes=%s days=%s business_date=%s region=%s mode=%s",
        source_type,
        source_id,
        delay_minutes,
        days,
        business_date,
        region,
        resolved_mode,
    )
    return await _run_projected_impact(
        driver,
        resolved_mode=resolved_mode,
        source_type=source_type,
        source_id=source_id,
        delay_minutes=delay_minutes,
        days=days,
        business_date=business_date,
        region=region,
    )
