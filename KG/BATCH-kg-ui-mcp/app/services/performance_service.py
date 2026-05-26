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
from config.settings import get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_Q_JOB_PERFORMANCE = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE j.name = $job_id
  AND e.businessDate >= date($start_date)
  AND e.durationMs IS NOT NULL
WITH j.name AS job_name,
     e.durationMs / 1000.0 AS duration_seconds,
     e.status AS status
RETURN
    job_name,
    avg(duration_seconds)   AS avg_duration_seconds,
    min(duration_seconds)   AS min_duration_seconds,
    max(duration_seconds)   AS max_duration_seconds,
    count(*)                AS execution_count,
    sum(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) AS success_count,
    sum(CASE WHEN status = 'FAILED'    THEN 1 ELSE 0 END) AS failure_count
"""

_Q_SLOW_JOBS = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE e.businessDate >= date($start_date)
  AND e.durationMs IS NOT NULL
  AND e.durationMs > $threshold_ms
RETURN
    j.name                      AS job_name,
    e.id                        AS execution_id,
    toString(e.businessDate) + 'T' + toString(e.startTime)  AS start_time,
    toString(e.businessDate) + 'T' + toString(e.endTime)    AS end_time,
    e.status                    AS status,
    e.durationMs / 1000         AS duration_seconds,
    round(e.durationMs / 60000.0, 2) AS duration_minutes
ORDER BY e.durationMs DESC
LIMIT $limit
"""

_Q_COMPARE_JOBS = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE j.name IN $job_ids
  AND e.businessDate >= date($start_date)
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
        coalesce(toString(latest.executionDate), toString(latest.businessDate)) AS execution_date,
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
WHERE jce.businessDate >= date($start_date)
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
WHERE jce.businessDate >= date($start_date)
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
WHERE jce.businessDate >= date($start_date)
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

_Q_JG_CASCADE_FROM_SICS = """
UNWIND $sic_eids AS sic_eid
MATCH (sic:ScheduleInstanceContext)
WHERE elementId(sic) = sic_eid
MATCH (sic)-[:FOR_GROUP]->(root_jg:JobGroup)
MATCH (root_jg)-[:PRECEDES*1..50]->(downstream_jg:JobGroup)
WITH collect(DISTINCT downstream_jg) AS all_jgs
UNWIND all_jgs AS jg
MATCH (down_sic:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
OPTIONAL MATCH (down_sic)-[:FOR_JOB]->(job:Job)
OPTIONAL MATCH (jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(down_sic)
WHERE jce.businessDate >= date($start_date)
  AND jce.durationMs IS NOT NULL
WITH down_sic, jg, job, avg(jce.durationMs) AS avg_duration_ms
RETURN DISTINCT
    elementId(down_sic) AS sic_eid,
    down_sic.id         AS sic_id,
    down_sic.name       AS sic_name,
    elementId(jg)       AS jg_eid,
    jg.id               AS jg_id,
    jg.name             AS jg_name,
    elementId(job)      AS job_eid,
    job.id              AS job_id,
    job.name            AS job_name,
    avg_duration_ms
"""

_Q_JG_CASCADE_FROM_SICS_IN_SCOPE = """
UNWIND $sic_eids AS sic_eid
MATCH (sic:ScheduleInstanceContext)
WHERE elementId(sic) = sic_eid
MATCH (sic)-[:FOR_GROUP]->(root_jg:JobGroup)
MATCH (root_jg)-[:PRECEDES*1..50]->(downstream_jg:JobGroup)
WITH collect(DISTINCT downstream_jg) AS all_jgs
UNWIND all_jgs AS jg
MATCH (down_sic:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
WHERE elementId(down_sic) IN $scope_sic_eids
OPTIONAL MATCH (down_sic)-[:FOR_JOB]->(job:Job)
OPTIONAL MATCH (jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(down_sic)
WHERE jce.businessDate >= date($start_date)
  AND jce.durationMs IS NOT NULL
WITH down_sic, jg, job, avg(jce.durationMs) AS avg_duration_ms
RETURN DISTINCT
    elementId(down_sic) AS sic_eid,
    down_sic.id         AS sic_id,
    down_sic.name       AS sic_name,
    elementId(jg)       AS jg_eid,
    jg.id               AS jg_id,
    jg.name             AS jg_name,
    elementId(job)      AS job_eid,
    job.id              AS job_id,
    job.name            AS job_name,
    avg_duration_ms
"""

_Q_SLA_ROWS_FOR_SICS = """
UNWIND $sic_eids AS sic_eid
MATCH (sic:ScheduleInstanceContext)
WHERE elementId(sic) = sic_eid
MATCH (sic)-[:FOR_GROUP]->(jg:JobGroup)
CALL (sic, jg) {
        OPTIONAL MATCH (sic)-[:HAS_SLA]->(sic_sla:SLA)
        WHERE coalesce(sic_sla.enabled, true) = true
        OPTIONAL MATCH (jg)-[:HAS_SLA]->(jg_sla:SLA)
        WHERE coalesce(jg_sla.enabled, true) = true
        WITH collect(DISTINCT {sla: sic_sla, owner_type: 'SIC', owner_id: sic.id, owner_name: sic.name}) +
                 collect(DISTINCT {sla: jg_sla, owner_type: 'JOB_GROUP', owner_id: jg.id, owner_name: jg.name})
                 AS all_rows
        UNWIND all_rows AS row
        WITH row
        WHERE row.sla IS NOT NULL
        RETURN DISTINCT row
}
RETURN DISTINCT
    sic_eid,
    row.owner_type          AS owner_type,
    row.owner_id            AS owner_id,
    row.owner_name          AS owner_name,
    row.sla.id              AS sla_id,
    row.sla.name            AS sla_name,
    row.sla.type            AS sla_type,
    row.sla.durationMs      AS sla_duration_ms,
    row.sla.time            AS sla_time
"""

_Q_SIC_ANOMALY_HIST = """
UNWIND $sic_eids AS sic_eid
MATCH (sic:ScheduleInstanceContext)
WHERE elementId(sic) = sic_eid
OPTIONAL MATCH (jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(sic)
WHERE jce.businessDate >= date($hist_start_date)
  AND jce.businessDate < date($business_date)
  AND jce.durationMs IS NOT NULL
WITH sic_eid,
     avg(jce.durationMs)   AS hist_avg_ms,
     stdev(jce.durationMs) AS hist_std_ms,
     count(jce)            AS hist_sample_count
RETURN sic_eid, hist_avg_ms, hist_std_ms, hist_sample_count
"""

_Q_JOB_DURATION_TIMESERIES = """
MATCH (e:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WHERE j.name = $job_id
  AND e.businessDate >= date($start_date)
  AND e.durationMs IS NOT NULL
WITH toString(e.businessDate) AS business_date,
     avg(e.durationMs)        AS avg_duration_ms,
     count(e)                 AS execution_count
ORDER BY business_date ASC
RETURN business_date, avg_duration_ms, execution_count
"""


# ---------------------------------------------------------------------------
# Anomaly / trend configuration — loaded once from config/config.yaml
# ---------------------------------------------------------------------------
_cfg = get_settings().config
_ANOMALY_HIST_DAYS: int = _cfg.anomaly_hist_days
_ANOMALY_K_FACTOR: float = _cfg.anomaly_k_factor
_ANOMALY_MIN_SAMPLES: int = _cfg.anomaly_min_samples
_TREND_MIN_POINTS: int = _cfg.trend_min_points
_TREND_DETERIORATING_MS: int = _cfg.trend_deteriorating_ms
_TREND_IMPROVING_MS: int = _cfg.trend_improving_ms


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _start_date(days: int) -> str:
    return (date.today() - timedelta(days=days)).strftime('%Y-%m-%d')


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


def _compute_linear_slope(points: list[tuple[int, float]]) -> float | None:
    """Ordinary least squares slope (units: y-units per x-unit, i.e. ms per day index)."""
    n = len(points)
    if n < 2:
        return None
    sum_x = sum(x for x, _ in points)
    sum_y = sum(y for _, y in points)
    sum_xy = sum(x * y for x, y in points)
    sum_xx = sum(x * x for x, _ in points)
    denom = n * sum_xx - sum_x * sum_x
    if denom == 0:
        return None
    return (n * sum_xy - sum_x * sum_y) / denom


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
    business_date: str,
) -> dict[str, Any]:
    actual_duration_ms = int(sic_row.get("duration_ms") or 0)
    threshold_ms = int(sla_row.get("sla_duration_ms") or 0)
    has_duration_threshold = threshold_ms > 0
    sla_type_upper = (sla_row.get("sla_type") or "").upper()

    # RELATIVE SLA: breach when job ran longer than the allowed duration
    duration_breach = (
        sla_type_upper == "RELATIVE"
        and has_duration_threshold
        and actual_duration_ms > threshold_ms
    )

    # ABSOLUTE SLA: breach when full end datetime exceeds the SLA deadline on business_date.
    # For nightly jobs, execution_date (calendar date the job ran) differs from
    # business_date (the logical date the SLA belongs to).
    # Example: job starts 22:30 on May 21 → execution_date=May 21, business_date=May 22
    #          SLA time = 02:00 → deadline = May 22 02:00 → job ends at May 21 23:30 → meets SLA ✓
    # Comparing wall-clock times alone (22:30 > 02:00) would incorrectly flag a breach.
    execution_date_str = sic_row.get("execution_date")  # calendar date job started ("YYYY-MM-DD")
    start_time_str = sic_row.get("start_time")          # "HH:MM:SS"
    end_datetime: datetime | None = None
    sla_deadline: datetime | None = None

    if sla_type_upper == "ABSOLUTE":
        sla_clock_str = sla_row.get("sla_time")
        if sla_clock_str:
            sla_t = _parse_sla_clock(sla_clock_str)
            if sla_t:
                try:
                    # Strip tzinfo so the deadline is always a naive datetime.
                    # tz-aware and the other naive raises TypeError on Python 3.11+
                    # when Neo4j returns time strings with an offset (e.g. "02:00:00+05:30").
                    sla_deadline = datetime.combine(
                        date.fromisoformat(business_date), sla_t.replace(tzinfo=None)
                    )
                except (ValueError, TypeError):
                    pass
        if execution_date_str and start_time_str and actual_duration_ms:
            start_t = _parse_sla_clock(start_time_str)
            if start_t:
                try:
                    start_dt = datetime.combine(
                        date.fromisoformat(execution_date_str), start_t.replace(tzinfo=None)
                    )
                    end_datetime = start_dt + timedelta(milliseconds=actual_duration_ms)
                except (ValueError, TypeError):
                    pass

    absolute_time_breach = bool(
        sla_type_upper == "ABSOLUTE"
        and end_datetime and sla_deadline and end_datetime > sla_deadline
    )

    breached = bool(duration_breach or absolute_time_breach)
    if sla_type_upper == "RELATIVE":
        computable = has_duration_threshold
    elif sla_type_upper == "ABSOLUTE":
        computable = bool(end_datetime and sla_deadline)
    else:
        computable = bool(has_duration_threshold or (end_datetime and sla_deadline))
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
        "execution_date": execution_date_str,
        "start_time": sic_row.get("start_time"),
        "end_time": sic_row.get("end_time"),
        "actual_duration_ms": actual_duration_ms,
        "owner_type": sla_row.get("owner_type"),
        "owner_id": sla_row.get("owner_id"),
        "owner_name": sla_row.get("owner_name"),
        "sla_id": sla_row.get("sla_id"),
        "sla_name": sla_row.get("sla_name"),
        "sla_type": sla_row.get("sla_type"),
        "sla_duration_ms": threshold_ms if has_duration_threshold else None,
        "sla_time": sla_row.get("sla_time"),
        "sla_deadline_datetime": sla_deadline.isoformat() if sla_deadline else None,
        "sla_coverage": "evaluated",
        "meets_sla": computable and not breached,
        "breached": breached,
        "breach_reason": breach_reason,
        "breach_by_ms": max(0, actual_duration_ms - threshold_ms) if duration_breach else 0,
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
    sla_type_upper = (sla_row.get("sla_type") or "").upper()

    # ABSOLUTE SLA: derive deadline from sla_time (wall-clock on business date)
    if sla_type_upper == "ABSOLUTE":
        base_deadline_ms = _clock_to_ms(sla_row.get("sla_time"))
    else:
        base_deadline_ms = None  # RELATIVE uses durationMs only
    effective_deadline_ms = base_deadline_ms
    if base_deadline_ms is not None and owner_type == "JOB_GROUP" and downstream_after_ms is not None:
        effective_deadline_ms = max(0, base_deadline_ms - downstream_after_ms)

    threshold_ms = int(sla_row.get("sla_duration_ms") or 0)
    has_duration_threshold = threshold_ms > 0

    # Calculate buffer: slack time between baseline finish and SLA deadline
    buffer_ms = (
        effective_deadline_ms - baseline_finish_ms
        if effective_deadline_ms is not None and baseline_finish_ms is not None
        else None
    )

    # RELATIVE SLA: breach when effective duration exceeds threshold
    duration_breach = bool(
        sla_type_upper == "RELATIVE"
        and has_duration_threshold and duration_ms is not None and duration_ms > threshold_ms
    )

    # ABSOLUTE SLA: breach when projected finish exceeds the effective deadline
    absolute_breach = bool(
        sla_type_upper == "ABSOLUTE"
        and effective_deadline_ms is not None
        and projected_finish_ms is not None
        and projected_finish_ms > effective_deadline_ms
    )

    projected_breach = bool(duration_breach or absolute_breach)

    # Calculate real SLA impact = the actual breach amount after considering delay
    # For ABSOLUTE SLA: how much the projected finish exceeds the deadline
    # For RELATIVE SLA: how much the duration exceeds the threshold
    if sla_type_upper == "ABSOLUTE" and effective_deadline_ms is not None and projected_finish_ms is not None:
        real_sla_impact_ms = max(0, projected_finish_ms - effective_deadline_ms)
    elif sla_type_upper == "RELATIVE" and has_duration_threshold and duration_ms is not None:
        real_sla_impact_ms = max(0, duration_ms - threshold_ms)
    else:
        real_sla_impact_ms = 0

    if projected_breach and absolute_breach and duration_breach:
        risk_reason = "absolute_and_duration_breach"
    elif projected_breach and absolute_breach:
        risk_reason = "absolute_time_breach"
    elif projected_breach and duration_breach:
        risk_reason = "duration_threshold_breach"
    elif buffer_ms is not None and buffer_ms >= 0:
        risk_reason = "within_buffer"
    elif has_duration_threshold:
        risk_reason = "within_duration_threshold"
    else:
        risk_reason = "no_computable_threshold"

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
        "sla_duration_ms": threshold_ms if has_duration_threshold else None,
        "sla_time": sla_row.get("sla_time"),
        "duration_source": duration_source,
        "effective_duration_ms": duration_ms,
        "propagated_delay_ms": propagated_delay_ms,
        "baseline_finish_ms": baseline_finish_ms,
        "projected_finish_ms": projected_finish_ms,
        "base_deadline_ms": base_deadline_ms,
        "effective_deadline_ms": effective_deadline_ms,
        "downstream_after_ms": downstream_after_ms,
        "buffer_ms": buffer_ms,
        "real_sla_impact_ms": real_sla_impact_ms,
        "projected_breach": projected_breach,
        "at_risk": projected_breach,
        "risk_reason": risk_reason,
    }


def _consolidate_sic_impacts(
    *,
    impacted_by_sic: dict[str, dict[str, Any]],
    base_fields_by_sic: dict[str, dict[str, Any]],
    sla_impacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    def _compact_sla_row(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "sla_id": row.get("sla_id"),
            "sla_name": row.get("sla_name"),
            "sla_type": row.get("sla_type"),
            "sla_duration_ms": row.get("sla_duration_ms"),
            "sla_time": row.get("sla_time"),
            "buffer_ms": row.get("buffer_ms"),
            "projected_breach": row.get("projected_breach"),
            "real_sla_impact_ms": row.get("real_sla_impact_ms"),
            "at_risk": row.get("at_risk"),
            "risk_reason": row.get("risk_reason"),
        }

    sla_by_sic: dict[str, list[dict[str, Any]]] = {}
    for row in sla_impacts:
        sic_eid = row.get("sic_eid")
        if sic_eid:
            sla_by_sic.setdefault(sic_eid, []).append(_compact_sla_row(row))

    # Debug: log SICs with SLA data
    logger.debug(f"SLA data found for {len(sla_by_sic)} SICs out of {len(impacted_by_sic)} total impacted SICs")
    
    consolidated: list[dict[str, Any]] = []
    for sic_eid, sic_row in impacted_by_sic.items():
        sic_sla_rows = sla_by_sic.get(sic_eid, [])
        
        # Select primary SLA (worst impact) if any SLAs exist
        if sic_sla_rows:
            primary_sla = max(
                sic_sla_rows,
                key=lambda r: (
                    int(r.get("real_sla_impact_ms") or 0),
                    1 if r.get("projected_breach") else 0,
                    1 if r.get("at_risk") else 0,
                    1 if r.get("sla_id") else 0,
                ),
            )
        else:
            primary_sla = None
            logger.debug(f"No SLA data for SIC {sic_row.get('sic_id')} ({sic_eid})")
        
        # Compute aggregate values
        at_risk_val = any(bool(r.get("at_risk")) for r in sic_sla_rows) if sic_sla_rows else False
        real_sla_impact_val = max(
            (int(r.get("real_sla_impact_ms") or 0) for r in sic_sla_rows),
            default=0,
        )
        
        # Get base fields
        base_fields = base_fields_by_sic.get(sic_eid, {})
        
        # Helper to convert ms to seconds with rounding
        def _to_sec(ms_val):
            return round(ms_val / 1000.0, 2) if ms_val is not None else None
        
        # Convert baseline and projected finish from absolute times to durations
        duration_val = base_fields.get("effective_duration_ms")
        delay_val = base_fields.get("propagated_delay_ms", 0)
        baseline_duration_sec = _to_sec(duration_val)
        projected_duration_sec = _to_sec(duration_val + delay_val) if duration_val is not None else None
        
        # Build minimal response with only requested fields (in seconds)
        consolidated.append({
            "sic_eid": sic_row.get("sic_eid"),
            "sic_id": sic_row.get("sic_id"),
            "sic_name": sic_row.get("sic_name"),
            "jg_eid": sic_row.get("jg_eid"),
            "jg_id": sic_row.get("jg_id"),
            "jg_name": sic_row.get("jg_name"),
            "job_eid": sic_row.get("job_eid"),
            "job_name": sic_row.get("job_name"),
            "at_risk": at_risk_val,
            "effective_duration_sec": baseline_duration_sec,
            "baseline_finish_sec": baseline_duration_sec,
            "projected_finish_sec": projected_duration_sec,
            "real_sla_impact_sec": _to_sec(real_sla_impact_val),
            "sla_id": primary_sla.get("sla_id") if primary_sla else None,
            "sla_name": primary_sla.get("sla_name") if primary_sla else None,
            "sla_type": primary_sla.get("sla_type") if primary_sla else None,
            "sla_duration_sec": _to_sec(primary_sla.get("sla_duration_ms")) if primary_sla else None,
            "sla_time": primary_sla.get("sla_time") if primary_sla else None,
            "buffer_sec": _to_sec(primary_sla.get("buffer_ms")) if primary_sla else None,
            "risk_reason": primary_sla.get("risk_reason") if primary_sla else None,
        })
    return consolidated


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

        eligible_eids_list = list(eligible_eids)
        precedes_rows: list[dict[str, Any]] = []
        if eligible_eids_list:
            precedes_rows = await (await session.run(
                _Q_PRECEDES_BETWEEN_CONTEXTS,
                sic_eids=eligible_eids_list,
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

        anomaly_rows: list[dict[str, Any]] = []
        executed_sic_eids = list(actual_by_eid.keys())
        if executed_sic_eids:
            anomaly_rows = await (await session.run(
                _Q_SIC_ANOMALY_HIST,
                sic_eids=executed_sic_eids,
                hist_start_date=(business_day - timedelta(days=_ANOMALY_HIST_DAYS)).isoformat(),
                business_date=business_date,
            )).data()

    # ── Build PRECEDES relationships between eligible SICs ───────────────────
    relationships = [
        {
            "id": row["relationship_id"],
            "type": "PRECEDES",
            "startNodeId": row["start_sic_eid"],
            "endNodeId": row["end_sic_eid"],
        }
        for row in precedes_rows
        if row.get("relationship_id") and row.get("start_sic_eid") and row.get("end_sic_eid")
    ]

    # ── Evaluate SLA for every eligible SIC ──────────────────────────────────
    # Group SLA rows by SIC element ID
    sla_by_sic: dict[str, list[dict[str, Any]]] = {}
    for sla_row in sla_rows:
        sic_eid = sla_row.get("sic_eid")
        if sic_eid:
            sla_by_sic.setdefault(sic_eid, []).append(sla_row)

    all_sla_results: list[dict[str, Any]] = []
    breach_count = 0
    met_count = 0

    for sic_eid, sic_row in scope_rows_by_eid.items():
        actual = actual_by_eid.get(sic_eid)
        sic_sla_rows = sla_by_sic.get(sic_eid, [])

        if not sic_sla_rows:
            # No SLA defined — one informational row per SIC
            all_sla_results.append({
                "sic_eid": sic_eid,
                "sic_id": sic_row.get("sic_id"),
                "sic_name": sic_row.get("sic_name"),
                "job_id": sic_row.get("job_id"),
                "job_name": sic_row.get("job_name"),
                "job_group_id": sic_row.get("jg_id"),
                "job_group_name": sic_row.get("jg_name"),
                "planned_for_date": sic_row.get("planned_for_date"),
                "has_actual_execution": bool(actual),
                "execution_id": actual.get("execution_id") if actual else None,
                "execution_status": actual.get("execution_status") if actual else None,
                "execution_date": actual.get("execution_date") if actual else None,
                "start_time": actual.get("start_time") if actual else None,
                "end_time": actual.get("end_time") if actual else None,
                "actual_duration_ms": int(actual.get("duration_ms") or 0) if actual else None,
                "sla_coverage": "no_sla_defined",
                "meets_sla": None,
                "breached": None,
                "breach_reason": "no_sla_defined",
                "breach_by_ms": 0,
            })
        else:
            # One row per SLA definition
            for sla_row in sic_sla_rows:
                threshold_ms_val = int(sla_row.get("sla_duration_ms") or 0)
                if not actual:
                    # SLA defined but job did not execute on this business date
                    all_sla_results.append({
                        "sic_eid": sic_eid,
                        "sic_id": sic_row.get("sic_id"),
                        "sic_name": sic_row.get("sic_name"),
                        "job_id": sic_row.get("job_id"),
                        "job_name": sic_row.get("job_name"),
                        "job_group_id": sic_row.get("jg_id"),
                        "job_group_name": sic_row.get("jg_name"),
                        "planned_for_date": sic_row.get("planned_for_date"),
                        "has_actual_execution": False,
                        "execution_id": None,
                        "execution_status": None,
                        "execution_date": None,
                        "start_time": None,
                        "end_time": None,
                        "actual_duration_ms": None,
                        "owner_type": sla_row.get("owner_type"),
                        "owner_id": sla_row.get("owner_id"),
                        "owner_name": sla_row.get("owner_name"),
                        "sla_id": sla_row.get("sla_id"),
                        "sla_name": sla_row.get("sla_name"),
                        "sla_type": sla_row.get("sla_type"),
                        "sla_duration_ms": threshold_ms_val if threshold_ms_val > 0 else None,
                        "sla_time": sla_row.get("sla_time"),
                        "sla_deadline_datetime": None,
                        "sla_coverage": "sla_defined_no_execution",
                        "meets_sla": None,
                        "breached": None,
                        "breach_reason": "no_execution_data",
                        "breach_by_ms": 0,
                    })
                else:
                    # Both execution and SLA exist — full evaluation
                    result = _evaluate_observed_sla(sic_row, sla_row, business_date)
                    all_sla_results.append(result)
                    if result.get("breached"):
                        breach_count += 1
                    elif result.get("meets_sla"):
                        met_count += 1

    # ── Merge anomaly data into every SLA result row ──────────────────────────
    anomaly_by_eid = {row["sic_eid"]: row for row in anomaly_rows if row.get("sic_eid")}
    anomaly_count = 0
    for row in all_sla_results:
        sic_eid = row.get("sic_eid")
        anom = anomaly_by_eid.get(sic_eid)
        hist_avg = float(anom["hist_avg_ms"]) if anom and anom.get("hist_avg_ms") is not None else None
        hist_std = float(anom["hist_std_ms"]) if anom and anom.get("hist_std_ms") is not None else 0.0
        sample_count = int(anom["hist_sample_count"]) if anom and anom.get("hist_sample_count") else 0
        actual_dur = row.get("actual_duration_ms")
        if actual_dur is not None and hist_avg is not None and sample_count >= _ANOMALY_MIN_SAMPLES:
            is_anomaly = actual_dur > hist_avg + _ANOMALY_K_FACTOR * hist_std
            deviation_factor = round(actual_dur / hist_avg, 3) if hist_avg > 0 else None
        else:
            is_anomaly = None
            deviation_factor = None
        if is_anomaly:
            anomaly_count += 1
        row["hist_avg_ms"] = int(hist_avg) if hist_avg is not None else None
        row["hist_std_ms"] = int(hist_std) if hist_std else None
        row["hist_sample_count"] = sample_count
        row["is_duration_anomaly"] = is_anomaly
        row["anomaly_deviation_factor"] = deviation_factor

    return {
        "business_date": business_date,
        "region": region,
        "relationships": relationships,
        "sla_results": all_sla_results,
        "summary": {
            "eligible_sic_count": len(eligible_eids),
            "executed_sic_count": len(actual_by_eid),
            "not_executed_count": len(eligible_eids - set(actual_by_eid)),
            "sla_evaluated_count": sum(1 for r in all_sla_results if r.get("breached") is not None),
            "breach_count": breach_count,
            "met_count": met_count,
            "no_sla_defined_count": sum(1 for r in all_sla_results if r.get("breach_reason") == "no_sla_defined"),
            "no_execution_count": sum(1 for r in all_sla_results if r.get("breach_reason") == "no_execution_data"),
            "anomaly_count": anomaly_count,
            "relationship_count": len(relationships),
        },
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
                }

            impacted_rows = await (
                await session.run(
                    _Q_IMPACTED_SICS_IN_SCOPE_BASE,
                    root_sic_eids=root_sic_eids,
                    scope_sic_eids=list(eligible_eids),
                )
            ).data()

            # JG-level cascade: SICs in JobGroups downstream via JobGroup PRECEDES chain
            jg_cascade_rows = await (
                await session.run(
                    _Q_JG_CASCADE_FROM_SICS_IN_SCOPE,
                    sic_eids=root_sic_eids,
                    scope_sic_eids=list(eligible_eids),
                    start_date=start_date,
                )
            ).data()
            _existing_eids = {row["sic_eid"] for row in impacted_rows if row.get("sic_eid")}
            jg_cascade_count = sum(1 for row in jg_cascade_rows if row.get("sic_eid") and row["sic_eid"] not in _existing_eids)
            impacted_rows.extend(
                row for row in jg_cascade_rows
                if row.get("sic_eid") and row["sic_eid"] not in _existing_eids
            )
            logger.debug(f"date_projection: Added {jg_cascade_count} dependent JobGroup SICs via cascade (total impacted: {len(impacted_rows)})")

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

        logger.debug(f"date_projection: Found {len(sla_rows)} SLA rows for {len(impacted_by_sic)} impacted SICs")
        sla_impacts = []
        skipped_slas = 0
        for sla_row in sla_rows:
            sic_eid = sla_row.get("sic_eid")
            if not sic_eid or sic_eid not in impacted_by_sic:
                skipped_slas += 1
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
        logger.debug(f"date_projection: Created {len(sla_impacts)} SLA impact evaluations (skipped {skipped_slas} SLA rows)")

        projected_breach_count = sum(1 for row in sla_impacts if row.get("projected_breach"))
        at_risk_count = sum(1 for row in sla_impacts if row.get("at_risk"))
        sla_evaluated_count = sum(1 for row in sla_impacts if row.get("sla_id"))

        # Keep absolute times internally for correct calculations
        base_fields_by_sic = {
            sic_eid: {
                "duration_source": duration_source.get(sic_eid, "missing"),
                "effective_duration_ms": duration_ms.get(sic_eid),
                "propagated_delay_ms": propagated_delay_ms.get(sic_eid, 0),
                "baseline_finish_ms": baseline_finish_ms.get(sic_eid),
                "projected_finish_ms": projected_finish_ms.get(sic_eid),
                "downstream_after_ms": downstream_after_ms.get(sic_eid),
            }
            for sic_eid in impacted_by_sic
        }
        impacted_sics_enriched = _consolidate_sic_impacts(
            impacted_by_sic=impacted_by_sic,
            base_fields_by_sic=base_fields_by_sic,
            sla_impacts=sla_impacts,
        )

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
            "impacted_sic_count": len(impacted_by_sic),
            "sla_evaluated_count": sla_evaluated_count,
            "projected_breach_count": projected_breach_count,
            "at_risk_count": at_risk_count,
            "impacted_sics": impacted_sics_enriched,
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

        # JG-level cascade: SICs in JobGroups downstream via JobGroup PRECEDES chain
        jg_cascade_query = _Q_JG_CASCADE_FROM_SICS_IN_SCOPE if eligible_eids else _Q_JG_CASCADE_FROM_SICS
        jg_cascade_params: dict[str, Any] = {"sic_eids": root_sic_eids, "start_date": start_date}
        if eligible_eids:
            jg_cascade_params["scope_sic_eids"] = list(eligible_eids)
        jg_cascade_rows = await (await session.run(jg_cascade_query, **jg_cascade_params)).data()
        _existing_eids = {row["sic_eid"] for row in impacted_rows if row.get("sic_eid")}
        jg_cascade_count = sum(1 for row in jg_cascade_rows if row.get("sic_eid") and row["sic_eid"] not in _existing_eids)
        impacted_rows.extend(
            row for row in jg_cascade_rows
            if row.get("sic_eid") and row["sic_eid"] not in _existing_eids
        )
        logger.debug(f"hypothetical_projection: Added {jg_cascade_count} dependent JobGroup SICs via cascade (total impacted: {len(impacted_rows)})")
        impacted_sic_eids = [row["sic_eid"] for row in impacted_rows if row.get("sic_eid")]

        sla_rows: list[dict[str, Any]] = []
        precedes_rows: list[dict[str, Any]] = []
        avg_rows: list[dict[str, Any]] = []
        if impacted_sic_eids:
            sla_rows = await (await session.run(_Q_SLA_ROWS_FOR_SICS, sic_eids=impacted_sic_eids)).data()
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

    duration_ms: dict[str, int | None] = {}
    duration_source: dict[str, str] = {}
    for sic_eid in node_set:
        impacted_avg = impacted_by_sic[sic_eid].get("avg_duration_ms")
        if avg_by_sic.get(sic_eid) is not None:
            duration_ms[sic_eid] = avg_by_sic[sic_eid]
            duration_source[sic_eid] = "average"
        elif impacted_avg is not None:
            duration_ms[sic_eid] = int(impacted_avg)
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
        {},
        0,
    )

    logger.debug(f"hypothetical_projection: Found {len(sla_rows)} SLA rows for {len(impacted_by_sic)} impacted SICs")
    sla_impacts = []
    skipped_slas = 0
    for sla_row in sla_rows:
        sic_eid = sla_row.get("sic_eid")
        if not sic_eid or sic_eid not in impacted_by_sic:
            skipped_slas += 1
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
    logger.debug(f"hypothetical_projection: Created {len(sla_impacts)} SLA impact evaluations (skipped {skipped_slas} SLA rows)")

    projected_breach_count = sum(1 for row in sla_impacts if row.get("projected_breach"))
    at_risk_count = sum(1 for row in sla_impacts if row.get("at_risk"))
    sla_evaluated_count = sum(1 for row in sla_impacts if row.get("sla_id"))

    # Keep absolute times internally for correct calculations
    base_fields_by_sic = {
        sic_eid: {
            "duration_source": duration_source.get(sic_eid, "missing"),
            "effective_duration_ms": duration_ms.get(sic_eid),
            "propagated_delay_ms": propagated_delay_ms.get(sic_eid, 0),
            "baseline_finish_ms": baseline_finish_ms.get(sic_eid),
            "projected_finish_ms": projected_finish_ms.get(sic_eid),
            "downstream_after_ms": downstream_after_ms.get(sic_eid),
        }
        for sic_eid in impacted_by_sic
    }
    impacted_sics_enriched = _consolidate_sic_impacts(
        impacted_by_sic=impacted_by_sic,
        base_fields_by_sic=base_fields_by_sic,
        sla_impacts=sla_impacts,
    )

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
        "impacted_sic_count": len(impacted_by_sic),
        "sla_evaluated_count": sla_evaluated_count,
        "projected_breach_count": projected_breach_count,
        "at_risk_count": at_risk_count,
        "impacted_sics": impacted_sics_enriched,
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
    start = _start_date(days)
    async with kg_session(driver) as session:
        result = await session.run(_Q_JOB_PERFORMANCE, job_id=job_id, start_date=start)
        record = await result.single()
        ts_result = await session.run(_Q_JOB_DURATION_TIMESERIES, job_id=job_id, start_date=start)
        ts_rows = await ts_result.data()
    if not record:
        return {}
    data = dict(record)
    points = [
        (i, float(row["avg_duration_ms"]))
        for i, row in enumerate(ts_rows)
        if row.get("avg_duration_ms") is not None
    ]
    slope = _compute_linear_slope(points)
    if slope is None or len(points) < _TREND_MIN_POINTS:
        trend = "insufficient_data"
    elif slope >= _TREND_DETERIORATING_MS:
        trend = "deteriorating"
    elif slope <= _TREND_IMPROVING_MS:
        trend = "improving"
    else:
        trend = "stable"
    data["time_series"] = ts_rows
    data["data_points_count"] = len(ts_rows)
    data["slope_ms_per_day"] = round(slope, 2) if slope is not None else None
    data["trend"] = trend
    return data


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
