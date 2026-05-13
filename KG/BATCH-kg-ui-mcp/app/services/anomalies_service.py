"""Calendar anomaly detection — Use Case 1.1.

Algorithm
---------
1. Fetch every ScheduleInstanceContext (SIC) in the KG (total picture).
2. Fetch every ALLOWS / DENIES rule attached to JobGroups.
3. Fetch every ALLOWS / DENIES rule attached directly to SICs.
4. Python: build a per-SIC rule map (fan-out JG rules to all SICs of that JG).
5. Python: evaluate each SIC for the requested business_date ->  planned list.
   - Has ALLOW rules and at least one matches AND no DENY matches -> planned
   - Has ALLOW rules and none match                               -> not planned
   - Has only DENY rules (no ALLOW) and none match               -> planned (open)
   - Has only DENY rules and any match                           -> not planned
   - No rules at all                                             -> planned (unrestricted)
6. Fetch SICs that actually executed on business_date via
   JobGroupExecution -> JobContextExecution -[:EXECUTES_CONTEXT]-> SIC.
7. Anomaly detection:
   - executed but NOT in planned  -> wrongly_executed
   - planned  but NOT in executed -> missed
8. Cascading impact: traverse PRECEDES from all anomaly SICs.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime
from typing import Any

from app.core.database import kg_session
from app.evaluators.calendar_evaluators import EVALUATOR_REGISTRY

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Cypher
# -----------------------------------------------------------------------------

# Q1 -- All SICs with their owning Job and JobGroup
_Q_ALL_SICS = """
MATCH (sic:ScheduleInstanceContext)-[:FOR_GROUP]->(jg:JobGroup)
MATCH (sic)-[:FOR_JOB]->(job:Job)
RETURN
  elementId(sic) AS sic_eid,
  sic.id         AS sic_id,
  sic.enabled    AS sic_enabled,
  job.name       AS job_name,
  elementId(job) AS job_eid,
  elementId(jg)  AS jg_eid,
  jg.name        AS jg_name
"""

# Q2a -- JobGroup-level ALLOWS / DENIES rules
_Q_JG_RULES = """
MATCH (jg:JobGroup)-[rel:ALLOWS|DENIES]->(jr:JobRule)-[:USES_PATTERN]->(cp:CalendarPattern)
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

# Q2b -- SIC-level ALLOWS / DENIES rules
_Q_SIC_RULES = """
MATCH (sic:ScheduleInstanceContext)-[rel:ALLOWS|DENIES]->(jr:JobRule)-[:USES_PATTERN]->(cp:CalendarPattern)
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

# Q3 -- SICs that actually ran on business_date
_Q_EXECUTED_SICS = """
MATCH (jge:JobGroupExecution)
WHERE jge.businessDate = date($business_date)
   OR toString(jge.businessDate) = $business_date
MATCH (jge)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)
      -[:EXECUTES_CONTEXT]->(sic:ScheduleInstanceContext)
OPTIONAL MATCH (sic)-[:FOR_JOB]->(job:Job)
RETURN
  elementId(sic) AS sic_eid,
  sic.id         AS sic_id,
  job.name       AS job_name,
  elementId(job) AS job_eid,
  jce.status     AS status
"""

# Q4 -- Cascading downstream impact via PRECEDES
_Q_CASCADING_IMPACT = """
UNWIND $impacted_sic_eids AS root_eid
MATCH (root:ScheduleInstanceContext)
WHERE elementId(root) = root_eid
MATCH p = (root)-[:PRECEDES*1..50]->(ds:ScheduleInstanceContext)
OPTIONAL MATCH (ds)-[:FOR_JOB]->(ds_job:Job)
WITH ds, ds_job, min(length(p)) AS min_distance
RETURN
  elementId(ds) AS sic_eid,
  ds.id         AS sic_id,
  ds_job.name   AS job_name
"""


# -----------------------------------------------------------------------------
# Phase helpers
# -----------------------------------------------------------------------------

def _build_sic_map(
    all_sics: list,
    jg_rules: list,
    sic_rules: list,
) -> dict:
    """Build a per-SIC rule map for SICs that have rules.

    Only SICs with at least one ALLOW or DENY rule are included.
    JG-level rules are fanned-out to every SIC that belongs to that JG.
    """
    jg_to_sics: dict = {}
    sic_map: dict = {}

    for s in all_sics:
        eid = s["sic_eid"]
        jg_eid = s["jg_eid"]
        sic_map[eid] = {
            "sic_id":      s["sic_id"],
            "job_name":    s["job_name"],
            "job_eid":     s["job_eid"],
            "jg_eid":      jg_eid,
            "jg_name":     s.get("jg_name"),
            "allow_rules": [],
            "deny_rules":  [],
        }
        jg_to_sics.setdefault(jg_eid, []).append(eid)

    def _normalise(raw: dict) -> dict:
        return {
            "rule_id":     raw.get("rule_id"),
            "evaluatorFn": raw.get("evaluatorFn"),
            "params":      raw.get("params"),
            "holidays":    [h for h in (raw.get("holidays") or []) if h is not None],
        }

    def _attach(sic_eid: str, raw: dict) -> None:
        if sic_eid not in sic_map:
            return
        entry = _normalise(raw)
        if raw["rule_type"] == "ALLOWS":
            sic_map[sic_eid]["allow_rules"].append(entry)
        else:
            sic_map[sic_eid]["deny_rules"].append(entry)

    for rule in jg_rules:
        for sic_eid in jg_to_sics.get(rule["target_eid"], []):
            _attach(sic_eid, rule)

    for rule in sic_rules:
        _attach(rule["target_eid"], rule)

    # Filter: only include SICs that have at least one rule
    sic_map_with_rules = {
        eid: entry for eid, entry in sic_map.items()
        if entry["allow_rules"] or entry["deny_rules"]
    }

    return sic_map_with_rules


def _invoke_evaluator(rule: dict, business_date_obj: date, region: str) -> bool:
    """Call one calendar evaluator; returns True if the rule matches."""
    evaluator_fn = rule.get("evaluatorFn")
    if not evaluator_fn or evaluator_fn not in EVALUATOR_REGISTRY:
        logger.debug("Unknown evaluatorFn %r -- skipping", evaluator_fn)
        return False

    full_args: dict = {"date": business_date_obj, "region": region}

    raw_params = rule.get("params")
    if raw_params:
        try:
            parsed = json.loads(raw_params) if isinstance(raw_params, str) else raw_params
            if isinstance(parsed, dict):
                full_args.update(parsed)
        except (json.JSONDecodeError, ValueError):
            logger.warning(
                "Could not parse params for rule %r: %r",
                rule.get("rule_id"), raw_params,
            )

    if evaluator_fn in ("holiday"):
        full_args["holiday_set"] = [
            {
                "date":   h["date"],
                "region": h.get("region", "ALL"),
                "name":   h.get("name", ""),
            }
            for h in rule.get("holidays", [])
            if h is not None
        ]

    try:
        return bool(EVALUATOR_REGISTRY[evaluator_fn](**full_args))
    except Exception as exc:
        logger.warning("Evaluator %s raised: %s", evaluator_fn, exc)
        return False


def _evaluate_sic(
    sic_entry: dict,
    business_date_obj: date,
    region: str,
) -> tuple:
    """Decide whether a SIC is planned to run on business_date.

    Returns (should_run: bool, reason: str).

    Logic:
      - ALLOW only:            planned only if at least one ALLOW matches
      - DENY only:             NOT planned (no explicit ALLOW to permit execution)
      - ALLOW + DENY:          planned when ALLOW matches AND no DENY matches

    (SICs with no rules are already filtered out in _build_sic_map)
    """
    allow_rules = sic_entry.get("allow_rules", [])
    deny_rules  = sic_entry.get("deny_rules",  [])

    # If there are ALLOW rules, at least one must match
    if allow_rules:
        allow_matched = any(
            _invoke_evaluator(r, business_date_obj, region) for r in allow_rules
        )
        if not allow_matched:
            return False, "no_allow_matched"
    elif deny_rules:
        # DENY-only rules: no explicit ALLOW to permit execution
        return False, "deny_only_no_explicit_allow"

    # Check DENY rules (reached when ALLOW matched or no ALLOW rules exist)
    for rule in deny_rules:
        if _invoke_evaluator(rule, business_date_obj, region):
            return False, "denied_by:{}".format(rule.get("rule_id", "unknown"))

    return True, "allowed"


# -----------------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------------

async def detect_calendar_anomalies(
    business_date: str,
    region: str,
    driver: Any,
) -> dict:
    """Full calendar anomaly detection for Use Case 1.1."""
    logger.info("detect_calendar_anomalies: date=%s region=%s", business_date, region)
    business_date_obj = datetime.fromisoformat(business_date).date()

    # Steps 1-3: fetch all KG data in a single session
    async with kg_session(driver) as session:
        r_sics      = await (await session.run(_Q_ALL_SICS)).fetch(2000)
        r_jg_rules  = await (await session.run(_Q_JG_RULES)).fetch(2000)
        r_sic_rules = await (await session.run(_Q_SIC_RULES)).fetch(2000)
        r_exec      = await (await session.run(
            _Q_EXECUTED_SICS, business_date=business_date
        )).fetch(2000)

    all_sics  = [dict(r) for r in r_sics]
    jg_rules  = [dict(r) for r in r_jg_rules]
    sic_rules = [dict(r) for r in r_sic_rules]
    executed  = [dict(r) for r in r_exec]

    logger.info(
        "Fetched: %d SICs | %d JG rules | %d SIC rules | %d executions",
        len(all_sics), len(jg_rules), len(sic_rules), len(executed),
    )

    # Step 4: build per-SIC rule map
    sic_map = _build_sic_map(all_sics, jg_rules, sic_rules)

    # Step 5: evaluate each SIC -> planned set
    planned_eids: set = set()
    planned_details: list = []

    for sic_eid, sic_entry in sic_map.items():
        should_run, reason = _evaluate_sic(sic_entry, business_date_obj, region)
        if should_run:
            planned_eids.add(sic_eid)
            planned_details.append({
                "sic_eid":  sic_eid,
                "sic_id":   sic_entry["sic_id"],
                "job_name": sic_entry["job_name"],
                "reason":   reason,
            })

    # Step 6: build executed SIC set
    executed_eids: set = {r["sic_eid"] for r in executed}
    executed_by_eid: dict = {r["sic_eid"]: r for r in executed}

    logger.info("Planned: %d | Executed: %d", len(planned_eids), len(executed_eids))

    # Step 7: anomaly detection
    anomalies: list = []

    # Executed but not planned -> wrongly_executed
    for sic_eid in executed_eids - planned_eids:
        rec = executed_by_eid[sic_eid]
        anomalies.append({
            "sic_eid":      sic_eid,
            "sic_id":       rec.get("sic_id"),
            "job_name":     rec.get("job_name"),
            "anomaly_type": "wrongly_executed",
            "reason":       "ran on a day not permitted by calendar rules",
        })

    # Planned but not executed -> missed
    for detail in planned_details:
        if detail["sic_eid"] not in executed_eids:
            anomalies.append({
                "sic_eid":      detail["sic_eid"],
                "sic_id":       detail["sic_id"],
                "job_name":     detail["job_name"],
                "anomaly_type": "missed",
                "reason":       "calendar rules permitted execution but no run was found",
            })

    wrongly_executed = [a for a in anomalies if a["anomaly_type"] == "wrongly_executed"]
    missed           = [a for a in anomalies if a["anomaly_type"] == "missed"]

    logger.info(
        "Anomalies: %d wrongly_executed | %d missed",
        len(wrongly_executed), len(missed),
    )

    # Step 8: cascading downstream impact
    cascading: list = []
    impacted_eids = [a["sic_eid"] for a in anomalies if a.get("sic_eid")]

    if impacted_eids:
        async with kg_session(driver) as session:
            r_cascade = await (await session.run(
                _Q_CASCADING_IMPACT, impacted_sic_eids=impacted_eids
            )).fetch(5000)
        cascading = [dict(r) for r in r_cascade]
        logger.info("Cascading impact: %d downstream SICs", len(cascading))

    return {
        "business_date":          business_date,
        "region":                 region,
        "total_sic_count":        len(all_sics),
        "planned_count":          len(planned_eids),
        "executed_count":         len(executed_eids),
        "anomaly_count":          len(anomalies),
        "wrongly_executed_count": len(wrongly_executed),
        "missed_count":           len(missed),
        "anomalies":              anomalies,
        "cascading_impact":       cascading,
        "summary": {
            "total_sic_count":      len(all_sics),
            "planned_count":        len(planned_eids),
            "executed_count":       len(executed_eids),
            "anomaly_count":        len(anomalies),
            "wrongly_executed":     len(wrongly_executed),
            "missed":               len(missed),
            "cascading_downstream": len(cascading),
        },
    }
