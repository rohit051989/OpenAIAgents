"""Dependency service — job dependency chains and execution flow ordering.

Covers:
  - Upstream / downstream dependency chain for a single JobContext  (via BFS)
  - Topological execution flow for all JobGroupContexts of a JobGroup
  - Internal step-flow graphlet for a Job (Step/Decision/Block PRECEDES chain)
"""

import logging
from collections import deque
from typing import Any

from neo4j import AsyncDriver

from app.core.database import kg_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cypher — Q17 job execution context across all groups (upstream + downstream)
# ---------------------------------------------------------------------------

_Q_JOB_DEPENDENCY_CHAIN = """
MATCH (j:Job {name: $jobName})
MATCH (targetSic:ScheduleInstanceContext)-[:FOR_JOB]->(j)
MATCH (targetSic)-[:FOR_GROUP]->(jg:JobGroup)

OPTIONAL MATCH downPath = (targetSic)-[:PRECEDES*1..30]->(ds:ScheduleInstanceContext)
WITH j, jg, targetSic,
     collect(DISTINCT ds) AS downstreamSics,
     collect(downPath)    AS downPaths

OPTIONAL MATCH upPath = (us:ScheduleInstanceContext)-[:PRECEDES*1..30]->(targetSic)
WITH j, jg, targetSic, downstreamSics, downPaths,
     collect(DISTINCT us) AS upstreamSics,
     collect(upPath)      AS upPaths

WITH j, jg, targetSic, downstreamSics, upstreamSics,
     reduce(ns = [], p IN downPaths | ns + nodes(p)) + [targetSic] +
     reduce(ns = [], p IN upPaths   | ns + nodes(p)) AS rawNodes,
     reduce(rs = [], p IN downPaths | rs + relationships(p)) +
     reduce(rs = [], p IN upPaths   | rs + relationships(p)) AS rawRels

UNWIND rawNodes AS nd
WITH j, jg, targetSic, downstreamSics, upstreamSics, rawRels,
     collect(DISTINCT nd) AS allNodes

UNWIND rawRels AS rel
WITH j, jg, targetSic, downstreamSics, upstreamSics, allNodes,
     collect(DISTINCT rel) AS allRels

UNWIND allNodes AS sn
OPTIONAL MATCH (sn)-[:FOR_JOB]->(relJob:Job)
OPTIONAL MATCH (ctxJob:Job {id: sn.contextForEntityId})
WITH j, jg, targetSic, allRels,
     collect({
       sic      : sn,
       jobName  : coalesce(
                    relJob.name,
                    ctxJob.name,
                    CASE WHEN sn.name STARTS WITH 'Context_'
                         THEN substring(sn.name, 8)
                         ELSE '' END
                  ),
       direction: CASE
                    WHEN elementId(sn) = elementId(targetSic) THEN 'TARGET'
                    WHEN sn IN upstreamSics                   THEN 'UPSTREAM'
                    WHEN sn IN downstreamSics                 THEN 'DOWNSTREAM'
                    ELSE 'OTHER'
                  END,
       enabled  : coalesce(sn.enabled, true)
     }) AS enrichedNodes

WITH j, jg, targetSic, allRels, enrichedNodes,
     [en IN enrichedNodes WHERE en.direction = 'UPSTREAM'   | en.jobName] AS upstreamJobs,
     [en IN enrichedNodes WHERE en.direction = 'DOWNSTREAM' | en.jobName] AS downstreamJobs

RETURN
  {
    nodes: [en IN enrichedNodes | {
      id       : elementId(en.sic),
      labels   : labels(en.sic),
      name     : coalesce(en.sic.name, ''),
      jobName  : en.jobName,
      direction: en.direction,
      enabled  : en.enabled
    }],
    links: [r IN allRels | {
      source: elementId(startNode(r)),
      target: elementId(endNode(r)),
      on    : coalesce(r.on, 'DEFAULT')
    }]
  } AS graphlet,
  {
    jobName            : j.name,
    jobGroupName       : jg.name,
    targetContext      : targetSic.name,
    totalContexts      : size(enrichedNodes),
    upstreamJobCount   : size(upstreamJobs),
    downstreamJobCount : size(downstreamJobs),
    upstreamJobs       : upstreamJobs,
    downstreamJobs     : downstreamJobs
  } AS flowSummary
"""

# ---------------------------------------------------------------------------
# Cypher — job group execution flow
# ---------------------------------------------------------------------------

_Q_JG_NODES = """
MATCH (jg:JobGroup {id: $job_group_id})
MATCH (ctx:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
MATCH (ctx)-[:FOR_JOB]->(j:Job)
RETURN
    jg.id   AS jobGroupId,
    jg.name AS jobGroupName,
    ctx.id  AS ctxId,
    j.id    AS jobId,
    j.name  AS jobName
"""

_Q_JG_EDGES = """
MATCH (jg:JobGroup {id: $job_group_id})
MATCH (ownerCtx:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
MATCH (ownerCtx)-[:PRECEDES]->(depCtx:ScheduleInstanceContext)
WHERE (depCtx)-[:FOR_GROUP]->(jg)
MATCH (depCtx)-[:FOR_JOB]->(j:Job)
RETURN
    depCtx.id   AS upstreamCtxId,
    ownerCtx.id AS downstreamCtxId,
    j.id        AS jobId,
    j.name      AS jobName
"""


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

async def get_job_dependency_chain(
    driver: AsyncDriver,
    job_name: str,
) -> dict[str, Any]:
    """Return the upstream/downstream graphlet for a Job across all its JobGroups.

    Executes the Q17 Cypher query which, for every JobGroup containing this
    job, walks the PRECEDES chain in both directions (up to depth 30) and
    returns an enriched graphlet with direction tags (TARGET / UPSTREAM /
    DOWNSTREAM) plus a per-group flow summary.

    Args:
        driver: Shared Neo4j async driver.
        job_name: The ``name`` property of the target ``Job`` node.

    Returns:
        ``{"jobName": ..., "groupCount": N, "groups": [{"graphlet": {...},
        "flowSummary": {...}}, ...]}``
    """
    logger.info("get_job_dependency_chain job_name=%s", job_name)

    async with kg_session(driver) as session:
        result = await session.run(_Q_JOB_DEPENDENCY_CHAIN, jobName=job_name)
        rows = await result.data()

    if not rows:
        logger.warning("No ScheduleInstanceContext found for job_name=%s", job_name)
        return {"jobName": job_name, "error": "Job not found or has no schedule context"}

    groups = [
        {
            "graphlet": dict(row["graphlet"]),
            "flowSummary": dict(row["flowSummary"]),
        }
        for row in rows
    ]

    return {
        "jobName": job_name,
        "groupCount": len(groups),
        "groups": groups,
    }


async def get_jobgroup_execution_flow(
    driver: AsyncDriver,
    job_group_id: str,
) -> dict[str, Any]:
    """Compute topological execution order for all JobGroup contexts.

    Uses Kahn's algorithm (BFS-based topological sort) on the
    PRECEDES-relationship DAG to determine the longest-path distance
    (i.e., the execution wave) for each ``ScheduleInstanceContext``.

    Args:
        driver: Shared Neo4j async driver.
        job_group_id: The ``id`` property of the target ``JobGroup`` node.

    Returns:
        ``{"jobGroupId": ..., "jobGroupName": ..., "nodeCount": N, "nodes": [...]}``
        where each node has ``{jobContextId, jobId, jobName, distance, orderIndex}``.
    """
    logger.info("get_jobgroup_execution_flow job_group_id=%s", job_group_id)

    async with kg_session(driver) as session:
        res_nodes = await session.run(_Q_JG_NODES, job_group_id=job_group_id)
        rows_nodes = await res_nodes.data()

        res_edges = await session.run(_Q_JG_EDGES, job_group_id=job_group_id)
        rows_edges = await res_edges.data()

    if not rows_nodes:
        return {"jobGroupId": job_group_id, "error": "JobGroup not found or has no contexts"}

    job_group_name: str | None = rows_nodes[0].get("jobGroupName") if rows_nodes else None

    # Build node map
    ctx_map: dict[str, dict[str, Any]] = {
        row["ctxId"]: {"jobContextId": row["ctxId"], "jobId": row["jobId"], "jobName": row["jobName"]}
        for row in rows_nodes
    }
    ctx_ids = list(ctx_map.keys())

    # Adjacency (up -> down) and in-degree
    adjacency: dict[str, set] = {cid: set() for cid in ctx_ids}
    indegree: dict[str, int] = {cid: 0 for cid in ctx_ids}

    for edge in rows_edges:
        up, dn = edge["upstreamCtxId"], edge["downstreamCtxId"]
        if up not in ctx_map or dn not in ctx_map:
            continue
        if dn not in adjacency[up]:
            adjacency[up].add(dn)
            indegree[dn] += 1

    # Kahn's topological sort + longest-path distance
    distance: dict[str, int] = {cid: 0 for cid in ctx_ids}
    queue: deque[str] = deque(cid for cid, deg in indegree.items() if deg == 0)
    topo_order: list[str] = []

    while queue:
        current = queue.popleft()
        topo_order.append(current)
        for nxt in adjacency.get(current, []):
            new_dist = distance[current] + 1
            if new_dist > distance[nxt]:
                distance[nxt] = new_dist
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)

    has_cycle = len(topo_order) < len(ctx_ids)

    nodes = [
        {
            **ctx_map[ctx_id],
            "distance": distance.get(ctx_id, 0),
            "orderIndex": idx,
        }
        for idx, ctx_id in enumerate(topo_order)
    ]

    return {
        "jobGroupId": job_group_id,
        "jobGroupName": job_group_name,
        "nodeCount": len(ctx_ids),
        "orderedNodeCount": len(nodes),
        "hasCycle": has_cycle,
        "nodes": nodes,
    }


# ---------------------------------------------------------------------------
# Cypher — Q07 job internal step-flow graphlet
# ---------------------------------------------------------------------------

_Q_JOB_STEP_FLOW = """
MATCH (j:Job {name: $jobName})-[:ENTRY]->(entry)
MATCH p = (entry)-[:PRECEDES*0..20]->(n)
WITH j, collect(p) AS paths
WITH j,
     reduce(ns = [], pth IN paths | ns + nodes(pth))          AS rawNodes,
     reduce(rs = [], pth IN paths | rs + relationships(pth))  AS rawRels
UNWIND rawNodes AS nd
WITH j, rawRels, collect(DISTINCT nd) AS allNodes
UNWIND rawRels AS rel
WITH j, allNodes, collect(DISTINCT rel) AS allRels
RETURN
  {
    nodes: [n IN allNodes | {
      id       : elementId(n),
      labels   : labels(n),
      name     : coalesce(n.name, ''),
      stepKind : coalesce(n.stepKind, ''),
      blockType: coalesce(n.block_type, '')
    }],
    links: [r IN allRels | {
      source: elementId(startNode(r)),
      target: elementId(endNode(r)),
      on    : coalesce(r.on, 'DEFAULT')
    }]
  } AS graphlet,
  {
    jobName      : j.name,
    nodeCount    : size(allNodes),
    stepCount    : size([n IN allNodes WHERE 'Step'     IN labels(n)]),
    decisionCount: size([n IN allNodes WHERE 'Decision' IN labels(n)]),
    blockCount   : size([n IN allNodes WHERE 'Block'    IN labels(n)])
  } AS flowSummary
"""


async def get_job_step_flow(
    driver: AsyncDriver,
    job_name: str,
) -> dict[str, Any]:
    """Return the internal step-flow graphlet for a Job.

    Traverses the ``PRECEDES`` chain starting from the job's ``ENTRY`` node
    (up to depth 20) and returns a graphlet suitable for graph rendering, plus
    a JSON summary with node/step/decision/block counts.

    Args:
        driver: Shared Neo4j async driver.
        job_name: The ``name`` property of the target ``Job`` node.

    Returns:
        ``{"jobName": ..., "graphlet": {"nodes": [...], "links": [...]},
           "flowSummary": {"nodeCount": N, "stepCount": N, ...}}``
    """
    logger.info("get_job_step_flow job_name=%s", job_name)

    async with kg_session(driver) as session:
        result = await session.run(_Q_JOB_STEP_FLOW, jobName=job_name)
        row = await result.single()

    if row is None:
        logger.warning("No step-flow found for job_name=%s", job_name)
        return {"jobName": job_name, "error": "Job not found or has no step-flow"}

    return {
        "jobName": job_name,
        "graphlet": dict(row["graphlet"]),
        "flowSummary": dict(row["flowSummary"]),
    }
