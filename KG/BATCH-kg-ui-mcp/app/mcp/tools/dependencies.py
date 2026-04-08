"""MCP tools: job dependency chains and execution flow.

Registers the following MCP tools:
  - get_job_dependency_chain
  - get_jobgroup_execution_flow
  - get_job_step_flow

This module is intentionally thin: only MCP registration lives here.
All logic is in ``dependency_service``.
"""

import logging

from app.core.database import get_driver
from app.mcp.server import mcp
from app.services import dependency_service

logger = logging.getLogger(__name__)


@mcp.tool(name="get_job_dependency_chain")
async def tool_get_job_dependency_chain(job_name: str) -> dict:
    """Return the upstream/downstream graphlet for a Job across all its JobGroups.

    For every JobGroup containing this job, walks the PRECEDES chain in both
    directions (up to depth 30) and returns an enriched graphlet with direction
    tags (TARGET / UPSTREAM / DOWNSTREAM) plus a per-group flow summary.

    Args:
        job_name: The ``name`` property of the target Job node.

    Returns:
        ``{"jobName": ..., "groupCount": N, "groups": [{"graphlet": {"nodes": [...],
        "links": [...]}, "flowSummary": {"jobName": ..., "jobGroupName": ...,
        "targetContext": ..., "totalContexts": N, "upstreamJobCount": N,
        "downstreamJobCount": N, "upstreamJobs": [...], "downstreamJobs": [...]}}, ...]}``
    """
    logger.info("MCP tool get_job_dependency_chain job_name=%s", job_name)
    driver = await get_driver()
    return await dependency_service.get_job_dependency_chain(driver, job_name=job_name)


@mcp.tool(name="get_jobgroup_execution_flow")
async def tool_get_jobgroup_execution_flow(job_group_id: str) -> dict:
    """Compute the topological execution order of all jobs in a JobGroup.

    Uses Kahn's algorithm on the PRECEDES-relationship DAG to assign a
    ``distance`` (execution wave) and ``orderIndex`` to every
    ``ScheduleInstanceContext`` within the group.

    Args:
        job_group_id: The unique ``id`` property of the target JobGroup node.

    Returns:
        ``{"jobGroupId": ..., "jobGroupName": ..., "nodeCount": N, "nodes": [...]}``
        Each node has ``jobContextId``, ``jobId``, ``jobName``,
        ``distance``, ``orderIndex``. ``hasCycle`` is ``true`` if a cycle
        was detected (Kahn's algorithm could not order all nodes).
    """
    logger.info("MCP tool get_jobgroup_execution_flow job_group_id=%s", job_group_id)
    driver = await get_driver()
    return await dependency_service.get_jobgroup_execution_flow(driver, job_group_id=job_group_id)


@mcp.tool(name="get_job_step_flow")
async def tool_get_job_step_flow(job_name: str) -> dict:
    """Return the internal step-flow graphlet for a Job.

    Traverses the PRECEDES chain starting from the job's ENTRY node (up to
    depth 20) across Step, Decision, and Block nodes, and returns a graphlet
    suitable for graph rendering together with a summary of node counts.

    Args:
        job_name: The ``name`` property of the target Job node.

    Returns:
        ``{"jobName": ..., "graphlet": {"nodes": [...], "links": [...]},
        "flowSummary": {"jobName": ..., "nodeCount": N, "stepCount": N,
        "decisionCount": N, "blockCount": N}}``
    """
    logger.info("MCP tool get_job_step_flow job_name=%s", job_name)
    driver = await get_driver()
    return await dependency_service.get_job_step_flow(driver, job_name=job_name)
