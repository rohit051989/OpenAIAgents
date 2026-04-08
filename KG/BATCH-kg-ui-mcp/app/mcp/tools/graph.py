"""MCP tools: graph visualization.

Registers the following MCP tools:
  - get_entity_graph  — 1-hop subgraph centred on an entity
  - expand_node       — immediate neighbours of a node (incremental expansion)

This module is intentionally thin: only MCP registration lives here.
All logic is in ``graph_service``.
"""

import logging

from app.core.database import get_driver
from app.mcp.server import mcp
from app.services import graph_service

logger = logging.getLogger(__name__)


@mcp.tool(name="get_entity_graph")
async def tool_get_entity_graph(entity_id: str) -> dict:
    """Return a 1-hop subgraph centred on the given KG entity.

    Useful for visualising a Job, Step, JobGroup, or any other node and its
    immediate relationships in the Knowledge Graph.

    Args:
        entity_id: The ``id`` property, ``name``, or Neo4j element ID of the
            target node.

    Returns:
        ``{"nodes": [{id, labels, properties}],
           "relationships": [{id, type, startNodeId, endNodeId, properties}]}``
    """
    logger.info("MCP tool get_entity_graph entity_id=%s", entity_id)
    driver = await get_driver()
    return await graph_service.get_entity_graph(driver, entity_id=entity_id)


@mcp.tool(name="expand_node")
async def tool_expand_node(
    node_id: str,
    existing_node_ids: list[str] | None = None,
) -> dict:
    """Return immediate neighbours of a node not already present in the graph.

    Call this when the user clicks a node in the graph UI to progressively
    reveal connected nodes.

    Args:
        node_id: The ``id`` property or Neo4j element ID of the node to expand.
        existing_node_ids: List of node IDs already rendered by the frontend.
            These are excluded to avoid duplicating data.

    Returns:
        ``{"nodes": [...], "relationships": [...]}`` — only new nodes and the
        relationships that connect them.
    """
    logger.info("MCP tool expand_node node_id=%s", node_id)
    driver = await get_driver()
    return await graph_service.expand_node(
        driver,
        node_id=node_id,
        existing_node_ids=existing_node_ids or [],
    )
