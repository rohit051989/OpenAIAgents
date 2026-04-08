"""Graph visualization service — entity subgraph and node expansion queries.

Provides two operations:
  - ``get_entity_graph``  — subgraph centered on a KG entity (Job, Step, etc.)
  - ``expand_node``       — immediate neighbours of a single node, excluding
                           nodes the caller already has

Both return the standard ``GraphData`` shape:
    ``{"nodes": [{id, labels, properties}], "relationships": [{id, type, startNodeId, endNodeId, properties}]}``
"""

import logging
from typing import Any

from neo4j import AsyncDriver

from app.core.database import kg_session

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
