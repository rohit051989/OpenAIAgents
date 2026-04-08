"""Graph proxy routes — on-demand graph data for UI rendering.

These endpoints proxy to the MCP server's REST graph API so the React
frontend only ever talks to the backend.

  GET /api/v1/graph/{entity_id}
      Returns a 1-hop subgraph centred on the given entity.

  GET /api/v1/graph/expand/{node_id}
      Returns immediate neighbours of a node, excluding already-known nodes.

Both return ``GraphData``: ``{nodes: [...], relationships: [...]}``.
"""

import logging

import httpx
from fastapi import APIRouter, HTTPException, Query

from app.api.schemas import GraphData
from config.settings import get_settings

logger = logging.getLogger(__name__)
router = APIRouter()


def _mcp_base_url() -> str:
    """Return the MCP server base URL (strip the /mcp/sse suffix)."""
    url = get_settings().mcp_server_url
    return url.replace("/mcp/sse", "").replace("/sse", "").rstrip("/")


@router.get(
    "/{entity_id}",
    response_model=GraphData,
    summary="Get entity subgraph",
    description=(
        "Return a 1-hop subgraph centred on the given entity. "
        "The entity can be identified by its `id` property, `name`, or Neo4j element ID."
    ),
)
async def get_entity_graph(entity_id: str) -> GraphData:
    base = _mcp_base_url()
    url = f"{base}/api/graph/{entity_id}"
    logger.info("get_entity_graph proxying to %s", url)
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return GraphData(**resp.json())
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Cannot reach MCP server: {exc}") from exc


@router.get(
    "/expand/{node_id}",
    response_model=GraphData,
    summary="Expand a graph node",
    description=(
        "Return immediate neighbours of a node not already present in the graph. "
        "Pass `existing_node_ids` as a comma-separated list to avoid duplicate nodes."
    ),
)
async def expand_node(
    node_id: str,
    existing_node_ids: str = Query(default="", description="Comma-separated list of already-rendered node IDs"),
) -> GraphData:
    base = _mcp_base_url()
    url = f"{base}/api/graph/expand/{node_id}"
    logger.info("expand_node proxying to %s existing=%s", url, existing_node_ids)
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params={"existing_node_ids": existing_node_ids})
            resp.raise_for_status()
            return GraphData(**resp.json())
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Cannot reach MCP server: {exc}") from exc
