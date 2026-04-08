"""MCP proxy routes — tool discovery and schema fetching."""

import logging

from fastapi import APIRouter, HTTPException, Query

from app.api.schemas import ToolsResponse, McpTool
from app.llm.factory import LLMFactory
from app.mcp.client import MCPClient

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/tools", response_model=ToolsResponse, summary="List MCP tools")
async def list_tools(url: str = Query(..., description="MCP SSE server URL")) -> ToolsResponse:
    """Fetch available tools from the MCP server."""
    logger.info("list_tools mcp_url=%s", url)
    try:
        client = MCPClient(url)
        tools = await client.list_tools(exclude=["execute_cypher_query"])
        return ToolsResponse(tools=[McpTool(**t) for t in tools])
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Cannot reach MCP server: {exc}") from exc


@router.get("/schema", summary="Fetch KG schema from MCP server")
async def get_schema(url: str = Query(..., description="MCP SSE server URL")) -> dict:
    """Fetch the Knowledge Graph schema resource."""
    logger.info("get_schema mcp_url=%s", url)
    try:
        client = MCPClient(url)
        return await client.get_schema()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Cannot reach MCP server: {exc}") from exc


@router.get("/providers", summary="Available LLM providers")
async def get_providers() -> dict:
    """Return LLM providers that have their credentials configured."""
    return {"available_providers": LLMFactory.get_available_providers()}
