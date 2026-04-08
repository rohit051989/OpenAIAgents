"""MCP async client — wraps mcp.client.sse for tool discovery and execution.

All agents that need to call MCP tools or read resources use this module.
The client manages session lifecycle internally so callers never touch
the raw SSE transport.
"""

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from mcp import ClientSession
from mcp.client.sse import sse_client

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _session(server_url: str):
    """Open an MCP SSE session as an async context manager."""
    try:
        async with sse_client(server_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session
    except Exception as e:
        # Log the actual error for debugging
        logger.error("MCP session error for %s: %s", server_url, str(e), exc_info=True)
        # Re-raise with a cleaner message
        raise RuntimeError(f"Failed to connect to MCP server at {server_url}: {type(e).__name__}: {str(e)}") from e


class MCPClient:
    """High-level MCP client used by agents and API routes.

    Every method opens its own short-lived SSE session. This keeps
    connection management simple and avoids holding open connections
    across the lifetime of a request.
    """

    def __init__(self, server_url: str) -> None:
        self.server_url = server_url

    async def list_tools(self, exclude: list[str] | None = None) -> list[dict[str, Any]]:
        """Return the list of available MCP tools.

        Args:
            exclude: Optional list of tool names to omit (e.g. raw Cypher tool).

        Returns:
            List of dicts with ``name``, ``description``, ``inputSchema``.
        """
        exclude_set = set(exclude or [])
        async with _session(self.server_url) as session:
            result = await session.list_tools()
        tools = [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.inputSchema if hasattr(t, "inputSchema") else {},
            }
            for t in result.tools
            if t.name not in exclude_set
        ]
        logger.info("list_tools → %d tools (excluded=%s)", len(tools), exclude_set)
        return tools

    async def get_schema(self) -> dict[str, Any]:
        """Fetch the ``kg://schema`` MCP resource.

        Returns:
            Parsed schema dictionary, or ``{"error": "..."}`` on failure.
        """
        async with _session(self.server_url) as session:
            resources_resp = await session.list_resources()
            for resource in resources_resp.resources:
                uri_str = str(resource.uri)  # Convert AnyUrl to string
                if "schema" in uri_str.lower() or resource.name == "get_kg_schema":
                    result = await session.read_resource(resource.uri)
                    content = result.contents[0]
                    if hasattr(content, "text"):
                        return json.loads(content.text)
        logger.warning("kg://schema resource not found on %s", self.server_url)
        return {"error": "kg://schema resource not found"}

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke an MCP tool and return its result.

        Args:
            tool_name: Name of the MCP tool to call.
            arguments: Tool arguments dict.

        Returns:
            Parsed tool result dict, or ``{"error": "..."}`` on failure.
        """
        logger.info("call_tool tool_name=%s arguments=%s", tool_name, str(arguments)[:200])
        async with _session(self.server_url) as session:
            result = await session.call_tool(tool_name, arguments)

        if result.isError:
            error_text = result.content[0].text if result.content else "Unknown MCP error"
            logger.warning("MCP tool error: %s", error_text)
            return {"error": error_text}

        content = result.content[0] if result.content else None
        if content and hasattr(content, "text"):
            try:
                return json.loads(content.text)
            except json.JSONDecodeError:
                return {"result": content.text}
        return {}
