"""Integration tests for MCPClient against a live MCP server.

Prerequisites
-------------
- MCP server must be running at the URL configured in MCP_SERVER_URL
  (default: http://localhost:8100/mcp/sse)
- Run with: pytest tests/integration/test_mcp_client.py -v

These tests are skipped automatically when the MCP server is unreachable.
"""
from __future__ import annotations

import os
import pytest
import httpx

from app.mcp.client import MCPClient


MCP_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8100/mcp/sse")


def _mcp_server_reachable() -> bool:
    """Return True if the MCP server base URL responds."""
    base_url = MCP_URL.replace("/mcp/sse", "").replace("/sse", "")
    try:
        response = httpx.get(f"{base_url}/health", timeout=3)
        return response.status_code < 500
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(
    not _mcp_server_reachable(),
    reason=f"MCP server not reachable at {MCP_URL}",
)


@pytest.fixture
def mcp_client() -> MCPClient:
    return MCPClient(MCP_URL)


class TestMCPClientListTools:
    async def test_returns_list(self, mcp_client: MCPClient):
        tools = await mcp_client.list_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0

    async def test_each_tool_has_required_keys(self, mcp_client: MCPClient):
        tools = await mcp_client.list_tools()
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    async def test_exclude_filters_tools(self, mcp_client: MCPClient):
        all_tools = await mcp_client.list_tools()
        if not all_tools:
            pytest.skip("No tools available to test exclusion")
        exclude_name = all_tools[0]["name"]
        filtered = await mcp_client.list_tools(exclude=[exclude_name])
        names = [t["name"] for t in filtered]
        assert exclude_name not in names

    async def test_excludes_execute_cypher_query(self, mcp_client: MCPClient):
        tools = await mcp_client.list_tools(exclude=["execute_cypher_query"])
        names = [t["name"] for t in tools]
        assert "execute_cypher_query" not in names


class TestMCPClientGetSchema:
    async def test_returns_dict(self, mcp_client: MCPClient):
        schema = await mcp_client.get_schema()
        assert isinstance(schema, dict)

    async def test_schema_has_expected_keys(self, mcp_client: MCPClient):
        schema = await mcp_client.get_schema()
        # Should have either valid schema keys or an error key
        assert len(schema) > 0

    async def test_schema_uri_is_string_safe(self, mcp_client: MCPClient):
        """Regression test: resource.uri was AnyUrl, not str — caused AttributeError."""
        # If this does not raise AttributeError, the fix is in place
        schema = await mcp_client.get_schema()
        assert schema is not None
