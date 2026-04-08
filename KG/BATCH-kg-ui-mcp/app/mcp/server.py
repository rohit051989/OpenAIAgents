"""MCP server singleton.

All MCP tools and resources import ``mcp`` from this module to register
themselves.  The server is created once here; ``app.main`` mounts it on
the FastAPI application.
"""

from mcp.server.fastmcp import FastMCP

from config.settings import get_settings

_settings = get_settings()

mcp = FastMCP(_settings.mcp_server_name)
