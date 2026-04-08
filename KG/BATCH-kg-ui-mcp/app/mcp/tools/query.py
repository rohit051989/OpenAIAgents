"""MCP tool: execute_cypher_query

Allows agents to run arbitrary read-only Cypher queries against the
Knowledge Graph.  All queries are validated by ``security.is_read_only_cypher``
before reaching Neo4j.

This module is intentionally thin: only MCP registration and security
gating live here.  The actual query execution is handled by the driver
directly (no service wrapper needed for generic pass-through queries).
"""

import logging
from typing import Any

from app.core.database import get_driver, kg_session
from app.core.security import is_read_only_cypher
from app.mcp.server import mcp

logger = logging.getLogger(__name__)


@mcp.tool(name="execute_cypher_query")
async def tool_execute_cypher_query(
    cypher_query: str,
    parameters: dict[str, Any] | None = None,
) -> dict:
    """Execute a custom read-only Cypher query against the Knowledge Graph.

    The query is validated before execution — only MATCH / CALL / RETURN
    queries are permitted; any mutation or administration keywords are
    blocked and return an error immediately.

    Args:
        cypher_query: A read-only Cypher query string.
        parameters: Optional dict of query parameters (``$key`` placeholders).

    Returns:
        ``{"query": ..., "results": [...], "count": N}`` on success, or
        ``{"error": "..."}`` when the query fails the safety check.
    """
    logger.info("MCP tool execute_cypher_query query_preview=%s", cypher_query[:120])

    if not is_read_only_cypher(cypher_query):
        logger.warning("Blocked unsafe Cypher query: %s", cypher_query[:200])
        return {
            "error": (
                "Only read-only Cypher queries are allowed. "
                "Write and administration operations are blocked."
            )
        }

    params: dict[str, Any] = parameters or {}
    driver = await get_driver()

    async with kg_session(driver) as session:
        result = await session.run(cypher_query, **params)
        records = await result.data()

    return {
        "query": cypher_query,
        "results": records,
        "count": len(records),
    }
