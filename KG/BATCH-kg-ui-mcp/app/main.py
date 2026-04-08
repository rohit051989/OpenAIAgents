"""FastAPI application entry point.

Startup order:
  1. Logging is configured.
  2. FastMCP tools and resources are registered by importing their modules.
  3. FastAPI app is created with a lifespan that closes the Neo4j driver on shutdown.
  4. Health / info REST endpoints are added.
  5. The MCP ASGI app is mounted under ``/mcp``.

Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.core.database import check_connectivity, close_driver
from app.core.logging_config import configure_logging

# ------------------------------------------------------------------
# Logging must be configured before any module-level loggers fire.
# ------------------------------------------------------------------
configure_logging()

# ------------------------------------------------------------------
# Import all MCP tool / resource modules so their decorators run and
# register them with the FastMCP server instance.  These imports are
# intentionally side-effectful.
# ------------------------------------------------------------------
import app.mcp.resources.schema  # noqa: F401, E402
import app.mcp.tools.dependencies  # noqa: F401, E402
import app.mcp.tools.execution  # noqa: F401, E402
import app.mcp.tools.graph  # noqa: F401, E402
import app.mcp.tools.performance  # noqa: F401, E402
import app.mcp.tools.query  # noqa: F401, E402
import app.mcp.tools.topology  # noqa: F401, E402

from app.mcp.server import mcp  # noqa: E402 (after registrations)


# ------------------------------------------------------------------
# Application lifespan
# ------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):  # noqa: ARG001
    # Nothing to do at startup — Neo4j driver is lazily created.
    yield
    # Graceful shutdown: close the Neo4j connection pool.
    await close_driver()


# ------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------

app = FastAPI(
    title="Spring Batch KG MCP Server",
    description=(
        "FastAPI application that hosts the Spring Batch Knowledge Graph "
        "MCP server.  Connect your LLM agent to /mcp/sse."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ------------------------------------------------------------------
# REST endpoints (health / info)
# ------------------------------------------------------------------

@app.get("/health", tags=["ops"], summary="Health check")
async def health() -> JSONResponse:
    """Return server health including Neo4j connectivity status."""
    db_connected = await check_connectivity()
    status_code = 200 if db_connected else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ok" if db_connected else "degraded",
            "neo4j": "connected" if db_connected else "unreachable",
        },
    )


@app.get("/info", tags=["ops"], summary="Server information")
async def info() -> dict:
    """Return server metadata."""
    from config.settings import get_settings

    s = get_settings()
    return {
        "name": s.mcp_server_name,
        "version": "1.0.0",
        "env": s.app_env,
        "neo4j_uri": s.neo4j_uri,
        "mcp_sse_url": "/mcp/sse",
    }


# ------------------------------------------------------------------
# Graph REST endpoints (for direct frontend/backend consumption)
# ------------------------------------------------------------------

@app.get("/api/graph/{entity_id}", tags=["graph"], summary="Get entity subgraph")
async def get_entity_graph(entity_id: str) -> dict:
    """Return a 1-hop subgraph centred on the given entity.

    Looks up the entity by its ``id`` property, ``name``, or Neo4j element ID.
    Returns ``{nodes, relationships}`` in the standard GraphData format.
    """
    from app.core.database import get_driver
    from app.services.graph_service import get_entity_graph as _get_entity_graph

    driver = await get_driver()
    return await _get_entity_graph(driver, entity_id=entity_id)


@app.get("/api/graph/expand/{node_id}", tags=["graph"], summary="Expand a graph node")
async def expand_node(
    node_id: str,
    existing_node_ids: str = "",
) -> dict:
    """Return immediate neighbours of *node_id* not already in the graph.

    Pass ``existing_node_ids`` as a comma-separated list of node IDs already
    rendered by the frontend to avoid returning duplicate nodes.
    Returns ``{nodes, relationships}``.
    """
    from app.core.database import get_driver
    from app.services.graph_service import expand_node as _expand_node

    driver = await get_driver()
    ids = [i.strip() for i in existing_node_ids.split(",") if i.strip()]
    return await _expand_node(driver, node_id=node_id, existing_node_ids=ids)


# ------------------------------------------------------------------
# Mount MCP server
# ------------------------------------------------------------------

# The MCP SSE transport is available at /mcp/sse
# Agents should connect to: http://<host>:<port>/mcp/sse
app.mount("/mcp", mcp.sse_app())
