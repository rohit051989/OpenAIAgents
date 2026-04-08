# BATCH-kg-ui-mcp — Spring Batch KG MCP Server

FastAPI-based MCP (Model Context Protocol) server exposing Spring Batch Knowledge Graph data to LLM agents.

## Architecture

```
BATCH-kg-ui-mcp/
├── config/               # Pydantic settings & configuration
├── app/
│   ├── core/             # Infrastructure: DB client, logging, security
│   ├── services/         # Business logic and Cypher query execution
│   │   ├── schema_service.py
│   │   ├── topology_service.py
│   │   ├── execution_service.py
│   │   ├── performance_service.py
│   │   └── dependency_service.py
│   ├── mcp/              # MCP protocol exposure (thin wrappers only)
│   │   ├── server.py     # FastMCP instance
│   │   ├── resources/    # MCP resources (read-only data)
│   │   └── tools/        # MCP tools (invokable by agents)
│   └── main.py           # FastAPI app entry point
└── tests/
    ├── unit/             # Unit tests for services and core utilities
    └── integration/      # Integration tests against real Neo4j instance
```

**Key design principle:** MCP tools are thin wrappers — all business/query logic lives in `services/`.  
This keeps services independently testable and decoupled from the MCP protocol.

## Prerequisites

- Python 3.11+
- Neo4j 5.x running and accessible

## Quick Start

```bash
# 1. Clone and install
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env with your Neo4j credentials

# 3. Run the server (FastAPI + MCP via SSE)
uvicorn app.main:app --host 0.0.0.0 --port 8100 --reload
```

> The server starts on port **8100** by default in the examples below.
> Change `--port` to any free port; update client configs accordingly.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check — returns Neo4j connectivity status |
| `GET` | `/info` | Server metadata (name, version, env, Neo4j URI) |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/mcp/sse` | **MCP SSE stream** — LLM agents connect here |
| `POST` | `/mcp/messages/` | MCP message posting |

### Connecting from a client

| Client | Setting |
|--------|---------|
| Postman | `GET http://127.0.0.1:8100/mcp/sse` (set Accept: `text/event-stream`) |
| Claude Desktop / MCP agent | `url: http://127.0.0.1:8100/mcp/sse` |
| LangGraph agent | `transport="sse"`, `url="http://127.0.0.1:8100/mcp/sse"` |

> **Note:** Postman has limited SSE support. Use `/health` and `/info` for basic REST testing.
> For full MCP interaction, use an MCP-aware client or the `mcp` CLI:
> ```bash
> mcp dev http://127.0.0.1:8100/mcp/sse
> ```

## MCP Tools

| Tool | Description |
|------|-------------|
| `get_job_topology` | Job structure: steps, blocks, SLAs, calendars, resources |
| `get_failed_jobs` | Recent failed job executions |
| `get_common_errors` | Most frequent error messages |
| `get_job_performance` | Avg/min/max duration metrics per job |
| `get_slow_jobs` | Jobs exceeding execution time threshold |
| `get_step_failure_analysis` | Step-level failure rates for a job |
| `compare_jobs` | Side-by-side performance comparison |
| `get_execution_timeline` | Daily execution statistics |
| `get_job_execution_history` | Full execution history for a job |
| `get_all_active_jobs` | Jobs active in a recent time window |
| `get_job_dependency_chain` | Upstream/downstream dependency graph for a job context |
| `get_jobgroup_execution_flow` | Topological execution order for a job group |
| `execute_cypher_query` | Execute read-only Cypher (guarded by allowlist) |

## MCP Resources

| URI | Description |
|-----|-------------|
| `kg://schema` | Full KG schema: nodes, properties, relationships, patterns |

## Running Tests

```bash
# Unit tests only (no Neo4j required)
pytest tests/unit/ -v

# All tests (requires Neo4j)
pytest -v
```

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | — | Neo4j password |
| `NEO4J_DATABASE_KG` | `knowledgegraph` | Knowledge Graph database name (used by all MCP tools) |
| `NEO4J_DATABASE_IG` | `informationgraph` | Information Graph database name (Java class/method queries) |
| `NEO4J_MAX_CONNECTION_POOL_SIZE` | `50` | Max connection pool size |
| `NEO4J_CONNECTION_TIMEOUT` | `30` | Connection timeout (seconds) |
| `MCP_SERVER_NAME` | `Spring Batch KG MCP` | Server display name |
| `LOG_LEVEL` | `INFO` | Python logging level |
