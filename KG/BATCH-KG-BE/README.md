# BATCH-KG-BE — Spring Batch KG Agent Backend

FastAPI + LangGraph backend for the Spring Batch Knowledge Graph agent.
Hosts all intelligence: session management, LLM orchestration, MCP client, streaming SSE events.

---

## System Context

```
BATCH-KG-FE  (React UI — port 3000)
    │   REST + SSE  /api/*
    ▼
BATCH-KG-BE  (this project — port 8001)
    │   FastAPI · LangGraph · MCP client
    ▼
BATCH-kg-ui-mcp  (FastAPI MCP server — port 8100)
    │   MCP SSE / tool calls
    ▼
Neo4j  (knowledgegraph / informationgraph)
```

The frontend never speaks to the MCP server or Neo4j directly.

---

## Prerequisites

- Python 3.11+
- Running [BATCH-kg-ui-mcp](../BATCH-kg-ui-mcp) MCP server on port 8100
- At least one LLM API key (OpenAI / Azure OpenAI / AWS Bedrock / Google Gemini)

---

## Quick Start

```bash
# 1. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
copy .env.example .env
# Edit .env — set LLM_PROVIDER and the matching key(s)

# 4. Run
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

Swagger UI: `http://localhost:8001/docs`  
Health check: `GET http://localhost:8001/api/v1/health`

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `APP_PORT` | `8001` | Server port |
| `APP_ENV` | `development` | `development` → human logs; any other → JSON logs |
| `LOG_LEVEL` | `INFO` | Root log level |
| `ALLOWED_ORIGINS` | `["http://localhost:3000"]` | CORS origins (JSON list) |
| `MCP_SERVER_URL` | `http://localhost:8100/mcp/sse` | Default MCP SSE endpoint |
| `API_KEY` | *(unset)* | When set, requires `X-API-Key` header on all endpoints |
| `SESSION_TTL_HOURS` | `24` | How long in-memory sessions live |
| `LLM_PROVIDER` | `openai` | `openai` · `azure_openai` · `aws_bedrock` · `google_gemini` |
| `OPENAI_API_KEY` | — | OpenAI key |
| `AZURE_OPENAI_API_KEY` | — | Azure OpenAI key |
| `AZURE_OPENAI_ENDPOINT` | — | Azure endpoint URL |
| `AZURE_OPENAI_DEPLOYMENT` | — | Azure deployment name |
| `AWS_ACCESS_KEY_ID` | — | AWS Bedrock credentials |
| `AWS_SECRET_ACCESS_KEY` | — | |
| `AWS_REGION` | `us-east-1` | |
| `BEDROCK_MODEL_ID` | `anthropic.claude-3-5-sonnet-20241022-v2:0` | |
| `GOOGLE_API_KEY` | — | Gemini key |

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | — | Health check |
| `POST` | `/api/v1/chat` | ✓ | Blocking agentic chat (full response) |
| `POST` | `/api/v1/chat/stream` | ✓ | **SSE streaming** agentic chat |
| `POST` | `/api/v1/sessions` | ✓ | Create a conversation session |
| `GET` | `/api/v1/sessions` | ✓ | List active sessions |
| `GET` | `/api/v1/sessions/{id}` | ✓ | Get session + message history |
| `DELETE` | `/api/v1/sessions/{id}` | ✓ | Delete session |
| `GET` | `/api/v1/mcp/tools?url=` | ✓ | List MCP tools |
| `GET` | `/api/v1/mcp/schema?url=` | ✓ | Get KG schema |
| `GET` | `/api/v1/mcp/providers` | ✓ | Available LLM providers |

Auth = `X-API-Key` header required when `API_KEY` env var is set.

### Chat request (blocking + stream share the same body)

```json
{
  "question": "Show me all failed jobs in the last 24 hours",
  "mcp_url": "http://localhost:8100/mcp/sse",
  "llm_provider": "openai",
  "session_id": "optional-uuid",
  "history": []
}
```

### SSE event stream

Each `data:` frame is a JSON-serialised `AgentEvent`:

```
data: {"type":"plan_generated","plan":{...},"total_steps":3}

data: {"type":"step_started","step_number":1,"step_description":"..."}

data: {"type":"step_completed","step_number":1,"success":true}

data: {"type":"done","answer":"...","execution_log":[...]}

data: [DONE]
```

---

## Agent Graph

```
START
  └─► planner
        └─► executor_router
              ├─► execute_direct_tool ─►┐
              └─► execute_cypher      ─►┤
                                        └─► check_next_step
                                              ├─► executor_router  (loop)
                                              └─► summarizer
                                                    └─► END
```

Agent roles:
| Agent | Responsibility |
|---|---|
| **Planner** | Decomposes the user question into typed steps (direct tool vs. Cypher query) |
| **ToolExecutor** | Calls MCP tools or executes generated Cypher queries |
| **SchemaAnalyzer** | Extracts relevant schema context before Cypher generation |
| **CypherGenerator** | Produces a parameterised Cypher query from natural language |
| **Summarizer** | Synthesises step results into a final natural-language answer |

---

## Project Structure

```
BATCH-KG-BE/
├── requirements.txt
├── pyproject.toml           # pytest config + build metadata
├── .env.example
├── config/
│   └── settings.py          # Pydantic Settings (env-driven config)
├── app/
│   ├── main.py              # FastAPI app, CORS, CorrelationIdMiddleware, lifespan
│   ├── core/
│   │   ├── logging_config.py # Text (dev) / JSON (prod) structured logging
│   │   └── security.py       # require_auth dependency (X-API-Key)
│   ├── middleware/
│   │   └── correlation.py    # Injects X-Correlation-ID into every request/log
│   ├── models/
│   │   └── events.py         # Typed AgentEvent discriminated union (Pydantic)
│   ├── agents/
│   │   ├── orchestrator.py   # LangGraph StateGraph · run() · stream_run()
│   │   ├── state.py          # AgentState TypedDict
│   │   ├── planner.py
│   │   ├── tool_executor.py
│   │   ├── summarizer.py
│   │   ├── schema_analyzer.py
│   │   └── cypher_generator.py
│   ├── mcp/
│   │   └── client.py         # MCPClient — list_tools, get_schema, call_tool
│   ├── llm/
│   │   ├── base.py           # BaseLLM ABC
│   │   ├── factory.py        # LLMFactory.create_llm(provider)
│   │   └── providers/        # openai, azure_openai, bedrock, gemini
│   ├── services/
│   │   └── session_service.py # In-memory SessionStore + MemorySaver checkpointer
│   └── api/
│       ├── router.py
│       ├── schemas.py
│       └── routes/
│           ├── chat.py        # POST /chat  (blocking)
│           ├── stream.py      # POST /chat/stream  (SSE)
│           ├── sessions.py    # CRUD /sessions
│           ├── mcp.py
│           └── health.py
└── tests/
    ├── conftest.py
    └── unit/
        └── test_llm_factory.py
```

---

## Development

### Run tests

```bash
pip install -e ".[dev]"
pytest
```

### Type checking (optional)

```bash
pip install mypy
mypy app/ config/
```

---

## Observability

- **Correlation IDs** — every request gets a `X-Correlation-ID` echoed in the response header and injected into all log lines for that request
- **Structured JSON logs** in non-development environments — compatible with ELK, Grafana Loki, AWS CloudWatch
- **Future**: OpenTelemetry traces + Prometheus metrics (`/metrics` endpoint)

---

## State Store & Checkpointing

The `SessionStore` (in `app/services/session_service.py`) holds an in-memory `MemorySaver` checkpointer shared across all sessions. For each `session_id`:

- LangGraph graphs are compiled with `checkpointer=store.checkpointer`
- All runs use `thread_id=session_id` so graph state persists across turns
- **Future**: swap `MemorySaver` for a Redis or Postgres checkpointer for multi-instance deployments

---

## Stack

| | Technology |
|---|---|
| API framework | FastAPI + Uvicorn |
| Agent runtime | LangGraph 0.2+ |
| LLM abstraction | Custom `BaseLLM` factory (OpenAI / Azure / Bedrock / Gemini) |
| MCP transport | `mcp` SDK — SSE client |
| Configuration | Pydantic Settings v2 |
| Auth | API-key guard (`X-API-Key`) |
| Logging | Python `logging` — JSON in prod, text in dev |
| Testing | pytest + pytest-asyncio + pytest-mock |
