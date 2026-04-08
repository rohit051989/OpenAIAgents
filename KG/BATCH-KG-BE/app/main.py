"""FastAPI application entry point.

Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.logging_config import configure_logging

configure_logging()

from app.api.router import api_router  # noqa: E402
from app.middleware.correlation import CorrelationIdMiddleware  # noqa: E402
from app.services.session_service import init_session_store  # noqa: E402
from config.settings import get_settings  # noqa: E402


@asynccontextmanager
async def lifespan(application: FastAPI):  # noqa: ARG001
    settings = get_settings()
    init_session_store(ttl_hours=settings.session_ttl_hours)
    yield


settings = get_settings()

app = FastAPI(
    title="Spring Batch KG Agent Backend",
    description=(
        "FastAPI backend hosting LangGraph multi-agent workflow for Spring Batch KG.\n\n"
        "Key endpoints:\n"
        "- `POST /api/v1/chat` — blocking agentic chat\n"
        "- `POST /api/v1/chat/stream` — SSE streaming agentic chat\n"
        "- `POST /api/v1/sessions` — create a conversation session\n"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Correlation ID — must be added before CORS so the header is available
app.add_middleware(CorrelationIdMiddleware)

# CORS — origins driven by settings (env-configurable for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-API-Key", "X-Correlation-ID"],
    expose_headers=["X-Correlation-ID"],
)

app.include_router(api_router)
