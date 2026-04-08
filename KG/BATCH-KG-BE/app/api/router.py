"""Central API router — assembles all sub-routers under /api/v1."""

from fastapi import APIRouter

from app.api.routes import chat, graph, health, mcp, sessions, stream

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health.router, prefix="/health", tags=["ops"])
api_router.include_router(chat.router, prefix="/chat", tags=["agent"])
api_router.include_router(stream.router, prefix="/chat", tags=["agent"])
api_router.include_router(sessions.router, prefix="/sessions", tags=["sessions"])
api_router.include_router(mcp.router, prefix="/mcp", tags=["mcp"])
api_router.include_router(graph.router, prefix="/graph", tags=["graph"])
