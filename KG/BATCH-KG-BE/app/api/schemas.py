"""Pydantic models for API request/response.

Kept in sync with the TypeScript types in frontend/src/types/index.ts.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    question: str
    history: list[dict[str, str]] = Field(default_factory=list)
    mcp_url: Optional[str] = None
    llm_provider: Optional[str] = None
    # Optionally bind the request to a persisted session
    session_id: Optional[str] = None


class ExecutionLogEntry(BaseModel):
    agent: str
    message: str


# ---------------------------------------------------------------------------
# Graph visualization
# ---------------------------------------------------------------------------

class GraphNode(BaseModel):
    """A node in the Knowledge Graph for UI visualization."""

    id: str
    labels: list[str] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphRelationship(BaseModel):
    """A relationship in the Knowledge Graph for UI visualization."""

    id: str
    type: str
    startNodeId: str
    endNodeId: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphData(BaseModel):
    """Graph subgraph payload consumed by the frontend graph renderer."""

    nodes: list[GraphNode] = Field(default_factory=list)
    relationships: list[GraphRelationship] = Field(default_factory=list)


class ChatResponse(BaseModel):
    answer: str
    execution_log: list[dict[str, Any]] = Field(default_factory=list)
    plan: Optional[dict[str, Any]] = None
    step_results: dict[str, Any] = Field(default_factory=dict)
    graph_data: Optional[GraphData] = None
    session_id: Optional[str] = None


# ---------------------------------------------------------------------------
# MCP / providers
# ---------------------------------------------------------------------------

class McpTool(BaseModel):
    name: str
    description: str
    inputSchema: dict[str, Any] = Field(default_factory=dict)


class ToolsResponse(BaseModel):
    tools: list[McpTool]


class ProvidersResponse(BaseModel):
    available_providers: list[str]


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

class SessionCreate(BaseModel):
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionMessageOut(BaseModel):
    role: str
    content: str
    timestamp: str


class SessionOut(BaseModel):
    id: str
    created_at: str
    updated_at: str
    message_count: int
    messages: list[SessionMessageOut] = Field(default_factory=list)
