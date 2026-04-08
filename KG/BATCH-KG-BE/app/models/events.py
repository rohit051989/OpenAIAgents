"""Typed agent event hierarchy.

Every event that flows from the LangGraph orchestrator to the SSE transport
is represented as a Pydantic model.  The ``type`` field is a literal
discriminator so both Python and TypeScript consumers can deserialise the
correct variant without a large ``if/elif`` chain.

Event flow (happy path):
    plan_generated → step_started → step_completed (×N) → done

On failure:
    ... → error
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Union
from uuid import uuid4

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uid() -> str:
    return str(uuid4())


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class _EventBase(BaseModel):
    """Fields common to every agent event."""

    id: str = Field(default_factory=_uid, description="Unique event ID")
    timestamp: datetime = Field(default_factory=_now)
    session_id: str = Field(default="", description="Owning session (empty ⇒ stateless)")


# ---------------------------------------------------------------------------
# Concrete event types
# ---------------------------------------------------------------------------

class TokenEvent(_EventBase):
    """A single LLM output token (for future streaming LLM support)."""

    type: Literal["token"] = "token"
    content: str
    agent: str = ""


class PlanGeneratedEvent(_EventBase):
    """Emitted once the planner agent has produced the execution plan."""

    type: Literal["plan_generated"] = "plan_generated"
    plan: dict[str, Any]
    complexity: str = "medium"
    total_steps: int = 0


class StepStartedEvent(_EventBase):
    """Emitted before a tool/cypher step begins execution."""

    type: Literal["step_started"] = "step_started"
    step_number: int
    step_description: str
    step_type: str = ""  # "direct_tool" | "cypher_query"


class StepCompletedEvent(_EventBase):
    """Emitted after a tool/cypher step finishes."""

    type: Literal["step_completed"] = "step_completed"
    step_number: int
    success: bool
    result: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0


class ErrorEvent(_EventBase):
    """Terminal or non-terminal error during the workflow."""

    type: Literal["error"] = "error"
    error_code: str
    message: str
    recoverable: bool = False


class DoneEvent(_EventBase):
    """Final event — carries the complete answer and execution artefacts."""

    type: Literal["done"] = "done"
    answer: str
    execution_log: list[dict[str, Any]] = Field(default_factory=list)
    plan: dict[str, Any] | None = None
    step_results: dict[str, Any] = Field(default_factory=dict)
    graph_data: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Discriminated union — use this type in StreamingResponse / SSE consumers
# ---------------------------------------------------------------------------

AgentEvent = Annotated[
    Union[
        TokenEvent,
        PlanGeneratedEvent,
        StepStartedEvent,
        StepCompletedEvent,
        ErrorEvent,
        DoneEvent,
    ],
    Field(discriminator="type"),
]
