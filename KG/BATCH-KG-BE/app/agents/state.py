"""LangGraph agent state — shared TypedDict passed between all graph nodes."""

from typing import Annotated, Any, Optional, TypedDict
import operator


def _merge_dicts(left: dict, right: dict) -> dict:
    return {**left, **right}


class AgentState(TypedDict):
    """State flowing through the LangGraph workflow."""

    # ---- Inputs ----
    question: str
    mcp_server_url: str
    available_tools: list[dict[str, Any]]   # Tool metadata dicts (name, description, inputSchema)
    kg_schema: dict[str, Any]
    conversation_history: Optional[list[dict[str, str]]]

    # ---- Planning ----
    execution_plan: Optional[dict[str, Any]]
    current_step: int

    # ---- Execution (accumulated across nodes) ----
    step_results: Annotated[dict[str, Any], _merge_dicts]
    execution_log: Annotated[list[dict[str, str]], operator.add]

    # ---- Output ----
    final_answer: Optional[str]
    error: Optional[str]
