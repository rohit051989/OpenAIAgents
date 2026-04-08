"""LangGraph Orchestrator.

Wires the five agents into a directed graph:

  START
    └─► planner ──► executor_router ──┬─► execute_direct_tool ──► check_next_step
                                       ├─► execute_cypher       ──► check_next_step
                                       └─► (done) ──────────────────────────────────► summarizer ──► END
                                                                    check_next_step ──► executor_router (loop)

Public API
----------
``run()``         — awaitable, returns the full result dict (existing behaviour).
``stream_run()``  — async generator that yields typed :class:`~app.models.events.AgentEvent`
                    objects as each graph node completes.  Used by the SSE endpoint.
"""
from __future__ import annotations

import logging
from typing import Any, AsyncGenerator
from uuid import uuid4

from langgraph.graph import END, StateGraph

from app.agents.cypher_generator import CypherGeneratorAgent
from app.agents.graph_normalizer import extract_graph_data, sanitize_step_results
from app.agents.planner import PlannerAgent
from app.agents.schema_analyzer import SchemaAnalyzerAgent
from app.agents.state import AgentState
from app.agents.summarizer import SummarizerAgent
from app.agents.tool_executor import ToolExecutorAgent
from app.llm.base import BaseLLM
from app.mcp.client import MCPClient
from app.models.events import (
    AgentEvent,
    DoneEvent,
    ErrorEvent,
    PlanGeneratedEvent,
    StepCompletedEvent,
    StepStartedEvent,
)

logger = logging.getLogger(__name__)


class LangGraphOrchestrator:
    """Compiles and runs the multi-agent LangGraph workflow.

    Parameters
    ----------
    mcp_client:
        Configured MCP SSE client.
    llm:
        LLM instance from the factory.
    checkpointer:
        Optional LangGraph checkpointer (e.g. ``MemorySaver``).  When
        supplied every ``run()`` / ``stream_run()`` call that provides a
        ``thread_id`` will persist and restore state across requests,
        enabling multi-turn conversation memory at the graph level.
    """

    def __init__(self, mcp_client: MCPClient, llm: BaseLLM, checkpointer=None) -> None:
        self.mcp_client = mcp_client
        self.planner = PlannerAgent(llm)
        self.executor = ToolExecutorAgent(mcp_client, llm)
        self.summarizer = SummarizerAgent(llm)
        self.schema_analyzer = SchemaAnalyzerAgent(llm)
        self.cypher_generator = CypherGeneratorAgent(llm)
        self._checkpointer = checkpointer
        self.graph = self._build_graph()

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self):
        workflow = StateGraph(AgentState)

        workflow.add_node("planner", self._planner_node)
        workflow.add_node("executor_router", self._executor_router_node)
        workflow.add_node("execute_direct_tool", self._execute_direct_tool_node)
        workflow.add_node("execute_cypher", self._execute_cypher_node)
        workflow.add_node("check_next_step", self._check_next_step_node)
        workflow.add_node("summarizer", self._summarizer_node)

        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "executor_router")

        workflow.add_conditional_edges(
            "executor_router",
            self._route_execution,
            {"direct_tool": "execute_direct_tool", "cypher": "execute_cypher", "done": "summarizer"},
        )
        workflow.add_edge("execute_direct_tool", "check_next_step")
        workflow.add_edge("execute_cypher", "check_next_step")

        workflow.add_conditional_edges(
            "check_next_step",
            self._check_if_done,
            {"continue": "executor_router", "done": "summarizer"},
        )
        workflow.add_edge("summarizer", END)

        return workflow.compile(checkpointer=self._checkpointer)

    # ------------------------------------------------------------------
    # Node implementations
    # ------------------------------------------------------------------

    def _planner_node(self, state: AgentState) -> dict[str, Any]:
        plan = self.planner.create_plan(
            state["question"],
            state["available_tools"],
            state["kg_schema"],
        )
        logger.info("Planner created %d steps", len(plan.get("plan", [])))
        return {
            "execution_plan": plan,
            "current_step": 0,
            "execution_log": [{"agent": "Agent 1 (Planner)", "message": f"Plan created with {len(plan.get('plan', []))} steps"}],
        }

    def _executor_router_node(self, state: AgentState) -> dict[str, Any]:
        plan = state["execution_plan"]["plan"]
        step = state["current_step"]
        if step >= len(plan):
            return {}
        step_info = plan[step]
        return {
            "execution_log": [{"agent": f"Step {step_info['step']}", "message": f"Executing: {step_info['action']}"}]
        }

    def _route_execution(self, state: AgentState) -> str:
        plan = state["execution_plan"]["plan"]
        step = state["current_step"]
        if step >= len(plan):
            return "done"
        step_info = plan[step]
        if step_info["type"] == "direct_tool":
            return "direct_tool"
        if step_info["type"] == "cypher_query":
            return "cypher"
        return "done"

    async def _execute_direct_tool_node(self, state: AgentState) -> dict[str, Any]:
        plan = state["execution_plan"]["plan"]
        step_idx = state["current_step"]
        step_info = plan[step_idx]
        step_num = step_info["step"]
        tool_name = step_info.get("tool", "")

        # Find tool metadata
        tool_desc, input_schema = "", {}
        for t in state["available_tools"]:
            if t["name"] == tool_name:
                tool_desc = t.get("description", "")
                input_schema = t.get("inputSchema", {})
                break

        previous = self._previous_results_context(state)
        result = await self.executor.execute_tool(
            tool_name, tool_desc, input_schema, state["question"], previous
        )
        logger.info("Step %d direct_tool result: success=%s", step_num, result.get("success"))
        return {
            "step_results": {step_num: result},
            "execution_log": [{"agent": f"Step {step_num}", "message": f"Tool '{tool_name}' executed. Success={result.get('success')}"}],
            "current_step": step_idx + 1,
        }

    async def _execute_cypher_node(self, state: AgentState) -> dict[str, Any]:
        plan = state["execution_plan"]["plan"]
        step_idx = state["current_step"]
        step_info = plan[step_idx]
        step_num = step_info["step"]

        log_entries: list[dict[str, str]] = []

        # Step 1: schema analysis
        schema_analysis = self.schema_analyzer.analyze(step_info["action"], state["kg_schema"])
        log_entries.append({"agent": f"Step {step_num} (Schema Analyzer)", "message": "Schema analysis complete"})

        # Step 2: cypher generation
        cypher_result = self.cypher_generator.generate(step_info["action"], schema_analysis)

        if not cypher_result.get("cypher_query"):
            log_entries.append({"agent": f"Step {step_num} (Cypher Generator)", "message": f"Could not generate query: {cypher_result.get('error', 'unknown')}"})
            return {
                "step_results": {step_num: {"success": False, "error": cypher_result.get("explanation")}},
                "execution_log": log_entries,
                "current_step": step_idx + 1,
            }

        # Step 3: execute
        query_result = await self.executor.execute_cypher(
            cypher_result["cypher_query"],
            cypher_result.get("parameters", {}),
        )
        log_entries.append({"agent": f"Step {step_num} (Cypher Executor)", "message": f"Query executed: {cypher_result['cypher_query'][:80]}..."})

        return {
            "step_results": {step_num: {**query_result, "cypher_query": cypher_result["cypher_query"]}},
            "execution_log": log_entries,
            "current_step": step_idx + 1,
        }

    def _check_next_step_node(self, state: AgentState) -> dict[str, Any]:
        return {}

    def _check_if_done(self, state: AgentState) -> str:
        plan = state["execution_plan"]["plan"]
        if state["current_step"] >= len(plan):
            return "done"
        # Check all dependencies of the next step are resolved
        next_step = plan[state["current_step"]]
        for dep in next_step.get("depends_on", []):
            if dep not in state["step_results"]:
                return "done"
        return "continue"

    def _summarizer_node(self, state: AgentState) -> dict[str, Any]:
        answer = self.summarizer.summarize(
            state["question"],
            state["execution_plan"],
            state["step_results"],
            state.get("conversation_history"),
        )
        return {
            "final_answer": answer,
            "execution_log": [{"agent": "Agent 3 (Summarizer)", "message": "Final answer generated"}],
        }

    # ------------------------------------------------------------------
    # Public entry point — blocking (returns full result)
    # ------------------------------------------------------------------

    async def run(
        self,
        question: str,
        mcp_server_url: str,
        available_tools: list[dict[str, Any]],
        kg_schema: dict[str, Any],
        conversation_history: list[dict[str, str]] | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute the full agentic workflow and return the complete result.

        Args:
            question: The user's question.
            mcp_server_url: The MCP SSE URL for tool execution.
            available_tools: Tool metadata list from MCPClient.list_tools().
            kg_schema: Schema dict from MCPClient.get_schema().
            conversation_history: Recent chat history for context.
            thread_id: Optional session / thread identifier for checkpointing.

        Returns:
            Dict with ``answer``, ``execution_log``, ``plan``, ``step_results``.
        """
        initial_state = self._build_initial_state(
            question, mcp_server_url, available_tools, kg_schema, conversation_history
        )
        config = self._make_config(thread_id)

        logger.info("Starting LangGraph for question: %s thread_id=%s", question[:120], thread_id)
        final_state = await self.graph.ainvoke(initial_state, config=config)

        raw_step_results = {str(k): v for k, v in final_state.get("step_results", {}).items()}
        graph_data = extract_graph_data(raw_step_results)
        return {
            "answer": final_state.get("final_answer", "No answer generated."),
            "execution_log": final_state.get("execution_log", []),
            "plan": final_state.get("execution_plan"),
            "step_results": sanitize_step_results(raw_step_results),
            "graph_data": graph_data,
        }

    # ------------------------------------------------------------------
    # Public entry point — streaming (yields AgentEvent objects)
    # ------------------------------------------------------------------

    async def stream_run(
        self,
        question: str,
        mcp_server_url: str,
        available_tools: list[dict[str, Any]],
        kg_schema: dict[str, Any],
        conversation_history: list[dict[str, str]] | None = None,
        thread_id: str | None = None,
    ) -> AsyncGenerator[AgentEvent, None]:
        """Execute the workflow and yield typed events as each node completes.

        Event sequence (happy path):
            plan_generated → step_started (×N) → step_completed (×N) → done

        On failure: ``error`` event is yielded (non-raises).

        Yields
        ------
        AgentEvent
            One of: PlanGeneratedEvent, StepStartedEvent, StepCompletedEvent,
            DoneEvent, ErrorEvent.
        """
        initial_state = self._build_initial_state(
            question, mcp_server_url, available_tools, kg_schema, conversation_history
        )
        config = self._make_config(thread_id)
        sid = thread_id or ""

        # Accumulate step results so we can attach graph_data to DoneEvent
        accumulated_step_results: dict[str, Any] = {}

        try:
            async for chunk in self.graph.astream(initial_state, config=config):
                for node_name, update in chunk.items():
                    # Collect step results as they arrive
                    if node_name in ("execute_direct_tool", "execute_cypher"):
                        for k, v in update.get("step_results", {}).items():
                            accumulated_step_results[str(k)] = v

                    event = self._map_chunk_to_event(
                        node_name, update, sid, accumulated_step_results
                    )
                    if event is not None:
                        yield event
        except Exception as exc:  # noqa: BLE001
            logger.exception("stream_run error: %s", exc)
            yield ErrorEvent(
                session_id=sid,
                error_code="AGENT_ERROR",
                message=str(exc),
                recoverable=False,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_initial_state(
        self,
        question: str,
        mcp_server_url: str,
        available_tools: list[dict[str, Any]],
        kg_schema: dict[str, Any],
        conversation_history: list[dict[str, str]] | None,
    ) -> AgentState:
        return {
            "question": question,
            "mcp_server_url": mcp_server_url,
            "available_tools": available_tools,
            "kg_schema": kg_schema,
            "conversation_history": conversation_history or [],
            "execution_plan": None,
            "current_step": 0,
            "step_results": {},
            "execution_log": [],
            "final_answer": None,
            "error": None,
        }

    def _make_config(self, thread_id: str | None) -> dict:
        """Return a LangGraph config dict.  Requires thread_id when checkpointer is active."""
        if self._checkpointer is None:
            return {}
        return {"configurable": {"thread_id": thread_id or str(uuid4())}}

    def _map_chunk_to_event(
        self, node_name: str, update: dict[str, Any], session_id: str,
        accumulated_step_results: dict[str, Any] | None = None,
    ) -> AgentEvent | None:
        """Translate a LangGraph astream chunk into a typed AgentEvent."""

        if node_name == "planner":
            plan = update.get("execution_plan") or {}
            steps = plan.get("plan", [])
            return PlanGeneratedEvent(
                session_id=session_id,
                plan=plan,
                complexity=plan.get("complexity", "medium"),
                total_steps=len(steps),
            )

        if node_name == "executor_router":
            log = update.get("execution_log", [])
            if not log:
                return None
            entry = log[0]
            # Parse step number from agent label e.g. "Step 2"
            agent_label: str = entry.get("agent", "")
            try:
                step_num = int(agent_label.split()[-1])
            except (ValueError, IndexError):
                step_num = 0
            return StepStartedEvent(
                session_id=session_id,
                step_number=step_num,
                step_description=entry.get("message", ""),
            )

        if node_name in ("execute_direct_tool", "execute_cypher"):
            step_idx = update.get("current_step", 1) - 1  # current_step was incremented
            step_results: dict = update.get("step_results", {})
            result = step_results.get(step_idx + 1, step_results.get(step_idx, {}))
            return StepCompletedEvent(
                session_id=session_id,
                step_number=step_idx + 1,
                success=bool(result.get("success", True)),
                result=result,
            )

        if node_name == "summarizer":
            answer = update.get("final_answer", "")
            graph_data = extract_graph_data(accumulated_step_results or {})
            return DoneEvent(
                session_id=session_id,
                answer=answer,
                execution_log=update.get("execution_log", []),
                step_results=sanitize_step_results(accumulated_step_results or {}),
                graph_data=graph_data,
            )

        return None

    def _previous_results_context(self, state: AgentState) -> str:
        parts = [
            f"Step {k}: {str(v)[:400]}"
            for k, v in state.get("step_results", {}).items()
            if isinstance(v, dict) and v.get("success")
        ]
        return " | ".join(parts)
