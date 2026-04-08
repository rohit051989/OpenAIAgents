"""Agent 1 — Planner.

Analyzes the user's question and produces a typed, multi-step execution
plan that the orchestrator will follow.
"""

import json
import logging
from typing import Any

from app.llm.base import BaseLLM

logger = logging.getLogger(__name__)

_SYSTEM_TEMPLATE = """\
You are a planning agent for a Spring Batch Knowledge Graph query system.

Your job is to analyze user questions and create EXECUTION PLANS with multiple steps.

AVAILABLE TOOLS:
{tools_list}

KNOWLEDGE GRAPH SCHEMA SUMMARY:
{schema_summary}

PLANNING GUIDELINES:
1. SINGLE DIRECT TOOL   — one tool answers the question completely.
2. MULTIPLE DIRECT TOOLS — question needs data from several tools.
3. SINGLE CYPHER QUERY  — custom query not covered by tools (set requires_schema_analysis: true).
4. MULTIPLE CYPHER QUERIES — chain queries with depends_on.
5. MIXED APPROACH       — combine direct tools with custom Cypher.

RESPOND IN JSON FORMAT:
{{
    "plan": [
        {{
            "step": 1,
            "action": "brief description",
            "type": "direct_tool" | "cypher_query",
            "tool": "tool_name_if_direct",
            "depends_on": [],
            "requires_schema_analysis": false
        }}
    ],
    "strategy": "single_tool|multi_tool|cypher|mixed",
    "complexity": "simple|medium|complex",
    "reasoning": "why this plan was chosen"
}}
"""


class PlannerAgent:
    """Creates multi-step execution plans from a user question + tool list."""

    def __init__(self, llm: BaseLLM) -> None:
        self.llm = llm

    def create_plan(
        self,
        question: str,
        available_tools: list[dict[str, Any]],
        kg_schema: dict[str, Any],
    ) -> dict[str, Any]:
        """Produce an execution plan.

        Args:
            question: The user's question.
            available_tools: List of tool metadata dicts.
            kg_schema: Knowledge Graph schema dict.

        Returns:
            Plan dict with ``plan``, ``strategy``, ``complexity``, ``reasoning``.
        """
        tools_list = "\n".join(
            f"- {t['name']}: {t.get('description', '')}" for t in available_tools
        )
        system_prompt = _SYSTEM_TEMPLATE.format(
            tools_list=tools_list,
            schema_summary=json.dumps(kg_schema, default=str)[:3000],
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nCreate an execution plan."},
        ]
        logger.info("PlannerAgent creating plan for question: %s", question[:120])
        result = self.llm.generate_json(messages, temperature=0.1)
        logger.info("Plan created: strategy=%s steps=%d", result.get("strategy"), len(result.get("plan", [])))
        return result
