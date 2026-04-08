"""Agent 3 — Summarizer.

Takes raw multi-step execution results and produces a clean, natural
language answer for the user.
"""

import json
import logging
from typing import Any

from app.llm.base import BaseLLM

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a Spring Batch data analyst summarizing multi-step query results.

Your job is to:
1. Combine results from multiple execution steps into a coherent answer.
2. Cite specific data points (job names, counts, durations, error messages).
3. Present information logically — use bullet points for lists.
4. Bold important job names or metrics using Markdown.
5. Connect information across steps naturally.
6. If a step failed, explain what was attempted.

Be helpful and concise — synthesise, don't just list step results."""


class SummarizerAgent:
    """Generates natural-language summaries from multi-step results."""

    def __init__(self, llm: BaseLLM) -> None:
        self.llm = llm

    def summarize(
        self,
        question: str,
        plan: dict[str, Any],
        step_results: dict[str, Any],
        conversation_history: list[dict[str, str]] | None = None,
    ) -> str:
        """Produce a Markdown-formatted answer.

        Args:
            question: The original user question.
            plan: The execution plan from the planner agent.
            step_results: Dict of step_number → result from execution.
            conversation_history: Optional recent conversation context.

        Returns:
            Markdown string for display in the chat UI.
        """
        messages: list[dict[str, str]] = [{"role": "system", "content": _SYSTEM_PROMPT}]

        if conversation_history:
            messages.extend(conversation_history[-4:])

        user_content = (
            f"Original Question: {question}\n\n"
            f"Execution Plan:\n{json.dumps(plan, indent=2, default=str)}\n\n"
            f"Step Results:\n{json.dumps(step_results, indent=2, default=str)}\n\n"
            "Please provide a comprehensive answer."
        )
        messages.append({"role": "user", "content": user_content})

        logger.info("SummarizerAgent generating answer")
        return self.llm.generate(messages, temperature=0.2)
