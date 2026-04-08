"""Agent 2 — Tool Executor.

Uses the LLM to intelligently generate tool arguments from the plan step
and user context, then executes the tool via MCPClient.
"""

import json
import logging
from typing import Any

from app.llm.base import BaseLLM
from app.mcp.client import MCPClient

logger = logging.getLogger(__name__)


class ToolExecutorAgent:
    """Executes MCP tool calls based on plan step + LLM-generated arguments."""

    def __init__(self, mcp_client: MCPClient, llm: BaseLLM) -> None:
        self.mcp_client = mcp_client
        self.llm = llm

    async def generate_tool_arguments(
        self,
        tool_name: str,
        tool_description: str,
        input_schema: dict[str, Any],
        question: str,
        previous_results: str,
    ) -> dict[str, Any]:
        """Use the LLM to infer the right arguments for a tool call.

        Args:
            tool_name: Name of the MCP tool.
            tool_description: Tool's description text.
            input_schema: Tool's JSON input schema.
            question: The user's original question.
            previous_results: Serialised prior step results for context.

        Returns:
            Dict of arguments to pass to the tool.
        """
        prompt = f"""Generate arguments for this MCP tool call.

Tool Name: {tool_name}
Description: {tool_description}
Input Schema: {json.dumps(input_schema)}
User Question: {question}
Previous Results: {previous_results[:1000]}

Return a JSON object with the arguments to pass to the tool.
If multiple calls are needed, return an array of argument objects.
Respond with valid JSON only."""

        messages = [
            {"role": "system", "content": "You generate MCP tool call arguments as JSON. Respond with valid JSON only."},
            {"role": "user", "content": prompt},
        ]
        result = self.llm.generate_json(messages, temperature=0.1)
        logger.info("Generated arguments for %s: %s", tool_name, str(result)[:200])
        return result

    async def execute_tool(
        self,
        tool_name: str,
        tool_description: str,
        input_schema: dict[str, Any],
        question: str,
        previous_results: str,
    ) -> dict[str, Any]:
        """Generate arguments then execute the MCP tool.

        Returns:
            Dict with ``success``, ``result`` (or ``error``), and
            ``tool_name`` keys.
        """
        try:
            args = await self.generate_tool_arguments(
                tool_name, tool_description, input_schema, question, previous_results
            )
            # If LLM returned a list, execute all calls and merge
            if isinstance(args, list):
                results = []
                for arg_set in args:
                    r = await self.mcp_client.call_tool(tool_name, arg_set)
                    results.append(r)
                return {"success": True, "result": results, "tool_name": tool_name}

            result = await self.mcp_client.call_tool(tool_name, args)
            return {"success": True, "result": result, "tool_name": tool_name}

        except Exception as exc:  # noqa: BLE001
            logger.exception("Tool execution failed for %s", tool_name)
            return {"success": False, "error": str(exc), "tool_name": tool_name}

    async def execute_cypher(
        self, cypher_query: str, parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Execute a Cypher query through the MCP execute_cypher_query tool.

        Returns:
            Raw result dict from the MCP tool.
        """
        args: dict[str, Any] = {"cypher_query": cypher_query}
        if parameters:
            args["parameters"] = parameters
        return await self.mcp_client.call_tool("execute_cypher_query", args)
