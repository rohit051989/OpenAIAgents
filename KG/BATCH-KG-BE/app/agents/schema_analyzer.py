"""Agent 4 — Schema Analyzer.

Given the KG schema and a user question, identifies which nodes,
relationships, and properties are relevant for Cypher generation.
"""

import json
import logging
from typing import Any

from app.llm.base import BaseLLM

logger = logging.getLogger(__name__)

_SYSTEM_TEMPLATE = """\
You are a Knowledge Graph schema analyst for Spring Batch data.

KNOWLEDGE GRAPH SCHEMA:
{schema_json}

Analyze the user's question and identify:
1. Which NODE LABELS are needed.
2. Which RELATIONSHIP TYPES are needed.
3. Which PROPERTIES might be relevant.
4. What GRAPH PATTERN would answer the question.

CRITICAL RULES:
- ONLY use node labels, relationships, and patterns that EXIST in the schema.
- Check relationship_patterns for valid traversal paths.
- If the query cannot be answered by the schema, set schema_supports_query: false.

RESPOND IN JSON FORMAT:
{{
    "relevant_nodes": ["NodeLabel1"],
    "relevant_relationships": ["REL_TYPE1"],
    "relevant_properties": ["property1"],
    "query_pattern": "description of graph pattern needed",
    "reasoning": "why these components were chosen",
    "schema_supports_query": true,
    "alternative_suggestion": "only if schema_supports_query is false"
}}"""


class SchemaAnalyzerAgent:
    """Identifies relevant KG schema components for a given question."""

    def __init__(self, llm: BaseLLM) -> None:
        self.llm = llm

    def analyze(
        self,
        question: str,
        kg_schema: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze which schema components are needed to answer *question*.

        Args:
            question: The user's question (or the plan step's description).
            kg_schema: The full KG schema dict from MCPClient.get_schema().

        Returns:
            Analysis dict including ``relevant_nodes``, ``relevant_relationships``,
            ``query_pattern``, ``schema_supports_query``, and the schema itself
            for downstream use by CypherGeneratorAgent.
        """
        system_prompt = _SYSTEM_TEMPLATE.format(
            schema_json=json.dumps(kg_schema, default=str)[:4000]
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nWhat schema components are needed?"},
        ]
        logger.info("SchemaAnalyzerAgent analyzing for: %s", question[:120])
        result = self.llm.generate_json(messages, temperature=0.1)
        result["schema"] = kg_schema  # Pass schema through to cypher generator
        return result
