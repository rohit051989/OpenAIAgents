"""Agent 5 — Cypher Generator.

Uses schema analysis from Agent 4 to generate valid, safe Cypher queries.
"""

import json
import logging
from typing import Any

from app.llm.base import BaseLLM

logger = logging.getLogger(__name__)

_SYSTEM_TEMPLATE = """\
You are a Cypher query generator for a Spring Batch Knowledge Graph (Neo4j).

SCHEMA ANALYSIS:
{analysis_json}

RULES:
- ONLY use nodes, relationships, and properties listed in the schema analysis.
- Always use MATCH (never CREATE/MERGE/SET/DELETE).
- Use parameters ($param) for user-supplied values.
- Keep queries efficient — avoid cartesian products.
- LIMIT results to at most 100 unless the question asks for everything.

RESPOND IN JSON FORMAT:
{{
    "cypher_query": "MATCH ...",
    "parameters": {{}},
    "explanation": "what this query does"
}}"""


class CypherGeneratorAgent:
    """Generates Cypher queries from schema analysis output."""

    def __init__(self, llm: BaseLLM) -> None:
        self.llm = llm

    def generate(
        self,
        question: str,
        schema_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate a Cypher query for *question* using *schema_analysis*.

        Args:
            question: The user's question or plan step description.
            schema_analysis: Output from SchemaAnalyzerAgent.analyze().

        Returns:
            Dict with ``cypher_query``, ``parameters``, ``explanation``.
            Returns ``{"cypher_query": None, "error": "..."}`` if schema
            doesn't support the query.
        """
        if not schema_analysis.get("schema_supports_query", True):
            return {
                "cypher_query": None,
                "parameters": {},
                "explanation": schema_analysis.get("alternative_suggestion", "Query not supported by schema"),
                "error": "Schema does not support this query",
            }

        analysis_for_prompt = {
            k: v for k, v in schema_analysis.items() if k != "schema"
        }
        system_prompt = _SYSTEM_TEMPLATE.format(
            analysis_json=json.dumps(analysis_for_prompt, indent=2)
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Generate a Cypher query to answer: {question}"},
        ]
        logger.info("CypherGeneratorAgent generating for: %s", question[:120])
        return self.llm.generate_json(messages, temperature=0.1)
