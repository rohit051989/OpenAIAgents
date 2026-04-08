"""Cypher query safety validation.

Only read-only Cypher is permitted through the MCP ``execute_cypher_query``
tool.  This module validates a query string before it reaches Neo4j.

Design:
- An allowlist of safe starting keywords.
- A blocklist of write / admin keywords that must not appear anywhere.
"""

# Keywords that indicate mutating or administrative Cypher operations.
_FORBIDDEN_KEYWORDS: frozenset[str] = frozenset([
    "CREATE",
    "MERGE",
    "SET",
    "DELETE",
    "REMOVE",
    "FOREACH",
    "LOAD CSV",
    "DROP",
    "CALL DBMS",
    "CALL APOC.",
    "CALL DB.CREATE",
    ";",
])

# A safe query must start with one of these tokens.
_ALLOWED_STARTS: tuple[str, ...] = ("MATCH", "CALL", "RETURN", "WITH", "UNWIND")


def is_read_only_cypher(query: str) -> bool:
    """Return ``True`` only if *query* is a safe, read-only Cypher statement.

    Args:
        query: The raw Cypher query string submitted by the caller.

    Returns:
        ``True`` when the query starts with an allowed keyword **and** contains
        none of the forbidden mutation/admin keywords.
    """
    normalised = query.upper().strip()
    starts_with_safe_keyword = normalised.startswith(_ALLOWED_STARTS)
    contains_forbidden = any(kw in normalised for kw in _FORBIDDEN_KEYWORDS)
    return starts_with_safe_keyword and not contains_forbidden
