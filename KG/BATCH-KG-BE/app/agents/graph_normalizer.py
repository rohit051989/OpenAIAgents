"""Graph normalizer — converts heterogeneous MCP tool results into GraphData,
and strips raw graph bulk from step_results to avoid redundant data in the API
response.

Different MCP tools return graph-like data in different shapes:

  * ``get_job_dependency_chain``  →  ``{groups: [{graphlet: {nodes, links}, flowSummary}]}}``
  * ``get_job_step_flow``         →  ``{graphlet: {nodes, links}, flowSummary}``
  * ``get_entity_graph`` (new)    →  ``{nodes, relationships}``
  * other tools                   →  no graph data (pass through unchanged)

Public API
----------
``extract_graph_data(step_results)``  — returns normalised GraphData dict or None.
``sanitize_step_results(step_results)`` — returns a copy with raw graph bulk stripped;
    keeps only human-readable summary fields so the API response is clean.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _node_from_graphlet_node(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert a dependency-service graphlet node to GraphNode dict."""
    node_id = str(raw.get("id", ""))
    labels = raw.get("labels", [])
    props = {k: v for k, v in raw.items() if k not in ("id", "labels")}
    return {"id": node_id, "labels": labels, "properties": props}


def _rel_from_graphlet_link(raw: dict[str, Any], idx: int) -> dict[str, Any]:
    """Convert a dependency-service graphlet link (d3-style) to GraphRelationship dict."""
    return {
        "id": str(raw.get("id", f"rel-{idx}")),
        "type": str(raw.get("on", raw.get("type", "PRECEDES"))),
        "startNodeId": str(raw.get("source", raw.get("startNodeId", ""))),
        "endNodeId": str(raw.get("target", raw.get("endNodeId", ""))),
        "properties": {k: v for k, v in raw.items() if k not in ("id", "source", "target", "startNodeId", "endNodeId", "type", "on")},
    }


def _from_graphlet(graphlet: dict[str, Any]) -> tuple[list, list] | None:
    """Extract nodes + relationships from a ``{nodes, links}`` graphlet dict."""
    raw_nodes = graphlet.get("nodes", [])
    raw_links = graphlet.get("links", [])
    if not raw_nodes:
        return None
    nodes = [_node_from_graphlet_node(n) for n in raw_nodes if isinstance(n, dict)]
    rels = [_rel_from_graphlet_link(r, i) for i, r in enumerate(raw_links) if isinstance(r, dict)]
    return nodes, rels


def _merge(
    all_nodes: list[dict],
    all_rels: list[dict],
    new_nodes: list[dict],
    new_rels: list[dict],
) -> None:
    """Merge new_nodes / new_rels into accumulators, deduplicating by id."""
    seen_nodes = {n["id"] for n in all_nodes}
    seen_rels = {r["id"] for r in all_rels}
    for n in new_nodes:
        if n["id"] and n["id"] not in seen_nodes:
            all_nodes.append(n)
            seen_nodes.add(n["id"])
    for r in new_rels:
        if r["id"] not in seen_rels:
            all_rels.append(r)
            seen_rels.add(r["id"])


def _strip_graph_bulk(result: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a tool result dict with all raw graph bulk removed.

    Keeps human-readable summary fields; removes anything that is now
    represented in the dedicated ``graph_data`` response field.

    Rules:
      - Remove top-level ``graphlet`` key
      - Remove ``graphlet`` from each item in ``groups``; keep ``flowSummary``
      - Remove top-level ``nodes``/``relationships`` when they are the raw
        GraphData payload (i.e. list of dicts with ``id`` + ``labels``)
    """
    cleaned: dict[str, Any] = {}
    for key, value in result.items():
        # Remove raw graphlet blob
        if key == "graphlet":
            continue
        # Remove raw nodes/relationships from get_entity_graph tool output
        if key in ("nodes", "relationships") and isinstance(value, list):
            continue
        # Strip graphlet from each group in get_job_dependency_chain output,
        # keep only flowSummary and any non-graph metadata
        if key == "groups" and isinstance(value, list):
            cleaned["groups"] = [
                {k: v for k, v in group.items() if k != "graphlet"}
                for group in value
                if isinstance(group, dict)
            ]
            continue
        cleaned[key] = value
    return cleaned


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_graph_data(step_results: dict[str, Any]) -> dict[str, Any] | None:
    """Scan step_results for graph-renderable data and return a normalised
    ``GraphData``-compatible dict, or ``None`` if nothing graph-like is found.

    Each step value has the shape produced by ``ToolExecutorAgent.execute_tool``:
    ``{"success": bool, "tool_name": str, "result": <tool_output>}``
    """
    all_nodes: list[dict] = []
    all_rels: list[dict] = []

    for step_value in step_results.values():
        if not isinstance(step_value, dict):
            continue

        # Unwrap ToolExecutorAgent envelope
        if "result" in step_value and isinstance(step_value["result"], dict):
            candidates = [step_value["result"]]
        elif "result" in step_value and isinstance(step_value["result"], list):
            candidates = [r for r in step_value["result"] if isinstance(r, dict)]
        else:
            candidates = [step_value]

        for result in candidates:
            # Format 1: get_entity_graph / expand_node
            if "nodes" in result and "relationships" in result:
                nodes = [
                    {"id": str(n.get("id", "")), "labels": n.get("labels", []), "properties": n.get("properties", {})}
                    for n in result["nodes"] if isinstance(n, dict)
                ]
                rels = [
                    {
                        "id": str(r.get("id", "")),
                        "type": str(r.get("type", "")),
                        "startNodeId": str(r.get("startNodeId", "")),
                        "endNodeId": str(r.get("endNodeId", "")),
                        "properties": r.get("properties", {}),
                    }
                    for r in result["relationships"] if isinstance(r, dict)
                ]
                _merge(all_nodes, all_rels, nodes, rels)
                continue

            # Format 2: get_job_step_flow
            if "graphlet" in result:
                parsed = _from_graphlet(result["graphlet"])
                if parsed:
                    _merge(all_nodes, all_rels, *parsed)
                continue

            # Format 3: get_job_dependency_chain
            if "groups" in result:
                for group in result["groups"]:
                    if isinstance(group, dict) and "graphlet" in group:
                        parsed = _from_graphlet(group["graphlet"])
                        if parsed:
                            _merge(all_nodes, all_rels, *parsed)
                continue

    if not all_nodes:
        return None

    logger.debug("extract_graph_data → %d nodes, %d relationships", len(all_nodes), len(all_rels))
    return {"nodes": all_nodes, "relationships": all_rels}


def sanitize_step_results(step_results: dict[str, Any]) -> dict[str, Any]:
    """Return a cleaned copy of step_results with raw graph bulk removed.

    Since graph data is now surfaced in ``graph_data``, the raw ``graphlet``,
    ``nodes``, ``relationships``, and ``links`` blobs are stripped from
    ``step_results`` to keep the API response lean and non-redundant.

    The ``result`` envelope from ToolExecutorAgent is also unwrapped so the
    response presents clean tool output directly.
    """
    sanitized: dict[str, Any] = {}

    for step_key, step_value in step_results.items():
        if not isinstance(step_value, dict):
            sanitized[step_key] = step_value
            continue

        # Unwrap ToolExecutorAgent envelope: {"success", "tool_name", "result"}
        tool_name = step_value.get("tool_name", "")
        success = step_value.get("success", True)
        raw_result = step_value.get("result", step_value)

        if isinstance(raw_result, dict):
            clean_result = _strip_graph_bulk(raw_result)
        elif isinstance(raw_result, list):
            clean_result = [
                _strip_graph_bulk(r) if isinstance(r, dict) else r
                for r in raw_result
            ]
        else:
            clean_result = raw_result

        sanitized[step_key] = {
            "tool_name": tool_name,
            "success": success,
            "result": clean_result,
        }

    return sanitized



# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _node_from_graphlet_node(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert a dependency-service graphlet node to GraphNode dict."""
    node_id = str(raw.get("id", ""))
    labels = raw.get("labels", [])
    # Everything except id and labels becomes properties
    props = {k: v for k, v in raw.items() if k not in ("id", "labels")}
    return {"id": node_id, "labels": labels, "properties": props}


def _rel_from_graphlet_link(raw: dict[str, Any], idx: int) -> dict[str, Any]:
    """Convert a dependency-service graphlet link (d3-style) to GraphRelationship dict."""
    return {
        "id": str(raw.get("id", f"rel-{idx}")),
        "type": str(raw.get("on", raw.get("type", "PRECEDES"))),
        "startNodeId": str(raw.get("source", raw.get("startNodeId", ""))),
        "endNodeId": str(raw.get("target", raw.get("endNodeId", ""))),
        "properties": {k: v for k, v in raw.items() if k not in ("id", "source", "target", "startNodeId", "endNodeId", "type", "on")},
    }


def _from_graphlet(graphlet: dict[str, Any]) -> tuple[list, list] | None:
    """Extract nodes + relationships from a ``{nodes, links}`` graphlet dict."""
    raw_nodes = graphlet.get("nodes", [])
    raw_links = graphlet.get("links", [])
    if not raw_nodes:
        return None
    nodes = [_node_from_graphlet_node(n) for n in raw_nodes if isinstance(n, dict)]
    rels = [_rel_from_graphlet_link(r, i) for i, r in enumerate(raw_links) if isinstance(r, dict)]
    return nodes, rels


def _merge(
    all_nodes: list[dict],
    all_rels: list[dict],
    new_nodes: list[dict],
    new_rels: list[dict],
) -> None:
    """Merge new_nodes / new_rels into accumulators, deduplicating by id."""
    seen_nodes = {n["id"] for n in all_nodes}
    seen_rels = {r["id"] for r in all_rels}
    for n in new_nodes:
        if n["id"] and n["id"] not in seen_nodes:
            all_nodes.append(n)
            seen_nodes.add(n["id"])
    for r in new_rels:
        if r["id"] not in seen_rels:
            all_rels.append(r)
            seen_rels.add(r["id"])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_graph_data(step_results: dict[str, Any]) -> dict[str, Any] | None:
    """Scan step_results for graph-renderable data and return a normalised
    ``GraphData``-compatible dict, or ``None`` if nothing graph-like is found.

    Args:
        step_results: The ``step_results`` dict from the orchestrator, keyed
            by string step numbers.  Each value has the shape produced by
            ``ToolExecutorAgent.execute_tool``:
            ``{"success": bool, "tool_name": str, "result": <tool_output>}``

    Returns:
        ``{"nodes": [...], "relationships": [...]}`` or ``None``.
    """
    all_nodes: list[dict] = []
    all_rels: list[dict] = []

    for step_value in step_results.values():
        if not isinstance(step_value, dict):
            continue

        # ToolExecutorAgent wraps raw MCP output in {"success", "result", "tool_name"}
        # Unwrap it; fall back to scanning the value itself for direct GraphData
        if "result" in step_value and isinstance(step_value["result"], dict):
            candidates = [step_value["result"]]
        elif "result" in step_value and isinstance(step_value["result"], list):
            # Multiple calls merged as a list
            candidates = [r for r in step_value["result"] if isinstance(r, dict)]
        else:
            candidates = [step_value]

        for result in candidates:
            # ── Format 1: new get_entity_graph / expand_node tools ──────────
            # {nodes: [{id, labels, properties}], relationships: [{id, type, startNodeId, endNodeId}]}
            if "nodes" in result and "relationships" in result:
                raw_nodes = result["nodes"]
                raw_rels = result["relationships"]
                nodes = [
                    {"id": str(n.get("id", "")), "labels": n.get("labels", []), "properties": n.get("properties", {})}
                    for n in raw_nodes if isinstance(n, dict)
                ]
                rels = [
                    {
                        "id": str(r.get("id", "")),
                        "type": str(r.get("type", "")),
                        "startNodeId": str(r.get("startNodeId", "")),
                        "endNodeId": str(r.get("endNodeId", "")),
                        "properties": r.get("properties", {}),
                    }
                    for r in raw_rels if isinstance(r, dict)
                ]
                _merge(all_nodes, all_rels, nodes, rels)
                continue

            # ── Format 2: get_job_step_flow ─────────────────────────────────
            # {graphlet: {nodes, links}, flowSummary: {}}
            if "graphlet" in result:
                parsed = _from_graphlet(result["graphlet"])
                if parsed:
                    _merge(all_nodes, all_rels, *parsed)
                continue

            # ── Format 3: get_job_dependency_chain ──────────────────────────
            # {jobName, groupCount, groups: [{graphlet: {nodes, links}, flowSummary}]}
            if "groups" in result:
                for group in result["groups"]:
                    if isinstance(group, dict) and "graphlet" in group:
                        parsed = _from_graphlet(group["graphlet"])
                        if parsed:
                            _merge(all_nodes, all_rels, *parsed)
                continue

    if not all_nodes:
        return None

    logger.debug("extract_graph_data → %d nodes, %d relationships", len(all_nodes), len(all_rels))
    return {"nodes": all_nodes, "relationships": all_rels}
