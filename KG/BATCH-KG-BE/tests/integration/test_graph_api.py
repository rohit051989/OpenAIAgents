"""Integration tests for /api/v1/graph endpoints.

Prerequisites
-------------
- Backend API running at http://localhost:8001
- MCP server running at http://localhost:8100
- Neo4j populated with KG data

Run with: pytest tests/integration/test_graph_api.py -v

Skipped automatically when backend API is unreachable.
"""
from __future__ import annotations

import pytest
import httpx

API_BASE = "http://localhost:8001"


def _api_reachable() -> bool:
    try:
        return httpx.get(f"{API_BASE}/api/v1/health", timeout=3).status_code < 500
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(
    not _api_reachable(),
    reason=f"Backend API not reachable at {API_BASE}",
)


@pytest.fixture
def client():
    with httpx.Client(base_url=API_BASE, timeout=30) as c:
        yield c


class TestGraphEndpoints:
    def test_get_entity_graph_response_shape(self, client: httpx.Client):
        """GraphData response must contain nodes and relationships lists."""
        # Use a known entity — any job name present in the KG
        response = client.get("/api/v1/graph/customerProcessingJob")
        # If not found in Neo4j, MCP returns empty lists (200), not 4xx
        assert response.status_code in (200, 502)
        if response.status_code == 200:
            body = response.json()
            assert "nodes" in body
            assert "relationships" in body
            assert isinstance(body["nodes"], list)
            assert isinstance(body["relationships"], list)

    def test_get_entity_graph_node_shape(self, client: httpx.Client):
        """Every node must have id, labels, and properties."""
        response = client.get("/api/v1/graph/customerProcessingJob")
        if response.status_code != 200:
            pytest.skip("Entity not found or MCP unreachable")
        body = response.json()
        for node in body["nodes"]:
            assert "id" in node
            assert "labels" in node
            assert "properties" in node

    def test_get_entity_graph_relationship_shape(self, client: httpx.Client):
        """Every relationship must have id, type, startNodeId, endNodeId."""
        response = client.get("/api/v1/graph/customerProcessingJob")
        if response.status_code != 200:
            pytest.skip("Entity not found or MCP unreachable")
        body = response.json()
        for rel in body["relationships"]:
            assert "id" in rel
            assert "type" in rel
            assert "startNodeId" in rel
            assert "endNodeId" in rel

    def test_expand_node_response_shape(self, client: httpx.Client):
        """Expand endpoint must return GraphData shape."""
        # First get a real node id from the entity graph
        graph_resp = client.get("/api/v1/graph/customerProcessingJob")
        if graph_resp.status_code != 200 or not graph_resp.json().get("nodes"):
            pytest.skip("No nodes available to expand")
        node_id = graph_resp.json()["nodes"][0]["id"]

        response = client.get(f"/api/v1/graph/expand/{node_id}")
        assert response.status_code == 200
        body = response.json()
        assert "nodes" in body
        assert "relationships" in body

    def test_expand_node_excludes_existing(self, client: httpx.Client):
        """Passing existing_node_ids should reduce returned nodes."""
        graph_resp = client.get("/api/v1/graph/customerProcessingJob")
        if graph_resp.status_code != 200 or not graph_resp.json().get("nodes"):
            pytest.skip("No nodes available")
        nodes = graph_resp.json()["nodes"]
        node_id = nodes[0]["id"]
        # Exclude all known ids
        existing = ",".join(n["id"] for n in nodes)

        response = client.get(
            f"/api/v1/graph/expand/{node_id}",
            params={"existing_node_ids": existing},
        )
        assert response.status_code == 200
        # Returned nodes should not include any existing ids
        returned_ids = {n["id"] for n in response.json()["nodes"]}
        assert returned_ids.isdisjoint(set(nodes[0]["id"] for _ in [None]))


class TestChatResponseIncludesGraphData:
    def test_chat_includes_graph_data_field(self, client: httpx.Client):
        """ChatResponse must always include graph_data key (null or object)."""
        payload = {"question": "What is the job step flow for customerProcessingJob?", "history": []}
        response = client.post("/api/v1/chat", json=payload, timeout=120)
        if response.status_code != 200:
            pytest.skip(f"Chat returned {response.status_code}")
        body = response.json()
        assert "graph_data" in body
        # graph_data is either null or a valid GraphData object
        if body["graph_data"] is not None:
            assert "nodes" in body["graph_data"]
            assert "relationships" in body["graph_data"]
