"""Integration tests for the /api/v1/chat endpoint.

Prerequisites
-------------
- Backend API must be running at http://localhost:8001
- MCP server must be running at the configured MCP_SERVER_URL
- AWS credentials must be configured for Bedrock (or the relevant LLM provider)
- Run with: pytest tests/integration/test_chat_api.py -v

These tests are skipped automatically when the backend API is unreachable.
"""
from __future__ import annotations

import pytest
import httpx


API_BASE = "http://localhost:8001"


def _api_reachable() -> bool:
    try:
        response = httpx.get(f"{API_BASE}/api/v1/health", timeout=3)
        return response.status_code < 500
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(
    not _api_reachable(),
    reason=f"Backend API not reachable at {API_BASE}",
)


@pytest.fixture
def client():
    with httpx.Client(base_url=API_BASE, timeout=120) as c:
        yield c


class TestChatEndpoint:
    def test_missing_question_returns_422(self, client: httpx.Client):
        response = client.post("/api/v1/chat", json={"history": []})
        assert response.status_code == 422

    def test_no_mcp_url_uses_default(self, client: httpx.Client):
        """Frontend should not need to send mcp_url — backend uses its default."""
        payload = {
            "question": "List all available job names",
            "history": [],
        }
        response = client.post("/api/v1/chat", json=payload)
        # Should not get a 422 validation error for missing mcp_url
        assert response.status_code != 422

    def test_no_llm_provider_uses_default(self, client: httpx.Client):
        """Frontend should not need to send llm_provider — backend uses its default."""
        payload = {
            "question": "List all available job names",
            "history": [],
        }
        response = client.post("/api/v1/chat", json=payload)
        # Should not get a 400 LLM configuration error
        assert response.status_code != 400

    def test_invalid_session_id_returns_404(self, client: httpx.Client):
        payload = {
            "question": "List all available job names",
            "history": [],
            "session_id": "nonexistent-session-id-xyz",
        }
        response = client.post("/api/v1/chat", json=payload)
        assert response.status_code == 404
        assert "Session not found" in response.json()["detail"]

    def test_successful_chat_response_shape(self, client: httpx.Client):
        payload = {
            "question": "What job groups are available?",
            "history": [],
        }
        response = client.post("/api/v1/chat", json=payload)
        assert response.status_code == 200
        body = response.json()
        assert "answer" in body
        assert isinstance(body["answer"], str)
        assert len(body["answer"]) > 0
        assert "execution_log" in body
        assert isinstance(body["execution_log"], list)
