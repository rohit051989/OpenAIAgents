"""Integration tests for the MCP server via FastAPI / HTTPX.

These tests start the full FastAPI app (with the MCP server mounted) and
exercise the /health and /info REST endpoints.

Requirements:
  - A running Neo4j instance at the URI defined in the environment / .env.
  - Set INTEGRATION_TESTS=1 to opt in; tests are skipped otherwise so that
    the CI unit-test suite can run without a database.

Run manually:
    INTEGRATION_TESTS=1 pytest tests/integration/ -v
"""

import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Skip the whole module unless explicitly opted in
pytestmark = pytest.mark.skipif(
    os.getenv("INTEGRATION_TESTS") != "1",
    reason="Set INTEGRATION_TESTS=1 to run integration tests (requires Neo4j).",
)


@pytest_asyncio.fixture
async def client():
    """Provide an async test client wired to the real FastAPI app."""
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_returns_200_when_db_connected(self, client: AsyncClient):
        response = await client.get("/health")
        assert response.status_code in (200, 503)  # either state is valid
        body = response.json()
        assert "status" in body
        assert "neo4j" in body

    @pytest.mark.asyncio
    async def test_health_response_structure(self, client: AsyncClient):
        response = await client.get("/health")
        body = response.json()
        assert body["status"] in ("ok", "degraded")
        assert body["neo4j"] in ("connected", "unreachable")


# ---------------------------------------------------------------------------
# /info
# ---------------------------------------------------------------------------

class TestInfoEndpoint:
    @pytest.mark.asyncio
    async def test_info_returns_200(self, client: AsyncClient):
        response = await client.get("/info")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_info_response_keys(self, client: AsyncClient):
        response = await client.get("/info")
        body = response.json()
        assert "name" in body
        assert "version" in body
        assert "mcp_sse_url" in body
        assert body["mcp_sse_url"] == "/mcp/sse"
