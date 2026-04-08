"""Shared pytest fixtures for BATCH-KG-FE backend tests."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.llm.base import BaseLLM
from app.mcp.client import MCPClient


class FakeLLM(BaseLLM):
    """Controllable LLM stub for unit tests."""

    def __init__(self, response: str = "ok", json_response: dict | None = None) -> None:
        self._response = response
        self._json_response = json_response or {}

    def generate(self, prompt: str, **kwargs) -> str:
        return self._response

    def generate_json(self, prompt: str, **kwargs) -> dict:
        return self._json_response


@pytest.fixture
def fake_llm():
    return FakeLLM(response="ok", json_response={"steps": []})


@pytest.fixture
def mock_mcp_client(mocker):
    client = MagicMock(spec=MCPClient)
    client.list_tools = AsyncMock(return_value=[])
    client.get_schema = AsyncMock(return_value={})
    client.call_tool = AsyncMock(return_value={"result": "mocked"})
    return client
