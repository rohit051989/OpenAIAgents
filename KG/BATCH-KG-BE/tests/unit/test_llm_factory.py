"""Unit tests for LLMFactory."""
from __future__ import annotations

import pytest
from unittest.mock import patch

from app.llm.factory import LLMFactory, get_available_providers
from app.llm.providers.openai_provider import OpenAILLM, AzureOpenAILLM
from app.llm.providers.bedrock_provider import BedrockLLM
from config.settings import Settings


def _make_settings(**overrides):
    """Return a Settings instance with safe defaults plus any overrides."""
    defaults = dict(
        openai_api_key=None,
        openai_model="gpt-4o",
        azure_openai_api_key=None,
        azure_openai_endpoint=None,
        azure_openai_deployment=None,
        azure_openai_api_version="2024-08-01-preview",
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_region="us-east-1",
        bedrock_model_id="anthropic.claude-3-5-sonnet-20241022-v2:0",
        google_api_key=None,
        gemini_model="gemini-1.5-flash",
        llm_provider="openai",
        mcp_server_url="http://localhost:8100/mcp/sse",
    )
    defaults.update(overrides)
    return Settings.model_construct(**defaults)


class TestLLMFactory:
    def test_create_openai(self):
        mock_settings = _make_settings(openai_api_key="test-key")
        with patch("app.llm.factory.get_settings", return_value=mock_settings):
            llm = LLMFactory.create_llm("openai")
        assert isinstance(llm, OpenAILLM)

    def test_create_azure_openai(self):
        mock_settings = _make_settings(
            azure_openai_api_key="key",
            azure_openai_endpoint="https://test.openai.azure.com",
            azure_openai_deployment="gpt-4",
        )
        with patch("app.llm.factory.get_settings", return_value=mock_settings):
            llm = LLMFactory.create_llm("azure_openai")
        assert isinstance(llm, AzureOpenAILLM)

    def test_create_openai_missing_key_raises(self):
        mock_settings = _make_settings(openai_api_key=None)
        with patch("app.llm.factory.get_settings", return_value=mock_settings):
            with pytest.raises(ValueError, match="OPENAI_API_KEY"):
                LLMFactory.create_llm("openai")

    def test_unsupported_provider_raises(self):
        mock_settings = _make_settings()
        with patch("app.llm.factory.get_settings", return_value=mock_settings):
            with pytest.raises(ValueError, match="Unknown LLM provider"):
                LLMFactory.create_llm("nonexistent_provider")

    def test_get_available_providers_empty(self):
        # aws_bedrock is always available (uses boto3 credential chain)
        mock_settings = _make_settings()
        with patch("app.llm.factory.get_settings", return_value=mock_settings):
            providers = get_available_providers()
        assert "aws_bedrock" in providers

    def test_get_available_providers_no_openai_without_key(self):
        mock_settings = _make_settings(openai_api_key=None)
        with patch("app.llm.factory.get_settings", return_value=mock_settings):
            providers = get_available_providers()
        assert "openai" not in providers

    def test_get_available_providers_openai(self):
        mock_settings = _make_settings(openai_api_key="sk-test")
        with patch("app.llm.factory.get_settings", return_value=mock_settings):
            providers = get_available_providers()
        assert "openai" in providers

    def test_provider_defaults_to_settings_llm_provider(self):
        mock_settings = _make_settings(llm_provider="openai", openai_api_key="sk-test")
        with patch("app.llm.factory.get_settings", return_value=mock_settings):
            llm = LLMFactory.create_llm()  # no explicit provider
        assert isinstance(llm, OpenAILLM)

