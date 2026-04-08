"""LLM Factory — creates the right provider from settings/env."""

import logging

from app.llm.base import BaseLLM
from config.settings import get_settings

logger = logging.getLogger(__name__)


def get_available_providers() -> list[str]:
    """Return provider names for which all required credentials are configured."""
    s = get_settings()
    available = []
    if s.openai_api_key:
        available.append("openai")
    if s.azure_openai_api_key and s.azure_openai_endpoint and s.azure_openai_deployment:
        available.append("azure_openai")
    # aws_bedrock is available when explicit keys are set OR when aws configure
    # has been run (boto3 credential chain: env vars → ~/.aws/credentials → IAM role)
    available.append("aws_bedrock")
    if s.google_api_key:
        available.append("google_gemini")
    return available


class LLMFactory:
    """Creates a ``BaseLLM`` instance from application settings."""

    @staticmethod
    def get_available_providers() -> list[str]:
        return get_available_providers()

    @staticmethod
    def create_llm(provider: str | None = None) -> BaseLLM:
        """Instantiate and return the LLM for *provider*.

        Falls back to the configured ``llm_provider`` setting when not specified.

        Raises:
            ValueError: If the provider is unknown or its credentials are missing.
        """
        s = get_settings()
        resolved = provider or s.llm_provider

        if resolved == "openai":
            from app.llm.providers.openai_provider import OpenAILLM
            if not s.openai_api_key:
                raise ValueError("OPENAI_API_KEY is not configured in .env")
            logger.info("Creating OpenAI LLM (model=%s)", s.openai_model)
            return OpenAILLM(api_key=s.openai_api_key, model=s.openai_model)

        if resolved == "azure_openai":
            from app.llm.providers.openai_provider import AzureOpenAILLM
            if not s.azure_openai_api_key or not s.azure_openai_endpoint or not s.azure_openai_deployment:
                raise ValueError("AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, and AZURE_OPENAI_DEPLOYMENT must all be configured in .env")
            logger.info("Creating Azure OpenAI LLM")
            return AzureOpenAILLM(
                api_key=s.azure_openai_api_key,
                endpoint=s.azure_openai_endpoint,
                deployment_name=s.azure_openai_deployment,
                api_version=s.azure_openai_api_version,
            )

        if resolved == "aws_bedrock":
            from app.llm.providers.bedrock_provider import BedrockLLM
            # Pass explicit keys only when set; otherwise boto3 uses its credential
            # chain automatically: env vars → ~/.aws/credentials → IAM instance role
            logger.info("Creating Bedrock LLM (model_id=%s, region=%s)", s.bedrock_model_id, s.aws_region)
            return BedrockLLM(
                model_id=s.bedrock_model_id,
                region=s.aws_region,
                access_key_id=s.aws_access_key_id or None,
                secret_access_key=s.aws_secret_access_key or None,
            )

        if resolved == "google_gemini":
            from app.llm.providers.gemini_provider import GeminiLLM
            if not s.google_api_key:
                raise ValueError("GOOGLE_API_KEY is not configured in .env")
            logger.info("Creating Gemini LLM (model=%s)", s.gemini_model)
            return GeminiLLM(api_key=s.google_api_key, model=s.gemini_model)

        raise ValueError(f"Unknown LLM provider: '{resolved}'")
