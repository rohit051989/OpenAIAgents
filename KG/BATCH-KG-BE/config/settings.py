"""Application settings via Pydantic Settings."""

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_host: str = "0.0.0.0"
    app_port: int = 8001
    app_env: str = "development"
    log_level: str = "INFO"

    # CORS — comma-separated origins or "*" for all (dev only)
    allowed_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # MCP default
    mcp_server_url: str = "http://localhost:8100/mcp/sse"

    # LLM
    llm_provider: str = "openai"

    # OpenAI
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o"

    # Azure OpenAI
    azure_openai_api_key: Optional[str] = None
    azure_openai_endpoint: Optional[str] = None
    azure_openai_deployment: Optional[str] = None
    azure_openai_api_version: str = "2024-08-01-preview"

    # AWS Bedrock
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"

    # Google Gemini
    google_api_key: Optional[str] = None
    gemini_model: str = "gemini-1.5-flash"

    # Auth — when set, every endpoint requires X-API-Key: <api_key>
    # Leave unset (default) for local development; set in production.
    api_key: Optional[str] = None

    # Sessions
    session_ttl_hours: int = 24

    # Proxy configuration for external API Calls
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
