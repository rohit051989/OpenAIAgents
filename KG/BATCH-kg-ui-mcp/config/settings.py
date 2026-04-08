"""Application configuration via Pydantic Settings.

All values can be overridden through environment variables or a .env file.
Refer to .env.example for the full list of supported variables.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -----------------------------------------------------------------
    # Neo4j connection
    # -----------------------------------------------------------------
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "your_password_here"
    neo4j_database_kg: str = "knowledgegraph"
    neo4j_database_ig: str = "informationgraph"
    neo4j_max_connection_pool_size: int = 50
    neo4j_connection_timeout: int = 30

    # -----------------------------------------------------------------
    # MCP server identity
    # -----------------------------------------------------------------
    mcp_server_name: str = "Spring Batch KG MCP"
    mcp_transport: str = "sse"

    # -----------------------------------------------------------------
    # Runtime
    # -----------------------------------------------------------------
    app_env: str = "development"
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
