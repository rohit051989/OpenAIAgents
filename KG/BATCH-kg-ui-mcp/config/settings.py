"""Application configuration via Pydantic Settings.

All values can be overridden through environment variables or a .env file.
Refer to .env.example for the full list of supported variables.
"""

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_CONFIG_DIR = Path(__file__).parent  # config/ directory


# ---------------------------------------------------------------------------
# Configurations (loaded from config/config.yaml)
# ---------------------------------------------------------------------------

class Config(BaseModel):
    """Tuning knobs for anomaly detection and deterioration trend analysis."""

    # Anomaly detection (get_sla_execution_breach)
    anomaly_hist_days: int = 30
    anomaly_k_factor: float = 2.0
    anomaly_min_samples: int = 5

    # Deterioration trend (get_job_performance)
    trend_min_points: int = 7
    trend_deteriorating_ms: int = 500
    trend_improving_ms: int = -500


def _load_config() -> Config:
    """Load Config from config/config.yaml (called once as Settings field default)."""
    yaml_path = _CONFIG_DIR / "config.yaml"
    if yaml_path.exists():
        with open(yaml_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return Config(**(data.get("config") or {}))
    return Config()


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

    # -----------------------------------------------------------------
    # Configurations (loaded from config/config.yaml)
    # -----------------------------------------------------------------
    config: Config = Field(default_factory=_load_config)


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
