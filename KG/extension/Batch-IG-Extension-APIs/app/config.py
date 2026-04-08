from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Neo4j connection — override via .env or environment variables
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    neo4j_database: str = "information_graph"

    # Path to the application config YAML.
    # Default points to config/app_config.yaml inside this project.
    # Can be overridden with CONFIG_PATH in .env for custom deployments.
    config_path: str = "config/app_config.yaml"

    # API server (used when starting via main.py directly)
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
