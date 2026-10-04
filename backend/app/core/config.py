"""Central application configuration.

All configuration comes from environment variables (see .env.example at the
repo root). Nothing here is hard-coded to a specific OS path or a specific
LLM/embedding provider — see app.core.llm and app.core.embeddings for the
provider abstractions this config feeds into.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = Field(default="development", alias="ENVIRONMENT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Database
    database_url: str = Field(
        default="postgresql+psycopg://sentinelforge:sentinelforge_dev@localhost:5432/sentinelforge",
        alias="DATABASE_URL",
    )

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # Auth
    jwt_secret_key: str = Field(default="dev-only-not-secure", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS")

    # LLM provider abstraction (docs/ai/ai-agent.md §2)
    llm_provider: str = Field(default="mock", alias="LLM_PROVIDER")
    llm_model: str = Field(default="", alias="LLM_MODEL")
    llm_api_key: str = Field(default="", alias="LLM_API_KEY")

    # Embedding provider abstraction (docs/ai/ai-agent.md §2, RAG)
    embedding_provider: str = Field(default="mock", alias="EMBEDDING_PROVIDER")
    embedding_model: str = Field(default="", alias="EMBEDDING_MODEL")

    # Agent safety limits (docs/ai/ai-agent.md §6 — hard, not advisory)
    agent_max_steps: int = Field(default=12, alias="AGENT_MAX_STEPS")
    agent_max_tool_calls: int = Field(default=20, alias="AGENT_MAX_TOOL_CALLS")
    agent_max_retries: int = Field(default=2, alias="AGENT_MAX_RETRIES")
    agent_max_context_tokens: int = Field(default=32_000, alias="AGENT_MAX_CONTEXT_TOKENS")
    agent_max_investigation_seconds: int = Field(
        default=120, alias="AGENT_MAX_INVESTIGATION_SECONDS"
    )

    # Detection rules location (mounted read-only in docker-compose.yml)
    detection_rules_path: str = Field(default="detection-rules", alias="DETECTION_RULES_PATH")
    knowledge_base_path: str = Field(default="knowledge-base", alias="KNOWLEDGE_BASE_PATH")
    ml_models_path: str = Field(default="ml/models", alias="ML_MODELS_PATH")


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor — import and call this, don't instantiate
    Settings() directly, so the whole app shares one parsed config."""
    return Settings()
