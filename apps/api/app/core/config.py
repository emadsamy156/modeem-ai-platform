"""Application configuration using pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings, loaded from environment variables."""

    app_name: str = "Modeem AI Platform API"
    service_name: str = "modeem-ai-api"
    app_version: str = "0.1.0"
    environment: str = "development"
    api_version: str = "v1"

    database_url: str = ""

    # Redis-ready configuration (no worker implementation in this phase).
    redis_url: str = "redis://localhost:6379/0"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
