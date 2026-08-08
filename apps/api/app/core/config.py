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

    # Authentication (Phase 2A). AUTH_SECRET must come from the environment.
    # Falls back to SESSION_SECRET (provided by the hosting environment) so
    # development works without duplicating secrets. Never hardcode a value.
    auth_secret: str = ""
    session_secret: str = ""
    session_ttl_seconds: int = 60 * 60 * 12  # 12 hours

    # Bootstrap admin (development convenience; never commit real values).
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    bootstrap_tenant_name: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.auth_secret and settings.session_secret:
        settings.auth_secret = settings.session_secret
    return settings
