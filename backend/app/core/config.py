from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, sourced from environment variables / a .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="BASTION_",
        extra="ignore",
    )

    app_name: str = "Bastion"
    api_v1_prefix: str = "/api/v1"
    debug: bool = False

    # Comma-separated list of browser origins allowed to call the API via CORS.
    # Stored as a raw string (not a list) on purpose: pydantic-settings tries to
    # JSON-decode env values for complex/list fields, which would reject a plain
    # comma-separated string. We parse it ourselves in ``cors_origins``.
    #
    # The default is the local docker-compose / Vite dev origin. In production set
    # BASTION_CORS_ALLOWED_ORIGINS to the deployed frontend origin(s), e.g.
    # "https://bastion-scan.vercel.app". Never use "*" — credentials/headers like
    # the BYOK key must only be accepted from origins you trust.
    cors_allowed_origins: str = "http://localhost:5173"

    # Toggle HSTS. On (default) browsers are told to refuse plain-HTTP downgrades
    # for a long window. Only meaningful once the app is served over HTTPS, which
    # the BYOK key transiting the network makes a hard requirement.
    hsts_enabled: bool = True

    @property
    def cors_origins(self) -> list[str]:
        """The allowed CORS origins, parsed from the comma-separated setting."""
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (use as a FastAPI dependency)."""
    return Settings()


settings = get_settings()
