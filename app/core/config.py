"""RedPulse - Configuration Management

Loads configuration from environment variables using .env file.
Never commit .env to version control.
"""

from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Primary settings class loaded from environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="allow",
    )

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://localhost/RedPulse",
    )

    # Redis (for future worker setup)
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
    )

    # JWT configuration
    JWT_SECRET: str = Field(
        default="RedPulse-dev-secret-change-in-production",
    )
    JWT_ALGORITHM: str = Field(
        default="HS256",
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
    )
    ENVIRONMENT: str = Field(
        default="development",
    )

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = Field(
        default=["*"],
    )

    # Logging
    LOG_LEVEL: str = Field(
        default="INFO",
    )
    LOG_FORMAT: str = Field(
        default="json",
    )

    # Recon tool configuration
    SUBFINDER_BIN: str = Field(default="subfinder")
    HTTPX_BIN: str = Field(default="httpx")
    NMAP_BIN: str = Field(default="nmap")
    TOOL_TIMEOUT: int = Field(default=300)
    TOOL_MAX_WORKERS: int = Field(default=4)

    # Scanner configuration
    NUCLEI_BIN: str = Field(default="nuclei")
    SCANNER_TIMEOUT: int = Field(default=60)
    SCANNER_MAX_WORKERS: int = Field(default=4)

    # Bug bounty platform API tokens (optional)
    HACKERONE_API_TOKEN: str = Field(default="")
    HACKERONE_USERNAME: str = Field(default="")
    BUGCROWD_API_TOKEN: str = Field(default="")

    # Stripe billing (optional - test mode)
    STRIPE_SECRET_KEY: str = Field(default="")
    STRIPE_WEBHOOK_SECRET: str = Field(default="")
    STRIPE_PRICE_PRO: str = Field(default="price_test_pro_123")
    STRIPE_PRICE_HUNTER: str = Field(default="price_test_hunter_123")
    STRIPE_PRICE_BUSINESS: str = Field(default="price_test_business_123")
    STRIPE_PRICE_TEAM: str = Field(default="price_test_team_123")
    STRIPE_PRICE_ENTERPRISE: str = Field(default="price_test_enterprise_123")
    FRONTEND_URL: str = Field(default="http://localhost:3000")


# Global settings instance - loaded from .env or using defaults
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings