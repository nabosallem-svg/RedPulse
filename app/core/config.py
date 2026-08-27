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
        # Treat empty environment variables as unset so defaults apply.
        # Vercel provisions env vars with empty values, which otherwise
        # crashes pydantic_settings when decoding complex/list fields.
        env_ignore_empty=True,
    )

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://localhost/RedPulse",
        env="DATABASE_URL",
    )

    # Redis (for future worker setup)
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        env="REDIS_URL",
    )

    # JWT configuration
    JWT_SECRET: str = Field(
        default="RedPulse-dev-secret-change-in-production",
        env="JWT_SECRET",
    )
    JWT_ALGORITHM: str = Field(
        default="HS256",
        env="JWT_ALGORITHM",
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        env="ACCESS_TOKEN_EXPIRE_MINUTES",
    )
    ENVIRONMENT: str = Field(
        default="development",
        env="ENVIRONMENT",
    )

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = Field(
        default=["*"],
        env="BACKEND_CORS_ORIGINS",
    )

    # Logging
    LOG_LEVEL: str = Field(
        default="INFO",
        env="LOG_LEVEL",
    )
    LOG_FORMAT: str = Field(
        default="json",
        env="LOG_FORMAT",
    )


# Global settings instance - loaded from .env or using defaults
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings
