"""RedPulse - Configuration Management

Loads configuration from environment variables using .env file.
Never commit .env to version control.
"""

import os
from typing import List, Optional
from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Primary settings class loaded from environment."""
    
    # Database
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    # SQLite allowed only for dev/testing: sqlite+aiosqlite:///./RedPulse.db
    
    # Redis (for future worker setup)
    REDIS_URL: str = Field("", env="REDIS_URL")
    
    # External tool binaries - configurable paths
    SUBFINDER_BIN: str = Field("subfinder", env="SUBFINDER_BIN")
    HTTPX_BIN: str = Field("httpx", env="HTTPX_BIN")
    NUCLEI_BIN: str = Field("nuclei", env="NUCLEI_BIN")
    
    # AI configuration
    AI_PROVIDER: str = Field("openai", env="AI_PROVIDER")
    AI_API_KEY: str = Field("", env="AI_API_KEY")
    
    # Security
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    ALGORITHM: str = Field("HS256", env="ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # Telegram notifications
    TELEGRAM_BOT_TOKEN: str = Field("", env="TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID: str = Field("", env="TELEGRAM_CHAT_ID")
    
    # Logging
    LOG_LEVEL: str = Field("INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field("json", env="LOG_FORMAT")
    
    # SaaS usage limits
    FREE_PROJECTS_LIMIT: int = Field(1, env="FREE_PROJECTS_LIMIT")
    FREE_ASSETS_LIMIT: int = Field(100, env="FREE_ASSETS_LIMIT")
    FREE_SCANS_LIMIT: int = Field(5, env="FREE_SCANS_LIMIT")
    
    # Concurrency limits
    SCAN_CONCURRENCY_LIMIT: int = Field(50, env="SCAN_CONCURRENCY_LIMIT")
    RECON_CONCURRENCY_LIMIT: int = Field(100, env="RECON_CONCURRENCY_LIMIT")
    
    # Timeouts
    SCAN_TIMEOUT_SECONDS: int = Field(300, env="SCAN_TIMEOUT_SECONDS")
    RECON_TIMEOUT_SECONDS: int = Field(120, env="RECON_TIMEOUT_SECONDS")
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = Field(["*"], env="BACKEND_CORS_ORIGINS")
    
    @validator("DATABASE_URL")
    def validate_database_url(cls, v):
        """Validate database URL format."""
        if not v:
            raise ValueError("DATABASE_URL must be set")
        return v
    
    class Config:
        """Pydantic config."""
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings