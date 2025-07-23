"""
Application configuration for the RocketGraph Public API.

Manages environment-specific settings, security configuration,
and external service connections.
"""

from typing import Optional

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Application Settings
    APP_NAME: str = "RocketGraph Public API"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", description="Environment: development, staging, production")
    DEBUG: bool = Field(default=False, description="Enable debug mode")

    # Server Settings
    HOST: str = Field(default="0.0.0.0", description="Server host")
    PORT: int = Field(default=8000, description="Server port")
    WORKERS: int = Field(default=4, description="Number of worker processes")

    # Security Settings
    SECRET_KEY: str = Field(
        default="dev-secret-key-change-in-production",
        description="Secret key for cryptographic operations",
    )
    API_KEY_SALT: str = Field(default="dev-api-key-salt-change-in-production", description="Salt for API key hashing")
    ALLOWED_HOSTS: list[str] = Field(default=["*"], description="Allowed host headers")
    CORS_ORIGINS: list[str] = Field(default=[], description="Allowed CORS origins")

    # XGT Database Settings
    XGT_HOST: str = Field(default="localhost", description="XGT server host")
    XGT_PORT: int = Field(default=4367, description="XGT server port")
    XGT_USERNAME: str = Field(default="admin", description="XGT username")
    XGT_PASSWORD: str = Field(default="", description="XGT password")
    XGT_USE_SSL: bool = Field(default=False, description="Use SSL for XGT connection")
    XGT_SSL_CERT: Optional[str] = Field(default=None, description="Path to XGT SSL certificate")
    XGT_SERVER_CN: Optional[str] = Field(default=None, description="XGT server common name")

    # MongoDB Settings (for API metadata)
    MONGODB_URI: str = Field(default="mongodb://localhost:27017/rocketgraph_api", description="MongoDB connection URI")
    MONGODB_DATABASE: str = Field(default="rocketgraph_api", description="MongoDB database name")

    # Redis Settings (for caching and rate limiting)
    REDIS_URL: str = Field(default="redis://localhost:6379", description="Redis connection URL")
    REDIS_DB: int = Field(default=0, description="Redis database number")

    # Rate Limiting Settings
    RATE_LIMITING_ENABLED: bool = Field(default=True, description="Enable rate limiting")
    DEFAULT_RATE_LIMIT_PER_MINUTE: int = Field(default=100, description="Default requests per minute")
    DEFAULT_RATE_LIMIT_PER_HOUR: int = Field(default=1000, description="Default requests per hour")
    DEFAULT_RATE_LIMIT_PER_DAY: int = Field(default=10000, description="Default requests per day")

    # XGT Pass-through Authentication Settings
    JWT_SECRET_KEY: str = Field(
        default="dev-jwt-secret-key-change-in-production",
        description="JWT secret key for XGT credential encryption",
    )
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT algorithm")
    JWT_EXPIRY_SECONDS: int = Field(default=3600, description="JWT token expiry in seconds (1 hour)")

    # XGT Authentication Types Enabled
    XGT_BASIC_AUTH_ENABLED: bool = Field(default=True, description="Enable XGT Basic Auth (username/password)")
    XGT_PKI_AUTH_ENABLED: bool = Field(default=True, description="Enable XGT PKI certificate authentication")
    XGT_PROXY_PKI_AUTH_ENABLED: bool = Field(default=False, description="Enable XGT Proxy PKI authentication")

    # LLM Settings
    LLM_PROVIDERS: list[str] = Field(default=["openai", "anthropic"], description="Available LLM providers")
    OPENAI_API_KEY: Optional[str] = Field(default=None, description="OpenAI API key")
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None, description="Anthropic API key")

    # Monitoring Settings
    ENABLE_METRICS: bool = Field(default=True, description="Enable Prometheus metrics")
    METRICS_PORT: int = Field(default=9090, description="Metrics server port")

    # Logging Settings
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FORMAT: str = Field(default="json", description="Log format: json or text")

    # Security Headers
    SECURITY_HEADERS_ENABLED: bool = Field(default=True, description="Enable security headers")

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v):
        """Validate environment value."""
        allowed = ["development", "staging", "production"]
        if v.lower() not in allowed:
            raise ValueError(f"Environment must be one of: {allowed}")
        return v.lower()

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v):
        """Validate log level."""
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of: {allowed}")
        return v.upper()

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v):
        """Parse allowed hosts from string or list."""
        if isinstance(v, str):
            return [host.strip() for host in v.split(",") if host.strip()]
        return v

    @model_validator(mode="after")
    def validate_production_security(self):
        """Validate security settings in production."""
        if self.ENVIRONMENT == "production":
            if self.SECRET_KEY.startswith("dev-"):
                raise ValueError("Production environment requires a secure SECRET_KEY (not dev default)")
            if self.API_KEY_SALT.startswith("dev-"):
                raise ValueError("Production environment requires a secure API_KEY_SALT (not dev default)")
            if self.JWT_SECRET_KEY.startswith("dev-"):
                raise ValueError("Production environment requires a secure JWT_SECRET_KEY (not dev default)")
        return self

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.ENVIRONMENT == "development"

    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=True)


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get the global settings instance.

    Returns:
        Settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """
    Reload settings from environment.

    Returns:
        New settings instance
    """
    global _settings
    _settings = Settings()
    return _settings


# Rate limiting configurations
RATE_LIMIT_TIERS = {
    "free": {
        "requests_per_minute": 100,
        "requests_per_hour": 1000,
        "requests_per_day": 10000,
        "query_executions_per_hour": 100,
        "data_upload_per_day": 100 * 1024 * 1024,  # 100MB
    },
    "basic": {
        "requests_per_minute": 500,
        "requests_per_hour": 10000,
        "requests_per_day": 100000,
        "query_executions_per_hour": 1000,
        "data_upload_per_day": 1024 * 1024 * 1024,  # 1GB
    },
    "premium": {
        "requests_per_minute": 1000,
        "requests_per_hour": 50000,
        "requests_per_day": 1000000,
        "query_executions_per_hour": 10000,
        "data_upload_per_day": 10 * 1024 * 1024 * 1024,  # 10GB
    },
    "enterprise": {
        "requests_per_minute": 5000,
        "requests_per_hour": 200000,
        "requests_per_day": 10000000,
        "query_executions_per_hour": 100000,
        "data_upload_per_day": 100 * 1024 * 1024 * 1024,  # 100GB
    },
}


def get_rate_limits(tier: str) -> dict:
    """
    Get rate limits for a specific tier.

    Args:
        tier: Rate limit tier name

    Returns:
        Rate limit configuration
    """
    return RATE_LIMIT_TIERS.get(tier, RATE_LIMIT_TIERS["free"])
