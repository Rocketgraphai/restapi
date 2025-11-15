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

    # MCP Settings
    MCP_ENABLED: bool = Field(default=True, description="Enable MCP server functionality")
    MCP_STDIO_MODE: bool = Field(default=True, description="Run MCP in stdio mode")
    MCP_SESSION_TIMEOUT: int = Field(default=3600, description="MCP session timeout in seconds")
    MCP_MAX_CONCURRENT_SESSIONS: int = Field(default=100, description="Maximum concurrent MCP sessions")
    MCP_QUERY_TIMEOUT: int = Field(default=300, description="MCP query timeout in seconds")
    MCP_MAX_RESULT_ROWS: int = Field(default=10000, description="Maximum rows returned per MCP query")

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
            # Validate SECRET_KEY strength
            if self.SECRET_KEY.startswith("dev-"):
                raise ValueError("Production environment requires a secure SECRET_KEY (not dev default)")
            if len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "Production SECRET_KEY must be at least 32 characters long. "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )
            self._validate_key_entropy(self.SECRET_KEY, "SECRET_KEY")

            # Validate API_KEY_SALT strength
            if self.API_KEY_SALT.startswith("dev-"):
                raise ValueError("Production environment requires a secure API_KEY_SALT (not dev default)")
            if len(self.API_KEY_SALT) < 32:
                raise ValueError(
                    "Production API_KEY_SALT must be at least 32 characters long. "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )

            # Validate JWT_SECRET_KEY strength
            if self.JWT_SECRET_KEY.startswith("dev-"):
                raise ValueError("Production environment requires a secure JWT_SECRET_KEY (not dev default)")
            if len(self.JWT_SECRET_KEY) < 32:
                raise ValueError(
                    "Production JWT_SECRET_KEY must be at least 32 characters long. "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
                )
            self._validate_key_entropy(self.JWT_SECRET_KEY, "JWT_SECRET_KEY")

        return self

    @staticmethod
    def _validate_key_entropy(key: str, key_name: str) -> None:
        """
        Validate that a cryptographic key has sufficient entropy.

        Performs basic entropy checks to detect weak keys:
        - Checks for repeated characters
        - Validates character set diversity
        - Detects sequential patterns

        Args:
            key: The key to validate
            key_name: Name of the key (for error messages)

        Raises:
            ValueError: If key appears to have insufficient entropy
        """
        # Check for excessive repeated characters (possible weak key indicator)
        if len(set(key)) < len(key) / 4:  # Less than 25% unique characters
            raise ValueError(
                f"{key_name} appears to have low entropy (too many repeated characters). "
                "Use a cryptographically random key generator."
            )

        # Check for all-lowercase or all-uppercase (indicates not using full character set)
        if key.isalpha() and (key.islower() or key.isupper()):
            raise ValueError(
                f"{key_name} should use mixed case and special characters for better entropy. "
                "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )

        # Check for simple sequential patterns (e.g., "abcd", "1234")
        sequential_count = 0
        for i in range(len(key) - 2):
            if ord(key[i + 1]) == ord(key[i]) + 1 and ord(key[i + 2]) == ord(key[i]) + 2:
                sequential_count += 1
        if sequential_count > len(key) / 10:  # More than 10% sequential
            raise ValueError(
                f"{key_name} contains too many sequential patterns (possible weak key). "
                "Use a cryptographically random key generator."
            )

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
