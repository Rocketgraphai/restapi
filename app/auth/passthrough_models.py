"""
Models for XGT pass-through authentication.

Simple models for handling XGT credential pass-through without
managing user groups and labels in the REST API.
"""

from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, Field


class XGTAuthType(str, Enum):
    """XGT authentication types."""

    BASIC = "basic"
    PKI = "pki"
    PROXY_PKI = "proxy_pki"


class XGTBasicAuthRequest(BaseModel):
    """Request model for XGT Basic authentication."""

    auth_type: XGTAuthType = Field(default=XGTAuthType.BASIC, description="Authentication type")
    username: str = Field(..., description="XGT username", min_length=1)
    password: str = Field(..., description="XGT password", min_length=1)

    class Config:
        json_schema_extra = {
            "example": {
                "auth_type": "basic",
                "username": "analyst1",
                "password": "secure_password_123",
            }
        }


class XGTPKIAuthRequest(BaseModel):
    """Request model for XGT PKI certificate authentication."""

    auth_type: XGTAuthType = Field(default=XGTAuthType.PKI, description="Authentication type")

    # Certificate files (PEM format, base64 encoded for JSON transport)
    client_cert: str = Field(..., description="Client certificate (PEM format, base64 encoded)")
    client_key: str = Field(..., description="Client private key (PEM format, base64 encoded)")
    ca_chain: Optional[str] = Field(
        None, description="CA certificate chain (PEM format, base64 encoded)"
    )

    # SSL configuration
    ssl_server_cert: Optional[str] = Field(None, description="Server certificate path or content")
    ssl_server_cn: Optional[str] = Field(None, description="Expected server common name")

    class Config:
        json_schema_extra = {
            "example": {
                "auth_type": "pki",
                "client_cert": "LS0tLS1CRUdJTi...",  # base64 encoded PEM
                "client_key": "LS0tLS1CRUdJTi...",  # base64 encoded PEM
                "ca_chain": "LS0tLS1CRUdJTi...",  # base64 encoded PEM
                "ssl_server_cn": "xgt-server.company.com",
            }
        }


class XGTProxyPKIAuthRequest(BaseModel):
    """Request model for XGT Proxy PKI authentication."""

    auth_type: XGTAuthType = Field(default=XGTAuthType.PROXY_PKI, description="Authentication type")

    # For proxy PKI, the certificate comes from a validated proxy/host
    user_id: str = Field(..., description="User ID from PKI certificate", min_length=1)
    proxy_host: str = Field(..., description="Validated proxy host", min_length=1)

    # Certificate validation proof from proxy
    certificate_hash: str = Field(..., description="Hash of the PKI certificate for validation")
    proxy_signature: str = Field(..., description="Proxy signature validating the certificate")

    class Config:
        json_schema_extra = {
            "example": {
                "auth_type": "proxy_pki",
                "user_id": "analyst1",
                "proxy_host": "auth-proxy.company.com",
                "certificate_hash": "sha256:abc123...",
                "proxy_signature": "signature_from_proxy",
            }
        }


# Union type for all authentication requests
XGTAuthRequest = Union[XGTBasicAuthRequest, XGTPKIAuthRequest, XGTProxyPKIAuthRequest]


class XGTUserInfo(BaseModel):
    """Information about an authenticated XGT user."""

    username: str = Field(..., description="XGT username")
    namespace: Optional[str] = Field(None, description="User's default XGT namespace")
    authenticated_at: str = Field(..., description="Authentication timestamp (ISO 8601)")


class XGTAuthResponse(BaseModel):
    """Response model for successful XGT authentication."""

    access_token: str = Field(..., description="JWT access token with encrypted XGT credentials")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    user_info: XGTUserInfo = Field(..., description="Authenticated user information")

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 3600,
                "user_info": {
                    "username": "analyst1",
                    "namespace": "analyst1",
                    "authenticated_at": "2024-01-15T10:30:00Z",
                },
            }
        }


class XGTTokenValidation(BaseModel):
    """Response model for XGT token validation."""

    valid: bool = Field(..., description="Whether the token is valid")
    username: Optional[str] = Field(None, description="Username if token is valid")
    namespace: Optional[str] = Field(None, description="User's XGT namespace")
    authenticated_at: Optional[float] = Field(None, description="Unix timestamp when authenticated")
    expires_at: Optional[float] = Field(None, description="Unix timestamp when token expires")
    error: Optional[str] = Field(None, description="Error message if token is invalid")

    class Config:
        json_schema_extra = {
            "example": {
                "valid": True,
                "username": "analyst1",
                "namespace": "analyst1",
                "authenticated_at": 1642248000.0,
                "expires_at": 1642251600.0,
                "error": None,
            }
        }


class AuthenticatedXGTUser(BaseModel):
    """Represents an authenticated XGT user for dependency injection."""

    username: str = Field(..., description="XGT username")
    namespace: Optional[str] = Field(None, description="User's default XGT namespace")
    authenticated_at: float = Field(..., description="Unix timestamp when authenticated")
    expires_at: float = Field(..., description="Unix timestamp when token expires")

    # Internal credentials (not serialized in responses)
    credentials: Optional[Any] = Field(None, exclude=True, description="Encrypted XGT credentials")

    def is_expired(self) -> bool:
        """Check if the user's token has expired."""
        import time

        return time.time() > self.expires_at

    class Config:
        # Allow arbitrary types for internal use
        arbitrary_types_allowed = True


class XGTConnectionInfo(BaseModel):
    """Information about an XGT connection for debugging/monitoring."""

    username: str = Field(..., description="Connected username")
    namespace: str = Field(..., description="Active namespace")
    server_host: str = Field(..., description="XGT server host")
    server_port: int = Field(..., description="XGT server port")
    ssl_enabled: bool = Field(..., description="Whether SSL is enabled")
    connected_at: str = Field(..., description="Connection timestamp (ISO 8601)")

    class Config:
        json_schema_extra = {
            "example": {
                "username": "analyst1",
                "namespace": "analyst1",
                "server_host": "xgt.company.com",
                "server_port": 4367,
                "ssl_enabled": True,
                "connected_at": "2024-01-15T10:30:00Z",
            }
        }
