"""
MCP Authentication service for the RocketGraph Public API.

Provides MCP-specific authentication using the existing pass-through authentication system.
"""

import logging
from typing import Optional

from .passthrough import PassthroughAuthService
from .passthrough_models import (
    AuthenticatedXGTUser, 
    XGTBasicAuthRequest, 
    XGTPKIAuthRequest, 
    XGTProxyPKIAuthRequest,
    XGTAuthType
)
from ..config.app_config import get_settings
from ..utils.exceptions import XGTOperationError

logger = logging.getLogger(__name__)


class MCPAuthService:
    """Service for handling MCP authentication using existing passthrough auth."""

    def __init__(self):
        self.settings = get_settings()
        self.passthrough_auth = PassthroughAuthService()
        
    async def authenticate_mcp_user(
        self, 
        username: str, 
        password: str = "", 
        auth_method: str = "basic",
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None
    ) -> AuthenticatedXGTUser:
        """
        Authenticate MCP user using existing passthrough auth.
        
        Args:
            username: Username for authentication  
            password: Password (for basic auth)
            auth_method: Authentication method (basic, pki, proxy_pki)
            cert_path: Path to certificate file (for PKI auth)
            key_path: Path to private key file (for PKI auth)
            
        Returns:
            Authenticated XGT user
            
        Raises:
            XGTOperationError: If authentication fails
        """
        try:
            logger.info(f"Authenticating MCP user {username} with method {auth_method}")
            
            # Validate auth method is enabled
            if auth_method == "basic" and not self.settings.XGT_BASIC_AUTH_ENABLED:
                raise XGTOperationError("Basic authentication is disabled")
            elif auth_method == "pki" and not self.settings.XGT_PKI_AUTH_ENABLED:
                raise XGTOperationError("PKI authentication is disabled")
            elif auth_method == "proxy_pki" and not self.settings.XGT_PROXY_PKI_AUTH_ENABLED:
                raise XGTOperationError("Proxy PKI authentication is disabled")
            
            # Create appropriate auth request object based on method
            if auth_method == "basic":
                auth_request = XGTBasicAuthRequest(
                    username=username,
                    password=password
                )
            elif auth_method == "pki":
                if not cert_path or not key_path:
                    raise XGTOperationError("PKI authentication requires cert_path and key_path")
                
                # For MCP, we'll need to read the certificate files
                import base64
                try:
                    with open(cert_path, 'rb') as f:
                        client_cert = base64.b64encode(f.read()).decode('utf-8')
                    with open(key_path, 'rb') as f:
                        client_key = base64.b64encode(f.read()).decode('utf-8')
                except FileNotFoundError as e:
                    raise XGTOperationError(f"Certificate file not found: {e}")
                
                auth_request = XGTPKIAuthRequest(
                    client_cert=client_cert,
                    client_key=client_key
                )
            elif auth_method == "proxy_pki":
                # For proxy PKI, we need additional parameters
                # This is simplified - in practice you'd get these from the MCP context
                auth_request = XGTProxyPKIAuthRequest(
                    user_id=username,
                    proxy_host="mcp-proxy",  # Placeholder
                    certificate_hash="placeholder_hash",
                    proxy_signature="placeholder_signature"
                )
            else:
                raise XGTOperationError(f"Unsupported auth method: {auth_method}")
            
            # Use existing passthrough authentication
            auth_result = self.passthrough_auth.authenticate_xgt_user(auth_request)
            
            # Convert to AuthenticatedXGTUser format expected by MCP
            from .passthrough_models import AuthenticatedXGTUser
            
            # Extract information from auth_result
            jwt_token = auth_result.get("access_token")
            user_info = auth_result.get("user_info", {})
            
            # Decode JWT token to get credentials
            validated_token = self.passthrough_auth.validate_jwt_token(jwt_token)
            if not validated_token:
                raise XGTOperationError("Failed to validate generated token")
            
            # Extract already-decrypted credentials from validated token
            credentials = validated_token.get("credentials")
            if not credentials:
                raise XGTOperationError("No credentials found in token")
            
            # Create AuthenticatedXGTUser with proper timestamps
            import time
            authenticated_user = AuthenticatedXGTUser(
                username=user_info.get("username", username),
                namespace=user_info.get("namespace"),
                authenticated_at=validated_token.get("authenticated_at", time.time()),
                expires_at=validated_token.get("expires_at", time.time() + 3600),
                credentials=credentials
            )
            
            logger.info(f"MCP user {username} authenticated successfully")
            return authenticated_user
            
        except Exception as e:
            logger.error(f"MCP authentication failed for user {username}: {e}")
            raise XGTOperationError(f"Authentication failed: {str(e)}")
    
    def validate_session_timeout(self, authenticated_user: AuthenticatedXGTUser) -> bool:
        """
        Check if user session is still valid based on MCP timeout settings.
        
        Args:
            authenticated_user: Previously authenticated user
            
        Returns:
            True if session is still valid, False otherwise
        """
        try:
            import time
            
            # Check if user token has already expired (built-in expiration)
            if authenticated_user.is_expired():
                return False
                
            # Check if session has expired based on MCP timeout
            session_age = time.time() - authenticated_user.authenticated_at
            return session_age < self.settings.MCP_SESSION_TIMEOUT
            
        except Exception as e:
            logger.warning(f"Error validating session timeout: {e}")
            return False


# Global MCP authentication service instance
_mcp_auth_service: Optional[MCPAuthService] = None


def get_mcp_auth_service() -> MCPAuthService:
    """Get the global MCP authentication service instance."""
    global _mcp_auth_service
    if _mcp_auth_service is None:
        _mcp_auth_service = MCPAuthService()
    return _mcp_auth_service
