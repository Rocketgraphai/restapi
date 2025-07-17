"""
Authentication package for the RocketGraph Public API.

Provides XGT pass-through authentication with JWT token management.
"""

# Pass-through authentication (current system)
from .passthrough import get_passthrough_auth_service, PassthroughAuthService, XGTCredentials
from .passthrough_models import (
    AuthenticatedXGTUser,
    XGTAuthType,
    XGTBasicAuthRequest,
    XGTPKIAuthRequest,
    XGTProxyPKIAuthRequest,
    XGTAuthResponse,
    XGTUserInfo,
    XGTTokenValidation
)
from .passthrough_middleware import (
    get_current_xgt_user,
    require_xgt_authentication,
    require_xgt_namespace,
    get_xgt_permission_checker,
    XGTPermissionChecker
)

# Legacy models (kept for backward compatibility)
from .models import FrameACL

__all__ = [
    # Pass-through Authentication
    "get_passthrough_auth_service",
    "PassthroughAuthService",
    "XGTCredentials",
    
    # Pass-through Models
    "AuthenticatedXGTUser",
    "XGTAuthType",
    "XGTBasicAuthRequest",
    "XGTPKIAuthRequest", 
    "XGTProxyPKIAuthRequest",
    "XGTAuthResponse",
    "XGTUserInfo",
    "XGTTokenValidation",
    
    # Pass-through Middleware
    "get_current_xgt_user",
    "require_xgt_authentication",
    "require_xgt_namespace",
    "get_xgt_permission_checker",
    "XGTPermissionChecker",
    
    # Legacy Models
    "FrameACL"
]