"""
FastAPI middleware for XGT pass-through authentication.

Provides dependency injection for authenticated XGT users and
validates JWT tokens containing encrypted XGT credentials.
"""

import logging
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer

from .passthrough import PassthroughAuthService, get_passthrough_auth_service
from .passthrough_models import AuthenticatedXGTUser

logger = logging.getLogger(__name__)

# Security schemes for authentication
security = HTTPBearer(auto_error=False, scheme_name="BearerAuth")
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/xgt/token", scheme_name="OAuth2PasswordBearer", auto_error=False
)


async def get_current_xgt_user(
    bearer_token: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    oauth2_token: Annotated[Optional[str], Depends(oauth2_scheme)],
    auth_service: Annotated[PassthroughAuthService, Depends(get_passthrough_auth_service)],
) -> Optional[AuthenticatedXGTUser]:
    """
    Get the current authenticated XGT user from JWT token.

    Accepts tokens from either Bearer Auth or OAuth2 scheme.
    Returns None if no token provided or token is invalid.
    This is the optional authentication dependency.
    """
    # Get token from either source
    token = None
    if bearer_token:
        token = bearer_token.credentials
    elif oauth2_token:
        token = oauth2_token

    if not token:
        return None

    try:
        # Validate JWT token and extract XGT credentials
        validation_result = auth_service.validate_jwt_token(token)

        if not validation_result or not validation_result.get("valid"):
            return None

        # Create authenticated user object
        user = AuthenticatedXGTUser(
            username=validation_result["username"],
            namespace=validation_result.get("namespace"),
            authenticated_at=validation_result["authenticated_at"],
            expires_at=validation_result["expires_at"],
            credentials=validation_result["credentials"],
        )

        logger.debug(f"Authenticated XGT user: {user.username} (namespace: {user.namespace})")
        return user

    except Exception as e:
        logger.error(f"XGT token validation error: {e}")
        return None


async def require_xgt_authentication(
    current_user: Annotated[Optional[AuthenticatedXGTUser], Depends(get_current_xgt_user)],
) -> AuthenticatedXGTUser:
    """
    Require XGT authentication for an endpoint.

    Raises HTTPException if user is not authenticated.
    This is the required authentication dependency.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "XGT_AUTHENTICATION_REQUIRED",
                "message": "Valid XGT authentication token required",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if token has expired
    if current_user.is_expired():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "TOKEN_EXPIRED", "message": "Authentication token has expired"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    return current_user


def require_xgt_namespace(required_namespace: str):
    """
    Dependency factory that requires access to a specific XGT namespace.

    Args:
        required_namespace: The XGT namespace required for access

    Returns:
        FastAPI dependency function
    """

    async def check_namespace(
        current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    ) -> AuthenticatedXGTUser:
        """Check if user has access to the required namespace."""
        # User can only access their own namespace
        if current_user.namespace != required_namespace:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "NAMESPACE_ACCESS_DENIED",
                    "message": f"Access denied to namespace '{required_namespace}'",
                    "required_namespace": required_namespace,
                    "user_namespace": current_user.namespace,
                },
            )
        return current_user

    return check_namespace


class XGTPermissionChecker:
    """Helper class for checking XGT permissions in endpoint logic."""

    def __init__(self, user: AuthenticatedXGTUser, auth_service: PassthroughAuthService):
        self.user = user
        self.auth_service = auth_service

    def check_namespace_access(self, namespace: str) -> bool:
        """Check if user can access a specific namespace."""
        return self.user.namespace == namespace

    def require_namespace_access(self, namespace: str) -> None:
        """Require namespace access or raise exception."""
        if not self.check_namespace_access(namespace):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "NAMESPACE_ACCESS_DENIED",
                    "message": f"Access denied to namespace '{namespace}'",
                },
            )

    def get_xgt_connection(self):
        """Get XGT connection using user's credentials."""
        if not self.user.credentials:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "CREDENTIALS_UNAVAILABLE",
                    "message": "XGT credentials not available",
                },
            )

        return self.auth_service.create_xgt_connection(self.user.credentials)


async def get_xgt_permission_checker(
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    auth_service: Annotated[PassthroughAuthService, Depends(get_passthrough_auth_service)],
) -> XGTPermissionChecker:
    """Dependency that provides an XGT permission checker for the current user."""
    return XGTPermissionChecker(current_user, auth_service)
