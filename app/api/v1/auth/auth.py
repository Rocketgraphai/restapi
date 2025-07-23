"""
Authentication endpoints for the RocketGraph Public API.

Provides login and token management functionality with User -> Group -> Label resolution.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ....auth.middleware import get_current_user, require_authentication
from ....auth.models import (
    AuthenticatedUser,
    AuthenticationRequest,
    AuthenticationResponse,
    TokenValidationResponse,
)
from ....auth.service import AuthenticationService, get_auth_service
from ....utils.exceptions import XGTConnectionError, XGTOperationError

router = APIRouter()
logger = logging.getLogger(__name__)


class UserInfoResponse(BaseModel):
    """Response model for user information."""

    user_id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Username")
    email: str = Field(None, description="User email")
    labels: list[str] = Field(..., description="Security labels user has access to")
    auth_time: str = Field(..., description="When user was authenticated (ISO 8601)")
    labels_resolved_at: str = Field(None, description="When labels were last resolved (ISO 8601)")


@router.post("/login", response_model=AuthenticationResponse)
async def login(
    auth_request: AuthenticationRequest,
    auth_service: Annotated[AuthenticationService, Depends(get_auth_service)],
):
    """
    Authenticate a user and return JWT token with resolved permissions.

    This endpoint authenticates users against the XGT server and resolves their
    security labels through the User -> Group -> Label relationship model.

    Args:
        auth_request: Username and password for authentication

    Returns:
        JWT token and user details with resolved security labels

    Raises:
        HTTPException: If authentication fails or XGT server is unavailable
    """
    try:
        logger.info(f"Authentication attempt for user: {auth_request.username}")

        # Authenticate user and resolve permissions
        auth_response = auth_service.authenticate_user(
            username=auth_request.username, password=auth_request.password
        )

        logger.info(f"User {auth_request.username} authenticated successfully")
        return auth_response

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed during authentication: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Authentication service unavailable",
                "details": "Cannot connect to user authentication database",
            },
        )
    except XGTOperationError as e:
        logger.warning(f"Authentication failed for user {auth_request.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_FAILED",
                "message": "Invalid username or password",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected error during authentication: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Authentication service error",
                "details": "An unexpected error occurred during authentication",
            },
        )


@router.get("/me", response_model=UserInfoResponse)
async def get_current_user_info(
    current_user: Annotated[AuthenticatedUser, Depends(require_authentication)],
):
    """
    Get information about the currently authenticated user.

    Returns detailed information about the authenticated user including
    their security labels and authentication metadata.

    Returns:
        Current user information with security labels

    Raises:
        HTTPException: If user is not authenticated
    """
    try:
        return UserInfoResponse(
            user_id=current_user.user_id,
            username=current_user.username,
            email=current_user.email,
            labels=list(current_user.labels),
            auth_time=current_user.auth_time.isoformat(),
            labels_resolved_at=current_user.labels_resolved_at.isoformat()
            if current_user.labels_resolved_at
            else None,
        )
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Failed to retrieve user information",
            },
        )


@router.post("/validate", response_model=TokenValidationResponse)
async def validate_token(
    current_user: Annotated[AuthenticatedUser | None, Depends(get_current_user)],
):
    """
    Validate a JWT token and return user information.

    This endpoint can be used by other services to validate tokens
    and get user information without requiring re-authentication.

    Returns:
        Token validation result with user information if valid
    """
    try:
        if current_user:
            return TokenValidationResponse(valid=True, user=current_user, error=None)
        else:
            return TokenValidationResponse(valid=False, user=None, error="Invalid or expired token")
    except Exception as e:
        logger.error(f"Error validating token: {e}")
        return TokenValidationResponse(
            valid=False, user=None, error="Token validation service error"
        )


@router.post("/refresh", response_model=AuthenticationResponse)
async def refresh_token(
    current_user: Annotated[AuthenticatedUser, Depends(require_authentication)],
    auth_service: Annotated[AuthenticationService, Depends(get_auth_service)],
):
    """
    Refresh user's security labels and generate new token.

    This endpoint refreshes the user's group memberships and security labels
    from the XGT server and generates a new JWT token with updated permissions.
    Useful when user permissions may have changed.

    Returns:
        New JWT token with refreshed user permissions

    Raises:
        HTTPException: If refresh fails or user is not authenticated
    """
    try:
        logger.info(f"Refreshing token for user: {current_user.username}")

        # Force refresh of user labels
        refreshed_user = auth_service._refresh_user_labels(current_user)

        # Generate new token with refreshed information
        new_token = auth_service._generate_jwt_token(refreshed_user)

        logger.info(
            f"Token refreshed for user {current_user.username} "
            f"with {len(refreshed_user.labels)} labels"
        )

        return AuthenticationResponse(
            access_token=new_token,
            token_type="bearer",  # noqa: S106
            expires_in=auth_service.settings.JWT_EXPIRY_SECONDS,
            user=refreshed_user,
        )

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed during token refresh: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Token refresh service unavailable",
                "details": "Cannot connect to user permission database",
            },
        )
    except Exception as e:
        logger.error(f"Error refreshing token for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Token refresh failed",
                "details": "An unexpected error occurred during token refresh",
            },
        )
