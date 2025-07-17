"""
Authentication middleware for FastAPI endpoints.

Provides dependency injection for authenticated users and permission checking.
"""

import logging
from typing import Optional, Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .service import get_auth_service, AuthenticationService
from .models import AuthenticatedUser, FrameACL

logger = logging.getLogger(__name__)

# Security scheme for Bearer token authentication
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    auth_service: Annotated[AuthenticationService, Depends(get_auth_service)]
) -> Optional[AuthenticatedUser]:
    """
    Get the current authenticated user from JWT token.
    
    Returns None if no token provided or token is invalid.
    This is the optional authentication dependency.
    """
    if not credentials:
        return None
    
    try:
        user = auth_service.validate_token(credentials.credentials)
        if user:
            logger.debug(f"Authenticated user: {user.username} with labels: {user.labels}")
        return user
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return None


async def require_authentication(
    current_user: Annotated[Optional[AuthenticatedUser], Depends(get_current_user)]
) -> AuthenticatedUser:
    """
    Require authentication for an endpoint.
    
    Raises HTTPException if user is not authenticated.
    This is the required authentication dependency.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_REQUIRED",
                "message": "Valid authentication token required"
            },
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return current_user


def require_label(required_label: str):
    """
    Dependency factory that requires a specific security label.
    
    Args:
        required_label: The security label required for access
        
    Returns:
        FastAPI dependency function
    """
    async def check_label(
        current_user: Annotated[AuthenticatedUser, Depends(require_authentication)]
    ) -> AuthenticatedUser:
        """Check if user has the required label."""
        if not current_user.has_label(required_label):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_PERMISSIONS",
                    "message": f"Access denied: requires '{required_label}' label",
                    "required_label": required_label,
                    "user_labels": list(current_user.labels)
                }
            )
        return current_user
    
    return check_label


def require_any_label(required_labels: set[str]):
    """
    Dependency factory that requires any of the specified security labels.
    
    Args:
        required_labels: Set of security labels (user needs at least one)
        
    Returns:
        FastAPI dependency function
    """
    async def check_any_label(
        current_user: Annotated[AuthenticatedUser, Depends(require_authentication)]
    ) -> AuthenticatedUser:
        """Check if user has any of the required labels."""
        if not current_user.has_any_label(required_labels):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_PERMISSIONS",
                    "message": f"Access denied: requires one of {required_labels}",
                    "required_labels": list(required_labels),
                    "user_labels": list(current_user.labels)
                }
            )
        return current_user
    
    return check_any_label


def require_all_labels(required_labels: set[str]):
    """
    Dependency factory that requires all of the specified security labels.
    
    Args:
        required_labels: Set of security labels (user needs all of them)
        
    Returns:
        FastAPI dependency function
    """
    async def check_all_labels(
        current_user: Annotated[AuthenticatedUser, Depends(require_authentication)]
    ) -> AuthenticatedUser:
        """Check if user has all of the required labels."""
        if not current_user.has_all_labels(required_labels):
            missing_labels = required_labels - current_user.labels
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_PERMISSIONS",
                    "message": f"Access denied: missing required labels {missing_labels}",
                    "required_labels": list(required_labels),
                    "missing_labels": list(missing_labels),
                    "user_labels": list(current_user.labels)
                }
            )
        return current_user
    
    return check_all_labels


def require_frame_permission(frame_acl: FrameACL, operation: str):
    """
    Dependency factory that checks frame-level permissions.
    
    Args:
        frame_acl: Frame Access Control List
        operation: Operation type ('create', 'read', 'update', 'delete')
        
    Returns:
        FastAPI dependency function
    """
    async def check_frame_permission(
        current_user: Annotated[AuthenticatedUser, Depends(require_authentication)],
        auth_service: Annotated[AuthenticationService, Depends(get_auth_service)]
    ) -> AuthenticatedUser:
        """Check if user has permission for the frame operation."""
        
        if not auth_service.check_frame_permission(current_user, frame_acl, operation):
            # Get required labels for the operation
            operation_labels = getattr(frame_acl, operation.lower(), set())
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_FRAME_PERMISSIONS",
                    "message": f"Access denied: cannot {operation} on this frame",
                    "operation": operation,
                    "required_labels": list(operation_labels),
                    "user_labels": list(current_user.labels)
                }
            )
        
        return current_user
    
    return check_frame_permission


class PermissionChecker:
    """Helper class for checking permissions in endpoint logic."""
    
    def __init__(self, user: AuthenticatedUser, auth_service: AuthenticationService):
        self.user = user
        self.auth_service = auth_service
    
    def check_label(self, label: str) -> bool:
        """Check if user has a specific label."""
        return self.user.has_label(label)
    
    def check_any_label(self, labels: set[str]) -> bool:
        """Check if user has any of the specified labels."""
        return self.user.has_any_label(labels)
    
    def check_all_labels(self, labels: set[str]) -> bool:
        """Check if user has all of the specified labels."""
        return self.user.has_all_labels(labels)
    
    def check_frame_permission(self, frame_acl: FrameACL, operation: str) -> bool:
        """Check frame-level permission."""
        return self.auth_service.check_frame_permission(self.user, frame_acl, operation)
    
    def require_label(self, label: str) -> None:
        """Require a specific label or raise exception."""
        if not self.check_label(label):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_PERMISSIONS",
                    "message": f"Access denied: requires '{label}' label"
                }
            )
    
    def require_frame_permission(self, frame_acl: FrameACL, operation: str) -> None:
        """Require frame permission or raise exception."""
        if not self.check_frame_permission(frame_acl, operation):
            operation_labels = getattr(frame_acl, operation.lower(), set())
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_FRAME_PERMISSIONS",
                    "message": f"Access denied: cannot {operation} on this frame",
                    "operation": operation,
                    "required_labels": list(operation_labels)
                }
            )


async def get_permission_checker(
    current_user: Annotated[AuthenticatedUser, Depends(require_authentication)],
    auth_service: Annotated[AuthenticationService, Depends(get_auth_service)]
) -> PermissionChecker:
    """Dependency that provides a permission checker for the current user."""
    return PermissionChecker(current_user, auth_service)