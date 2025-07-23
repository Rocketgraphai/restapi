"""
Authentication service for the RocketGraph Public API.

Handles User -> Group -> Label resolution and JWT token management.
"""

from datetime import datetime, timedelta
import logging
from typing import Any, Dict, Optional, Set

from cachetools import TTLCache
import jwt as pyjwt

from ..config.app_config import get_settings
from ..utils.exceptions import XGTOperationError
from ..utils.xgt_operations import create_xgt_operations
from .models import AuthenticatedUser, AuthenticationResponse, UserGroup

logger = logging.getLogger(__name__)


class AuthenticationService:
    """Service for handling authentication and authorization."""

    def __init__(self):
        self.settings = get_settings()
        # Cache for user permissions (user_id -> labels)
        self._label_cache = TTLCache(maxsize=1000, ttl=900)  # 15 min TTL
        # Cache for group-to-label mappings
        self._group_label_cache = TTLCache(maxsize=500, ttl=1800)  # 30 min TTL

    def authenticate_user(self, username: str, password: str) -> AuthenticationResponse:
        """
        Authenticate a user and return JWT token with resolved permissions.

        Args:
            username: Username to authenticate
            password: Password for authentication

        Returns:
            Authentication response with token and user details

        Raises:
            XGTConnectionError: If XGT connection fails
            XGTOperationError: If authentication fails
        """
        try:
            # Step 1: Authenticate with XGT server
            xgt_ops = create_xgt_operations()
            auth_result = self._authenticate_with_xgt(xgt_ops, username, password)

            if not auth_result["success"]:
                raise XGTOperationError(
                    f"Authentication failed: {auth_result.get('error', 'Invalid credentials')}"
                )

            user_id = auth_result["user_id"]

            # Step 2: Resolve user groups and labels
            user_groups = self._get_user_groups(xgt_ops, user_id)
            user_labels = self._resolve_user_labels(xgt_ops, user_groups)

            # Step 3: Create authenticated user object
            authenticated_user = AuthenticatedUser(
                user_id=user_id,
                username=username,
                email=auth_result.get("email"),
                groups=set(group.group_id for group in user_groups),
                labels=user_labels,
                labels_resolved_at=datetime.utcnow(),
            )

            # Step 4: Cache the user's labels
            self._label_cache[user_id] = user_labels

            # Step 5: Generate JWT token
            access_token = self._generate_jwt_token(authenticated_user)

            logger.info(
                f"User {username} authenticated successfully with {len(user_labels)} labels"
            )

            return AuthenticationResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=self.settings.JWT_EXPIRY_SECONDS,
                user=authenticated_user,
            )

        except Exception as e:
            logger.error(f"Authentication failed for user {username}: {e}")
            raise

    def validate_token(self, token: str) -> Optional[AuthenticatedUser]:
        """
        Validate JWT token and return authenticated user.

        Args:
            token: JWT token to validate

        Returns:
            Authenticated user if token is valid, None otherwise
        """
        try:
            # Decode JWT token
            payload = pyjwt.decode(
                token, self.settings.JWT_SECRET_KEY, algorithms=[self.settings.JWT_ALGORITHM]
            )

            user_id = payload.get("sub")
            if not user_id:
                return None

            # Check if labels need refresh
            auth_time = datetime.fromtimestamp(payload.get("iat", 0))
            labels_resolved_at = datetime.fromtimestamp(payload.get("labels_resolved_at", 0))

            user = AuthenticatedUser(
                user_id=user_id,
                username=payload.get("username", ""),
                email=payload.get("email"),
                groups=set(payload.get("groups", [])),
                labels=set(payload.get("labels", [])),
                auth_time=auth_time,
                labels_resolved_at=labels_resolved_at,
            )

            # Refresh labels if needed
            if user.needs_label_refresh():
                user = self._refresh_user_labels(user)

            return user

        except pyjwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except pyjwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return None

    def _authenticate_with_xgt(self, xgt_ops, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user against XGT server."""
        try:
            # Query XGT for user authentication
            # This would typically check a users table/frame in XGT
            query = """
            MATCH (u:User {username: $username, password: $password})
            RETURN u.user_id as user_id, u.email as email, u.active as active
            """

            result = xgt_ops._execute_query_sync(
                query, {"username": username, "password": password}
            )

            if result and len(result) > 0:
                user_data = result[0]
                if user_data.get("active", True):  # Default to active if not specified
                    return {
                        "success": True,
                        "user_id": user_data["user_id"],
                        "email": user_data.get("email"),
                    }
                else:
                    return {"success": False, "error": "User account is inactive"}
            else:
                return {"success": False, "error": "Invalid username or password"}

        except Exception as e:
            logger.error(f"XGT authentication error: {e}")
            return {"success": False, "error": str(e)}

    def _get_user_groups(self, xgt_ops, user_id: str) -> list[UserGroup]:
        """Get groups that a user belongs to."""
        try:
            # Query XGT for user's group memberships
            query = """
            MATCH (u:User {user_id: $user_id})-[r:ISINGROUP]->(g:Group)
            RETURN g.group_id as group_id, g.group_name as group_name, g.description as description
            """

            result = xgt_ops._execute_query_sync(query, {"user_id": user_id})

            groups = []
            for row in result:
                group = UserGroup(
                    group_id=row["group_id"],
                    group_name=row["group_name"],
                    description=row.get("description"),
                )
                groups.append(group)

            return groups

        except Exception as e:
            logger.error(f"Error getting user groups: {e}")
            return []

    def _resolve_user_labels(self, xgt_ops, user_groups: list[UserGroup]) -> Set[str]:
        """Resolve security labels from user's groups."""
        all_labels = set()

        for group in user_groups:
            # Check cache first
            if group.group_id in self._group_label_cache:
                group_labels = self._group_label_cache[group.group_id]
            else:
                # Query XGT for group's labels
                group_labels = self._get_group_labels(xgt_ops, group.group_id)
                # Cache the result
                self._group_label_cache[group.group_id] = group_labels

            all_labels.update(group_labels)

        return all_labels

    def _get_group_labels(self, xgt_ops, group_id: str) -> Set[str]:
        """Get security labels for a specific group."""
        try:
            # Query XGT for group's labels
            query = """
            MATCH (g:Group {group_id: $group_id})-[r:CONTAINS]->(l:Label)
            RETURN l.label_name as label_name
            """

            result = xgt_ops._execute_query_sync(query, {"group_id": group_id})

            labels = set()
            for row in result:
                labels.add(row["label_name"])

            return labels

        except Exception as e:
            logger.error(f"Error getting group labels for {group_id}: {e}")
            return set()

    def _refresh_user_labels(self, user: AuthenticatedUser) -> AuthenticatedUser:
        """Refresh user's labels from XGT server."""
        try:
            xgt_ops = create_xgt_operations()

            # Get updated groups for user
            user_groups = self._get_user_groups(xgt_ops, user.user_id)

            # Resolve updated labels
            updated_labels = self._resolve_user_labels(xgt_ops, user_groups)

            # Update user object
            user.groups = set(group.group_id for group in user_groups)
            user.labels = updated_labels
            user.labels_resolved_at = datetime.utcnow()

            # Update cache
            self._label_cache[user.user_id] = updated_labels

            logger.info(f"Refreshed labels for user {user.username}: {len(updated_labels)} labels")

            return user

        except Exception as e:
            logger.error(f"Error refreshing user labels: {e}")
            # Return user with existing labels if refresh fails
            return user

    def _generate_jwt_token(self, user: AuthenticatedUser) -> str:
        """Generate JWT token for authenticated user."""
        now = datetime.utcnow()
        payload = {
            "sub": user.user_id,
            "username": user.username,
            "email": user.email,
            "groups": list(user.groups),
            "labels": list(user.labels),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=self.settings.JWT_EXPIRY_SECONDS)).timestamp()),
            "labels_resolved_at": int(user.labels_resolved_at.timestamp())
            if user.labels_resolved_at
            else int(now.timestamp()),
        }

        token = pyjwt.encode(
            payload, self.settings.JWT_SECRET_KEY, algorithm=self.settings.JWT_ALGORITHM
        )

        return token

    def check_frame_permission(
        self, user: AuthenticatedUser, frame_acl: "FrameACL", operation: str
    ) -> bool:
        """Check if user has permission for a frame operation."""
        return frame_acl.check_permission(operation, user.labels)

    def get_user_labels(self, user_id: str) -> Set[str]:
        """Get cached labels for a user."""
        return self._label_cache.get(user_id, set())


# Global authentication service instance
_auth_service = None


def get_auth_service() -> AuthenticationService:
    """Get the global authentication service instance."""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthenticationService()
    return _auth_service
