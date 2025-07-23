"""
Authentication models for the RocketGraph Public API.

Implements User -> Group -> Label based access control.
"""

from datetime import datetime, timedelta
from typing import Optional

from pydantic import BaseModel, Field


class AuthenticatedUser(BaseModel):
    """Represents an authenticated user with resolved permissions."""

    user_id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., description="Username")
    email: Optional[str] = Field(None, description="User email address")
    groups: set[str] = Field(default_factory=set, description="Groups user belongs to")
    labels: set[str] = Field(
        default_factory=set, description="Security labels resolved from groups"
    )
    auth_time: datetime = Field(
        default_factory=datetime.utcnow, description="When user was authenticated"
    )
    labels_resolved_at: Optional[datetime] = Field(
        None, description="When labels were last resolved"
    )

    def has_label(self, label: str) -> bool:
        """Check if user has a specific security label."""
        return label in self.labels

    def has_any_label(self, labels: set[str]) -> bool:
        """Check if user has any of the specified labels."""
        return bool(self.labels.intersection(labels))

    def has_all_labels(self, labels: set[str]) -> bool:
        """Check if user has all of the specified labels."""
        return labels.issubset(self.labels)

    def needs_label_refresh(self, ttl_minutes: int = 15) -> bool:
        """Check if user's labels need to be refreshed."""
        if self.labels_resolved_at is None:
            return True
        return datetime.utcnow() - self.labels_resolved_at > timedelta(minutes=ttl_minutes)


class UserGroup(BaseModel):
    """Represents a user group."""

    group_id: str = Field(..., description="Unique group identifier")
    group_name: str = Field(..., description="Group name")
    description: Optional[str] = Field(None, description="Group description")
    labels: set[str] = Field(default_factory=set, description="Security labels this group contains")


class SecurityLabel(BaseModel):
    """Represents a security label/permission."""

    label_id: str = Field(..., description="Unique label identifier")
    label_name: str = Field(..., description="Label name")
    description: Optional[str] = Field(None, description="Label description")
    category: Optional[str] = Field(
        None, description="Label category (role, clearance, department, etc.)"
    )


class AuthenticationRequest(BaseModel):
    """Request model for authentication."""

    username: str = Field(..., description="Username", min_length=1)
    password: str = Field(..., description="Password", min_length=1)


class AuthenticationResponse(BaseModel):
    """Response model for successful authentication."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    user: AuthenticatedUser = Field(..., description="Authenticated user details")


class TokenValidationResponse(BaseModel):
    """Response model for token validation."""

    valid: bool = Field(..., description="Whether token is valid")
    user: Optional[AuthenticatedUser] = Field(None, description="User details if token is valid")
    error: Optional[str] = Field(None, description="Error message if token is invalid")


class FrameACL(BaseModel):
    """Access Control List for a frame."""

    create: set[str] = Field(
        default_factory=set, description="Labels required for CREATE operations"
    )
    read: set[str] = Field(default_factory=set, description="Labels required for READ operations")
    update: set[str] = Field(
        default_factory=set, description="Labels required for UPDATE operations"
    )
    delete: set[str] = Field(
        default_factory=set, description="Labels required for DELETE operations"
    )

    def can_create(self, user_labels: set[str]) -> bool:
        """Check if user can create based on labels."""
        if not self.create:  # Empty ACL = open access
            return True
        return bool(user_labels.intersection(self.create))

    def can_read(self, user_labels: set[str]) -> bool:
        """Check if user can read based on labels."""
        if not self.read:  # Empty ACL = open access
            return True
        return bool(user_labels.intersection(self.read))

    def can_update(self, user_labels: set[str]) -> bool:
        """Check if user can update based on labels."""
        if not self.update:  # Empty ACL = open access
            return True
        return bool(user_labels.intersection(self.update))

    def can_delete(self, user_labels: set[str]) -> bool:
        """Check if user can delete based on labels."""
        if not self.delete:  # Empty ACL = open access
            return True
        return bool(user_labels.intersection(self.delete))

    def check_permission(self, operation: str, user_labels: set[str]) -> bool:
        """Check permission for a specific operation."""
        operation = operation.lower()
        if operation == "create":
            return self.can_create(user_labels)
        elif operation == "read":
            return self.can_read(user_labels)
        elif operation == "update":
            return self.can_update(user_labels)
        elif operation == "delete":
            return self.can_delete(user_labels)
        else:
            return False
