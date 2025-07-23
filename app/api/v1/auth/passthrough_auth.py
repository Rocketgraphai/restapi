"""
Pass-through authentication endpoints for XGT credentials.

Provides authentication endpoints that validate user credentials directly
against XGT server and return JWT tokens for API access.
"""

from datetime import datetime
import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, status
from pydantic import BaseModel, Field

from ....auth.passthrough import PassthroughAuthService, get_passthrough_auth_service
from ....auth.passthrough_middleware import get_current_xgt_user, require_xgt_authentication
from ....auth.passthrough_models import (
    AuthenticatedXGTUser,
    XGTAuthResponse,
    XGTBasicAuthRequest,
    XGTPKIAuthRequest,
    XGTProxyPKIAuthRequest,
    XGTTokenValidation,
    XGTUserInfo,
)
from ....utils.exceptions import XGTConnectionError, XGTOperationError

router = APIRouter()
logger = logging.getLogger(__name__)


class XGTConnectionTest(BaseModel):
    """Response for XGT connection test."""

    success: bool = Field(..., description="Whether connection test succeeded")
    username: str = Field(..., description="Connected username")
    namespace: str = Field(..., description="User's namespace")
    server_info: dict = Field(..., description="XGT server information")
    auth_type: str = Field(..., description="Authentication type used")


class OAuth2Token(BaseModel):
    """OAuth2-compatible token response for Swagger UI."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiry in seconds")


@router.post("/auth/xgt/basic", response_model=XGTAuthResponse)
async def authenticate_basic(
    auth_request: XGTBasicAuthRequest,
    auth_service: Annotated[PassthroughAuthService, Depends(get_passthrough_auth_service)],
):
    """
    Authenticate using XGT Basic Auth (username/password).

    Tests the provided credentials against the XGT server and returns
    a JWT token containing encrypted credentials for subsequent API calls.

    Args:
        auth_request: Basic authentication credentials

    Returns:
        JWT token and user information

    Raises:
        HTTPException: If authentication fails
    """
    try:
        logger.info(f"Basic auth attempt for user: {auth_request.username}")

        # Authenticate with XGT server
        auth_result = auth_service.authenticate_xgt_user(auth_request)

        return XGTAuthResponse(
            access_token=auth_result["access_token"],
            token_type=auth_result["token_type"],
            expires_in=auth_result["expires_in"],
            user_info=XGTUserInfo(**auth_result["user_info"]),
        )

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server",
                "details": str(e),
            },
        )
    except XGTOperationError as e:
        logger.warning(f"Basic auth failed for {auth_request.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_FAILED",
                "message": "Invalid XGT credentials",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected auth error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "INTERNAL_SERVER_ERROR", "message": "Authentication service error"},
        )


@router.post(
    "/auth/xgt/token",
    response_model=OAuth2Token,
    summary="OAuth2 Password Flow (Swagger UI Compatible)",
    description="OAuth2-compatible endpoint for Swagger UI authentication",
)
async def oauth2_authenticate_basic(
    username: Annotated[str, Form(description="XGT username")],
    password: Annotated[str, Form(description="XGT password")],
    auth_service: Annotated[PassthroughAuthService, Depends(get_passthrough_auth_service)],
):
    """
    OAuth2 Password Flow authentication for Swagger UI.

    This endpoint provides OAuth2-compatible authentication that works
    seamlessly with Swagger UI's built-in authorization flow.

    Just click the "Authorize" button in Swagger UI and enter your
    XGT username and password.
    """
    try:
        logger.info(f"OAuth2 auth attempt for user: {username}")

        # Create auth request from form data
        auth_request = XGTBasicAuthRequest(username=username, password=password)

        # Authenticate with XGT server
        auth_result = auth_service.authenticate_xgt_user(auth_request)

        return OAuth2Token(
            access_token=auth_result["access_token"],
            token_type=auth_result["token_type"],
            expires_in=auth_result["expires_in"],
        )

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server",
                "details": str(e),
            },
        )
    except XGTOperationError as e:
        logger.warning(f"OAuth2 auth failed for {username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_FAILED",
                "message": "Invalid XGT credentials",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected OAuth2 auth error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "INTERNAL_SERVER_ERROR", "message": "Authentication service error"},
        )


@router.post("/auth/xgt/pki", response_model=XGTAuthResponse)
async def authenticate_pki(
    auth_request: XGTPKIAuthRequest,
    auth_service: Annotated[PassthroughAuthService, Depends(get_passthrough_auth_service)],
):
    """
    Authenticate using XGT PKI certificates.

    Validates the provided PKI certificates against the XGT server and
    returns a JWT token containing encrypted certificate data.

    Args:
        auth_request: PKI certificate authentication data

    Returns:
        JWT token and user information

    Raises:
        HTTPException: If authentication fails
    """
    try:
        logger.info("PKI auth attempt")

        # Authenticate with XGT server
        auth_result = auth_service.authenticate_xgt_user(auth_request)

        return XGTAuthResponse(
            access_token=auth_result["access_token"],
            token_type=auth_result["token_type"],
            expires_in=auth_result["expires_in"],
            user_info=XGTUserInfo(**auth_result["user_info"]),
        )

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server with PKI",
                "details": str(e),
            },
        )
    except XGTOperationError as e:
        logger.warning(f"PKI auth failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "PKI_AUTHENTICATION_FAILED",
                "message": "Invalid PKI certificate or configuration",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected PKI auth error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "PKI authentication service error",
            },
        )


@router.post("/auth/xgt/proxy-pki", response_model=XGTAuthResponse)
async def authenticate_proxy_pki(
    auth_request: XGTProxyPKIAuthRequest,
    auth_service: Annotated[PassthroughAuthService, Depends(get_passthrough_auth_service)],
):
    """
    Authenticate using XGT Proxy PKI.

    Validates proxy-provided PKI certificate information against the XGT
    server and returns a JWT token.

    Args:
        auth_request: Proxy PKI authentication data

    Returns:
        JWT token and user information

    Raises:
        HTTPException: If authentication fails
    """
    try:
        logger.info(f"Proxy PKI auth attempt for user: {auth_request.user_id}")

        # Authenticate with XGT server
        auth_result = auth_service.authenticate_xgt_user(auth_request)

        return XGTAuthResponse(
            access_token=auth_result["access_token"],
            token_type=auth_result["token_type"],
            expires_in=auth_result["expires_in"],
            user_info=XGTUserInfo(**auth_result["user_info"]),
        )

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server with Proxy PKI",
                "details": str(e),
            },
        )
    except XGTOperationError as e:
        logger.warning(f"Proxy PKI auth failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "PROXY_PKI_AUTHENTICATION_FAILED",
                "message": "Invalid proxy PKI configuration or signature",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected proxy PKI auth error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Proxy PKI authentication service error",
            },
        )


@router.post("/auth/validate", response_model=XGTTokenValidation)
async def validate_token(
    current_user: Annotated[Optional[AuthenticatedXGTUser], Depends(get_current_xgt_user)],
):
    """
    Validate an XGT authentication token.

    Checks if the provided JWT token is valid and contains valid XGT credentials.
    This endpoint can be used by other services to validate tokens.

    Returns:
        Token validation result with user information if valid
    """
    try:
        if current_user:
            return XGTTokenValidation(
                valid=True,
                username=current_user.username,
                namespace=current_user.namespace,
                authenticated_at=current_user.authenticated_at,
                expires_at=current_user.expires_at,
                error=None,
            )
        else:
            return XGTTokenValidation(
                valid=False,
                username=None,
                namespace=None,
                authenticated_at=None,
                expires_at=None,
                error="Invalid or expired token",
            )
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return XGTTokenValidation(
            valid=False,
            username=None,
            namespace=None,
            authenticated_at=None,
            expires_at=None,
            error="Token validation service error",
        )


@router.get("/auth/me", response_model=XGTUserInfo)
async def get_current_user_info(
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
):
    """
    Get information about the currently authenticated XGT user.

    Returns detailed information about the authenticated user including
    their namespace and authentication metadata.

    Returns:
        Current user information

    Raises:
        HTTPException: If user is not authenticated
    """
    try:
        return XGTUserInfo(
            username=current_user.username,
            namespace=current_user.namespace,
            authenticated_at=datetime.fromtimestamp(current_user.authenticated_at).isoformat(),
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


@router.post("/auth/test-connection", response_model=XGTConnectionTest)
async def test_xgt_connection(
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    auth_service: Annotated[PassthroughAuthService, Depends(get_passthrough_auth_service)],
):
    """
    Test the current user's XGT connection.

    Creates a test connection to XGT using the user's credentials to verify
    they are still valid and gather server information.

    Returns:
        Connection test results and server information

    Raises:
        HTTPException: If connection test fails
    """
    try:
        # Create XGT connection using user's credentials
        connection = auth_service.create_xgt_connection(current_user.credentials)

        # Get server information
        try:
            namespace = getattr(
                connection, "get_default_namespace", lambda: current_user.namespace
            )()
            server_version = getattr(connection, "server_version", "unknown")

            server_info = {"version": str(server_version), "namespace": namespace}
        except Exception as e:
            logger.warning(f"Could not get complete server info: {e}")
            server_info = {"version": "unknown", "namespace": current_user.namespace}

        # Close connection safely
        try:
            if hasattr(connection, "close"):
                connection.close()
        except Exception:
            pass  # Ignore close errors

        return XGTConnectionTest(
            success=True,
            username=current_user.username,
            namespace=current_user.namespace or "default",
            server_info=server_info,
            auth_type=current_user.credentials.auth_type.value,
        )

    except Exception as e:
        logger.error(f"XGT connection test failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "XGT_CONNECTION_TEST_FAILED",
                "message": "Cannot connect to XGT server with current credentials",
                "details": str(e),
            },
        )
