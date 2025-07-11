"""
Health check endpoints for the RocketGraph Public API.

Provides system health status and readiness checks for monitoring
and load balancer health probes.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Dict, Optional
import time
import asyncio
from datetime import datetime, timezone

from ....config.app_config import get_settings
from ....utils.exceptions import XGTConnectionError

router = APIRouter()


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str
    timestamp: datetime
    version: str
    uptime_seconds: float
    services: Dict[str, str]


class ReadinessResponse(BaseModel):
    """Readiness check response model."""
    status: str
    ready: bool
    checks: Dict[str, bool]


# Track application start time
_start_time = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Comprehensive health check endpoint.
    
    Returns detailed health information about the API and its dependencies.
    Suitable for monitoring systems that need detailed status information.
    
    Returns:
        HealthResponse: Detailed health status
    """
    settings = get_settings()
    start_check_time = time.time()
    
    # Initialize service status
    services = {
        "api": "healthy",
        "xgt": "unknown",
        "mongodb": "unknown", 
        "redis": "unknown"
    }
    
    overall_status = "healthy"
    
    # Check XGT connection
    try:
        import xgt
        
        # Test actual XGT server connectivity without namespace
        auth = xgt.BasicAuth(
            username=settings.XGT_USERNAME,
            password=settings.XGT_PASSWORD
        )
        
        conn_flags = {}
        if settings.XGT_USE_SSL:
            conn_flags = {
                'ssl': True,
                'ssl_server_cert': settings.XGT_SSL_CERT,
                'ssl_server_cn': settings.XGT_SERVER_CN
            }
        
        connection = xgt.Connection(
            host=settings.XGT_HOST,
            port=settings.XGT_PORT,
            auth=auth,
            flags=conn_flags
        )
        
        # Test actual server connectivity and protocol compatibility
        server_version = connection.server_version
        server_protocol = connection.server_protocol  # e.g., (1, 1, 0)
        sdk_version = xgt.__version__
        
        # Get the actual client protocol version from SDK
        import xgt.connection
        client_protocol = xgt.connection.__protobuf_version__  # e.g., (1, 1, 0)
        
        # Use same compatibility logic as SDK: server_protocol >= client_protocol
        if server_protocol and client_protocol and len(server_protocol) >= 2 and len(client_protocol) >= 2:
            # Compare as tuples - Python does lexicographic comparison
            protocol_compatible = server_protocol >= client_protocol
            
            if protocol_compatible:
                services["xgt"] = f"healthy (server:v{server_version} protocol:{server_protocol}, sdk:v{sdk_version} client_protocol:{client_protocol})"
            else:
                services["xgt"] = f"degraded: protocol incompatible (server:{server_protocol} < client:{client_protocol})"
                overall_status = "degraded"
        else:
            # Fallback if protocol parsing fails
            services["xgt"] = f"healthy (server:v{server_version}, sdk:v{sdk_version})"
        
    except ImportError:
        services["xgt"] = "unhealthy: XGT library not available"
        overall_status = "degraded" if overall_status == "healthy" else overall_status
    except Exception as e:
        services["xgt"] = f"unhealthy: {str(e)}"
        if "Connection refused" in str(e) or "timeout" in str(e).lower():
            # Real server connectivity issue
            overall_status = "degraded"
        else:
            # Other connection error
            overall_status = "degraded"
    
    # Check MongoDB connection
    try:
        # This would be a quick MongoDB ping
        # For now, assume healthy
        services["mongodb"] = "healthy"
    except Exception:
        services["mongodb"] = "unhealthy"
        overall_status = "degraded"
    
    # Check Redis connection
    try:
        # This would be a quick Redis ping
        # For now, assume healthy
        services["redis"] = "healthy"
    except Exception:
        services["redis"] = "unhealthy"
        # Redis is not critical for basic functionality
        if overall_status == "healthy":
            overall_status = "degraded"
    
    # If any critical service is down, mark as unhealthy
    if services["xgt"] == "unhealthy":
        overall_status = "unhealthy"
    
    return HealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        version=settings.APP_VERSION,
        uptime_seconds=time.time() - _start_time,
        services=services
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check():
    """
    Kubernetes readiness probe endpoint.
    
    Checks if the service is ready to receive traffic.
    Should return 200 when ready, 503 when not ready.
    
    Returns:
        ReadinessResponse: Readiness status
    """
    checks = {
        "startup_complete": True,  # Always true once we're running
        "configuration_loaded": True,  # Always true if we got this far
        "dependencies_available": True  # Could check critical dependencies
    }
    
    # All checks must pass for ready status
    ready = all(checks.values())
    status = "ready" if ready else "not_ready"
    
    return ReadinessResponse(
        status=status,
        ready=ready,
        checks=checks
    )


@router.get("/live")
async def liveness_check():
    """
    Kubernetes liveness probe endpoint.
    
    Simple endpoint that returns 200 if the service is alive.
    If this fails, Kubernetes will restart the container.
    
    Returns:
        Simple status response
    """
    return {"status": "alive", "timestamp": datetime.now(timezone.utc)}


@router.get("/version")
async def version_info():
    """
    Get API version information.
    
    Returns basic version and build information for the API.
    
    Returns:
        Version information
    """
    settings = get_settings()
    
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "uptime_seconds": time.time() - _start_time
    }