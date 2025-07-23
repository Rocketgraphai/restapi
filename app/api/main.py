"""
Main FastAPI application for the RocketGraph Public API.

Configures the FastAPI app with middleware, routes, and error handling.
"""

from contextlib import asynccontextmanager
import logging
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from ..config.app_config import get_settings
from ..utils.exceptions import BaseAPIException
from .v1.auth import passthrough_auth
from .v1.public import datasets, frames, health, query

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    settings = get_settings()
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    yield
    logger.info("Shutting down RocketGraph Public API")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application
    """
    settings = get_settings()

    # Security schemes are now auto-detected from FastAPI dependencies

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=("Secure REST API for graph database operations using XGT with pass-through authentication"),
        docs_url="/docs" if not settings.is_production else None,  # Disable docs in prod
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # Add security middleware
    if settings.SECURITY_HEADERS_ENABLED:

        @app.middleware("http")
        async def add_security_headers(request: Request, call_next):
            """Add security headers to responses."""
            response = await call_next(request)

            # Security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["X-API-Version"] = settings.APP_VERSION

            if settings.is_production:
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

            return response

    # Add trusted host middleware
    if settings.ALLOWED_HOSTS != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

    # Add CORS middleware
    if settings.CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["*"],
        )

    # Add request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        """Add processing time to response headers."""
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response

    # Global exception handler
    @app.exception_handler(BaseAPIException)
    async def api_exception_handler(request: Request, exc: BaseAPIException):
        """Handle custom API exceptions."""
        return JSONResponse(
            status_code=400,
            content={"error": {"code": exc.error_code, "message": exc.message, "details": exc.details}},
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": f"HTTP_{exc.status_code}", "message": exc.detail, "details": {}}},
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle unexpected exceptions."""
        logger.exception("Unhandled exception occurred")

        if settings.DEBUG:
            # In debug mode, show the actual error
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "INTERNAL_SERVER_ERROR",
                        "message": str(exc),
                        "details": {"type": type(exc).__name__},
                    }
                },
            )
        else:
            # In production, hide internal details
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "INTERNAL_SERVER_ERROR",
                        "message": "An internal server error occurred",
                        "details": {},
                    }
                },
            )

    # Include routers

    # Authentication endpoints (no prefix, public access)
    app.include_router(passthrough_auth.router, prefix="/api/v1", tags=["authentication"])

    # Public endpoints (will require authentication after migration)
    app.include_router(health.router, prefix="/api/v1/public", tags=["health"])

    app.include_router(datasets.router, prefix="/api/v1/public", tags=["datasets"])

    app.include_router(frames.router, prefix="/api/v1/public", tags=["frames"])

    app.include_router(query.router, prefix="/api/v1/public", tags=["query"])

    return app


# Create the app instance
app = create_app()
