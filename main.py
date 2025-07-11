"""
RocketGraph Public API

Main application entry point for the RocketGraph Public API.
Provides secure, scalable REST API access to graph database operations.
"""

import uvicorn
from app.config.app_config import get_settings


def main():
    """Main entry point for the application."""
    settings = get_settings()
    
    uvicorn.run(
        "app.api.main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS if not settings.DEBUG else 1,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True
    )


if __name__ == "__main__":
    main()