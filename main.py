"""
RocketGraph Public API

Main application entry point for the RocketGraph Public API.
Provides secure, scalable REST API access to graph database operations.
Supports both REST API and MCP (Model Context Protocol) modes.
"""

import asyncio
import sys
import uvicorn

from app.config.app_config import get_settings


async def run_mcp_server():
    """Run MCP server in stdio mode."""
    from app.api.mcp_server import run_mcp_server
    await run_mcp_server()


def run_rest_server():
    """Run REST API server."""
    settings = get_settings()
    
    uvicorn.run(
        "app.api.main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=1,  # Force single worker for hybrid mode
        reload=False,  # Disable reload for hybrid mode
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
    )


async def run_rest_server_async():
    """Run REST API server in async mode for hybrid operation."""
    settings = get_settings()
    
    # Import here to avoid circular imports
    import uvicorn
    from app.api.main import app
    
    # Create uvicorn config for async operation
    config = uvicorn.Config(
        app=app,
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
    )
    
    # Create and run server
    server = uvicorn.Server(config)
    await server.serve()


async def run_hybrid_server():
    """Run both REST and MCP servers concurrently."""
    print("Starting REST API server...")
    print("Starting MCP server...")
    
    # Create tasks for both servers
    rest_task = asyncio.create_task(run_rest_server_async())
    mcp_task = asyncio.create_task(run_mcp_server())
    
    # Run both concurrently
    await asyncio.gather(rest_task, mcp_task)


def determine_mode() -> str:
    """Determine runtime mode from command line arguments and settings."""
    settings = get_settings()
    
    if "--mcp-only" in sys.argv:
        return "mcp"
    elif "--rest-only" in sys.argv:
        return "rest"
    elif "--hybrid" in sys.argv:
        return "hybrid"
    elif settings.MCP_ENABLED:
        # Default to hybrid mode when MCP is enabled - provides both REST and MCP
        return "hybrid"
    else:
        # Fallback to REST-only mode when MCP is disabled
        return "rest"


def main():
    """Main entry point for the application."""
    mode = determine_mode()
    
    if mode == "mcp":
        print("Starting RocketGraph MCP server...")
        asyncio.run(run_mcp_server())
    elif mode == "hybrid":
        print("Starting RocketGraph in hybrid mode (REST + MCP)...")
        asyncio.run(run_hybrid_server())
    else:
        print("Starting RocketGraph REST API server...")
        run_rest_server()


if __name__ == "__main__":
    main()
