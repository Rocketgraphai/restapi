"""
Shared pytest configuration and fixtures.
"""

import asyncio
from collections.abc import AsyncGenerator

from fastapi.testclient import TestClient
from httpx import AsyncClient
import pytest

from app.api.main import app


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def client() -> TestClient:
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client for the FastAPI app."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_settings():
    """Mock application settings for testing."""
    from app.config.app_config import Settings

    return Settings(
        APP_NAME="Test API",
        APP_VERSION="0.1.0",
        ENVIRONMENT="testing",
        SECRET_KEY="test-secret-key",
        API_KEY_SALT="test-salt",
        XGT_HOST="localhost",
        XGT_PORT=4367,
        XGT_USERNAME="test",
        XGT_PASSWORD="test",
        MONGODB_URI="mongodb://localhost:27017/test",
        REDIS_URL="redis://localhost:6379",
    )


@pytest.fixture(autouse=True)
def reset_settings():
    """Reset settings after each test."""
    yield
    # Clear any cached settings
    from app.config import app_config

    app_config._settings = None
