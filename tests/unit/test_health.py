"""
Unit tests for health check endpoints.

Tests the health, readiness, liveness, and version endpoints
with various scenarios including service failures and XGT connection issues.
"""

import os
import sys
import time
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Mock the problematic imports before importing app modules
with patch.dict('sys.modules', {'xgt_connector': Mock(), 'xgt': Mock()}):
    from app.api.main import app
    from app.config.app_config import Settings


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    return Settings(
        APP_NAME="RocketGraph Public API",
        APP_VERSION="1.0.0",
        ENVIRONMENT="test",
        SECRET_KEY="test-secret-key",
        API_KEY_SALT="test-salt",
        XGT_HOST="localhost",
        XGT_PORT=4367,
        XGT_USERNAME="test",
        XGT_PASSWORD="test",
        MONGODB_URI="mongodb://localhost:27017/test",
        REDIS_URL="redis://localhost:6379"
    )


class TestHealthEndpoint:
    """Test health check endpoint."""

    @patch('app.api.v1.public.health.get_settings')
    def test_health_check_all_services_healthy(self, mock_get_settings, client):
        """Test health check when all services are healthy."""
        mock_settings = Mock()
        mock_settings.APP_VERSION = "1.0.0"
        mock_settings.XGT_USERNAME = "admin"
        mock_settings.XGT_PASSWORD = "password"
        mock_settings.XGT_USE_SSL = False
        mock_settings.XGT_HOST = "localhost"
        mock_settings.XGT_PORT = 4367
        mock_get_settings.return_value = mock_settings

        # Mock XGT at sys.modules level since it's imported dynamically
        mock_xgt = Mock()
        mock_connection = Mock()
        mock_connection.server_version = "2.3.1"
        mock_connection.server_protocol = (1, 1, 0)  # Server protocol (compatible)
        mock_xgt.Connection.return_value = mock_connection
        mock_xgt.BasicAuth.return_value = Mock()
        mock_xgt.__version__ = "2.3.0"

        # Mock the connection module with client protocol
        mock_xgt_connection = Mock()
        mock_xgt_connection.__protobuf_version__ = (1, 1, 0)  # Client protocol
        mock_xgt.connection = mock_xgt_connection

        with patch.dict('sys.modules', {'xgt': mock_xgt, 'xgt.connection': mock_xgt_connection}):
            response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert "timestamp" in data
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], float)

        assert data["services"]["api"] == "healthy"
        assert data["services"]["xgt"].startswith("healthy (server:v")
        assert "protocol:(1, 1, 0)" in data["services"]["xgt"]
        assert "client_protocol:(1, 1, 0)" in data["services"]["xgt"]
        assert data["services"]["mongodb"] == "healthy"
        assert data["services"]["redis"] == "healthy"

    @patch('app.api.v1.public.health.get_settings')
    def test_health_check_xgt_unavailable(self, mock_get_settings, client):
        """Test health check when XGT is not available (development scenario)."""
        mock_settings = Mock()
        mock_settings.APP_VERSION = "1.0.0"
        mock_get_settings.return_value = mock_settings

        # This test verifies that our health check gracefully handles the actual case
        # where XGT is available but the server isn't running (which will be the common case)
        mock_xgt = Mock()
        mock_xgt.Connection.side_effect = Exception("Connection refused")
        mock_xgt.BasicAuth.return_value = Mock()

        with patch.dict('sys.modules', {'xgt': mock_xgt}):
            response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "degraded"
        assert "Connection refused" in data["services"]["xgt"]

    @patch('app.api.v1.public.health.get_settings')
    def test_health_check_xgt_connection_error(self, mock_get_settings, client):
        """Test health check when XGT connection fails."""
        mock_settings = Mock()
        mock_settings.APP_VERSION = "1.0.0"
        mock_settings.XGT_USERNAME = "admin"
        mock_settings.XGT_PASSWORD = "password"
        mock_settings.XGT_USE_SSL = False
        mock_settings.XGT_HOST = "localhost"
        mock_settings.XGT_PORT = 4367
        mock_get_settings.return_value = mock_settings

        # Mock XGT connection to raise connection error
        mock_xgt = Mock()
        mock_xgt.Connection.side_effect = Exception("Connection refused")
        mock_xgt.BasicAuth.return_value = Mock()

        with patch.dict('sys.modules', {'xgt': mock_xgt}):
            response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "degraded"
        assert data["services"]["xgt"] == "unhealthy: Connection refused"

    @patch('app.api.v1.public.health.get_settings')
    def test_health_check_critical_failure(self, mock_get_settings, client):
        """Test health check when critical services fail."""
        mock_settings = Mock()
        mock_settings.APP_VERSION = "1.0.0"
        mock_settings.XGT_USERNAME = "admin"
        mock_settings.XGT_PASSWORD = "password"
        mock_settings.XGT_USE_SSL = False
        mock_settings.XGT_HOST = "localhost"
        mock_settings.XGT_PORT = 4367
        mock_get_settings.return_value = mock_settings

        # Mock XGT connection to raise critical failure
        mock_xgt = Mock()
        mock_xgt.Connection.side_effect = Exception("Critical XGT failure")
        mock_xgt.BasicAuth.return_value = Mock()

        with patch.dict('sys.modules', {'xgt': mock_xgt}):
            response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        # XGT failure should result in degraded status
        assert data["status"] == "degraded"
        assert "Critical XGT failure" in data["services"]["xgt"]

    @patch('app.api.v1.public.health.get_settings')
    def test_health_check_version_mismatch(self, mock_get_settings, client):
        """Test health check when XGT SDK and server versions are incompatible."""
        mock_settings = Mock()
        mock_settings.APP_VERSION = "1.0.0"
        mock_settings.XGT_USERNAME = "admin"
        mock_settings.XGT_PASSWORD = "password"
        mock_settings.XGT_USE_SSL = False
        mock_settings.XGT_HOST = "localhost"
        mock_settings.XGT_PORT = 4367
        mock_get_settings.return_value = mock_settings

        # Mock XGT with protocol incompatibility (server < client)
        mock_xgt = Mock()
        mock_connection = Mock()
        mock_connection.server_version = "2.2.0"
        mock_connection.server_protocol = (1, 0, 0)  # Older server protocol
        mock_xgt.Connection.return_value = mock_connection
        mock_xgt.BasicAuth.return_value = Mock()
        mock_xgt.__version__ = "2.3.0"

        # Mock newer client protocol
        mock_xgt_connection = Mock()
        mock_xgt_connection.__protobuf_version__ = (1, 1, 0)  # Newer client protocol
        mock_xgt.connection = mock_xgt_connection

        with patch.dict('sys.modules', {'xgt': mock_xgt, 'xgt.connection': mock_xgt_connection}):
            response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "degraded"
        assert "degraded: protocol incompatible" in data["services"]["xgt"]
        assert "server:(1, 0, 0) < client:(1, 1, 0)" in data["services"]["xgt"]

    @patch('app.api.v1.public.health.get_settings')
    def test_health_check_version_compatible_patch(self, mock_get_settings, client):
        """Test health check when patch versions differ but major.minor match."""
        mock_settings = Mock()
        mock_settings.APP_VERSION = "1.0.0"
        mock_settings.XGT_USERNAME = "admin"
        mock_settings.XGT_PASSWORD = "password"
        mock_settings.XGT_USE_SSL = False
        mock_settings.XGT_HOST = "localhost"
        mock_settings.XGT_PORT = 4367
        mock_get_settings.return_value = mock_settings

        # Mock XGT with compatible protocols (server >= client)
        mock_xgt = Mock()
        mock_connection = Mock()
        mock_connection.server_version = "2.3.5"
        mock_connection.server_protocol = (1, 2, 0)  # Newer server protocol
        mock_xgt.Connection.return_value = mock_connection
        mock_xgt.BasicAuth.return_value = Mock()
        mock_xgt.__version__ = "2.3.0"

        # Mock older client protocol
        mock_xgt_connection = Mock()
        mock_xgt_connection.__protobuf_version__ = (1, 1, 0)  # Older client protocol
        mock_xgt.connection = mock_xgt_connection

        with patch.dict('sys.modules', {'xgt': mock_xgt, 'xgt.connection': mock_xgt_connection}):
            response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "healthy (server:v2.3.5 protocol:(1, 2, 0), sdk:v2.3.0 client_protocol:(1, 1, 0))" in data["services"]["xgt"]

    @patch('app.api.v1.public.health.get_settings')
    def test_health_check_malformed_version(self, mock_get_settings, client):
        """Test health check when version strings are malformed."""
        mock_settings = Mock()
        mock_settings.APP_VERSION = "1.0.0"
        mock_settings.XGT_USERNAME = "admin"
        mock_settings.XGT_PASSWORD = "password"
        mock_settings.XGT_USE_SSL = False
        mock_settings.XGT_HOST = "localhost"
        mock_settings.XGT_PORT = 4367
        mock_get_settings.return_value = mock_settings

        # Mock XGT with malformed protocol (empty tuple)
        mock_xgt = Mock()
        mock_connection = Mock()
        mock_connection.server_version = "dev-build"
        mock_connection.server_protocol = ()  # Malformed protocol
        mock_xgt.Connection.return_value = mock_connection
        mock_xgt.BasicAuth.return_value = Mock()
        mock_xgt.__version__ = "2.3.0"

        # Mock connection module
        mock_xgt_connection = Mock()
        mock_xgt_connection.__protobuf_version__ = (1, 1, 0)
        mock_xgt.connection = mock_xgt_connection

        with patch.dict('sys.modules', {'xgt': mock_xgt, 'xgt.connection': mock_xgt_connection}):
            response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        # Should fallback gracefully and still report as healthy
        assert data["status"] == "healthy"
        assert "server:vdev-build" in data["services"]["xgt"]
        assert "sdk:v2.3.0" in data["services"]["xgt"]

    def test_health_check_response_structure(self, client):
        """Test that health check response has correct structure."""
        response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        # Check required fields
        required_fields = ["status", "timestamp", "version", "uptime_seconds", "services"]
        for field in required_fields:
            assert field in data

        # Check services structure
        required_services = ["api", "xgt", "mongodb", "redis"]
        for service in required_services:
            assert service in data["services"]

        # Check data types
        assert isinstance(data["uptime_seconds"], float)
        assert data["uptime_seconds"] >= 0


class TestReadinessEndpoint:
    """Test readiness check endpoint."""

    def test_readiness_check_success(self, client):
        """Test successful readiness check."""
        response = client.get("/api/v1/public/ready")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "ready"
        assert data["ready"] is True

        # Check all required checks
        required_checks = ["startup_complete", "configuration_loaded", "dependencies_available"]
        for check in required_checks:
            assert check in data["checks"]
            assert data["checks"][check] is True

    def test_readiness_check_response_structure(self, client):
        """Test readiness check response structure."""
        response = client.get("/api/v1/public/ready")

        assert response.status_code == 200
        data = response.json()

        # Check required fields
        required_fields = ["status", "ready", "checks"]
        for field in required_fields:
            assert field in data

        # Check data types
        assert isinstance(data["ready"], bool)
        assert isinstance(data["checks"], dict)


class TestLivenessEndpoint:
    """Test liveness check endpoint."""

    def test_liveness_check_success(self, client):
        """Test successful liveness check."""
        response = client.get("/api/v1/public/live")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "alive"
        assert "timestamp" in data

    def test_liveness_check_response_structure(self, client):
        """Test liveness check response structure."""
        response = client.get("/api/v1/public/live")

        assert response.status_code == 200
        data = response.json()

        # Check required fields
        required_fields = ["status", "timestamp"]
        for field in required_fields:
            assert field in data

        assert data["status"] == "alive"


class TestVersionEndpoint:
    """Test version information endpoint."""

    @patch('app.api.v1.public.health.get_settings')
    def test_version_info_success(self, mock_get_settings, client):
        """Test successful version info retrieval with comprehensive version data."""
        mock_settings = Mock()
        mock_settings.APP_NAME = "RocketGraph Public API"
        mock_settings.APP_VERSION = "1.0.0"
        mock_settings.ENVIRONMENT = "test"
        mock_settings.XGT_USERNAME = "admin"
        mock_settings.XGT_PASSWORD = "password"
        mock_settings.XGT_USE_SSL = False
        mock_settings.XGT_HOST = "localhost"
        mock_settings.XGT_PORT = 4367
        mock_get_settings.return_value = mock_settings

        # Mock XGT for version endpoint
        mock_xgt = Mock()
        mock_connection = Mock()
        mock_connection.server_version = "2.3.1"
        mock_connection.server_protocol = (1, 1, 0)
        mock_xgt.Connection.return_value = mock_connection
        mock_xgt.BasicAuth.return_value = Mock()
        mock_xgt.__version__ = "2.3.0"

        # Mock connection module
        mock_xgt_connection = Mock()
        mock_xgt_connection.__protobuf_version__ = (1, 1, 0)
        mock_xgt.connection = mock_xgt_connection

        with patch.dict('sys.modules', {'xgt': mock_xgt, 'xgt.connection': mock_xgt_connection}):
            response = client.get("/api/v1/public/version")

        assert response.status_code == 200
        data = response.json()

        # Check API version info
        assert "api" in data
        assert data["api"]["name"] == "RocketGraph Public API"
        assert data["api"]["version"] == "1.0.0"
        assert data["api"]["environment"] == "test"
        assert "uptime_seconds" in data["api"]
        assert isinstance(data["api"]["uptime_seconds"], float)
        assert "build_timestamp" in data["api"]

        # Check XGT version info
        assert "xgt" in data
        assert data["xgt"]["server_version"] == "2.3.1"
        assert data["xgt"]["server_protocol"] == [1, 1, 0]
        assert data["xgt"]["sdk_version"] == "2.3.0"
        assert data["xgt"]["client_protocol"] == [1, 1, 0]
        assert data["xgt"]["connection_status"] == "connected"
        assert data["xgt"]["protocol_compatible"] is True

        # Check system info
        assert "system" in data
        assert "python_version" in data["system"]
        assert "platform" in data["system"]

    def test_version_info_response_structure(self, client):
        """Test version info response structure."""
        response = client.get("/api/v1/public/version")

        assert response.status_code == 200
        data = response.json()

        # Check top-level structure
        required_sections = ["api", "xgt", "system"]
        for section in required_sections:
            assert section in data

        # Check API section
        api_fields = ["name", "version", "environment", "uptime_seconds", "build_timestamp"]
        for field in api_fields:
            assert field in data["api"]

        # Check XGT section (basic structure)
        xgt_fields = ["server_version", "server_protocol", "sdk_version", "client_protocol", "connection_status"]
        for field in xgt_fields:
            assert field in data["xgt"]

        # Check system section
        system_fields = ["python_version", "platform"]
        for field in system_fields:
            assert field in data["system"]

        # Check data types
        assert isinstance(data["api"]["uptime_seconds"], float)
        assert data["api"]["uptime_seconds"] >= 0

    def test_version_info_xgt_unavailable(self, client):
        """Test version info when XGT is not available."""
        response = client.get("/api/v1/public/version")

        assert response.status_code == 200
        data = response.json()

        # Should still return structure with XGT unavailable
        assert "api" in data
        assert "xgt" in data
        assert "system" in data

        # XGT should show as unavailable
        assert data["xgt"]["connection_status"] in ["sdk_not_available", "error", "disconnected"]


class TestHealthEndpointIntegration:
    """Integration tests for health endpoints."""

    def test_all_health_endpoints_accessible(self, client):
        """Test that all health endpoints are accessible."""
        endpoints = [
            "/api/v1/public/health",
            "/api/v1/public/ready",
            "/api/v1/public/live",
            "/api/v1/public/version"
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == 200, f"Endpoint {endpoint} failed"

    def test_health_check_timing(self, client):
        """Test that health check responds within reasonable time."""
        start_time = time.time()
        response = client.get("/api/v1/public/health")
        end_time = time.time()

        assert response.status_code == 200
        assert (end_time - start_time) < 5.0  # Should respond within 5 seconds

    @patch('app.api.v1.public.health.get_settings')
    def test_health_check_error_handling(self, mock_get_settings, client):
        """Test health check handles various error types gracefully."""
        mock_settings = Mock()
        mock_settings.APP_VERSION = "1.0.0"
        mock_settings.XGT_USERNAME = "admin"
        mock_settings.XGT_PASSWORD = "password"
        mock_settings.XGT_USE_SSL = False
        mock_settings.XGT_HOST = "localhost"
        mock_settings.XGT_PORT = 4367
        mock_get_settings.return_value = mock_settings

        # Test with different exception types
        error_scenarios = [
            ConnectionError("Cannot connect to XGT"),
            TimeoutError("XGT connection timeout"),
            Exception("Generic XGT error")
        ]

        for error in error_scenarios:
            mock_xgt = Mock()
            mock_xgt.Connection.side_effect = error
            mock_xgt.BasicAuth.return_value = Mock()

            with patch.dict('sys.modules', {'xgt': mock_xgt}):
                response = client.get("/api/v1/public/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] in ["degraded", "unhealthy"]
            assert str(error) in data["services"]["xgt"]
