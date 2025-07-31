"""
Integration tests for API endpoints.

Tests the full API stack without requiring external dependencies.
"""

import time
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import pytest


class TestAPIEndpointsIntegration:
    """Integration tests for API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client for the API with mocked authentication."""
        from app.api.main import app
        from app.auth.passthrough_middleware import require_xgt_authentication
        from app.auth.passthrough_models import AuthenticatedXGTUser, XGTAuthType

        # Create a mock user for testing
        mock_credentials = Mock()
        mock_credentials.auth_type = XGTAuthType.BASIC
        mock_credentials.username = "test_user"
        mock_credentials.password = "test_password"

        mock_user = AuthenticatedXGTUser(
            username="test_user",
            authenticated_at=time.time(),
            expires_at=time.time() + 3600,
            credentials=mock_credentials,
        )

        # Override the authentication dependency
        app.dependency_overrides[require_xgt_authentication] = lambda: mock_user

        yield TestClient(app)

        # Clean up dependency overrides
        app.dependency_overrides.clear()

    @patch("app.utils.xgt_operations.xgt")
    def test_graphs_endpoint_integration(self, mock_xgt, client):
        """Test graphs endpoint with mocked XGT but real API stack."""
        # Mock XGT connection and operations
        mock_connection = Mock()
        mock_connection.get_namespaces.return_value = ["admin", "test_namespace"]
        mock_connection.get_default_namespace.return_value = "admin"
        mock_connection.get_frames.return_value = []
        mock_connection.close = Mock()

        mock_xgt.Connection.return_value = mock_connection
        mock_xgt.BasicAuth.return_value = Mock()

        # Test the full API request
        response = client.get("/api/v1/public/graphs")

        assert response.status_code == 200
        data = response.json()

        assert "graphs" in data
        assert "total_count" in data
        assert isinstance(data["graphs"], list)
        assert data["total_count"] == 0  # No frames in mock

    @patch("app.utils.xgt_operations.xgt")
    def test_graphs_with_data_integration(self, mock_xgt, client):
        """Test graphs endpoint with mock data."""
        # Mock XGT with sample data
        mock_connection = Mock()
        mock_connection.get_namespaces.return_value = ["admin"]
        mock_connection.get_default_namespace.return_value = "admin"

        # Mock vertex frame
        mock_vertex = Mock()
        mock_vertex.name = "users"
        mock_vertex.schema = [["id", "TEXT"], ["name", "TEXT"]]
        mock_vertex.num_rows = 100
        mock_vertex.user_permissions = {"create_rows": True, "delete_frame": False}
        mock_vertex.key = "id"

        # Mock edge frame
        mock_edge = Mock()
        mock_edge.name = "friendships"
        mock_edge.schema = [["created_at", "DATETIME"]]
        mock_edge.num_rows = 50
        mock_edge.user_permissions = {"create_rows": True, "delete_frame": False}
        mock_edge.source_name = "users"
        mock_edge.target_name = "users"
        mock_edge.source_key = "id"
        mock_edge.target_key = "id"

        def mock_get_frames(namespace=None, frame_type=None):
            if frame_type == "vertex":
                return [mock_vertex]
            elif frame_type == "edge":
                return [mock_edge]
            return []

        mock_connection.get_frames.side_effect = mock_get_frames
        mock_connection.close = Mock()

        mock_xgt.Connection.return_value = mock_connection
        mock_xgt.BasicAuth.return_value = Mock()

        # Test the API
        response = client.get("/api/v1/public/graphs")

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 1
        assert len(data["graphs"]) == 1

        graph = data["graphs"][0]
        assert graph["name"] == "admin"
        assert len(graph["vertices"]) == 1
        assert len(graph["edges"]) == 1

        # Check vertex data
        vertex = graph["vertices"][0]
        assert vertex["name"] == "users"
        assert vertex["num_rows"] == 100
        assert vertex["key"] == "id"

        # Check edge data
        edge = graph["edges"][0]
        assert edge["name"] == "friendships"
        assert edge["source_frame"] == "users"
        assert edge["target_frame"] == "users"

    def test_health_endpoint_integration(self, client):
        """Test health endpoint integration."""
        response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        # Basic health response structure
        assert "status" in data
        assert "timestamp" in data
        assert "services" in data  # Updated to match actual response structure

    def test_api_error_handling_integration(self, client):
        """Test API error handling."""
        # Test 404 for non-existent endpoint
        response = client.get("/api/v1/public/nonexistent")
        assert response.status_code == 404

    @patch("app.utils.xgt_operations.xgt", None)
    def test_xgt_unavailable_integration(self, client):
        """Test API behavior when XGT is unavailable."""
        response = client.get("/api/v1/public/graphs")

        # Should return 500 when XGT library is not available (internal server error)
        assert response.status_code == 500
        data = response.json()
        assert "error" in data
