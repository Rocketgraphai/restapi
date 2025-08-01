"""
Unit tests for graph endpoints.
"""

import time
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import pytest


@pytest.fixture
def client():
    """Create test client with mocked authentication."""
    from app.api.main import app
    from app.auth.passthrough_middleware import require_xgt_authentication
    from app.auth.passthrough_models import AuthenticatedXGTUser

    # Create a mock user for testing
    mock_user = AuthenticatedXGTUser(
        username="test_user",
        namespace="test_namespace",
        authenticated_at=time.time(),
        expires_at=time.time() + 3600,
        credentials=Mock(),
    )

    # Override the authentication dependency
    app.dependency_overrides[require_xgt_authentication] = lambda: mock_user

    yield TestClient(app)

    # Clean up dependency overrides
    app.dependency_overrides.clear()


class TestGraphsEndpoint:
    """Test graphs listing endpoint."""

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_list_graphs_success(self, mock_create_user_xgt_ops, client):
        """Test successful graphs listing."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.graphs_info.return_value = [
            {
                "name": "test_namespace",
                "vertices": [
                    {
                        "name": "users",
                        "schema": [["id", "TEXT"], ["name", "TEXT"]],
                        "num_rows": 100,
                        "create_rows": True,
                        "delete_frame": True,
                        "key": "id",
                    }
                ],
                "edges": [],
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs")

        assert response.status_code == 200
        data = response.json()

        assert "graphs" in data
        assert "total_count" in data

        # Should have one graph with vertices
        assert data["total_count"] == 1
        assert len(data["graphs"]) == 1

        graph = data["graphs"][0]
        assert graph["name"] == "test_namespace"
        assert len(graph["vertices"]) == 1
        assert len(graph["edges"]) == 0

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_list_graphs_empty(self, mock_create_user_xgt_ops, client):
        """Test graphs listing when no graphs exist."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.graphs_info.return_value = []
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs")

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 0
        assert len(data["graphs"]) == 0

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_list_graphs_xgt_connection_error(self, mock_create_user_xgt_ops, client):
        """Test graphs listing when XGT connection fails."""
        from app.utils.exceptions import XGTConnectionError

        mock_xgt_ops = Mock()
        mock_xgt_ops.graphs_info.side_effect = XGTConnectionError("Connection failed")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs")

        # Should return 503 when XGT connection fails
        assert response.status_code == 503
        data = response.json()

        assert data["error"]["code"] == "HTTP_503"
        error_message = data["error"]["message"]
        assert error_message["error"] == "XGT_CONNECTION_ERROR"

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_get_graph_info_success(self, mock_create_user_xgt_ops, client):
        """Test successful single graph retrieval."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.graphs_info.return_value = [
            {
                "name": "social_network",
                "vertices": [
                    {
                        "name": "users",
                        "schema": [["id", "TEXT"], ["name", "TEXT"], ["age", "INTEGER"]],
                        "num_rows": 1000,
                        "create_rows": True,
                        "delete_frame": False,
                        "key": "id",
                    }
                ],
                "edges": [],
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs/social_network")

        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "social_network"
        assert len(data["vertices"]) == 1
        assert len(data["edges"]) == 0

        vertex = data["vertices"][0]
        assert vertex["name"] == "users"
        assert vertex["num_rows"] == 1000

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_get_graph_info_not_found(self, mock_create_user_xgt_ops, client):
        """Test graph retrieval when graph doesn't exist."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.graphs_info.return_value = []
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs/nonexistent")

        assert response.status_code == 404
        data = response.json()

        # FastAPI wraps HTTPException in custom error handler format
        assert data["error"]["code"] == "HTTP_404"
        error_message = data["error"]["message"]
        assert error_message["error"] == "GRAPH_NOT_FOUND"
        assert "nonexistent" in error_message["message"]


class TestGraphSchemaEndpoint:
    """Test graph schema endpoint."""

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_get_graph_schema_success(self, mock_create_user_xgt_ops, client):
        """Test successful schema retrieval."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_schema.return_value = {
            "graph": "test_graph",
            "nodes": [
                {
                    "name": "Customer",
                    "properties": [
                        {"name": "id", "type": "TEXT", "leaf_type": "TEXT", "depth": 1},
                        {"name": "name", "type": "TEXT", "leaf_type": "TEXT", "depth": 1},
                        {"name": "age", "type": "INTEGER", "leaf_type": "INTEGER", "depth": 1},
                    ],
                    "key": "id",
                }
            ],
            "edges": [
                {
                    "name": "PURCHASED",
                    "properties": [
                        {"name": "amount", "type": "FLOAT", "leaf_type": "FLOAT", "depth": 1},
                        {"name": "date", "type": "DATETIME", "leaf_type": "DATETIME", "depth": 1},
                    ],
                    "source": "Customer",
                    "target": "Product",
                    "source_key": "id",
                    "target_key": "id",
                }
            ],
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs/test_graph/schema")

        assert response.status_code == 200
        data = response.json()

        assert data["graph"] == "test_graph"
        assert len(data["nodes"]) == 1
        assert len(data["edges"]) == 1

        # Check node schema
        node = data["nodes"][0]
        assert node["name"] == "Customer"
        assert node["key"] == "id"
        assert len(node["properties"]) == 3

        # Check property structure
        id_prop = node["properties"][0]
        assert id_prop["name"] == "id"
        assert id_prop["type"] == "TEXT"
        assert id_prop["leaf_type"] == "TEXT"
        assert id_prop["depth"] == 1

        # Check edge schema
        edge = data["edges"][0]
        assert edge["name"] == "PURCHASED"
        assert edge["source"] == "Customer"
        assert edge["target"] == "Product"
        assert edge["source_key"] == "id"
        assert edge["target_key"] == "id"
        assert len(edge["properties"]) == 2

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_get_graph_schema_with_params(self, mock_create_user_xgt_ops, client):
        """Test schema retrieval with query parameters."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_schema.return_value = {"graph": "test_graph", "nodes": [], "edges": []}
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs/test_graph/schema?fully_qualified=true&add_missing_edge_nodes=true")

        assert response.status_code == 200

        # Verify that the parameters were passed to get_schema (now using graph_name)
        mock_xgt_ops.get_schema.assert_called_once_with(graph_name="test_graph", fully_qualified=True, add_missing_edge_nodes=True)

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_get_graph_schema_xgt_error(self, mock_create_user_xgt_ops, client):
        """Test schema retrieval when XGT operation fails."""
        from app.utils.exceptions import XGTOperationError

        mock_xgt_ops = Mock()
        mock_xgt_ops.get_schema.side_effect = XGTOperationError("Schema not found")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs/test_graph/schema")

        assert response.status_code == 500
        data = response.json()

        # FastAPI wraps HTTPException in custom error handler format
        assert data["error"]["code"] == "HTTP_500"
        error_message = data["error"]["message"]
        assert error_message["error"] == "XGT_OPERATION_ERROR"
        assert "Failed to retrieve schema" in error_message["message"]

    @patch("app.api.v1.public.graphs.create_user_xgt_operations")
    def test_get_graph_schema_empty_graph(self, mock_create_user_xgt_ops, client):
        """Test schema retrieval for graph with no frames."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_schema.return_value = {"graph": "empty_graph", "nodes": [], "edges": []}
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/graphs/empty_graph/schema")

        assert response.status_code == 200
        data = response.json()

        assert data["graph"] == "empty_graph"
        assert len(data["nodes"]) == 0
        assert len(data["edges"]) == 0
