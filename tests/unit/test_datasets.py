"""
Unit tests for dataset endpoints.
"""

from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import pytest


@pytest.fixture
def client():
    """Create test client."""
    from app.api.main import app
    return TestClient(app)


class TestDatasetsEndpoint:
    """Test datasets listing endpoint."""

    @patch('app.api.v1.public.datasets.create_xgt_operations')
    def test_list_datasets_success(self, mock_create_xgt_ops, client):
        """Test successful datasets listing."""
        # Mock XGT operations
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'test_dataset',
                'vertices': [
                    {
                        'name': 'users',
                        'schema': [['id', 'TEXT'], ['name', 'TEXT']],
                        'num_rows': 100,
                        'create_rows': True,
                        'delete_frame': False,
                        'key': 'id'
                    }
                ],
                'edges': [
                    {
                        'name': 'friendships',
                        'schema': [['created_at', 'DATETIME']],
                        'num_rows': 50,
                        'create_rows': True,
                        'delete_frame': False,
                        'source_frame': 'users',
                        'source_key': 'id',
                        'target_frame': 'users',
                        'target_key': 'id'
                    }
                ]
            }
        ]
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/datasets")

        assert response.status_code == 200
        data = response.json()

        assert "datasets" in data
        assert "total_count" in data
        # organization_id removed - XGT handles access control via authentication
        assert data["total_count"] == 1
        assert len(data["datasets"]) == 1

        dataset = data["datasets"][0]
        assert dataset["name"] == "test_dataset"
        assert len(dataset["vertices"]) == 1
        assert len(dataset["edges"]) == 1

        # Check vertex structure
        vertex = dataset["vertices"][0]
        assert vertex["name"] == "users"
        assert vertex["num_rows"] == 100
        assert vertex["key"] == "id"

        # Check edge structure
        edge = dataset["edges"][0]
        assert edge["name"] == "friendships"
        assert edge["source_frame"] == "users"
        assert edge["target_frame"] == "users"

    @patch('app.api.v1.public.datasets.create_xgt_operations')
    def test_list_datasets_empty(self, mock_create_xgt_ops, client):
        """Test datasets listing when no datasets exist."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = []
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/datasets")

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 0
        assert len(data["datasets"]) == 0

    @patch('app.api.v1.public.datasets.create_xgt_operations')
    def test_list_datasets_xgt_connection_error(self, mock_create_xgt_ops, client):
        """Test datasets listing when XGT connection fails."""
        from app.utils.exceptions import XGTConnectionError

        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.side_effect = XGTConnectionError("Connection refused")
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/datasets")

        assert response.status_code == 503
        data = response.json()

        # FastAPI wraps HTTPException in custom error handler format
        assert data["error"]["code"] == "HTTP_503"
        error_message = data["error"]["message"]
        assert error_message["error"] == "XGT_CONNECTION_ERROR"
        assert "Cannot connect to XGT server" in error_message["message"]

    @patch('app.api.v1.public.datasets.create_xgt_operations')
    def test_get_dataset_info_success(self, mock_create_xgt_ops, client):
        """Test successful single dataset retrieval."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'social_network',
                'vertices': [
                    {
                        'name': 'users',
                        'schema': [['id', 'TEXT'], ['name', 'TEXT'], ['age', 'INTEGER']],
                        'num_rows': 1000,
                        'create_rows': True,
                        'delete_frame': False,
                        'key': 'id'
                    }
                ],
                'edges': []
            }
        ]
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/datasets/social_network")

        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "social_network"
        assert len(data["vertices"]) == 1
        assert len(data["edges"]) == 0

        vertex = data["vertices"][0]
        assert vertex["name"] == "users"
        assert vertex["num_rows"] == 1000

    @patch('app.api.v1.public.datasets.create_xgt_operations')
    def test_get_dataset_info_not_found(self, mock_create_xgt_ops, client):
        """Test dataset retrieval when dataset doesn't exist."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = []
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/datasets/nonexistent")

        assert response.status_code == 404
        data = response.json()

        # FastAPI wraps HTTPException in custom error handler format
        assert data["error"]["code"] == "HTTP_404"
        error_message = data["error"]["message"]
        assert error_message["error"] == "DATASET_NOT_FOUND"
        assert "nonexistent" in error_message["message"]
