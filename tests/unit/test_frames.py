"""
Unit tests for frame endpoints.
"""

from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import pytest


@pytest.fixture
def client():
    """Create test client."""
    from app.api.main import app
    return TestClient(app)


class TestFrameDataEndpoint:
    """Test frame data endpoint."""

    @patch('app.api.v1.public.frames.create_xgt_operations')
    def test_get_frame_data_success(self, mock_create_xgt_ops, client):
        """Test successful frame data retrieval."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.return_value = {
            'frame_name': 'ecommerce__customers',
            'frame_type': 'vertex',
            'namespace': 'ecommerce',
            'columns': ['id', 'name', 'email', 'created_at'],
            'rows': [
                ['cust_001', 'John Doe', 'john@example.com', '2024-01-15T10:30:00'],
                ['cust_002', 'Jane Smith', 'jane@example.com', '2024-01-16T14:20:00']
            ],
            'total_rows': 10000,
            'offset': 0,
            'limit': 100,
            'returned_rows': 2
        }
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/ecommerce__customers/data")

        assert response.status_code == 200
        data = response.json()

        assert data["frame_name"] == "ecommerce__customers"
        assert data["frame_type"] == "vertex"
        assert data["namespace"] == "ecommerce"
        assert len(data["columns"]) == 4
        assert len(data["rows"]) == 2
        assert data["total_rows"] == 10000
        assert data["returned_rows"] == 2

        # Verify XGT operations was called correctly
        mock_xgt_ops.get_frame_data.assert_called_once_with(
            frame_name='ecommerce__customers',
            offset=0,
            limit=100
        )

    @patch('app.api.v1.public.frames.create_xgt_operations')
    def test_get_frame_data_with_pagination(self, mock_create_xgt_ops, client):
        """Test frame data retrieval with pagination parameters."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.return_value = {
            'frame_name': 'users',
            'frame_type': 'vertex',
            'namespace': None,
            'columns': ['id', 'name'],
            'rows': [['003', 'Bob Wilson']],
            'total_rows': 1000,
            'offset': 50,
            'limit': 25,
            'returned_rows': 1
        }
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/users/data?offset=50&limit=25")

        assert response.status_code == 200
        data = response.json()

        assert data["frame_name"] == "users"
        assert data["namespace"] is None  # Simple frame name
        assert data["offset"] == 50
        assert data["limit"] == 25

        # Verify pagination parameters were passed
        mock_xgt_ops.get_frame_data.assert_called_once_with(
            frame_name='users',
            offset=50,
            limit=25
        )

    @patch('app.api.v1.public.frames.create_xgt_operations')
    def test_get_frame_data_edge_frame(self, mock_create_xgt_ops, client):
        """Test frame data retrieval for edge frame."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.return_value = {
            'frame_name': 'social__friendships',
            'frame_type': 'edge',
            'namespace': 'social',
            'columns': ['source_id', 'target_id', 'created_at', 'weight'],
            'rows': [
                ['user_001', 'user_002', '2024-01-15T10:30:00', 0.8],
                ['user_002', 'user_003', '2024-01-16T14:20:00', 0.6]
            ],
            'total_rows': 5000,
            'offset': 0,
            'limit': 100,
            'returned_rows': 2
        }
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/social__friendships/data")

        assert response.status_code == 200
        data = response.json()

        assert data["frame_name"] == "social__friendships"
        assert data["frame_type"] == "edge"
        assert data["namespace"] == "social"
        assert len(data["columns"]) == 4

    @patch('app.api.v1.public.frames.create_xgt_operations')
    def test_get_frame_data_not_found(self, mock_create_xgt_ops, client):
        """Test frame data retrieval when frame doesn't exist."""
        from app.utils.exceptions import XGTOperationError

        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.side_effect = XGTOperationError("Frame 'nonexistent' not found")
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/nonexistent/data")

        assert response.status_code == 404
        data = response.json()

        assert data["error"]["code"] == "HTTP_404"
        error_message = data["error"]["message"]
        assert error_message["error"] == "FRAME_NOT_FOUND"
        assert "nonexistent" in error_message["message"]

    @patch('app.api.v1.public.frames.create_xgt_operations')
    def test_get_frame_data_xgt_connection_error(self, mock_create_xgt_ops, client):
        """Test frame data retrieval when XGT connection fails."""
        from app.utils.exceptions import XGTConnectionError

        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.side_effect = XGTConnectionError("Connection refused")
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/test_frame/data")

        assert response.status_code == 503
        data = response.json()

        assert data["error"]["code"] == "HTTP_503"
        error_message = data["error"]["message"]
        assert error_message["error"] == "XGT_CONNECTION_ERROR"

    @patch('app.api.v1.public.frames.create_xgt_operations')
    def test_get_frame_data_invalid_parameters(self, mock_create_xgt_ops, client):
        """Test frame data retrieval with invalid parameters."""
        # Test negative offset
        response = client.get("/api/v1/public/frames/test_frame/data?offset=-1")
        assert response.status_code == 422  # Validation error

        # Test limit too large
        response = client.get("/api/v1/public/frames/test_frame/data?limit=20000")
        assert response.status_code == 422  # Validation error

        # Test zero limit
        response = client.get("/api/v1/public/frames/test_frame/data?limit=0")
        assert response.status_code == 422  # Validation error

    @patch('app.api.v1.public.frames.create_xgt_operations')
    def test_get_frame_data_empty_frame(self, mock_create_xgt_ops, client):
        """Test frame data retrieval for empty frame."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.return_value = {
            'frame_name': 'empty_frame',
            'frame_type': 'vertex',
            'namespace': None,
            'columns': ['id', 'name'],
            'rows': [],
            'total_rows': 0,
            'offset': 0,
            'limit': 100,
            'returned_rows': 0
        }
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/empty_frame/data")

        assert response.status_code == 200
        data = response.json()

        assert data["frame_name"] == "empty_frame"
        assert len(data["rows"]) == 0
        assert data["total_rows"] == 0
        assert data["returned_rows"] == 0

    @patch('app.api.v1.public.frames.create_xgt_operations')
    def test_get_frame_data_table_frame(self, mock_create_xgt_ops, client):
        """Test frame data retrieval for table frame (different get_data signature)."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.return_value = {
            'frame_name': 'aml__Transaction',
            'frame_type': 'table',
            'namespace': 'aml',
            'columns': ['id', 'amount', 'timestamp', 'account'],
            'rows': [
                ['txn_001', 1000.50, '2024-01-15T10:30:00', 'acc_123'],
                ['txn_002', 250.75, '2024-01-16T14:20:00', 'acc_456']
            ],
            'total_rows': 50000,
            'offset': 0,
            'limit': 100,
            'returned_rows': 2
        }
        mock_create_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/aml__Transaction/data")

        assert response.status_code == 200
        data = response.json()

        assert data["frame_name"] == "aml__Transaction"
        assert data["frame_type"] == "table"
        assert data["namespace"] == "aml"
        assert len(data["columns"]) == 4
        assert len(data["rows"]) == 2
        assert data["total_rows"] == 50000