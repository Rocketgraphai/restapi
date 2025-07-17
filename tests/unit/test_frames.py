"""
Unit tests for frame endpoints.
"""

from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import pytest


@pytest.fixture
def client():
    """Create test client with mocked authentication."""
    import time
    from app.api.main import app
    from app.auth.passthrough_middleware import require_xgt_authentication
    from app.auth.passthrough_models import AuthenticatedXGTUser
    from unittest.mock import Mock
    
    # Create a mock user for testing
    mock_user = AuthenticatedXGTUser(
        username="test_user",
        namespace="test_namespace",
        authenticated_at=time.time(),
        expires_at=time.time() + 3600,
        credentials=Mock()
    )
    
    # Override the authentication dependency
    app.dependency_overrides[require_xgt_authentication] = lambda: mock_user
    
    yield TestClient(app)
    
    # Clean up dependency overrides
    app.dependency_overrides.clear()


class TestFrameDataEndpoint:
    """Test frame data endpoint."""

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_get_frame_data_success(self, mock_create_user_xgt_ops, client):
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
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

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

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
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
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

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

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
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
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/social__friendships/data")

        assert response.status_code == 200
        data = response.json()

        assert data["frame_name"] == "social__friendships"
        assert data["frame_type"] == "edge"
        assert data["namespace"] == "social"
        assert len(data["columns"]) == 4

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_get_frame_data_not_found(self, mock_create_xgt_ops, client):
        """Test frame data retrieval when frame doesn't exist."""
        from app.utils.exceptions import XGTOperationError

        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.side_effect = XGTOperationError("Frame 'nonexistent' not found")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/nonexistent/data")

        assert response.status_code == 404
        data = response.json()

        assert data["error"]["code"] == "HTTP_404"
        error_message = data["error"]["message"]
        assert error_message["error"] == "FRAME_NOT_FOUND"
        assert "nonexistent" in error_message["message"]

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_get_frame_data_xgt_connection_error(self, mock_create_xgt_ops, client):
        """Test frame data retrieval when XGT connection fails."""
        from app.utils.exceptions import XGTConnectionError

        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data.side_effect = XGTConnectionError("Connection refused")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/test_frame/data")

        assert response.status_code == 503
        data = response.json()

        assert data["error"]["code"] == "HTTP_503"
        error_message = data["error"]["message"]
        assert error_message["error"] == "XGT_CONNECTION_ERROR"

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
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

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
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
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/empty_frame/data")

        assert response.status_code == 200
        data = response.json()

        assert data["frame_name"] == "empty_frame"
        assert len(data["rows"]) == 0
        assert data["total_rows"] == 0
        assert data["returned_rows"] == 0

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
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
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames/aml__Transaction/data")

        assert response.status_code == 200
        data = response.json()

        assert data["frame_name"] == "aml__Transaction"
        assert data["frame_type"] == "table"
        assert data["namespace"] == "aml"
        assert len(data["columns"]) == 4
        assert len(data["rows"]) == 2
        assert data["total_rows"] == 50000


class TestFramesListEndpoint:
    """Test frames listing endpoint."""

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_success(self, mock_create_xgt_ops, client):
        """Test successful frames listing."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'ecommerce',
                'vertices': [
                    {
                        'name': 'customers',
                        'schema': [['id', 'TEXT'], ['name', 'TEXT']],
                        'num_rows': 1000,
                        'key': 'id'
                    },
                    {
                        'name': 'products',
                        'schema': [['id', 'TEXT'], ['name', 'TEXT'], ['price', 'FLOAT']],
                        'num_rows': 500,
                        'key': 'id'
                    }
                ],
                'edges': [
                    {
                        'name': 'purchases',
                        'schema': [['amount', 'FLOAT'], ['date', 'DATETIME']],
                        'num_rows': 2000,
                        'source_frame': 'customers',
                        'target_frame': 'products',
                        'source_key': 'id',
                        'target_key': 'id'
                    }
                ]
            },
            {
                'name': 'social',
                'vertices': [
                    {
                        'name': 'users',
                        'schema': [['id', 'TEXT'], ['username', 'TEXT']],
                        'num_rows': 100,
                        'key': 'id'
                    }
                ],
                'edges': []
            },
            {
                'name': 'xgt__',  # This should be excluded
                'vertices': [
                    {
                        'name': 'system_frame',
                        'schema': [['id', 'TEXT']],
                        'num_rows': 10,
                        'key': 'id'
                    }
                ],
                'edges': []
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames")

        assert response.status_code == 200
        data = response.json()

        assert "frames" in data
        assert "total_count" in data
        assert "namespaces" in data
        
        # Should have 4 frames (3 from ecommerce, 1 from social), excluding xgt__
        assert data["total_count"] == 4
        assert len(data["frames"]) == 4
        assert set(data["namespaces"]) == {"ecommerce", "social"}
        
        # Check first frame (should be sorted)
        first_frame = data["frames"][0]
        assert first_frame["namespace"] == "ecommerce"
        assert first_frame["frame_type"] in ["vertex", "edge"]
        assert "full_name" in first_frame
        assert "schema_definition" in first_frame

        # Verify XGT operations was called correctly
        mock_xgt_ops.datasets_info.assert_called_once()

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_with_namespace_filter(self, mock_create_xgt_ops, client):
        """Test frames listing with namespace filter."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'ecommerce',
                'vertices': [
                    {
                        'name': 'customers',
                        'schema': [['id', 'TEXT'], ['name', 'TEXT']],
                        'num_rows': 1000,
                        'key': 'id'
                    }
                ],
                'edges': []
            },
            {
                'name': 'social',
                'vertices': [
                    {
                        'name': 'users',
                        'schema': [['id', 'TEXT']],
                        'num_rows': 100,
                        'key': 'id'
                    }
                ],
                'edges': []
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames?namespace=ecommerce")

        assert response.status_code == 200
        data = response.json()

        # Should only have frames from ecommerce namespace
        assert data["total_count"] == 1
        assert len(data["frames"]) == 1
        assert data["namespaces"] == ["ecommerce"]
        assert data["frames"][0]["namespace"] == "ecommerce"
        assert data["frames"][0]["name"] == "customers"

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_with_frame_type_filter(self, mock_create_xgt_ops, client):
        """Test frames listing with frame type filter."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'ecommerce',
                'vertices': [
                    {
                        'name': 'customers',
                        'schema': [['id', 'TEXT']],
                        'num_rows': 1000,
                        'key': 'id'
                    }
                ],
                'edges': [
                    {
                        'name': 'purchases',
                        'schema': [['amount', 'FLOAT']],
                        'num_rows': 2000,
                        'source_frame': 'customers',
                        'target_frame': 'products',
                        'source_key': 'id',
                        'target_key': 'id'
                    }
                ]
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames?frame_type=vertex")

        assert response.status_code == 200
        data = response.json()

        # Should only have vertex frames
        assert data["total_count"] == 1
        assert len(data["frames"]) == 1
        assert data["frames"][0]["frame_type"] == "vertex"
        assert data["frames"][0]["name"] == "customers"

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_edge_frame_details(self, mock_create_xgt_ops, client):
        """Test frames listing includes edge frame details."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'social',
                'vertices': [],
                'edges': [
                    {
                        'name': 'friendships',
                        'schema': [['created_at', 'DATETIME'], ['weight', 'FLOAT']],
                        'num_rows': 5000,
                        'source_frame': 'users',
                        'target_frame': 'users',
                        'source_key': 'id',
                        'target_key': 'id'
                    }
                ]
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames")

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 1
        edge_frame = data["frames"][0]
        assert edge_frame["frame_type"] == "edge"
        assert edge_frame["name"] == "friendships"
        assert edge_frame["full_name"] == "social__friendships"
        assert edge_frame["source_name"] == "users"
        assert edge_frame["target_name"] == "users"
        assert edge_frame["source_key"] == "id"
        assert edge_frame["target_key"] == "id"
        assert edge_frame["key"] is None  # Edge frames don't have keys

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_vertex_frame_details(self, mock_create_xgt_ops, client):
        """Test frames listing includes vertex frame details."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'ecommerce',
                'vertices': [
                    {
                        'name': 'customers',
                        'schema': [['id', 'TEXT'], ['name', 'TEXT'], ['email', 'TEXT']],
                        'num_rows': 10000,
                        'key': 'id'
                    }
                ],
                'edges': []
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames")

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 1
        vertex_frame = data["frames"][0]
        assert vertex_frame["frame_type"] == "vertex"
        assert vertex_frame["name"] == "customers"
        assert vertex_frame["full_name"] == "ecommerce__customers"
        assert vertex_frame["key"] == "id"
        assert vertex_frame["source_name"] is None  # Vertex frames don't have source/target
        assert vertex_frame["target_name"] is None
        assert vertex_frame["source_key"] is None
        assert vertex_frame["target_key"] is None

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_empty_result(self, mock_create_xgt_ops, client):
        """Test frames listing when no frames exist."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = []
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames")

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 0
        assert len(data["frames"]) == 0
        assert len(data["namespaces"]) == 0

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_excludes_xgt_namespace(self, mock_create_xgt_ops, client):
        """Test that xgt__ namespace is excluded from results."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'xgt__',
                'vertices': [
                    {
                        'name': 'system_frame',
                        'schema': [['id', 'TEXT']],
                        'num_rows': 10,
                        'key': 'id'
                    }
                ],
                'edges': []
            },
            {
                'name': 'user_data',
                'vertices': [
                    {
                        'name': 'customers',
                        'schema': [['id', 'TEXT']],
                        'num_rows': 100,
                        'key': 'id'
                    }
                ],
                'edges': []
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames")

        assert response.status_code == 200
        data = response.json()

        # Should only have the user_data frame, xgt__ should be excluded
        assert data["total_count"] == 1
        assert len(data["frames"]) == 1
        assert data["namespaces"] == ["user_data"]
        assert data["frames"][0]["namespace"] == "user_data"

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_xgt_connection_error(self, mock_create_xgt_ops, client):
        """Test frames listing when XGT connection fails."""
        from app.utils.exceptions import XGTConnectionError

        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.side_effect = XGTConnectionError("Connection refused")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames")

        assert response.status_code == 503
        data = response.json()

        assert data["error"]["code"] == "HTTP_503"
        error_message = data["error"]["message"]
        assert error_message["error"] == "XGT_CONNECTION_ERROR"

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_table_frame_details(self, mock_create_xgt_ops, client):
        """Test frames listing includes table frame details."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'haglin',
                'vertices': [],
                'edges': [],
                'tables': [
                    {
                        'name': 'Answer_1752513727_510279',
                        'schema': [['device', 'TEXT'], ['count', 'INTEGER'], ['timestamp', 'DATETIME']],
                        'num_rows': 10952,
                        'create_rows': False,
                        'delete_frame': False
                    }
                ]
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames")

        assert response.status_code == 200
        data = response.json()

        assert data["total_count"] == 1
        table_frame = data["frames"][0]
        assert table_frame["frame_type"] == "table"
        assert table_frame["name"] == "Answer_1752513727_510279"
        assert table_frame["full_name"] == "haglin__Answer_1752513727_510279"
        assert table_frame["namespace"] == "haglin"
        assert table_frame["num_rows"] == 10952
        assert table_frame["key"] is None  # Table frames don't have keys
        assert table_frame["source_name"] is None  # Table frames don't have source/target
        assert table_frame["target_name"] is None
        assert table_frame["source_key"] is None
        assert table_frame["target_key"] is None

    @patch('app.api.v1.public.frames.create_user_xgt_operations')
    def test_list_frames_with_table_frame_type_filter(self, mock_create_xgt_ops, client):
        """Test frames listing with table frame type filter."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.datasets_info.return_value = [
            {
                'name': 'haglin',
                'vertices': [
                    {
                        'name': 'users',
                        'schema': [['id', 'TEXT']],
                        'num_rows': 100,
                        'key': 'id'
                    }
                ],
                'edges': [],
                'tables': [
                    {
                        'name': 'query_results',
                        'schema': [['result', 'TEXT']],
                        'num_rows': 500,
                        'create_rows': False,
                        'delete_frame': False
                    }
                ]
            }
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/frames?frame_type=table")

        assert response.status_code == 200
        data = response.json()

        # Should only have table frames
        assert data["total_count"] == 1
        assert len(data["frames"]) == 1
        assert data["frames"][0]["frame_type"] == "table"
        assert data["frames"][0]["name"] == "query_results"