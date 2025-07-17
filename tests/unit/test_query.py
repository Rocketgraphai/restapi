"""
Unit tests for query endpoints.
"""

import time
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import pytest
from fastapi import FastAPI


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
        credentials=Mock()
    )
    
    # Override the authentication dependency
    app.dependency_overrides[require_xgt_authentication] = lambda: mock_user
    
    yield TestClient(app)
    
    # Clean up dependency overrides
    app.dependency_overrides.clear()




class TestQueryExecution:
    """Test query execution endpoint."""

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_execute_query_success(self, mock_create_user_xgt_ops, client):
        """Test successful query execution."""
        # Mock XGT operations
        mock_xgt_ops = Mock()
        mock_xgt_ops.execute_query.return_value = [
            {'customer_name': 'John Doe'},
            {'customer_name': 'Jane Smith'}
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        query_data = {
            "query": "MATCH (c:Customer) RETURN c.name LIMIT 10",
            "parameters": None,
            "format": "json",
            "limit": 1000
        }

        response = client.post("/api/v1/public/datasets/ecommerce/query", json=query_data)

        assert response.status_code == 200
        data = response.json()

        assert "job_id" in data
        assert data["status"] == "completed"
        assert data["query"] == "MATCH (c:Customer) RETURN c.name LIMIT 10"
        assert data["dataset_name"] == "ecommerce"
        assert "submitted_at" in data

        # Verify XGT operations was called correctly
        mock_xgt_ops.execute_query.assert_called_once_with("MATCH (c:Customer) RETURN c.name LIMIT 10")

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_execute_query_with_parameters(self, mock_create_user_xgt_ops, client):
        """Test query execution with parameters."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.execute_query.return_value = [
            {'customer_name': 'Adult Customer 1'},
            {'customer_name': 'Adult Customer 2'}
        ]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        query_data = {
            "query": "MATCH (c:Customer) WHERE c.age > $min_age RETURN c.name",
            "parameters": {"min_age": 18},
            "format": "json"
        }

        response = client.post("/api/v1/public/datasets/test_dataset/query", json=query_data)

        assert response.status_code == 200
        data = response.json()

        assert "job_id" in data
        assert data["status"] == "completed"
        assert data["dataset_name"] == "test_dataset"

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_execute_query_invalid_query(self, mock_create_user_xgt_ops, client):
        """Test query execution with invalid query (INTO clause)."""
        from app.utils.exceptions import XGTOperationError

        mock_xgt_ops = Mock()
        mock_xgt_ops.execute_query.side_effect = XGTOperationError("INTO clauses not allowed in public API")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        query_data = {
            "query": "MATCH (c:Customer) RETURN c.name INTO temp_table",
            "format": "json"
        }

        response = client.post("/api/v1/public/datasets/test_dataset/query", json=query_data)

        assert response.status_code == 400
        data = response.json()

        assert data["error"]["code"] == "HTTP_400"
        error_message = data["error"]["message"]
        assert error_message["error"] == "INVALID_QUERY"
        assert "forbidden operations" in error_message["message"]

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_execute_query_xgt_connection_error(self, mock_create_user_xgt_ops, client):
        """Test query execution when XGT connection fails."""
        from app.utils.exceptions import XGTConnectionError

        mock_xgt_ops = Mock()
        mock_xgt_ops.execute_query.side_effect = XGTConnectionError("Connection refused")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        query_data = {
            "query": "MATCH (c:Customer) RETURN c.name LIMIT 10",
            "format": "json"
        }

        response = client.post("/api/v1/public/datasets/test_dataset/query", json=query_data)

        assert response.status_code == 503
        data = response.json()

        assert data["error"]["code"] == "HTTP_503"
        error_message = data["error"]["message"]
        assert error_message["error"] == "XGT_CONNECTION_ERROR"

    def test_execute_query_validation_error(self, client):
        """Test query execution with invalid request format."""
        # Empty query
        response = client.post("/api/v1/public/datasets/test_dataset/query", json={
            "query": "",
            "format": "json"
        })
        assert response.status_code == 422

        # Invalid format
        response = client.post("/api/v1/public/datasets/test_dataset/query", json={
            "query": "MATCH (c:Customer) RETURN c.name",
            "format": "invalid_format"
        })
        assert response.status_code == 422

        # Missing query
        response = client.post("/api/v1/public/datasets/test_dataset/query", json={
            "format": "json"
        })
        assert response.status_code == 422


class TestQueryStatus:
    """Test query status endpoint."""

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_status_success(self, mock_create_user_xgt_ops, client):
        """Test successful query status retrieval."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.job_status.return_value = {
            'job_id': 12345,
            'status': 'completed',
            'progress': 1.0,
            'start_time': 1642248000.0,
            'end_time': 1642248045.0
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/12345/status")

        assert response.status_code == 200
        data = response.json()

        assert data["job_id"] == 12345
        assert data["status"] == "completed"
        assert data["progress"] == 1.0
        assert data["start_time"] == 1642248000.0
        assert data["end_time"] == 1642248045.0
        assert data["processing_time_ms"] == 45000  # 45 seconds

        # Verify XGT operations was called correctly
        mock_xgt_ops.job_status.assert_called_once_with(12345)

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_status_running(self, mock_create_user_xgt_ops, client):
        """Test query status for running job."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.job_status.return_value = {
            'job_id': 12346,
            'status': 'running',
            'progress': 0.5,
            'start_time': 1642248000.0,
            'end_time': None
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/12346/status")

        assert response.status_code == 200
        data = response.json()

        assert data["job_id"] == 12346
        assert data["status"] == "running"
        assert data["progress"] == 0.5
        assert data["end_time"] is None
        assert data["processing_time_ms"] is None

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_status_not_found(self, mock_create_user_xgt_ops, client):
        """Test query status for non-existent job."""
        from app.utils.exceptions import XGTOperationError

        mock_xgt_ops = Mock()
        mock_xgt_ops.job_status.side_effect = XGTOperationError("Job not found")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/99999/status")

        assert response.status_code == 404
        data = response.json()

        assert data["error"]["code"] == "HTTP_404"
        error_message = data["error"]["message"]
        assert error_message["error"] == "JOB_NOT_FOUND"
        assert "99999" in error_message["message"]


class TestQueryResults:
    """Test query results endpoint."""

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_results_success(self, mock_create_user_xgt_ops, client):
        """Test successful query results retrieval."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_query_answer.return_value = {
            'job_id': 12345,
            'status': 'completed',
            'results': [
                ['John Doe', 299.99, 'Smartphone'],
                ['Jane Smith', 1299.99, 'Laptop']
            ],
            'offset': 0,
            'length': 2
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/12345/results")

        assert response.status_code == 200
        data = response.json()

        assert data["job_id"] == 12345
        assert data["status"] == "completed"
        assert len(data["columns"]) == 3  # Inferred columns
        assert len(data["rows"]) == 2
        assert data["rows"][0] == ['John Doe', 299.99, 'Smartphone']
        assert data["returned_rows"] == 2
        assert data["offset"] == 0
        assert data["limit"] == 1000

        # Verify XGT operations was called correctly
        mock_xgt_ops.get_query_answer.assert_called_once_with(
            job_id=12345,
            offset=0,
            length=1000
        )

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_results_with_pagination(self, mock_create_user_xgt_ops, client):
        """Test query results with pagination."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_query_answer.return_value = {
            'job_id': 12346,
            'status': 'completed',
            'results': [
                ['Bob Wilson', 150.00, 'Headphones']
            ],
            'offset': 50,
            'length': 1
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/12346/results?offset=50&limit=25")

        assert response.status_code == 200
        data = response.json()

        assert data["offset"] == 50
        assert data["limit"] == 25
        assert data["returned_rows"] == 1

        # Verify pagination parameters were passed
        mock_xgt_ops.get_query_answer.assert_called_once_with(
            job_id=12346,
            offset=50,
            length=25
        )

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_results_not_completed(self, mock_create_user_xgt_ops, client):
        """Test query results for job that's not completed."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_query_answer.return_value = {
            'job_id': 12347,
            'status': 'running',
            'results': None,
            'offset': 0,
            'length': 0
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/12347/results")

        assert response.status_code == 200
        data = response.json()

        assert data["job_id"] == 12347
        assert data["status"] == "running"
        assert data["columns"] is None
        assert data["rows"] is None
        assert data["returned_rows"] == 0
        assert data["result_metadata"]["query_execution_completed"] is False

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_results_dict_format(self, mock_create_user_xgt_ops, client):
        """Test query results with dictionary format."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_query_answer.return_value = {
            'job_id': 12348,
            'status': 'completed',
            'results': [
                {'name': 'John Doe', 'amount': 299.99, 'product': 'Smartphone'},
                {'name': 'Jane Smith', 'amount': 1299.99, 'product': 'Laptop'}
            ],
            'offset': 0,
            'length': 2
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/12348/results")

        assert response.status_code == 200
        data = response.json()

        assert data["columns"] == ['name', 'amount', 'product']
        assert data["rows"][0] == ['John Doe', 299.99, 'Smartphone']
        assert data["rows"][1] == ['Jane Smith', 1299.99, 'Laptop']

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_results_not_found(self, mock_create_user_xgt_ops, client):
        """Test query results for non-existent job."""
        from app.utils.exceptions import XGTOperationError

        mock_xgt_ops = Mock()
        mock_xgt_ops.get_query_answer.side_effect = XGTOperationError("Job not found")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/99999/results")

        assert response.status_code == 404
        data = response.json()

        assert data["error"]["code"] == "HTTP_404"
        error_message = data["error"]["message"]
        assert error_message["error"] == "JOB_NOT_FOUND"
        assert "99999" in error_message["message"]

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_query_results_empty_results(self, mock_create_user_xgt_ops, client):
        """Test query results with empty result set."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_query_answer.return_value = {
            'job_id': 12349,
            'status': 'completed',
            'results': [],
            'offset': 0,
            'length': 0
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/12349/results")

        assert response.status_code == 200
        data = response.json()

        assert data["job_id"] == 12349
        assert data["status"] == "completed"
        assert data["columns"] == []
        assert data["rows"] == []
        assert data["returned_rows"] == 0


class TestJobHistory:
    """Test job history endpoint."""

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_job_history_success(self, mock_create_user_xgt_ops, client):
        """Test successful job history retrieval."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_job_history.return_value = {
            'jobs': [
                {
                    'job_id': 12345,
                    'status': 'completed',
                    'query': 'MATCH (c:Customer) RETURN c.name LIMIT 10',
                    'dataset_name': 'ecommerce',
                    'submitted_at': 1642248000.0,
                    'start_time': 1642248000.0,
                    'end_time': 1642248045.0
                },
                {
                    'job_id': 12344,
                    'status': 'completed',
                    'query': 'MATCH (p:Product) RETURN p.name',
                    'dataset_name': 'catalog',
                    'submitted_at': 1642247000.0,
                    'start_time': 1642247000.0,
                    'end_time': 1642247030.0
                }
            ],
            'total_count': 2,
            'page': 1,
            'per_page': 50,
            'has_more': False
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/jobs")

        assert response.status_code == 200
        data = response.json()

        assert len(data["jobs"]) == 2
        assert data["total_count"] == 2
        assert data["page"] == 1
        assert data["per_page"] == 50
        assert data["has_more"] is False

        # Check first job details
        job1 = data["jobs"][0]
        assert job1["job_id"] == 12345
        assert job1["status"] == "completed"
        assert job1["query"] == "MATCH (c:Customer) RETURN c.name LIMIT 10"
        assert job1["dataset_name"] == "ecommerce"
        assert job1["processing_time_ms"] == 45000

        # Verify XGT operations was called correctly
        mock_xgt_ops.get_job_history.assert_called_once_with(
            page=1,
            per_page=50,
            status_filter=None,
            dataset_filter=None
        )

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_job_history_with_pagination(self, mock_create_user_xgt_ops, client):
        """Test job history retrieval with pagination."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_job_history.return_value = {
            'jobs': [
                {
                    'job_id': 12343,
                    'status': 'completed',
                    'query': 'MATCH (o:Order) RETURN o.id',
                    'dataset_name': 'orders',
                    'submitted_at': 1642246000.0,
                    'start_time': 1642246000.0,
                    'end_time': 1642246015.0
                }
            ],
            'total_count': 10,
            'page': 2,
            'per_page': 5,
            'has_more': True
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/jobs?page=2&per_page=5")

        assert response.status_code == 200
        data = response.json()

        assert len(data["jobs"]) == 1
        assert data["total_count"] == 10
        assert data["page"] == 2
        assert data["per_page"] == 5
        assert data["has_more"] is True

        # Verify pagination parameters were passed
        mock_xgt_ops.get_job_history.assert_called_once_with(
            page=2,
            per_page=5,
            status_filter=None,
            dataset_filter=None
        )

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_job_history_with_filters(self, mock_create_user_xgt_ops, client):
        """Test job history retrieval with status and dataset filters."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_job_history.return_value = {
            'jobs': [
                {
                    'job_id': 12346,
                    'status': 'failed',
                    'query': 'MATCH (x:InvalidType) RETURN x',
                    'dataset_name': 'ecommerce',
                    'submitted_at': 1642249000.0,
                    'start_time': 1642249000.0,
                    'end_time': 1642249005.0
                }
            ],
            'total_count': 1,
            'page': 1,
            'per_page': 50,
            'has_more': False
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/jobs?status=failed&dataset_name=ecommerce")

        assert response.status_code == 200
        data = response.json()

        assert len(data["jobs"]) == 1
        assert data["jobs"][0]["status"] == "failed"
        assert data["jobs"][0]["dataset_name"] == "ecommerce"

        # Verify filter parameters were passed
        mock_xgt_ops.get_job_history.assert_called_once_with(
            page=1,
            per_page=50,
            status_filter="failed",
            dataset_filter="ecommerce"
        )

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_job_history_empty(self, mock_create_user_xgt_ops, client):
        """Test job history retrieval when no jobs exist."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_job_history.return_value = {
            'jobs': [],
            'total_count': 0,
            'page': 1,
            'per_page': 50,
            'has_more': False
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/jobs")

        assert response.status_code == 200
        data = response.json()

        assert len(data["jobs"]) == 0
        assert data["total_count"] == 0
        assert data["has_more"] is False

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_job_history_xgt_error(self, mock_create_user_xgt_ops, client):
        """Test job history retrieval when XGT operation fails."""
        from app.utils.exceptions import XGTOperationError

        mock_xgt_ops = Mock()
        mock_xgt_ops.get_job_history.side_effect = XGTOperationError("Job history retrieval failed")
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/jobs")

        assert response.status_code == 500
        data = response.json()

        assert data["error"]["code"] == "HTTP_500"
        error_message = data["error"]["message"]
        assert error_message["error"] == "XGT_OPERATION_ERROR"
        assert "Failed to retrieve job history" in error_message["message"]

    def test_get_job_history_invalid_parameters(self, client):
        """Test job history retrieval with invalid parameters."""
        # Test invalid page
        response = client.get("/api/v1/public/query/jobs?page=0")
        assert response.status_code == 422

        # Test invalid per_page
        response = client.get("/api/v1/public/query/jobs?per_page=0")
        assert response.status_code == 422

        # Test per_page too large
        response = client.get("/api/v1/public/query/jobs?per_page=300")
        assert response.status_code == 422

    @patch('app.api.v1.public.query.create_user_xgt_operations')
    def test_get_job_history_processing_time_calculation(self, mock_create_user_xgt_ops, client):
        """Test that processing time is calculated correctly."""
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_job_history.return_value = {
            'jobs': [
                {
                    'job_id': 12347,
                    'status': 'completed',
                    'query': 'MATCH (c:Customer) RETURN count(c)',
                    'dataset_name': 'ecommerce',
                    'submitted_at': 1642248000.0,
                    'start_time': 1642248000.0,
                    'end_time': 1642248002.5  # 2.5 seconds later
                }
            ],
            'total_count': 1,
            'page': 1,
            'per_page': 50,
            'has_more': False
        }
        mock_create_user_xgt_ops.return_value = mock_xgt_ops

        response = client.get("/api/v1/public/query/jobs")

        assert response.status_code == 200
        data = response.json()

        job = data["jobs"][0]
        assert job["processing_time_ms"] == 2500  # 2.5 seconds = 2500ms