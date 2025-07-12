"""
Integration tests for XGT datasets endpoints.

These tests require a running XGT server instance.
"""


import pytest
import requests


class TestXGTDatasetsIntegration:
    """Integration tests for datasets endpoints with real XGT server."""

    @pytest.fixture(scope="class")
    def base_url(self) -> str:
        """Base URL for the API server."""
        return "http://localhost:8000"

    @pytest.fixture(scope="class")
    def xgt_available(self) -> bool:
        """Check if XGT server is available for testing."""
        try:
            import xgt
            # Try to connect to XGT directly to verify it's running
            conn = xgt.Connection(host="localhost", port=4367,
                                auth=xgt.BasicAuth(username="admin", password=""))
            conn.close()
            return True
        except Exception:
            return False

    @pytest.fixture(scope="class")
    def api_server_running(self, base_url: str) -> bool:
        """Check if API server is running."""
        try:
            response = requests.get(f"{base_url}/api/v1/public/health", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def test_datasets_endpoint_with_xgt(self, base_url: str, xgt_available: bool,
                                       api_server_running: bool):
        """Test datasets endpoint with real XGT connection."""
        if not xgt_available:
            pytest.skip("XGT server not available")
        if not api_server_running:
            pytest.skip("API server not running")

        # Test the datasets listing endpoint
        response = requests.get(f"{base_url}/api/v1/public/datasets")

        assert response.status_code == 200
        data = response.json()

        # Verify response structure
        assert "datasets" in data
        assert "total_count" in data
        assert isinstance(data["datasets"], list)
        assert isinstance(data["total_count"], int)

        # The admin namespace should be accessible
        for _dataset in data["datasets"]:
            pass

    def test_health_endpoint_xgt_connection(self, base_url: str, xgt_available: bool):
        """Test health endpoint shows XGT connection status."""
        if not xgt_available:
            pytest.skip("XGT server not available")

        response = requests.get(f"{base_url}/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        # Check XGT connection info in health response
        assert "xgt" in data
        xgt_info = data["xgt"]

        # Should have connection details when XGT is available
        assert "connection_status" in xgt_info
        assert "server_version" in xgt_info


    def test_datasets_endpoint_error_handling(self, base_url: str):
        """Test datasets endpoint error handling."""
        # Test with invalid dataset name
        response = requests.get(f"{base_url}/api/v1/public/datasets/nonexistent_dataset")

        # Should return 404 for non-existent dataset
        assert response.status_code == 404
        data = response.json()

        assert "error" in data
        assert data["error"]["code"] == "HTTP_404"

    def test_datasets_with_query_parameters(self, base_url: str, xgt_available: bool):
        """Test datasets endpoint with query parameters."""
        if not xgt_available:
            pytest.skip("XGT server not available")

        # Test with include_empty parameter
        response = requests.get(f"{base_url}/api/v1/public/datasets?include_empty=true")

        assert response.status_code == 200
        data = response.json()

        assert "datasets" in data
        assert "total_count" in data

    @pytest.mark.slow
    def test_concurrent_requests(self, base_url: str, xgt_available: bool):
        """Test multiple concurrent requests to datasets endpoint."""
        if not xgt_available:
            pytest.skip("XGT server not available")

        import concurrent.futures

        def make_request():
            response = requests.get(f"{base_url}/api/v1/public/datasets")
            return response.status_code == 200

        # Make 5 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(5)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        # All requests should succeed
        assert all(results), "Some concurrent requests failed"
