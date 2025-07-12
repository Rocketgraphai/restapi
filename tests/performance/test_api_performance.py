"""
Performance tests for the RocketGraph Public API.
"""

import time

from fastapi.testclient import TestClient
import pytest


@pytest.mark.performance
class TestAPIPerformance:
    """Test API performance characteristics."""

    def test_health_endpoint_response_time(self, client: TestClient):
        """Test that health endpoint responds within acceptable time."""
        start_time = time.time()
        response = client.get("/api/v1/public/health")
        end_time = time.time()

        response_time = end_time - start_time

        assert response.status_code == 200
        assert response_time < 1.0  # Should respond in under 1 second

    def test_concurrent_health_requests(self, client: TestClient):
        """Test health endpoint under concurrent load."""
        import concurrent.futures

        def make_request():
            response = client.get("/api/v1/public/health")
            return response.status_code

        # Simulate 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        # All requests should succeed
        assert all(status == 200 for status in results)
        assert len(results) == 10

    def test_memory_usage_stability(self, client: TestClient):
        """Test that memory usage remains stable under repeated requests."""
        import os

        import psutil

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Make 100 requests
        for _ in range(100):
            response = client.get("/api/v1/public/health")
            assert response.status_code == 200

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable (less than 50MB)
        assert memory_increase < 50 * 1024 * 1024
