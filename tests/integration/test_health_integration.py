"""
Integration tests for health endpoints with real services.
"""

from fastapi.testclient import TestClient
import pytest


@pytest.mark.integration
class TestHealthIntegration:
    """Integration tests for health check endpoints."""

    def test_health_with_redis_connection(self, client: TestClient):
        """Test health check with actual Redis connection."""
        response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        # Check that we got a response structure
        assert "status" in data
        assert "services" in data
        assert "redis" in data["services"]

    def test_health_with_mongodb_connection(self, client: TestClient):
        """Test health check with actual MongoDB connection."""
        response = client.get("/api/v1/public/health")

        assert response.status_code == 200
        data = response.json()

        # Check that we got a response structure
        assert "status" in data
        assert "services" in data
        assert "mongodb" in data["services"]

    def test_readiness_probe_kubernetes_style(self, client: TestClient):
        """Test readiness endpoint as Kubernetes would."""
        response = client.get("/api/v1/public/ready")

        # Kubernetes expects 200 for ready, 503 for not ready
        assert response.status_code in [200, 503]

        if response.status_code == 200:
            data = response.json()
            assert data["status"] == "ready"
            assert data["ready"] is True

    def test_liveness_probe_kubernetes_style(self, client: TestClient):
        """Test liveness endpoint as Kubernetes would."""
        response = client.get("/api/v1/public/live")

        # Kubernetes expects 200 for alive
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "alive"
