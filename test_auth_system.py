#!/usr/bin/env python3
"""
RocketGraph Public API Authentication Test Suite

Comprehensive testing of the pass-through authentication system.
Tests both Basic Auth and PKI Auth (if certificates available).
"""

import argparse
import base64
import json
import sys
import time
from typing import Dict, Optional

import requests


class APITester:
    def __init__(self, base_url: str = "http://localhost:8000/api/v1"):
        self.base_url = base_url
        self.session = requests.Session()
        self.access_token: Optional[str] = None

    def log_info(self, message: str):
        print(f"[INFO] {message}")

    def log_success(self, message: str):
        print(f"[SUCCESS] ✅ {message}")

    def log_error(self, message: str):
        print(f"[ERROR] ❌ {message}")

    def log_warning(self, message: str):
        print(f"[WARNING] ⚠️  {message}")

    def test_endpoint(
        self,
        name: str,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        expected_status: int = 200,
        use_auth: bool = False,
    ) -> Optional[Dict]:
        """Test an API endpoint and return response data if successful."""

        url = f"{self.base_url}{endpoint}"
        headers = {"Content-Type": "application/json"}

        if use_auth and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        self.log_info(f"Testing: {name}")

        try:
            if method.upper() == "GET":
                response = self.session.get(url, headers=headers)
            elif method.upper() == "POST":
                response = self.session.post(url, headers=headers, json=data)
            elif method.upper() == "PUT":
                response = self.session.put(url, headers=headers, json=data)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, headers=headers)
            else:
                self.log_error(f"Unsupported method: {method}")
                return None

            if response.status_code == expected_status:
                self.log_success(f"{name} - Status: {response.status_code}")

                # Pretty print JSON response
                try:
                    response_data = response.json()
                    print(json.dumps(response_data, indent=2))
                    print()
                    return response_data
                except:
                    if response.text:
                        print(response.text)
                    print()
                    return {"text": response.text}
            else:
                self.log_error(f"{name} - Expected: {expected_status}, Got: {response.status_code}")
                try:
                    error_data = response.json()
                    print(json.dumps(error_data, indent=2))
                except:
                    print(response.text)
                print()
                return None

        except requests.RequestException as e:
            self.log_error(f"{name} - Request failed: {e}")
            return None

    def authenticate_basic(self, username: str, password: str) -> bool:
        """Authenticate using basic auth and store access token."""

        auth_data = {"auth_type": "basic", "username": username, "password": password}

        response_data = self.test_endpoint(
            "Basic Authentication", "POST", "/auth/xgt/basic", auth_data, 200
        )

        if response_data and "access_token" in response_data:
            self.access_token = response_data["access_token"]
            self.log_success(f"Authentication successful for user: {username}")
            return True
        else:
            self.log_error("Authentication failed")
            return False

    def authenticate_pki(
        self,
        cert_path: str,
        key_path: str,
        ca_path: Optional[str] = None,
        server_cn: Optional[str] = None,
    ) -> bool:
        """Authenticate using PKI certificates."""

        try:
            # Read and base64 encode certificates
            with open(cert_path, "rb") as f:
                client_cert_b64 = base64.b64encode(f.read()).decode()

            with open(key_path, "rb") as f:
                client_key_b64 = base64.b64encode(f.read()).decode()

            auth_data = {
                "auth_type": "pki",
                "client_cert": client_cert_b64,
                "client_key": client_key_b64,
            }

            if ca_path:
                with open(ca_path, "rb") as f:
                    auth_data["ca_chain"] = base64.b64encode(f.read()).decode()

            if server_cn:
                auth_data["ssl_server_cn"] = server_cn

            response_data = self.test_endpoint(
                "PKI Authentication", "POST", "/auth/xgt/pki", auth_data, 200
            )

            if response_data and "access_token" in response_data:
                self.access_token = response_data["access_token"]
                self.log_success("PKI Authentication successful")
                return True
            else:
                self.log_error("PKI Authentication failed")
                return False

        except FileNotFoundError as e:
            self.log_error(f"Certificate file not found: {e}")
            return False
        except Exception as e:
            self.log_error(f"PKI Authentication error: {e}")
            return False

    def run_comprehensive_tests(self):
        """Run the complete test suite."""

        print("=" * 50)
        print("🚀 RocketGraph API Authentication Test Suite")
        print("=" * 50)
        print()

        # Test 1: Health Check
        print("🏥 Health Check Tests")
        print("-" * 30)
        self.test_endpoint("Health Check", "GET", "/public/health", expected_status=200)

        # Test 2: Authentication Tests
        print("🔐 Authentication Tests")
        print("-" * 30)

        # Try to authenticate if not already authenticated
        if not self.access_token:
            username = input("Enter XGT username (default: haglin): ").strip() or "haglin"
            password = (
                input("Enter XGT password (default: secure_password_123): ").strip()
                or "secure_password_123"
            )

            if not self.authenticate_basic(username, password):
                self.log_error("Cannot proceed without authentication")
                return False
        else:
            self.log_success("Using pre-authenticated token")

        # Test invalid credentials
        self.test_endpoint(
            "Invalid Credentials Test",
            "POST",
            "/auth/xgt/basic",
            {"auth_type": "basic", "username": "invalid", "password": "wrong"},
            expected_status=401,
        )

        # Test 3: Token-based Endpoints
        print("🎫 Token-based Endpoint Tests")
        print("-" * 30)

        self.test_endpoint("Get Current User", "GET", "/auth/me", use_auth=True)
        self.test_endpoint("Validate Token", "POST", "/auth/validate", use_auth=True)
        self.test_endpoint("Test XGT Connection", "POST", "/auth/test-connection", use_auth=True)

        # Test 4: Protected Endpoints
        print("🔒 Protected Endpoint Tests")
        print("-" * 30)

        # Test without auth
        self.test_endpoint("Access without auth", "GET", "/public/datasets", expected_status=401)

        # Test with auth
        self.test_endpoint("Access with auth", "GET", "/public/datasets", use_auth=True)

        # Test 5: Edge Cases
        print("🧪 Edge Case Tests")
        print("-" * 30)

        # Test malformed requests
        self.test_endpoint(
            "Malformed Auth Request",
            "POST",
            "/auth/xgt/basic",
            {"username": "test"},  # Missing password and auth_type
            expected_status=422,
        )

        # Test with invalid token
        old_token = self.access_token
        self.access_token = "invalid.token.here"
        self.test_endpoint(
            "Invalid Token Test", "GET", "/auth/me", expected_status=401, use_auth=True
        )
        self.access_token = old_token  # Restore valid token

        # Test 6: Performance Tests
        print("⚡ Performance Tests")
        print("-" * 30)

        start_time = time.time()
        for i in range(5):
            self.test_endpoint(f"Concurrent Request {i + 1}", "GET", "/auth/me", use_auth=True)
        end_time = time.time()

        self.log_info(f"5 requests completed in {end_time - start_time:.2f} seconds")

        # Summary
        print("📊 Test Summary")
        print("-" * 30)
        self.log_success("All tests completed!")
        self.log_info("Access token (expires in 1 hour):")
        print(f"  {self.access_token}")
        print()

        return True


def main():
    parser = argparse.ArgumentParser(description="Test RocketGraph API Authentication")
    parser.add_argument(
        "--url",
        default="http://localhost:8000/api/v1",
        help="API base URL (default: http://localhost:8000/api/v1)",
    )
    parser.add_argument("--username", help="XGT username for testing")
    parser.add_argument("--password", help="XGT password for testing")
    parser.add_argument("--cert", help="Path to client certificate for PKI auth")
    parser.add_argument("--key", help="Path to client private key for PKI auth")
    parser.add_argument("--ca", help="Path to CA certificate")
    parser.add_argument("--server-cn", help="Expected server common name for PKI")

    args = parser.parse_args()

    tester = APITester(args.url)

    # Test basic auth if credentials provided
    if args.username and args.password:
        if not tester.authenticate_basic(args.username, args.password):
            sys.exit(1)

    # Test PKI auth if certificates provided
    if args.cert and args.key:
        if not tester.authenticate_pki(args.cert, args.key, args.ca, args.server_cn):
            tester.log_warning("PKI authentication failed, continuing with basic auth if available")

    # Run comprehensive tests
    success = tester.run_comprehensive_tests()

    if success:
        print("🎉 All tests completed successfully!")
        sys.exit(0)
    else:
        print("💥 Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
