#!/bin/bash

# RocketGraph Public API Authentication Test Suite
# Tests the pass-through authentication system with XGT credentials

set -e  # Exit on any error

# Configuration
API_BASE="http://localhost:8000/api/v1"
TEST_USERNAME="haglin"
TEST_PASSWORD="secure_password_123"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

test_endpoint() {
    local name="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local headers="$5"
    local expected_status="$6"
    
    log_info "Testing: $name"
    
    if [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
            -H "Content-Type: application/json" \
            $headers \
            -d "$data")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$url" \
            $headers)
    fi
    
    # Split response and status code
    status_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | sed '$d')
    
    if [ "$status_code" = "$expected_status" ]; then
        log_success "$name - Status: $status_code"
        if [ "$status_code" = "200" ] || [ "$status_code" = "201" ]; then
            echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body"
        fi
        echo ""
        return 0
    else
        log_error "$name - Expected: $expected_status, Got: $status_code"
        echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body"
        echo ""
        return 1
    fi
}

# Test 1: Health Check (No auth required)
echo "=================================="
echo "🏥 HEALTH CHECK TESTS"
echo "=================================="

test_endpoint "Health Check" "GET" "$API_BASE/public/health" "" "" "200"

# Test 2: Authentication Tests
echo "=================================="
echo "🔐 AUTHENTICATION TESTS"
echo "=================================="

# Test 2a: Basic Authentication
log_info "Testing Basic Authentication..."
auth_data='{
  "auth_type": "basic",
  "username": "'$TEST_USERNAME'",
  "password": "'$TEST_PASSWORD'"
}'

auth_response=$(curl -s -X POST "$API_BASE/auth/xgt/basic" \
    -H "Content-Type: application/json" \
    -d "$auth_data")

if echo "$auth_response" | jq -e '.access_token' > /dev/null 2>&1; then
    log_success "Basic Authentication successful"
    ACCESS_TOKEN=$(echo "$auth_response" | jq -r '.access_token')
    echo "$auth_response" | jq '.'
    echo ""
else
    log_error "Basic Authentication failed"
    echo "$auth_response" | jq '.' 2>/dev/null || echo "$auth_response"
    exit 1
fi

# Test 2b: Invalid credentials
log_info "Testing invalid credentials..."
invalid_auth_data='{
  "auth_type": "basic",
  "username": "invalid_user",
  "password": "wrong_password"
}'

test_endpoint "Invalid Credentials" "POST" "$API_BASE/auth/xgt/basic" "$invalid_auth_data" "" "401"

# Test 3: Token-based endpoint tests
echo "=================================="
echo "🎫 TOKEN-BASED ENDPOINT TESTS"
echo "=================================="

AUTH_HEADER="-H \"Authorization: Bearer $ACCESS_TOKEN\""

# Test 3a: Get current user info
test_endpoint "Get Current User Info" "GET" "$API_BASE/auth/me" "" "$AUTH_HEADER" "200"

# Test 3b: Validate token
test_endpoint "Validate Token" "POST" "$API_BASE/auth/validate" "" "$AUTH_HEADER" "200"

# Test 3c: Test XGT connection
test_endpoint "Test XGT Connection" "POST" "$API_BASE/auth/test-connection" "" "$AUTH_HEADER" "200"

# Test 4: Protected endpoints (require authentication)
echo "=================================="
echo "🔒 PROTECTED ENDPOINT TESTS"
echo "=================================="

# Test 4a: Access protected endpoint without token
test_endpoint "Access without token" "GET" "$API_BASE/public/datasets" "" "" "401"

# Test 4b: Access protected endpoint with valid token
test_endpoint "Access with valid token" "GET" "$API_BASE/public/datasets" "" "$AUTH_HEADER" "200"

# Test 4c: Access with invalid token
invalid_token_header="-H \"Authorization: Bearer invalid.token.here\""
test_endpoint "Access with invalid token" "GET" "$API_BASE/public/datasets" "" "$invalid_token_header" "401"

# Test 5: Token expiry simulation
echo "=================================="
echo "⏰ TOKEN EXPIRY TESTS"
echo "=================================="

# Test 5a: Try to validate an obviously expired/malformed token
expired_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ.invalid"
expired_token_header="-H \"Authorization: Bearer $expired_token\""
test_endpoint "Expired Token Validation" "POST" "$API_BASE/auth/validate" "" "$expired_token_header" "200"

# Test 6: Edge cases
echo "=================================="
echo "🧪 EDGE CASE TESTS"
echo "=================================="

# Test 6a: Malformed auth request
malformed_auth='{
  "username": "'$TEST_USERNAME'"
}'
test_endpoint "Malformed Auth Request" "POST" "$API_BASE/auth/xgt/basic" "$malformed_auth" "" "422"

# Test 6b: Empty auth request
test_endpoint "Empty Auth Request" "POST" "$API_BASE/auth/xgt/basic" "{}" "" "422"

# Test 6c: Missing Authorization header format
missing_bearer_header="-H \"Authorization: $ACCESS_TOKEN\""
test_endpoint "Missing Bearer Prefix" "GET" "$API_BASE/auth/me" "" "$missing_bearer_header" "401"

# Test 7: PKI Authentication (if certificates available)
echo "=================================="
echo "📜 PKI AUTHENTICATION TESTS"
echo "=================================="

log_warning "PKI tests require valid certificates - skipping for now"
log_info "To test PKI authentication, create certificates and update this script"

# Example PKI test (commented out):
# if [ -f "client.cert.pem" ] && [ -f "client.key.pem" ]; then
#     CLIENT_CERT_B64=$(base64 -w 0 client.cert.pem)
#     CLIENT_KEY_B64=$(base64 -w 0 client.key.pem)
#     
#     pki_auth_data='{
#       "auth_type": "pki",
#       "client_cert": "'$CLIENT_CERT_B64'",
#       "client_key": "'$CLIENT_KEY_B64'",
#       "ssl_server_cn": "xgt-server.company.com"
#     }'
#     
#     test_endpoint "PKI Authentication" "POST" "$API_BASE/auth/xgt/pki" "$pki_auth_data" "" "200"
# fi

# Test 8: Load testing (basic)
echo "=================================="
echo "⚡ BASIC LOAD TESTS"
echo "=================================="

log_info "Testing multiple concurrent requests..."
for i in {1..5}; do
    test_endpoint "Concurrent Request $i" "GET" "$API_BASE/auth/me" "" "$AUTH_HEADER" "200" &
done
wait
log_success "Concurrent requests completed"

# Summary
echo "=================================="
echo "📊 TEST SUMMARY"
echo "=================================="

log_success "Authentication system tests completed!"
log_info "Key findings:"
echo "  ✅ Basic authentication working"
echo "  ✅ JWT token generation working"
echo "  ✅ Protected endpoints secured"
echo "  ✅ Token validation working"
echo "  ✅ Error handling proper"
echo ""
log_info "Your access token (valid for 1 hour):"
echo "  $ACCESS_TOKEN"
echo ""
log_info "Use this token in your API calls or FastAPI docs for testing"