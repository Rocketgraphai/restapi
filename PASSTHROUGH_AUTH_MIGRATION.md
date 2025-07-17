# Migration Guide: Pass-Through Authentication

This guide explains how to migrate from admin-credential XGT connections to user pass-through authentication.

## Overview

**Before:** REST API used single admin credentials from `.env` file  
**After:** Each API call uses the authenticated user's own XGT credentials

## Required Changes

### 1. Environment Configuration

The `.env` file no longer needs XGT admin credentials for regular operations:

```bash
# BEFORE: Required admin credentials
XGT_USERNAME=admin
XGT_PASSWORD=admin_secret

# AFTER: Only needed for system admin operations (optional)
# XGT_USERNAME=admin  # Only for admin endpoints
# XGT_PASSWORD=admin_secret  # Only for admin endpoints

# Still required: XGT server connection details
XGT_HOST=localhost
XGT_PORT=4367
XGT_USE_SSL=false
XGT_SSL_CERT=/path/to/cert.pem
XGT_SERVER_CN=xgt-server.company.com

# New: JWT configuration for encrypted credential storage
JWT_SECRET_KEY=your-secure-jwt-secret-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRY_SECONDS=3600
SECRET_KEY=your-32-char-encryption-key-here
```

### 2. Client Authentication Flow

#### Before: No authentication required
```bash
curl http://localhost:8000/api/v1/public/query/123/results
```

#### After: Must authenticate first

**Step 1: Authenticate with XGT credentials**
```bash
# Basic Auth
curl -X POST http://localhost:8000/api/v1/auth/xgt/basic \
  -H "Content-Type: application/json" \
  -d '{
    "auth_type": "basic",
    "username": "your_xgt_username", 
    "password": "your_xgt_password"
  }'

# Response includes JWT token
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user_info": {
    "username": "your_xgt_username",
    "namespace": "your_xgt_username",
    "groups": ["your_xgt_username"],
    "authenticated_at": "2024-01-15T10:30:00Z",
    "auth_type": "basic"
  }
}
```

**Step 2: Use JWT token for API calls**
```bash
curl http://localhost:8000/api/v1/public/query/123/results \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 3. PKI Authentication (New Feature)

For PKI certificate authentication:

```bash
# Convert certificates to base64
CLIENT_CERT_B64=$(base64 -w 0 /path/to/client.cert.pem)
CLIENT_KEY_B64=$(base64 -w 0 /path/to/client.key.pem)
CA_CHAIN_B64=$(base64 -w 0 /path/to/ca-chain.cert.pem)

# Authenticate with PKI
curl -X POST http://localhost:8000/api/v1/auth/xgt/pki \
  -H "Content-Type: application/json" \
  -d '{
    "auth_type": "pki",
    "client_cert": "'$CLIENT_CERT_B64'",
    "client_key": "'$CLIENT_KEY_B64'", 
    "ca_chain": "'$CA_CHAIN_B64'",
    "ssl_server_cn": "xgt-server.company.com"
  }'
```

### 4. Application Code Changes

#### Before: Using admin operations
```python
from app.utils.xgt_operations import create_xgt_operations

xgt_ops = create_xgt_operations()  # Uses admin credentials
results = xgt_ops.get_query_answer(job_id)
```

#### After: Using user operations
```python
from app.utils.xgt_user_operations import create_user_xgt_operations
from app.auth.passthrough_middleware import require_xgt_authentication

# In FastAPI endpoint
@router.get("/some-endpoint")
async def my_endpoint(
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)]
):
    # Create user-specific XGT operations
    user_xgt_ops = create_user_xgt_operations(current_user.credentials)
    
    # Execute query using user's credentials
    results = user_xgt_ops.execute_query("MATCH (n) RETURN n LIMIT 10")
    
    return {"results": results}
```

### 5. Endpoint Updates Required

All existing endpoints need to be updated to use pass-through auth:

```python
# OLD: No authentication
@router.get("/query/{job_id}/results")
async def get_query_results(job_id: int):
    xgt_ops = create_xgt_operations()  # Admin credentials
    return xgt_ops.get_query_answer(job_id)

# NEW: User authentication required  
@router.get("/query/{job_id}/results")
async def get_query_results(
    job_id: int,
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)]
):
    user_xgt_ops = create_user_xgt_operations(current_user.credentials)
    return user_xgt_ops.execute_query(f"/* get job {job_id} results */")
```

## New Authentication Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/auth/xgt/basic` | POST | Basic username/password auth |
| `/api/v1/auth/xgt/pki` | POST | PKI certificate auth |
| `/api/v1/auth/xgt/proxy-pki` | POST | Proxy PKI auth |
| `/api/v1/auth/validate` | POST | Validate JWT token |
| `/api/v1/auth/me` | GET | Get current user info |
| `/api/v1/auth/test-connection` | POST | Test XGT connection |

## Security Benefits

1. **User Isolation**: Each user only accesses their own XGT namespace
2. **Credential Security**: User credentials encrypted in JWT tokens
3. **No Shared Admin**: No single admin credential compromise risk
4. **Audit Trail**: All operations traced to specific users
5. **PKI Support**: Enterprise-grade certificate authentication

## Migration Checklist

- [ ] Update `.env` file with JWT configuration
- [ ] Remove or secure XGT admin credentials
- [ ] Update client applications to authenticate first
- [ ] Test Basic Auth flow
- [ ] Test PKI Auth flow (if using certificates)
- [ ] Update all API endpoints to require authentication
- [ ] Verify user isolation and permissions
- [ ] Update documentation and examples

## Backward Compatibility

The old admin-credential system can run alongside the new pass-through system during migration:

1. Keep admin credentials in `.env` for legacy endpoints
2. Gradually migrate endpoints to use pass-through auth
3. Remove admin credentials once migration is complete

## Troubleshooting

**Problem: "XGT_AUTHENTICATION_REQUIRED" error**  
Solution: Authenticate first with `/api/v1/auth/xgt/basic` or `/api/v1/auth/xgt/pki`

**Problem: "TOKEN_EXPIRED" error**  
Solution: Re-authenticate to get a new JWT token

**Problem: PKI authentication fails**  
Solution: Verify certificate format, ensure userId in certificate subject

**Problem: "Cannot connect to XGT server"**  
Solution: Check XGT server configuration and user credentials

For support, check the logs for detailed error messages and verify XGT server accessibility.