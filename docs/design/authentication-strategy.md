# Authentication Strategy

## Overview

The RocketGraph Public API uses **API Key Authentication** as the primary authentication mechanism, designed for security, scalability, and ease of integration for external developers.

## Authentication Methods

### Primary: API Key Authentication

**Bearer Token Format**
```http
Authorization: Bearer rg_live_<32-character-random-string>
```

**API Key Structure**
- **Prefix**: `rg_live_` (production) or `rg_test_` (development)
- **Body**: 32-character cryptographically secure random string
- **Example**: `rg_live_sk_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p`

**Generation Algorithm**
```python
import secrets
import string

def generate_api_key(environment='live'):
    """Generate a secure API key"""
    prefix = f"rg_{environment}_"
    # Generate 32 secure random characters
    chars = string.ascii_letters + string.digits
    key_body = ''.join(secrets.choice(chars) for _ in range(32))
    return f"{prefix}{key_body}"
```

### Alternative: JWT Tokens (Future)

For enterprise customers requiring additional security features:
- Short-lived access tokens (15 minutes)
- Refresh token mechanism
- Signed with RS256 algorithm
- Custom claims for fine-grained permissions

## Multi-Tenant Architecture

### Organization-Based Keys

**Hierarchy**
```
Organization (tenant)
├── API Keys (multiple per org)
│   ├── Production Keys
│   └── Development Keys
├── Users (multiple per org)
├── Resources (scoped to org)
└── Permissions (org-level policies)
```

**Key Scoping**
Each API key is associated with:
- **Organization ID**: Unique tenant identifier
- **Environment**: `production`, `staging`, `development`
- **Scopes**: Specific permissions granted
- **Expiration**: Optional automatic expiration
- **Usage Limits**: Rate limits and quotas

### Resource Isolation

**Database Level**
```python
# All queries automatically scoped by organization
def get_datasets(api_key):
    org_id = api_key.organization_id
    return xgt_ops.get_datasets(organization_id=org_id)
```

**XGT Connection Isolation**
- Separate XGT schemas per organization
- Connection pooling by organization
- Query result filtering by tenant

## API Key Management

### Key Lifecycle

1. **Creation**
   ```http
   POST /api/v1/admin/api-keys
   {
     "name": "Production Integration",
     "scopes": ["datasets:read", "queries:execute"],
     "expires_at": "2025-12-31T23:59:59Z"
   }
   ```

2. **Rotation**
   ```http
   POST /api/v1/admin/api-keys/{key_id}/rotate
   # Returns new key, marks old key for deprecation
   ```

3. **Revocation**
   ```http
   DELETE /api/v1/admin/api-keys/{key_id}
   # Immediately invalidates the key
   ```

### Key Storage

**Database Schema**
```python
class ApiKey:
    id: str                    # Unique identifier
    organization_id: str       # Tenant identifier
    key_hash: str             # SHA-256 hash of the key
    key_prefix: str           # First 8 characters for identification
    name: str                 # Human-readable name
    scopes: List[str]         # Permission scopes
    created_at: datetime
    expires_at: datetime      # Optional expiration
    last_used_at: datetime    # Track usage
    is_active: bool           # Enable/disable flag
    usage_count: int          # Request counter
    rate_limit: dict          # Custom rate limits
```

**Security Measures**
- Store only SHA-256 hash of API key
- Salt with organization ID before hashing
- Never log full API keys
- Secure key generation using cryptographic random

## Scope-Based Permissions

### Permission Model

**Scope Format**: `resource:action`

**Available Scopes**
```python
SCOPES = {
    # Dataset operations
    'datasets:read',          # List and view datasets
    'datasets:create',        # Create new datasets
    'datasets:modify',        # Update dataset metadata
    'datasets:delete',        # Delete datasets
    
    # Query operations  
    'queries:execute',        # Run graph queries
    'queries:history',        # View query history
    
    # Schema operations
    'schemas:read',           # View schema information
    'schemas:infer',          # Use schema inference
    'schemas:modify',         # Update schemas
    
    # Data operations
    'data:upload',            # Upload data to datasets
    'data:download',          # Download query results
    
    # Administrative
    'admin:keys',             # Manage API keys
    'admin:users',            # Manage organization users
    'admin:audit',            # Access audit logs
    
    # Special scopes
    'read_only',              # All read operations
    'full_access'             # All operations (dangerous)
}
```

**Scope Validation**
```python
def check_permission(api_key, required_scope):
    """Check if API key has required permission"""
    if 'full_access' in api_key.scopes:
        return True
    
    if 'read_only' in api_key.scopes:
        if required_scope.endswith(':read'):
            return True
    
    return required_scope in api_key.scopes
```

### Role-Based Templates

**Predefined Roles**
```python
ROLE_TEMPLATES = {
    'viewer': [
        'datasets:read',
        'queries:execute',
        'schemas:read'
    ],
    
    'developer': [
        'datasets:read',
        'datasets:create',
        'queries:execute',
        'queries:history',
        'schemas:read',
        'schemas:infer',
        'data:upload',
        'data:download'
    ],
    
    'admin': [
        'full_access'
    ]
}
```

## Authentication Flow

### Request Authentication

```python
def authenticate_request(request):
    """Authenticate API request"""
    
    # 1. Extract API key from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        raise AuthenticationError("Missing or invalid Authorization header")
    
    api_key = auth_header[7:]  # Remove "Bearer " prefix
    
    # 2. Validate key format
    if not validate_key_format(api_key):
        raise AuthenticationError("Invalid API key format")
    
    # 3. Hash the key for database lookup
    key_hash = hash_api_key(api_key)
    
    # 4. Look up key in database
    key_record = db.api_keys.find_one({
        'key_hash': key_hash,
        'is_active': True
    })
    
    if not key_record:
        raise AuthenticationError("Invalid API key")
    
    # 5. Check expiration
    if key_record.expires_at and key_record.expires_at < datetime.utcnow():
        raise AuthenticationError("API key has expired")
    
    # 6. Update usage tracking
    db.api_keys.update_one(
        {'_id': key_record['_id']},
        {
            '$set': {'last_used_at': datetime.utcnow()},
            '$inc': {'usage_count': 1}
        }
    )
    
    # 7. Return authenticated context
    return AuthContext(
        api_key=key_record,
        organization_id=key_record['organization_id'],
        scopes=key_record['scopes']
    )
```

### Error Handling

**Authentication Errors**
```python
HTTP_401_RESPONSES = {
    'missing_auth': {
        'error': 'authentication_required',
        'message': 'Authorization header is required',
        'details': 'Include "Authorization: Bearer YOUR_API_KEY" header'
    },
    
    'invalid_key': {
        'error': 'invalid_api_key',
        'message': 'The provided API key is invalid',
        'details': 'Check your API key format and ensure it\'s active'
    },
    
    'expired_key': {
        'error': 'api_key_expired',
        'message': 'The API key has expired',
        'details': 'Generate a new API key or contact support'
    },
    
    'insufficient_scope': {
        'error': 'insufficient_permissions',
        'message': 'API key lacks required permissions',
        'details': 'Contact your organization admin to update key permissions'
    }
}
```

## Security Implementation

### Key Hashing

```python
import hashlib
import hmac

def hash_api_key(api_key: str, organization_id: str) -> str:
    """Securely hash API key with organization salt"""
    salt = f"rg_salt_{organization_id}"
    return hashlib.sha256(f"{salt}:{api_key}".encode()).hexdigest()
```

### Rate Limiting Integration

```python
def get_rate_limit_key(auth_context):
    """Generate rate limiting key"""
    return f"rate_limit:{auth_context.organization_id}:{auth_context.api_key.id}"
```

### Audit Logging

```python
def log_api_access(auth_context, request, response):
    """Log API access for audit trail"""
    audit_log = {
        'timestamp': datetime.utcnow(),
        'organization_id': auth_context.organization_id,
        'api_key_id': auth_context.api_key.id,
        'api_key_name': auth_context.api_key.name,
        'method': request.method,
        'endpoint': request.path,
        'user_agent': request.headers.get('User-Agent'),
        'ip_address': get_client_ip(request),
        'status_code': response.status_code,
        'response_time_ms': response.processing_time,
        'request_id': request.id
    }
    
    audit_collection.insert_one(audit_log)
```

## Key Management Best Practices

### For API Consumers

1. **Secure Storage**
   - Store keys in environment variables
   - Use secure secret management systems
   - Never commit keys to version control

2. **Key Rotation**
   - Rotate keys regularly (90 days recommended)
   - Use overlapping key validity for zero-downtime rotation
   - Monitor key usage before deactivation

3. **Scope Management**
   - Use least-privilege principle
   - Create separate keys for different use cases
   - Regular permission audits

### For API Providers

1. **Key Generation**
   - Use cryptographically secure random generators
   - Implement proper entropy sources
   - Validate uniqueness across all keys

2. **Storage Security**
   - Hash keys before storage
   - Use organization-specific salts
   - Implement secure backup procedures

3. **Monitoring**
   - Track key usage patterns
   - Alert on suspicious activity
   - Automated threat detection

## Future Enhancements

### Advanced Authentication

1. **Certificate-Based Authentication**
   - mTLS for high-security environments
   - Hardware security module integration

2. **OAuth 2.0 Integration**
   - Third-party identity provider support
   - Standard OAuth flows

3. **Temporary Access Tokens**
   - Short-lived tokens for specific operations
   - Delegation and impersonation support

This authentication strategy provides enterprise-grade security while maintaining developer-friendly integration patterns.