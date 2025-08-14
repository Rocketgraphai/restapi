# FastAPI Docs with Pass-Through Authentication

When you visit `http://localhost:8000/docs`, you'll see the new authentication system integrated into the Swagger UI interface.

## What You'll See in the Docs

### 1. Security Scheme Configuration

At the top right of the Swagger UI, you'll see a **"Authorize"** button. Clicking it will show:

```
🔒 BearerAuth (http, Bearer)
Description: JWT token obtained from XGT authentication endpoints

Value: [Input field for Bearer token]
```

### 2. New Authentication Section

A new **"authentication"** section will appear with these endpoints:

#### **POST** `/api/v1/auth/xgt/basic` - Basic Authentication
```json
Request Body:
{
  "auth_type": "basic",
  "username": "your_xgt_username",
  "password": "your_xgt_password"
}

Response (200):
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

#### **POST** `/api/v1/auth/xgt/pki` - PKI Authentication  
```json
Request Body:
{
  "auth_type": "pki",
  "client_cert": "LS0tLS1CRUdJTi...",  // base64 encoded PEM
  "client_key": "LS0tLS1CRUdJTi...",   // base64 encoded PEM
  "ca_chain": "LS0tLS1CRUdJTi...",     // base64 encoded PEM
  "ssl_server_cn": "xgt-server.company.com"
}
```

#### **POST** `/api/v1/auth/xgt/proxy-pki` - Proxy PKI Authentication
#### **POST** `/api/v1/auth/validate` - Validate Token
#### **GET** `/api/v1/auth/me` - Get Current User Info 🔒
#### **POST** `/api/v1/auth/test-connection` - Test XGT Connection 🔒

### 3. Updated Public Endpoints

All existing endpoints in the **"query"**, **"graphs"**, and **"frames"** sections will show:

- 🔒 **Lock icon** indicating authentication required
- **Security: BearerAuth** requirement
- **401 Unauthorized** and **403 Forbidden** response examples

## How to Use the Interactive Docs

### Step 1: Authenticate
1. Go to the **authentication** section
2. Click **"Try it out"** on `/api/v1/auth/xgt/basic`
3. Enter your XGT credentials:
   ```json
   {
     "auth_type": "basic",
     "username": "your_username",
     "password": "your_password"  
   }
   ```
4. Click **"Execute"**
5. Copy the `access_token` from the response

### Step 2: Authorize in Swagger UI
1. Click the **"Authorize"** button (🔒) at the top right
2. Paste your token in the **BearerAuth** field
3. Click **"Authorize"**
4. Click **"Close"**

### Step 3: Test Protected Endpoints
Now you can test any endpoint with the 🔒 icon:
- `/api/v1/public/query/{job_id}/results`
- `/api/v1/public/graphs`
- `/api/v1/auth/me`

## Visual Changes in Swagger UI

### Before (Admin Credentials)
```
📁 health
  GET /api/v1/public/health

📁 query  
  GET /api/v1/public/query/{job_id}/results    [No lock icon]
  POST /api/v1/public/graphs/{graph_name}/query

📁 graphs
  GET /api/v1/public/graphs
```

### After (Pass-Through Auth)
```
🔐 Authorize    [Button at top right]

📁 authentication
  POST /api/v1/auth/xgt/basic              [No lock - public]
  POST /api/v1/auth/xgt/pki               [No lock - public] 
  POST /api/v1/auth/xgt/proxy-pki         [No lock - public]
  POST /api/v1/auth/validate              [No lock - public]
  GET  /api/v1/auth/me                    🔒 [Requires auth]
  POST /api/v1/auth/test-connection       🔒 [Requires auth]

📁 health
  GET /api/v1/public/health               [No lock - still public]

📁 query
  GET  /api/v1/public/query/{job_id}/results    🔒 [Now requires auth]
  POST /api/v1/public/graphs/{graph_name}/query  🔒 [Now requires auth]

📁 graphs  
  GET /api/v1/public/graphs             🔒 [Now requires auth]

📁 frames
  GET /api/v1/public/frames               🔒 [Now requires auth]
```

## Example Error Responses

When you try to access a protected endpoint without authentication:

**401 Unauthorized:**
```json
{
  "detail": {
    "error": "XGT_AUTHENTICATION_REQUIRED",
    "message": "Valid XGT authentication token required"
  }
}
```

**403 Forbidden** (if user lacks permissions):
```json
{
  "detail": {
    "error": "INSUFFICIENT_XGT_PERMISSIONS", 
    "message": "Access denied: requires 'admin' group membership",
    "required_group": "admin",
    "user_groups": ["analyst1"]
  }
}
```

## Testing Different Auth Types

### Basic Auth Test
```bash
# Copy this into the "Try it out" section
{
  "auth_type": "basic",
  "username": "analyst1",
  "password": "password123"
}
```

### PKI Auth Test  
```bash
# Convert your certificates first:
# base64 -w 0 client.cert.pem
# base64 -w 0 client.key.pem

{
  "auth_type": "pki",
  "client_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...",
  "client_key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...",
  "ssl_server_cn": "xgt-server.company.com"
}
```

The interactive docs make it easy to test both authentication methods and see exactly how the pass-through system works with your XGT server!