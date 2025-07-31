# RocketGraph Public API - Developer Guide

A comprehensive guide for developers to interact with the RocketGraph Public API, a secure REST API for graph database operations using XGT with pass-through authentication.

## Table of Contents

- [Getting Started](#getting-started)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
- [Code Examples](#code-examples)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)
- [SDK Examples](#sdk-examples)

## Getting Started

### Base URL

```
https://api.rocketgraph.com/api/v1
```

For local development:
```
http://localhost:8000/api/v1
```

### Content Type

All API requests must include the appropriate content type header:

```http
Content-Type: application/json
```

### Response Format

All API responses follow a consistent JSON format:

**Success Response:**
```json
{
  "data": { ... },
  "metadata": { ... }
}
```

**Error Response:**
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": { ... }
  }
}
```

## Authentication

The API uses pass-through authentication with JWT tokens. Your XGT credentials are encrypted and stored in the JWT token for secure access.

### 1. Authenticate with XGT Credentials

#### Basic Authentication (Username/Password)

```http
POST /auth/xgt/basic
Content-Type: application/json

{
  "username": "your-xgt-username",
  "password": "your-xgt-password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user_info": {
    "username": "your-xgt-username",
    "namespace": "your-namespace",
    "authenticated_at": "2024-01-15T10:30:00Z"
  }
}
```

#### OAuth2 Compatible (for Swagger UI)

```http
POST /auth/xgt/token
Content-Type: application/x-www-form-urlencoded

username=your-xgt-username&password=your-xgt-password
```

#### PKI Authentication

```http
POST /auth/xgt/pki
Content-Type: application/json

{
  "client_cert": "base64-encoded-cert",
  "client_key": "base64-encoded-key",
  "ca_chain": "base64-encoded-ca-chain",
  "ssl_server_cert": "path-to-server-cert",
  "ssl_server_cn": "server-common-name"
}
```

### 2. Using the JWT Token

Include the JWT token in the Authorization header for all subsequent requests:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 3. Token Validation

Check if your token is still valid:

```http
POST /auth/validate
Authorization: Bearer your-jwt-token
```

### 4. Get Current User Info

```http
GET /auth/me
Authorization: Bearer your-jwt-token
```

## API Endpoints

### Health & Status

#### System Health Check
```http
GET /public/health
```

Returns comprehensive health information including XGT server status, versions, and connectivity.

#### Readiness Check
```http
GET /public/ready
```

Kubernetes-compatible readiness probe.

#### Liveness Check
```http
GET /public/live
```

Kubernetes-compatible liveness probe.

#### Version Information
```http
GET /public/version
```

Detailed version information for API, XGT server, and SDK components.

### Graphs

#### List All Graphs
```http
GET /public/graphs
Authorization: Bearer your-jwt-token
```

**Query Parameters:**
- `include_empty` (boolean, default: false) - Include graphs with no frames

**Response:**
```json
{
  "graphs": [
    {
      "name": "ecommerce",
      "vertices": [
        {
          "name": "customers",
          "schema_definition": [["id", "TEXT"], ["name", "TEXT"], ["email", "TEXT"]],
          "num_rows": 10000,
          "create_rows": true,
          "delete_frame": false,
          "key": "id"
        }
      ],
      "edges": [
        {
          "name": "purchases",
          "schema_definition": [["amount", "FLOAT"], ["date", "DATETIME"]],
          "num_rows": 25000,
          "create_rows": true,
          "delete_frame": false,
          "source_frame": "customers",
          "source_key": "id",
          "target_frame": "products",
          "target_key": "id"
        }
      ]
    }
  ],
  "total_count": 1
}
```

#### Get Specific Graph
```http
GET /public/graphs/{graph_name}
Authorization: Bearer your-jwt-token
```

#### Get Graph Schema
```http
GET /public/graphs/{graph_name}/schema
Authorization: Bearer your-jwt-token
```

**Query Parameters:**
- `fully_qualified` (boolean, default: false) - Include namespace in frame names
- `add_missing_edge_nodes` (boolean, default: false) - Include missing edge nodes

**Response:**
```json
{
  "graph": "ecommerce",
  "nodes": [
    {
      "name": "Customer",
      "properties": [
        {
          "name": "id",
          "type": "TEXT",
          "leaf_type": "TEXT",
          "depth": 1
        }
      ],
      "key": "id"
    }
  ],
  "edges": [
    {
      "name": "PURCHASED",
      "properties": [
        {
          "name": "amount",
          "type": "FLOAT",
          "leaf_type": "FLOAT",
          "depth": 1
        }
      ],
      "source": "Customer",
      "target": "Product",
      "source_key": "id",
      "target_key": "id"
    }
  ]
}
```

### Frames

#### List All Frames
```http
GET /public/frames
Authorization: Bearer your-jwt-token
```

**Query Parameters:**
- `namespace` (string) - Filter by namespace
- `frame_type` (string) - Filter by type: vertex, edge, table

**Response:**
```json
{
  "frames": [
    {
      "namespace": "ecommerce",
      "name": "customers",
      "full_name": "ecommerce__customers",
      "frame_type": "vertex",
      "num_rows": 10000,
      "schema_definition": [["id", "TEXT"], ["name", "TEXT"]],
      "key": "id",
      "source_name": null,
      "target_name": null,
      "source_key": null,
      "target_key": null
    }
  ],
  "total_count": 1,
  "namespaces": ["ecommerce"]
}
```

#### Get Frame Data
```http
GET /public/frames/{frame_name}/data
Authorization: Bearer your-jwt-token
```

**Query Parameters:**
- `offset` (integer, default: 0) - Starting row offset
- `limit` (integer, default: 100, max: 10000) - Number of rows to return

**Response:**
```json
{
  "frame_name": "ecommerce__customers",
  "frame_type": "vertex",
  "namespace": "ecommerce",
  "columns": ["id", "name", "email"],
  "rows": [
    ["cust_001", "John Doe", "john@example.com"],
    ["cust_002", "Jane Smith", "jane@example.com"]
  ],
  "total_rows": 10000,
  "offset": 0,
  "limit": 100,
  "returned_rows": 2
}
```

### Query Execution

#### Execute Cypher Query
```http
POST /public/graphs/{graph_name}/query
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "query": "MATCH (c:Customer) RETURN c.name LIMIT 10",
  "parameters": {
    "limit": 10
  },
  "format": "json",
  "limit": 1000
}
```

**Response:**
```json
{
  "job_id": 12345,
  "status": "completed",
  "query": "MATCH (c:Customer) RETURN c.name LIMIT 10",
  "graph_name": "ecommerce",
  "submitted_at": "2024-01-15T10:30:00Z",
  "estimated_completion": null
}
```

#### Get Query Status
```http
GET /public/query/{job_id}/status
Authorization: Bearer your-jwt-token
```

**Response:**
```json
{
  "job_id": 12345,
  "status": "completed",
  "progress": 1.0,
  "start_time": 1642248000.0,
  "end_time": 1642248045.0,
  "processing_time_ms": 45000,
  "error_message": null
}
```

#### Get Query Results
```http
GET /public/query/{job_id}/results
Authorization: Bearer your-jwt-token
```

**Query Parameters:**
- `offset` (integer, default: 0) - Starting row offset
- `limit` (integer, default: 1000) - Number of rows to return

**Response:**
```json
{
  "job_id": 12345,
  "status": "completed",
  "columns": ["name"],
  "rows": [
    ["John Doe"],
    ["Jane Smith"]
  ],
  "offset": 0,
  "limit": 1000,
  "returned_rows": 2,
  "total_rows": 2,
  "result_metadata": {
    "query_execution_completed": true,
    "has_more_results": false
  }
}
```

#### List Query History
```http
GET /public/query/jobs
Authorization: Bearer your-jwt-token
```

**Query Parameters:**
- `page` (integer, default: 1) - Page number
- `per_page` (integer, default: 50, max: 200) - Jobs per page
- `status` (string) - Filter by status
- `graph_name` (string) - Filter by graph

**Response:**
```json
{
  "jobs": [
    {
      "job_id": 12345,
      "status": "completed",
      "query": "MATCH (c:Customer) RETURN c.name",
      "graph_name": "ecommerce",
      "submitted_at": "2024-01-15T10:30:00Z",
      "start_time": 1642248000.0,
      "end_time": 1642248045.0,
      "processing_time_ms": 45000
    }
  ],
  "total_count": 1,
  "page": 1,
  "per_page": 50,
  "has_more": false
}
```

## Code Examples

### Python

```python
import requests
import json

class RocketGraphAPI:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.token = None
        self.authenticate(username, password)
    
    def authenticate(self, username, password):
        """Authenticate and get JWT token"""
        response = requests.post(
            f"{self.base_url}/auth/xgt/basic",
            json={"username": username, "password": password}
        )
        response.raise_for_status()
        self.token = response.json()["access_token"]
    
    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def list_graphs(self):
        """Get all graphs"""
        response = requests.get(
            f"{self.base_url}/public/graphs",
            headers=self._headers()
        )
        response.raise_for_status()
        return response.json()
    
    def execute_query(self, graph_name, query, parameters=None):
        """Execute a Cypher query"""
        payload = {
            "query": query,
            "format": "json"
        }
        if parameters:
            payload["parameters"] = parameters
            
        response = requests.post(
            f"{self.base_url}/public/graphs/{graph_name}/query",
            json=payload,
            headers=self._headers()
        )
        response.raise_for_status()
        return response.json()
    
    def get_query_results(self, job_id, offset=0, limit=1000):
        """Get results from a completed query"""
        response = requests.get(
            f"{self.base_url}/public/query/{job_id}/results",
            params={"offset": offset, "limit": limit},
            headers=self._headers()
        )
        response.raise_for_status()
        return response.json()

# Usage example
api = RocketGraphAPI("http://localhost:8000/api/v1", "your-username", "your-password")

# List graphs
graphs = api.list_graphs()
print(f"Found {graphs['total_count']} graphs")

# Execute query
query_job = api.execute_query(
    "ecommerce", 
    "MATCH (c:Customer) RETURN c.name, c.email LIMIT 10"
)
print(f"Query submitted with job ID: {query_job['job_id']}")

# Get results
results = api.get_query_results(query_job['job_id'])
print(f"Query returned {results['returned_rows']} rows")
for row in results['rows']:
    print(f"Customer: {row[0]}, Email: {row[1]}")
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

class RocketGraphAPI {
    constructor(baseUrl, username, password) {
        this.baseUrl = baseUrl;
        this.token = null;
        this.client = axios.create({
            baseURL: baseUrl,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    async authenticate(username, password) {
        const response = await this.client.post('/auth/xgt/basic', {
            username,
            password
        });
        this.token = response.data.access_token;
        
        // Set default authorization header
        this.client.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
    }

    async listGraphs() {
        const response = await this.client.get('/public/graphs');
        return response.data;
    }

    async executeQuery(graphName, query, parameters = null) {
        const payload = { query, format: 'json' };
        if (parameters) payload.parameters = parameters;

        const response = await this.client.post(
            `/public/graphs/${graphName}/query`,
            payload
        );
        return response.data;
    }

    async getQueryResults(jobId, offset = 0, limit = 1000) {
        const response = await this.client.get(
            `/public/query/${jobId}/results`,
            { params: { offset, limit } }
        );
        return response.data;
    }

    async getFrameData(frameName, offset = 0, limit = 100) {
        const response = await this.client.get(
            `/public/frames/${frameName}/data`,
            { params: { offset, limit } }
        );
        return response.data;
    }
}

// Usage example
(async () => {
    const api = new RocketGraphAPI('http://localhost:8000/api/v1');
    
    try {
        await api.authenticate('your-username', 'your-password');
        
        // List graphs
        const graphs = await api.listGraphs();
        console.log(`Found ${graphs.total_count} graphs`);
        
        // Execute query
        const queryJob = await api.executeQuery(
            'ecommerce',
            'MATCH (c:Customer) RETURN c.name, c.email LIMIT 10'
        );
        console.log(`Query submitted with job ID: ${queryJob.job_id}`);
        
        // Get results
        const results = await api.getQueryResults(queryJob.job_id);
        console.log(`Query returned ${results.returned_rows} rows`);
        
        results.rows.forEach(row => {
            console.log(`Customer: ${row[0]}, Email: ${row[1]}`);
        });
        
    } catch (error) {
        console.error('API Error:', error.response?.data || error.message);
    }
})();
```

### cURL Examples

#### Authentication
```bash
# Authenticate and save token
TOKEN=$(curl -s -X POST "http://localhost:8000/api/v1/auth/xgt/basic" \
  -H "Content-Type: application/json" \
  -d '{"username":"your-username","password":"your-password"}' \
  | jq -r '.access_token')

echo "Token: $TOKEN"
```

#### List Graphs
```bash
curl -X GET "http://localhost:8000/api/v1/public/graphs" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

#### Execute Query
```bash
JOB_ID=$(curl -s -X POST "http://localhost:8000/api/v1/public/graphs/ecommerce/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MATCH (c:Customer) RETURN c.name LIMIT 5",
    "format": "json"
  }' | jq -r '.job_id')

echo "Job ID: $JOB_ID"
```

#### Get Query Results
```bash
curl -X GET "http://localhost:8000/api/v1/public/query/$JOB_ID/results" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

## Error Handling

### Common Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | INVALID_REQUEST | Invalid request format or parameters |
| 401 | AUTHENTICATION_FAILED | Invalid or missing authentication |
| 403 | ACCESS_DENIED | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 422 | VALIDATION_ERROR | Request validation failed |
| 503 | XGT_CONNECTION_ERROR | Cannot connect to XGT server |
| 500 | INTERNAL_SERVER_ERROR | Internal server error |

### Error Response Format

```json
{
  "error": {
    "code": "XGT_CONNECTION_ERROR",
    "message": "Cannot connect to XGT server",
    "details": {
      "host": "localhost",
      "port": 4367,
      "timeout": "Connection timed out after 30 seconds"
    }
  }
}
```

### Error Handling Best Practices

1. **Always check HTTP status codes**
2. **Parse error messages for debugging**
3. **Implement retry logic for 503 errors**
4. **Handle token expiration (401 errors)**
5. **Log errors for troubleshooting**

## Best Practices

### Authentication
- Store JWT tokens securely
- Implement token refresh logic
- Use HTTPS in production
- Don't log credentials or tokens

### Query Execution
- Use parameterized queries to prevent injection
- Implement pagination for large result sets
- Set appropriate query timeouts
- Monitor query performance

### Rate Limiting
- Implement client-side rate limiting
- Handle 429 (Too Many Requests) responses
- Use exponential backoff for retries

### Data Handling
- Validate data types before processing
- Handle null/empty values gracefully
- Implement proper error recovery
- Use streaming for large graphs

### Security
- Always use HTTPS in production
- Validate all inputs
- Implement proper CORS settings
- Monitor API usage for anomalies

## API Limits

| Resource | Limit | Description |
|----------|--------|-------------|
| Request Rate | 1000/hour | Requests per hour per user |
| Query Timeout | 300 seconds | Maximum query execution time |
| Result Set | 10,000 rows | Maximum rows per request |
| Token Expiry | 1 hour | JWT token lifetime |
| Request Size | 10 MB | Maximum request body size |

## Support and Resources

- **API Documentation**: `/docs` (Swagger UI)
- **Alternative Docs**: `/redoc` (ReDoc)
- **Health Check**: `/api/v1/public/health`
- **Version Info**: `/api/v1/public/version`

For issues and support, please refer to your system administrator or the development team.