# API Design and Endpoints

## Design Principles

### RESTful Design
- **Resource-based URLs**: `/datasets/{id}` not `/getDataset?id=123`
- **HTTP Methods**: GET for retrieval, POST for creation, PUT for updates, DELETE for removal
- **Status Codes**: Meaningful HTTP status codes with consistent error responses
- **Stateless**: Each request contains all necessary information

### Versioning Strategy
- **URL Versioning**: `/api/v1/public/` prefix for all endpoints
- **Header Support**: `Accept: application/vnd.rocketgraph.v1+json`
- **Backward Compatibility**: Support N-1 versions with deprecation warnings
- **Breaking Changes**: Major version increments only

### Response Format
```json
{
  "data": { ... },           // Primary response data
  "meta": {                  // Metadata about the response
    "version": "1.0",
    "request_id": "req_123",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "pagination": {            // For paginated responses
    "page": 1,
    "per_page": 50,
    "total": 1000,
    "has_more": true
  }
}
```

## Base URL Structure

```
Production:  https://api.rocketgraph.com/api/v1/public/
Staging:     https://staging-api.rocketgraph.com/api/v1/public/
Development: https://dev-api.rocketgraph.com/api/v1/public/
```

## Core Endpoints

### 1. Dataset Operations

#### List Datasets
```http
GET /api/v1/public/datasets
Authorization: Bearer rg_live_...
```

**Query Parameters:**
- `page` (integer): Page number (default: 1)
- `per_page` (integer): Items per page (default: 50, max: 100)
- `search` (string): Search by dataset name or description
- `created_after` (ISO 8601): Filter by creation date

**Response:**
```json
{
  "data": [
    {
      "id": "ds_7f8e9d0c1b2a3456",
      "name": "customer_graph",
      "description": "Customer relationship and transaction data",
      "created_at": "2024-01-10T09:00:00Z",
      "updated_at": "2024-01-12T14:30:00Z",
      "size_bytes": 1048576,
      "node_count": 10000,
      "edge_count": 25000,
      "schema_version": "1.2",
      "status": "active"
    }
  ],
  "meta": {
    "version": "1.0",
    "request_id": "req_abc123",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 3,
    "has_more": false
  }
}
```

#### Get Dataset Details
```http
GET /api/v1/public/datasets/{dataset_id}
Authorization: Bearer rg_live_...
```

**Response:**
```json
{
  "data": {
    "id": "ds_7f8e9d0c1b2a3456",
    "name": "customer_graph",
    "description": "Customer relationship and transaction data",
    "created_at": "2024-01-10T09:00:00Z",
    "updated_at": "2024-01-12T14:30:00Z",
    "size_bytes": 1048576,
    "node_count": 10000,
    "edge_count": 25000,
    "schema": {
      "nodes": [
        {
          "name": "Customer",
          "properties": {
            "id": "string",
            "name": "string",
            "email": "string",
            "created_at": "datetime"
          }
        }
      ],
      "edges": [
        {
          "name": "PURCHASED",
          "source": "Customer",
          "target": "Product",
          "properties": {
            "amount": "float",
            "date": "datetime"
          }
        }
      ]
    },
    "permissions": ["read", "query", "export"],
    "status": "active"
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_def456",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Create Dataset
```http
POST /api/v1/public/datasets
Authorization: Bearer rg_live_...
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "new_dataset",
  "description": "Description of the new dataset",
  "schema": {
    "nodes": [
      {
        "name": "Entity",
        "properties": {
          "id": "string",
          "name": "string"
        }
      }
    ],
    "edges": [
      {
        "name": "RELATES_TO",
        "source": "Entity",
        "target": "Entity",
        "properties": {
          "weight": "float"
        }
      }
    ]
  }
}
```

**Response:**
```json
{
  "data": {
    "id": "ds_new123456789",
    "name": "new_dataset",
    "status": "creating",
    "created_at": "2024-01-15T10:30:00Z"
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_ghi789",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### 2. Query Operations

#### Execute Query
```http
POST /api/v1/public/datasets/{dataset_id}/query
Authorization: Bearer rg_live_...
Content-Type: application/json
```

**Request Body:**
```json
{
  "query": "MATCH (c:Customer)-[p:PURCHASED]->(pr:Product) WHERE pr.category = 'electronics' RETURN c.name, p.amount, pr.name",
  "parameters": {
    "min_amount": 100.0
  },
  "format": "json",
  "limit": 1000
}
```

**Response (Async Job):**
```json
{
  "data": {
    "job_id": "job_xyz789",
    "status": "queued",
    "estimated_completion": "2024-01-15T10:32:00Z",
    "query_hash": "sha256_abc123...",
    "estimated_result_size": 50000
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_jkl012",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Get Query Status
```http
GET /api/v1/public/query/{job_id}/status
Authorization: Bearer rg_live_...
```

**Response:**
```json
{
  "data": {
    "job_id": "job_xyz789",
    "status": "completed",
    "created_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:31:45Z",
    "processing_time_ms": 45000,
    "result_count": 1250,
    "result_size_bytes": 125000
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_mno345",
    "timestamp": "2024-01-15T10:32:00Z"
  }
}
```

#### Get Query Results
```http
GET /api/v1/public/query/{job_id}/results
Authorization: Bearer rg_live_...
```

**Query Parameters:**
- `page` (integer): Page number for paginated results
- `per_page` (integer): Results per page (max: 1000)
- `format` (string): `json`, `csv`, `parquet`

**Response:**
```json
{
  "data": {
    "columns": ["customer_name", "amount", "product_name"],
    "rows": [
      ["John Doe", 299.99, "Smartphone"],
      ["Jane Smith", 1299.99, "Laptop"],
      ["Bob Johnson", 149.99, "Headphones"]
    ],
    "result_metadata": {
      "total_rows": 1250,
      "page": 1,
      "per_page": 1000,
      "execution_time_ms": 45000
    }
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_pqr678",
    "timestamp": "2024-01-15T10:32:00Z"
  },
  "pagination": {
    "page": 1,
    "per_page": 1000,
    "total": 1250,
    "has_more": true
  }
}
```

### 3. Schema Operations

#### Get Schema Information
```http
GET /api/v1/public/datasets/{dataset_id}/schema
Authorization: Bearer rg_live_...
```

**Query Parameters:**
- `fully_qualified` (boolean): Include namespace information
- `include_stats` (boolean): Include property statistics

**Response:**
```json
{
  "data": {
    "schema_version": "1.2",
    "last_updated": "2024-01-12T14:30:00Z",
    "nodes": [
      {
        "name": "Customer",
        "count": 10000,
        "properties": {
          "id": {
            "type": "string",
            "nullable": false,
            "unique": true,
            "index": true
          },
          "name": {
            "type": "string",
            "nullable": false,
            "max_length": 255
          },
          "email": {
            "type": "string",
            "nullable": true,
            "pattern": "email"
          },
          "created_at": {
            "type": "datetime",
            "nullable": false
          }
        }
      }
    ],
    "edges": [
      {
        "name": "PURCHASED",
        "source": "Customer",
        "target": "Product",
        "count": 25000,
        "properties": {
          "amount": {
            "type": "float",
            "nullable": false,
            "min": 0.01,
            "max": 9999.99
          },
          "date": {
            "type": "datetime",
            "nullable": false
          }
        }
      }
    ]
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_stu901",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### Infer Schema from Data
```http
POST /api/v1/public/schemas/infer
Authorization: Bearer rg_live_...
Content-Type: application/json
```

**Request Body:**
```json
{
  "data_source": {
    "type": "upload",
    "files": [
      {
        "name": "customers.csv",
        "content": "data:text/csv;base64,aWQsbmFtZS..."
      }
    ]
  },
  "inference_options": {
    "sample_size": 1000,
    "detect_relationships": true,
    "confidence_threshold": 0.8
  }
}
```

**Response:**
```json
{
  "data": {
    "inferred_schema": {
      "confidence": 0.95,
      "nodes": [...],
      "edges": [...],
      "suggestions": [
        {
          "type": "index_recommendation",
          "property": "Customer.id",
          "reason": "High cardinality unique field"
        }
      ]
    },
    "processing_time_ms": 2500
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_vwx234",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### 4. Data Upload Operations

#### Upload Data to Dataset
```http
POST /api/v1/public/datasets/{dataset_id}/data
Authorization: Bearer rg_live_...
Content-Type: multipart/form-data
```

**Form Data:**
- `file`: CSV/JSON file with data
- `mapping`: JSON mapping configuration
- `options`: Upload options (delimiter, header mode, etc.)

**Response:**
```json
{
  "data": {
    "upload_id": "upload_abc123",
    "status": "processing",
    "estimated_completion": "2024-01-15T10:35:00Z"
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_yzx567",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### 5. System Information

#### API Health Check
```http
GET /api/v1/public/health
```

**Response:**
```json
{
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "uptime_seconds": 86400,
    "services": {
      "database": "healthy",
      "xgt": "healthy",
      "cache": "healthy"
    }
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_health",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### API Information
```http
GET /api/v1/public/info
Authorization: Bearer rg_live_...
```

**Response:**
```json
{
  "data": {
    "organization": {
      "id": "org_def456",
      "name": "Acme Corporation",
      "plan": "enterprise"
    },
    "api_key": {
      "id": "key_ghi789",
      "name": "Production API Key",
      "scopes": ["datasets:read", "queries:execute"],
      "rate_limits": {
        "requests_per_hour": 10000,
        "requests_per_day": 100000
      }
    },
    "usage": {
      "requests_today": 1250,
      "requests_this_hour": 150
    }
  },
  "meta": {
    "version": "1.0",
    "request_id": "req_info",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Error Handling

### Standard Error Response Format
```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested dataset does not exist",
    "details": "Dataset with ID 'ds_invalid123' was not found or you don't have access to it",
    "request_id": "req_error123",
    "timestamp": "2024-01-15T10:30:00Z",
    "documentation_url": "https://docs.rocketgraph.com/api/errors#resource-not-found"
  }
}
```

### HTTP Status Codes

**2xx Success**
- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `202 Accepted`: Async operation started
- `204 No Content`: Successful deletion

**4xx Client Errors**
- `400 Bad Request`: Invalid request format or parameters
- `401 Unauthorized`: Authentication required or invalid
- `403 Forbidden`: Valid authentication but insufficient permissions
- `404 Not Found`: Resource doesn't exist
- `409 Conflict`: Resource already exists or conflicting state
- `422 Unprocessable Entity`: Valid format but business logic error
- `429 Too Many Requests`: Rate limit exceeded

**5xx Server Errors**
- `500 Internal Server Error`: Unexpected server error
- `502 Bad Gateway`: Upstream service error
- `503 Service Unavailable`: Temporary service outage
- `504 Gateway Timeout`: Request timeout

### Common Error Codes

```python
ERROR_CODES = {
    # Authentication errors
    'AUTHENTICATION_REQUIRED': 'Authorization header is required',
    'INVALID_API_KEY': 'The provided API key is invalid',
    'API_KEY_EXPIRED': 'The API key has expired',
    'INSUFFICIENT_PERMISSIONS': 'API key lacks required permissions',
    
    # Resource errors
    'RESOURCE_NOT_FOUND': 'The requested resource does not exist',
    'RESOURCE_ALREADY_EXISTS': 'A resource with this identifier already exists',
    'RESOURCE_LIMIT_EXCEEDED': 'Organization resource limit exceeded',
    
    # Request errors
    'INVALID_REQUEST_FORMAT': 'Request body format is invalid',
    'MISSING_REQUIRED_FIELD': 'Required field is missing',
    'INVALID_FIELD_VALUE': 'Field value is invalid',
    'REQUEST_TOO_LARGE': 'Request payload exceeds size limit',
    
    # Rate limiting
    'RATE_LIMIT_EXCEEDED': 'Rate limit exceeded for this API key',
    'QUOTA_EXCEEDED': 'Monthly quota exceeded',
    
    # Query errors
    'INVALID_QUERY_SYNTAX': 'Graph query syntax is invalid',
    'QUERY_TIMEOUT': 'Query execution timed out',
    'QUERY_RESULT_TOO_LARGE': 'Query result exceeds size limits',
    
    # System errors
    'SERVICE_UNAVAILABLE': 'Service is temporarily unavailable',
    'MAINTENANCE_MODE': 'API is in maintenance mode'
}
```

## Pagination

### Standard Pagination
```http
GET /api/v1/public/datasets?page=2&per_page=50
```

### Cursor-Based Pagination (for large datasets)
```http
GET /api/v1/public/query/{job_id}/results?cursor=eyJpZCI6MTIzfQ&limit=1000
```

**Response with cursor:**
```json
{
  "data": [...],
  "pagination": {
    "cursor": "eyJpZCI6NDU2fQ",
    "has_more": true,
    "limit": 1000
  }
}
```

## Rate Limiting Headers

All responses include rate limiting information:
```http
X-RateLimit-Limit: 10000
X-RateLimit-Remaining: 9750
X-RateLimit-Reset: 1642248000
X-RateLimit-Window: 3600
```

## Async Operations

For long-running operations (queries, uploads, schema inference):

1. **Submit Request**: Returns job ID and estimated completion time
2. **Poll Status**: Check job status using job ID
3. **Retrieve Results**: Get results when job completes

**Webhook Support (Future)**
```json
{
  "webhook_url": "https://your-app.com/webhooks/rocketgraph",
  "events": ["query.completed", "upload.finished"]
}
```

This API design provides a comprehensive, secure, and developer-friendly interface for graph database operations while maintaining enterprise-grade reliability and performance.