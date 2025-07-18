# RocketGraph Public API Documentation

Welcome to the RocketGraph Public API documentation! This directory contains comprehensive resources to help you integrate with our secure REST API for graph database operations.

## 📚 Documentation Overview

### Getting Started
- **[Quick Start Guide](quick-start-guide.md)** - Get up and running in minutes
- **[Developer API Guide](developer-api-guide.md)** - Comprehensive API documentation
- **[OpenAPI Specification](openapi-spec.yaml)** - Machine-readable API spec for code generation

### Testing & Development Tools
- **[Postman Collection](RocketGraph-API.postman_collection.json)** - Pre-configured API calls for testing
- **Interactive Docs** - Available at `/docs` when the API is running
- **ReDoc Documentation** - Available at `/redoc` when the API is running

## 🚀 Quick Start

### 1. Authentication
```bash
curl -X POST "https://api.rocketgraph.com/api/v1/auth/xgt/basic" \
  -H "Content-Type: application/json" \
  -d '{"username": "your-username", "password": "your-password"}'
```

### 2. List Datasets
```bash
curl -X GET "https://api.rocketgraph.com/api/v1/public/datasets" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. Execute Query
```bash
curl -X POST "https://api.rocketgraph.com/api/v1/public/datasets/your-dataset/query" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "MATCH (n) RETURN n LIMIT 5", "format": "json"}'
```

## 📖 API Overview

### Base URL
- **Production**: `https://api.rocketgraph.com/api/v1`
- **Local Dev**: `http://localhost:8000/api/v1`

### Authentication
The API uses JWT Bearer tokens obtained by authenticating with your XGT credentials:
1. POST to `/auth/xgt/basic` with username/password
2. Include returned token in `Authorization: Bearer <token>` header

### Main Endpoints

| Category | Endpoint | Purpose |
|----------|----------|---------|
| **Auth** | `POST /auth/xgt/basic` | Authenticate with XGT credentials |
| **Health** | `GET /public/health` | System health and status |
| **Datasets** | `GET /public/datasets` | List available datasets |
| **Frames** | `GET /public/frames` | List available frames |
| **Query** | `POST /public/datasets/{name}/query` | Execute Cypher queries |
| **Results** | `GET /public/query/{job_id}/results` | Get query results |

## 🛠 Development Tools

### Postman Collection
Import the [Postman collection](RocketGraph-API.postman_collection.json) to get started immediately:

1. Open Postman
2. Click "Import" → "Upload Files"
3. Select `RocketGraph-API.postman_collection.json`
4. Update the `baseUrl` variable to your API endpoint
5. Run "Basic Authentication" to get a token
6. Explore other endpoints!

### OpenAPI/Swagger
Use the [OpenAPI specification](openapi-spec.yaml) to:
- Generate client SDKs in your preferred language
- Import into API development tools
- Validate requests and responses
- Generate documentation

### SDK Generation Examples

**Python SDK:**
```bash
openapi-generator generate -i openapi-spec.yaml -g python -o ./python-sdk
```

**JavaScript SDK:**
```bash
openapi-generator generate -i openapi-spec.yaml -g javascript -o ./js-sdk
```

**Java SDK:**
```bash
openapi-generator generate -i openapi-spec.yaml -g java -o ./java-sdk
```

## 📋 Code Examples

### Python
```python
import requests

# Authenticate
response = requests.post(
    "https://api.rocketgraph.com/api/v1/auth/xgt/basic",
    json={"username": "your-username", "password": "your-password"}
)
token = response.json()["access_token"]

# Execute query
headers = {"Authorization": f"Bearer {token}"}
query_job = requests.post(
    "https://api.rocketgraph.com/api/v1/public/datasets/your-dataset/query",
    json={"query": "MATCH (n) RETURN n LIMIT 5", "format": "json"},
    headers=headers
).json()

# Get results
results = requests.get(
    f"https://api.rocketgraph.com/api/v1/public/query/{query_job['job_id']}/results",
    headers=headers
).json()
```

### JavaScript
```javascript
const axios = require('axios');

const api = axios.create({
  baseURL: 'https://api.rocketgraph.com/api/v1',
  headers: { 'Content-Type': 'application/json' }
});

// Authenticate
const authResponse = await api.post('/auth/xgt/basic', {
  username: 'your-username',
  password: 'your-password'
});

api.defaults.headers.common['Authorization'] = `Bearer ${authResponse.data.access_token}`;

// Execute query
const queryJob = await api.post('/public/datasets/your-dataset/query', {
  query: 'MATCH (n) RETURN n LIMIT 5',
  format: 'json'
});

// Get results
const results = await api.get(`/public/query/${queryJob.data.job_id}/results`);
```

## 🔧 Testing Your Integration

### Health Check
Verify the API is running:
```bash
curl https://api.rocketgraph.com/api/v1/public/health
```

### Version Information
Check API and XGT versions:
```bash
curl https://api.rocketgraph.com/api/v1/public/version
```

### Test Authentication
Verify your credentials work:
```bash
curl -X POST "https://api.rocketgraph.com/api/v1/auth/test-connection" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 📊 Error Handling

All errors follow this format:
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description",
    "details": {}
  }
}
```

Common HTTP status codes:
- `401` - Authentication failed or token expired
- `403` - Access denied to resource
- `404` - Resource not found
- `422` - Request validation failed
- `503` - XGT server unavailable

## 🎯 Best Practices

### Security
- Always use HTTPS in production
- Store JWT tokens securely
- Implement token refresh logic
- Don't log sensitive credentials

### Performance
- Use pagination for large datasets
- Implement client-side caching
- Set appropriate query timeouts
- Monitor API usage

### Error Handling
- Implement retry logic with exponential backoff
- Handle token expiration gracefully
- Log errors for debugging
- Provide user-friendly error messages

## 📚 Additional Resources

### Interactive Documentation
When the API is running, visit:
- **Swagger UI**: `/docs` - Interactive API explorer
- **ReDoc**: `/redoc` - Clean, readable documentation

### Architecture Guides
- [API Design](api-design.md) - Design principles and patterns
- [Authentication Strategy](authentication-strategy.md) - Auth implementation details
- [Security Guidelines](security-guidelines.md) - Security best practices

### Deployment
- [Deployment Guide](deployment-guide.md) - Production deployment instructions
- [Monitoring & Auditing](monitoring-auditing.md) - Observability setup

## 🐛 Support & Issues

### Getting Help
1. Check the [FAQ](developer-api-guide.md#error-handling)
2. Review error messages and status codes
3. Test with the provided Postman collection
4. Contact your system administrator

### Reporting Issues
When reporting issues, please include:
- API endpoint and HTTP method
- Request headers and body
- Response status code and body
- Expected vs actual behavior
- Timestamp of the issue

---

**Happy coding! 🚀**

For the most up-to-date information, always refer to the interactive documentation at `/docs` when the API is running.