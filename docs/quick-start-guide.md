# RocketGraph API - Quick Start Guide

Get up and running with the RocketGraph Public API in minutes.

## 1. Authentication

First, authenticate with your XGT credentials to get a JWT token:

```bash
curl -X POST "https://api.rocketgraph.com/api/v1/auth/xgt/basic" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your-xgt-username",
    "password": "your-xgt-password"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Save the `access_token` for subsequent requests.

## 2. Explore Available Datasets

```bash
curl -X GET "https://api.rocketgraph.com/api/v1/public/datasets" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 3. Execute a Query

```bash
curl -X POST "https://api.rocketgraph.com/api/v1/public/datasets/your-dataset/query" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MATCH (n) RETURN n LIMIT 5",
    "format": "json"
  }'
```

**Response:**
```json
{
  "job_id": 12345,
  "status": "completed",
  "query": "MATCH (n) RETURN n LIMIT 5"
}
```

## 4. Get Query Results

```bash
curl -X GET "https://api.rocketgraph.com/api/v1/public/query/12345/results" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Python Example

```python
import requests

# 1. Authenticate
auth_response = requests.post(
    "https://api.rocketgraph.com/api/v1/auth/xgt/basic",
    json={"username": "your-username", "password": "your-password"}
)
token = auth_response.json()["access_token"]

headers = {"Authorization": f"Bearer {token}"}

# 2. List datasets
datasets = requests.get(
    "https://api.rocketgraph.com/api/v1/public/datasets",
    headers=headers
).json()

# 3. Execute query
query_job = requests.post(
    "https://api.rocketgraph.com/api/v1/public/datasets/your-dataset/query",
    json={"query": "MATCH (n) RETURN n LIMIT 5", "format": "json"},
    headers=headers
).json()

# 4. Get results
results = requests.get(
    f"https://api.rocketgraph.com/api/v1/public/query/{query_job['job_id']}/results",
    headers=headers
).json()

print(f"Found {results['returned_rows']} rows")
```

## JavaScript Example

```javascript
const axios = require('axios');

const api = axios.create({
  baseURL: 'https://api.rocketgraph.com/api/v1',
  headers: { 'Content-Type': 'application/json' }
});

async function quickStart() {
  // 1. Authenticate
  const authResponse = await api.post('/auth/xgt/basic', {
    username: 'your-username',
    password: 'your-password'
  });
  
  const token = authResponse.data.access_token;
  api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  
  // 2. List datasets
  const datasets = await api.get('/public/datasets');
  console.log(`Found ${datasets.data.total_count} datasets`);
  
  // 3. Execute query
  const queryJob = await api.post('/public/datasets/your-dataset/query', {
    query: 'MATCH (n) RETURN n LIMIT 5',
    format: 'json'
  });
  
  // 4. Get results
  const results = await api.get(`/public/query/${queryJob.data.job_id}/results`);
  console.log(`Query returned ${results.data.returned_rows} rows`);
}

quickStart().catch(console.error);
```

## Key Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/xgt/basic` | POST | Authenticate with username/password |
| `/public/datasets` | GET | List available datasets |
| `/public/datasets/{name}/query` | POST | Execute Cypher query |
| `/public/query/{job_id}/results` | GET | Get query results |
| `/public/frames` | GET | List all frames |
| `/public/frames/{name}/data` | GET | Get frame data |
| `/public/health` | GET | Check API health |

## Common Headers

```http
Content-Type: application/json
Authorization: Bearer YOUR_JWT_TOKEN
```

## Error Handling

All errors return this format:
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Description of the error",
    "details": {}
  }
}
```

Common HTTP status codes:
- `401` - Authentication failed
- `403` - Access denied
- `404` - Resource not found  
- `503` - XGT server unavailable

## Next Steps

- Read the [full API documentation](developer-api-guide.md)
- Explore the interactive docs at `/docs`
- Check system health at `/public/health`
- View API version info at `/public/version`

That's it! You're now ready to start building with the RocketGraph API.