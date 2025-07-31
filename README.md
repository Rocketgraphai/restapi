# RocketGraph Public API

A secure, scalable REST API for graph database operations using XGT. Provides multi-tenant access to graph analytics capabilities with enterprise-grade security, monitoring, and Claude AI integration via MCP (Model Context Protocol).

## Overview

The RocketGraph Public API is designed as a separate service from the desktop application, providing:

- **Secure API Key Authentication** - Bearer token authentication with scoped access
- **Multi-tenant Support** - Organization-based resource isolation  
- **Enterprise Security** - Rate limiting, audit logging, and comprehensive monitoring
- **Graph Database Operations** - Full access to XGT graph database functionality
- **RESTful Design** - Standard HTTP methods with JSON payloads
- **Claude AI Integration** - Direct Claude access via MCP for intelligent graph analysis

## Quick Start

### Prerequisites

- Python 3.11+
- XGT Graph Database
- MongoDB (for API metadata)
- Redis (for caching and rate limiting)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd public-api
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements/development.txt
   ```

4. **Configure environment**

   **Option A: Quick Development Setup**
   ```bash
   cp .env.development .env
   ```

   **Option B: Full Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your specific settings
   ```

5. **Run the application**
   ```bash
   python main.py
   ```

### Development Server

The API will be available at:
- **API Base URL**: http://localhost:8000/api/v1/public/
- **Health Check**: http://localhost:8000/api/v1/public/health
- **API Documentation**: http://localhost:8000/docs (development only)

### Development Workflow

**Auto-reload:** When `DEBUG=true` in your `.env` file, the server automatically reloads on code changes.

**Testing in Browser:**
- Visit http://localhost:8000/docs for interactive API testing (Swagger UI)
- Visit individual endpoints directly for GET requests
- Use browser developer tools to inspect responses

**Alternative Development Server:**
```bash
# Manual control with uvicorn
uvicorn app.api.main:app --reload --host 0.0.0.0 --port 8000
```

## API Documentation

Comprehensive API documentation is available in the `docs/` directory:

- **[Architecture Overview](docs/architecture-overview.md)** - System design and deployment options
- **[Authentication Strategy](docs/authentication-strategy.md)** - API key management and security  
- **[API Design](docs/api-design.md)** - Endpoint specifications and usage patterns
- **[Security Guidelines](docs/security-guidelines.md)** - Security best practices
- **[Deployment Guide](docs/deployment-guide.md)** - Production deployment instructions
- **[Rate Limiting](docs/rate-limiting.md)** - Rate limiting strategies
- **[Monitoring & Auditing](docs/monitoring-auditing.md)** - Observability and compliance

## Configuration

### Environment Files

The project provides two environment templates:

- **`.env.development`** - Minimal configuration for quick local development
- **`.env.example`** - Complete configuration template with all available options

### Environment Variables

Key configuration options:

```bash
# Security (REQUIRED)
SECRET_KEY=your-super-secure-secret-key
API_KEY_SALT=your-api-key-salt

# XGT Database
XGT_HOST=localhost
XGT_PORT=4367
XGT_USERNAME=admin
XGT_PASSWORD=your-password

# MongoDB for API metadata
MONGODB_URI=mongodb://localhost:27017/rocketgraph_api

# Redis for caching/rate limiting  
REDIS_URL=redis://localhost:6379
```

## Testing

### Running Tests

```bash
# Unit tests
pytest tests/unit/ -v

# Mock integration tests (no external dependencies)
pytest tests/integration/test_api_endpoints.py -v

# All tests with coverage
pytest --cov=app --cov-report=html
```

### Complete CI Test Suite

Run the **exact same tests** as GitHub Actions locally:

```bash
# Basic test suite (code quality + unit tests + mock integration)
./scripts/run-ci-tests.py

# Include XGT integration tests  
./scripts/run-ci-tests.py --with-xgt

# Use specific XGT version
./scripts/run-ci-tests.py --with-xgt --xgt-version 2.3.0

# Include security scans
./scripts/run-ci-tests.py --security-scans

# Stop on first failure
./scripts/run-ci-tests.py --fail-fast

# Bash version (same options)
./scripts/run-ci-tests.sh --with-xgt
```

### XGT Integration Testing

For standalone XGT testing:

#### Local Testing
```bash
# Run with latest XGT version
./scripts/test-with-xgt.sh

# Run with specific XGT version
./scripts/test-with-xgt.sh 2.3.0

# Smart pytest wrapper (auto-detects existing XGT)
./scripts/pytest-xgt.sh

# Run specific tests
./scripts/pytest-xgt.sh tests/integration/test_xgt_graphs.py -k "concurrent"
```

#### GitHub Actions Testing

The CI/CD pipeline includes multiple testing strategies:

1. **Unit Tests**: Mock-based tests for individual functions
2. **Mock Integration Tests**: Full API stack with mocked XGT (always run)
3. **XGT Integration Tests**: Real XGT server testing (conditional)

To enable XGT integration testing in GitHub Actions:

1. Set repository secrets:
   - `XGT_LICENSE_KEY`: Your XGT license key

2. Set repository variables:
   - `XGT_INTEGRATION_ENABLED`: `true` 
   - `XGT_VERSION`: `latest` or specific version (e.g., `2.3.0`)

The XGT integration tests will:
- Pull the latest `rocketgraph/xgt` Docker image
- Find an available port starting from 4367
- Start XGT server with health checks
- Run comprehensive integration tests
- Clean up automatically

### Rate Limiting Tiers

The API supports multiple rate limiting tiers:

- **Free**: 100 req/min, 1K req/hour, 10K req/day
- **Basic**: 500 req/min, 10K req/hour, 100K req/day  
- **Premium**: 1K req/min, 50K req/hour, 1M req/day
- **Enterprise**: 5K req/min, 200K req/hour, 10M req/day

## Project Structure

```
public-api/
├── app/                     # Main application code
│   ├── api/v1/public/      # Public API endpoints
│   ├── auth/               # Authentication & authorization
│   ├── middleware/         # Request middleware
│   ├── models/             # Data models
│   ├── utils/              # Utility functions
│   └── config/             # Configuration management
├── tests/                  # Test suites
├── deploy/                 # Deployment configurations
├── docs/                   # Documentation
└── requirements/           # Python dependencies
```

## Development

### Running Tests

```bash
# Unit tests
pytest tests/unit/

# Integration tests  
pytest tests/integration/

# Security tests
pytest tests/security/

# All tests with coverage
pytest --cov=app tests/
```

### Code Quality

```bash
# Format code
black app/ tests/

# Sort imports
isort app/ tests/

# Lint code
flake8 app/ tests/

# Type checking
mypy app/
```

### Docker Development

```bash
# Build development image
docker build -f deploy/docker/Dockerfile.dev -t rocketgraph-api:dev .

# Run with Docker Compose
docker-compose -f deploy/docker/docker-compose.yml up
```

## Deployment

### Production Deployment

For production deployment, see the comprehensive [Deployment Guide](docs/deployment-guide.md).

### Quick Docker Deployment

```bash
# Production build
docker build -f deploy/docker/Dockerfile -t rocketgraph-api:prod .

# Run production container
docker run -d \
  --name rocketgraph-api \
  -p 8000:8000 \
  --env-file .env \
  rocketgraph-api:prod
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f deploy/kubernetes/
```

## Security

### API Key Authentication

All API requests require a valid API key in the Authorization header:

```bash
curl -H "Authorization: Bearer rg_live_your_api_key_here" \
  https://api.rocketgraph.com/api/v1/public/graphs
```

### Security Features

- **Multi-layer rate limiting** - Network, application, and user-level
- **Input validation** - Comprehensive request validation and sanitization
- **Audit logging** - Complete audit trail for compliance
- **Encryption** - All data encrypted in transit and at rest
- **Network security** - WAF, DDoS protection, geographic restrictions

## Claude AI Integration via MCP

Connect Claude directly to your graph database for intelligent analysis:

### Quick Setup

```bash
# Start with MCP support (default hybrid mode)
python main.py --hybrid

# Or MCP-only mode for Claude
python main.py --mcp-only
```

### Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rocketgraph": {
      "command": "python",
      "args": ["/path/to/restapi/main.py", "--mcp-only"],
      "env": {
        "PYTHONPATH": "/path/to/restapi",
        "XGT_HOST": "your-xgt-server.com",
        "MCP_ENABLED": "true"
      }
    }
  }
}
```

### Available MCP Tools

- **rocketgraph_authenticate** - Authenticate with XGT
- **rocketgraph_query** - Execute Cypher queries  
- **rocketgraph_schema** - Get graph schemas
- **rocketgraph_list_graphs** - List available graphs
- **rocketgraph_frame_data** - Get sample data

### Documentation

- **[MCP Setup Guide](MCP_CLAUDE_SETUP.md)** - Complete setup instructions
- **[Quick Reference](MCP_QUICK_REFERENCE.md)** - Commands and troubleshooting
- **[Usage Examples](examples/claude_usage_examples.md)** - Real Claude conversation examples
- **[Test Connection](examples/test_mcp_connection.py)** - Test script to verify setup

### Example Usage

Once configured, ask Claude:
```
"Please connect to RocketGraph and show me the top customers by transaction volume"
```

Claude will authenticate, query your graph database, and provide intelligent analysis.

## Monitoring

### Health Checks

- **Health**: `/api/v1/public/health` - Detailed system health
- **Readiness**: `/api/v1/public/ready` - Kubernetes readiness probe
- **Liveness**: `/api/v1/public/live` - Kubernetes liveness probe

### Metrics

Prometheus metrics available at `:9090/metrics` (configurable):

- Request rates and latencies
- Error rates by endpoint
- Rate limiting violations  
- Business metrics (queries, graphs, etc.)
- MCP session metrics and usage

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

Copyright 2024-2025 Trovares Inc. dba Rocketgraph. All rights reserved.

## Support

- **Documentation**: See `docs/` directory
- **Issues**: Open an issue in the repository
- **Security**: Report security issues privately to security@rocketgraph.com