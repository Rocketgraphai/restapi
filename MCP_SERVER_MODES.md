# RocketGraph MCP Server Connection Modes

The RocketGraph MCP server supports multiple connection modes for different use cases.

## Connection Modes Overview

| Mode | Use Case | Claude Config | Server Command |
|------|----------|---------------|----------------|
| **Stdio** | Development, single-user | Launches process | `--mcp-only` |
| **TCP** | Production, multi-user | Connects to running server | `--mcp-tcp` |
| **Hybrid** | Both REST + MCP | Mixed usage | `--hybrid` |

## Mode 1: Stdio Mode (Current Default)

**Best for**: Development, personal use, simple setups

### How it Works
- Claude Desktop **launches** the MCP server process
- Communication via stdin/stdout pipes
- Server lifecycle managed by Claude
- One server instance per Claude session

### Claude Desktop Configuration
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

### Server Startup
```bash
# Claude launches this automatically
python main.py --mcp-only
```

**Pros:**
- ✅ Simple setup
- ✅ No network configuration needed
- ✅ Automatic process management
- ✅ Works well for single users

**Cons:**
- ❌ New process for each Claude session
- ❌ Cannot share server between multiple clients
- ❌ Higher resource usage for multiple users

## Mode 2: TCP Mode (Production Recommended)

**Best for**: Production, multi-user, persistent server

### How it Works
- MCP server runs as **persistent service**
- Claude connects via TCP to running server
- One server supports multiple Claude instances
- Better resource utilization and performance

### Current Limitation
**Note**: The current MCP server implementation only supports stdio mode. To use TCP mode, you would need to run the server separately and use a different MCP transport.

### Workaround for Running Server
You can run the REST API in hybrid mode and connect Claude via the REST endpoints using a custom MCP wrapper:

```bash
# Start the REST API with MCP tools available
python main.py --hybrid

# This runs both:
# - REST API on http://localhost:8000
# - MCP stdio server (when launched by Claude)
```

## Mode 3: Hybrid Mode (Recommended)

**Best for**: Most production scenarios

### How it Works
- Single server process runs **both** REST API and MCP
- REST API available at `http://localhost:8000`
- MCP server available for Claude connections
- Shared authentication and resource management

### Server Startup
```bash
# Start both REST and MCP
python main.py --hybrid  # This is the default
```

### Claude Configuration (Same as stdio)
```json
{
  "mcpServers": {
    "rocketgraph": {
      "command": "python",
      "args": ["/path/to/restapi/main.py", "--mcp-only"],
      "env": {
        "PYTHONPATH": "/path/to/restapi"
      }
    }
  }
}
```

**Benefits:**
- ✅ REST API available for other applications
- ✅ MCP available for Claude
- ✅ Shared resources and configuration
- ✅ Single process to manage

## Production Deployment Scenarios

### Scenario 1: Development Workstation
```bash
# Simple stdio mode
python main.py --mcp-only
```

### Scenario 2: Team Development Server
```bash
# Hybrid mode - REST API + MCP
python main.py --hybrid

# Multiple team members can:
# - Use REST API via curl/Postman
# - Connect Claude via MCP (each launches own MCP process)
```

### Scenario 3: Production with Docker
```dockerfile
# Dockerfile
FROM python:3.11-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements/production.txt
EXPOSE 8000
CMD ["python", "main.py", "--hybrid"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  rocketgraph-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - XGT_HOST=xgt-server
      - MCP_ENABLED=true
    depends_on:
      - xgt-server
```

### Scenario 4: Kubernetes Deployment
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rocketgraph-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rocketgraph-api
  template:
    metadata:
      labels:
        app: rocketgraph-api
    spec:
      containers:
      - name: api
        image: rocketgraph-api:latest
        ports:
        - containerPort: 8000
        command: ["python", "main.py", "--hybrid"]
        env:
        - name: XGT_HOST
          value: "xgt-service"
        - name: MCP_ENABLED
          value: "true"
---
apiVersion: v1
kind: Service
metadata:
  name: rocketgraph-api-service
spec:
  selector:
    app: rocketgraph-api
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: LoadBalancer
```

## Security Considerations by Mode

### Stdio Mode Security
- ✅ No network exposure for MCP
- ✅ Process isolation per user
- ⚠️ Local file system access required

### TCP Mode Security  
- ⚠️ Network authentication required
- ⚠️ Firewall configuration needed
- ✅ Centralized access control

### Hybrid Mode Security
- ✅ REST API has full authentication
- ✅ MCP uses same security model
- ⚠️ Two attack surfaces to secure

## Performance Comparison

| Aspect | Stdio Mode | TCP Mode | Hybrid Mode |
|--------|------------|----------|-------------|
| **Startup Time** | Fast (per session) | Instant (already running) | Medium (both services) |
| **Memory Usage** | High (multiple processes) | Low (shared server) | Medium (single process) |
| **Concurrent Users** | Limited | Excellent | Good |
| **Network Overhead** | None | Low | Low |

## Troubleshooting by Mode

### Stdio Mode Issues
```bash
# Test if MCP server starts
python main.py --mcp-only

# Check Claude can launch process
echo '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' | python main.py --mcp-only
```

### Hybrid Mode Issues
```bash
# Test REST API
curl http://localhost:8000/api/v1/public/health

# Test MCP (stdio still used by Claude)
echo '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' | python main.py --mcp-only
```

## Recommendations

### For Development
- Use **stdio mode** (`--mcp-only`) for simplicity
- Single developer, local testing

### For Team Development
- Use **hybrid mode** (`--hybrid`) 
- REST API for testing, MCP for Claude analysis

### For Production
- Use **hybrid mode** in containers
- Consider load balancing for high availability
- Implement proper monitoring and logging

## Future Enhancements

To support true TCP mode for MCP, we would need to:

1. **Add TCP transport support** to the MCP server
2. **Implement connection pooling** for multiple Claude instances  
3. **Add authentication** for TCP connections
4. **Create service discovery** for Claude to find running servers

Would you like me to implement TCP mode support for the MCP server?