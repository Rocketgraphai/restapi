# Connecting RocketGraph RestAPI with Claude via MCP

This guide explains how to connect Claude with the RocketGraph RestAPI using the Model Context Protocol (MCP) for direct graph database access.

## Overview

The RocketGraph RestAPI includes built-in MCP (Model Context Protocol) support that allows Claude to directly execute Cypher queries, inspect schemas, and analyze graph data without requiring manual API calls.

## Prerequisites

- RocketGraph RestAPI running with MCP enabled
- Claude Desktop or Claude Code (with MCP support)
- Valid XGT authentication credentials
- Network access between Claude and the RestAPI server

## Connection Modes

There are two ways to connect Claude to RocketGraph:

### Mode 1: Claude Launches MCP Server (Recommended for Development)
- Claude Desktop **starts** the MCP server process when needed
- Simple setup, automatic process management
- Best for single users and development

### Mode 2: Connect to Running Server (Recommended for Production)
- RocketGraph runs as persistent service
- Claude connects to existing server
- Better for teams and production environments

## Quick Start

### Option A: Let Claude Launch the Server (Simple)

**No server startup needed** - Claude will launch the MCP server automatically.

Just configure Claude Desktop (see Configuration section below).

### Option B: Run Persistent Server (Production)

```bash
# Start in hybrid mode (REST + MCP) - this is the default
python main.py

# Or explicitly enable hybrid mode  
python main.py --hybrid

# Or start MCP-only mode (if you don't need REST API)
python main.py --mcp-only
```

The server will output:
```
Starting RocketGraph in hybrid mode (REST + MCP)...
Starting REST API server...
Starting MCP server...
```

**Note**: Even with a running server, Claude still launches its own MCP process using stdio. The running server is useful for REST API access and testing.

### Which Mode Should I Use?

**Choose Option A (Claude Launches) if:**
- ✅ Single developer setup
- ✅ Personal/local development  
- ✅ Simple configuration preferred
- ✅ Don't need REST API access

**Choose Option B (Persistent Server) if:**
- ✅ Team/production environment
- ✅ Need REST API for other applications
- ✅ Multiple Claude users
- ✅ Want server monitoring/logging
- ✅ Docker/Kubernetes deployment

### 2. Configure Claude Desktop

Add the RocketGraph MCP server to your Claude Desktop configuration:

**Location**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)

```json
{
  "mcpServers": {
    "rocketgraph": {
      "command": "python",
      "args": ["/path/to/your/restapi/main.py", "--mcp-only"],
      "env": {
        "PYTHONPATH": "/path/to/your/restapi"
      }
    }
  }
}
```

### 3. Configure Claude Code (VS Code Extension)

If using Claude Code in VS Code, add to your workspace settings:

```json
{
  "claude-code.mcpServers": {
    "rocketgraph": {
      "command": "python",
      "args": ["/path/to/your/restapi/main.py", "--mcp-only"],
      "env": {
        "PYTHONPATH": "/path/to/your/restapi"
      }
    }
  }
}
```

## Authentication Setup

### Basic Authentication Example

1. **Set environment variables** (recommended):
```bash
export XGT_HOST="your-xgt-server.com"
export XGT_PORT="4367"
export XGT_USE_SSL="true"
export MCP_ENABLED="true"
```

2. **Or update your `.env` file**:
```env
# XGT Connection
XGT_HOST=your-xgt-server.com
XGT_PORT=4367
XGT_USE_SSL=true

# MCP Configuration
MCP_ENABLED=true
MCP_STDIO_MODE=true
MCP_SESSION_TIMEOUT=3600
MCP_MAX_CONCURRENT_SESSIONS=10
```

### PKI Authentication Setup

For PKI authentication, ensure your certificates are accessible:

```env
# PKI certificates (if using PKI auth)
XGT_SSL_CERT=/path/to/server.crt
XGT_SERVER_CN=your-server-name
```

## Available MCP Tools

Once connected, Claude will have access to these tools:

### 1. `rocketgraph_authenticate`
Authenticate with XGT using your credentials.

**Parameters:**
- `auth_type`: "basic", "pki", or "proxy_pki"
- `username`: Your username (for basic auth)
- `password`: Your password (for basic auth)
- `user_id`: User ID (for proxy PKI)
- `proxy_host`: Proxy host (for proxy PKI)

### 2. `rocketgraph_query`
Execute Cypher queries against the graph database.

**Parameters:**
- `query`: Cypher query string
- `session_id`: Authentication session ID
- `parameters`: Optional query parameters (JSON object)

### 3. `rocketgraph_schema`
Get schema information for graphs/datasets.

**Parameters:**
- `session_id`: Authentication session ID
- `dataset_name`: Optional specific dataset name
- `fully_qualified`: Include namespace in names (default: false)

### 4. `rocketgraph_list_graphs`
List all available graphs/datasets.

**Parameters:**
- `session_id`: Authentication session ID

### 5. `rocketgraph_frame_data`
Get sample data from specific frames/tables.

**Parameters:**
- `session_id`: Authentication session ID
- `frame_name`: Name of the frame to query
- `offset`: Starting row (default: 0)
- `limit`: Number of rows (default: 100)

## Usage Examples

### Example 1: Basic Authentication and Query

```
Claude, please connect to RocketGraph and run a query to find all customers.

I need to:
1. Authenticate with username "analyst" and password "mypassword"
2. Run this query: MATCH (c:Customer) RETURN c.name, c.id LIMIT 10
```

Claude will:
1. Use `rocketgraph_authenticate` with basic auth
2. Use `rocketgraph_query` to execute the Cypher query
3. Format and display the results

### Example 2: Schema Exploration

```
Claude, can you show me the schema for the "CustomerGraph" dataset in RocketGraph?
```

Claude will:
1. Use your existing session (or prompt for authentication)
2. Use `rocketgraph_schema` to get schema information
3. Present the node and edge definitions in a readable format

### Example 3: Data Analysis

```
Claude, please analyze the transaction patterns in the FinTech graph. 
Show me the top 10 customers by transaction volume.
```

Claude will:
1. Use `rocketgraph_list_graphs` to find available graphs
2. Use `rocketgraph_schema` to understand the data structure
3. Use `rocketgraph_query` to execute analytical queries
4. Present insights and visualizations

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_ENABLED` | Enable MCP server | `true` |
| `MCP_STDIO_MODE` | Use stdio communication | `true` |
| `MCP_SESSION_TIMEOUT` | Session timeout (seconds) | `3600` |
| `MCP_MAX_CONCURRENT_SESSIONS` | Max concurrent sessions | `10` |
| `MCP_MAX_QUERY_TIME` | Max query execution time (seconds) | `300` |
| `MCP_MAX_RESULT_ROWS` | Max rows returned per query | `10000` |

### Command Line Options

```bash
# Start modes
python main.py --hybrid      # REST + MCP (default)
python main.py --mcp-only    # MCP only
python main.py --rest-only   # REST only

# Check current mode
python main.py --help
```

## Troubleshooting

### Common Issues

1. **"MCP server not responding"**
   - Ensure the RestAPI is running: `python main.py --mcp-only`
   - Check that `MCP_ENABLED=true` in your environment
   - Verify the command path in Claude configuration

2. **"Authentication failed"** or **"authenticate_user method missing"**
   - Verify XGT connection settings (`XGT_HOST`, `XGT_PORT`)
   - Check username/password credentials
   - Ensure XGT server is accessible
   - **Note**: The MCP service uses `authenticate_xgt_user` from PassthroughAuthService (fixed in recent versions)

3. **"No graphs found"**
   - Confirm user has access to XGT namespaces
   - Check that frames exist in the user's namespace
   - Verify authentication was successful

4. **"Query timeout"**
   - Increase `MCP_MAX_QUERY_TIME` for complex queries
   - Optimize your Cypher queries
   - Check XGT server performance

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python main.py --mcp-only
```

### Logs Location

Check application logs for detailed error information:
- Console output shows MCP communication
- Application logs include XGT connection details
- Authentication attempts are logged with details

## Security Considerations

1. **Credential Management**
   - Never store passwords in configuration files
   - Use environment variables for sensitive data
   - Consider using PKI authentication for production

2. **Network Security**
   - Use SSL/TLS for XGT connections (`XGT_USE_SSL=true`)
   - Restrict network access to authorized users
   - Monitor authentication attempts

3. **Query Limits**
   - Configure appropriate `MCP_MAX_RESULT_ROWS` limits
   - Set reasonable `MCP_MAX_QUERY_TIME` timeouts
   - Monitor resource usage

## Advanced Configuration

### Custom MCP Server Port

If you need to run MCP on a specific port (not stdio):

```json
{
  "mcpServers": {
    "rocketgraph": {
      "command": "python",
      "args": ["/path/to/restapi/main.py", "--mcp-only"],
      "env": {
        "MCP_STDIO_MODE": "false",
        "MCP_PORT": "8080"
      }
    }
  }
}
```

### Multiple Graph Environments

Configure different MCP servers for different environments:

```json
{
  "mcpServers": {
    "rocketgraph-dev": {
      "command": "python",
      "args": ["/path/to/restapi/main.py", "--mcp-only"],
      "env": {
        "XGT_HOST": "dev-xgt-server.com",
        "ENVIRONMENT": "development"
      }
    },
    "rocketgraph-prod": {
      "command": "python",
      "args": ["/path/to/restapi/main.py", "--mcp-only"],
      "env": {
        "XGT_HOST": "prod-xgt-server.com",
        "ENVIRONMENT": "production"
      }
    }
  }
}
```

## Getting Help

- Check the [MCP Integration Documentation](MCP_integration.md) for technical details
- Review the [API Documentation](README.md) for REST endpoint information
- Enable debug logging for detailed troubleshooting information

## Next Steps

Once connected, you can:
- Ask Claude to explore your graph schemas
- Request complex analytical queries
- Generate insights from your graph data
- Create visualizations and reports
- Automate data analysis workflows