# Rocketgraph MCP Integration Design Plan

## Executive Summary

This document outlines the design for integrating Model Context Protocol (MCP) capabilities into the existing Rocketgraph REST API Python process. The integration will enable Anthropic Claude to directly interact with Rocketgraph's graph analytics platform through authenticated Cypher queries, while maintaining the existing REST API functionality.

## Architecture Overview

### Current State
- **Rocketgraph REST API**: Python process with FastAPI/Flask serving HTTP endpoints
- **Graph Analytics SDK**: Python SDK for executing graph workloads
- **Authentication**: Basic Auth (username/password) and PKI certificates
- **Query Language**: Cypher for property graph operations

### Target State
- **Hybrid Server**: Single Python process serving both REST API and MCP protocols
- **Shared Core Logic**: Authentication and query execution logic shared between interfaces
- **Dual Protocol Support**: HTTP REST for traditional clients, stdio/JSON-RPC for Claude MCP
- **Session Management**: Unified session handling across both protocols

## Technical Specifications

### MCP Protocol Requirements

#### Tools to Expose
1. **rocketgraph_authenticate**
   - Purpose: Establish authenticated session with Rocketgraph
   - Inputs: username, password, optional endpoint
   - Outputs: session_id, authentication status
   - Authentication methods: Basic Auth, PKI certificates

2. **rocketgraph_query**
   - Purpose: Execute Cypher queries against the graph
   - Inputs: cypher query, parameters (optional), session_id
   - Outputs: Formatted query results, execution metadata
   - Error handling: Query syntax errors, permission errors, timeout handling

#### MCP Server Capabilities
- **Tools**: Query execution and authentication
- **Resources**: None initially (future: schema introspection)
- **Prompts**: None initially (future: query templates)
- **Sampling**: Not applicable

### Core Components Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Rocketgraph Process                      │
├─────────────────────────────────────────────────────────────┤
│  REST API Server (FastAPI/Flask)  │  MCP Server (stdio)     │
│  ├─ /auth endpoint                │  ├─ rocketgraph_auth    │
│  ├─ /query endpoint               │  ├─ rocketgraph_query   │
│  └─ /health endpoint              │  └─ tool discovery      │
├─────────────────────────────────────────────────────────────┤
│                    Shared Service Layer                     │
│  ├─ AuthenticationManager         │  ├─ QueryExecutor      │
│  ├─ SessionManager                │  ├─ ResultFormatter    │
│  └─ ConfigurationManager          │  └─ ErrorHandler       │
├─────────────────────────────────────────────────────────────┤
│                    Graph Analytics SDK                      │
│  ├─ Cypher Query Engine           │  ├─ Graph Algorithms   │
│  ├─ Connection Management         │  ├─ Schema Management  │
│  └─ Transaction Handling          │  └─ Performance Metrics│
└─────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: Core MCP Integration (Week 1-2)

#### 1.1 Dependency Setup
```python
# Additional dependencies to add to requirements.txt
mcp>=1.0.0
pydantic>=2.0.0  # For request/response validation
asyncio-extras>=1.3.0  # For advanced async patterns
```

#### 1.2 MCP Server Bootstrap
Create `mcp_server.py` module:
- MCP server initialization
- Tool registration and discovery
- Protocol message handling
- Integration with existing authentication system

#### 1.3 Shared Service Extraction
Refactor existing code to create shared services:
- Extract authentication logic from REST endpoints
- Create unified session management
- Abstract query execution logic
- Standardize error handling

### Phase 2: Enhanced Functionality (Week 3)

#### 2.1 Advanced Query Features
- Query parameter validation and sanitization
- Query result pagination for large datasets
- Query performance monitoring and timeouts
- Query history and caching (optional)

#### 2.2 Security Enhancements
- Session timeout and cleanup
- Rate limiting for MCP queries
- Audit logging for MCP access
- Enhanced error messages without information leakage

#### 2.3 Configuration Management
- Environment-based configuration
- Runtime mode selection (REST-only, MCP-only, hybrid)
- Logging configuration for both protocols

### Phase 3: Production Readiness (Week 4)

#### 3.1 Testing and Validation
- Unit tests for MCP tools
- Integration tests with Claude
- Load testing for concurrent sessions
- Security penetration testing

#### 3.2 Documentation and Examples
- API documentation updates
- MCP usage examples
- Troubleshooting guide
- Performance tuning guide

## Detailed Implementation Specifications

### File Structure
```
rocketgraph/
├── main.py                    # Application entry point
├── config/
│   ├── __init__.py
│   ├── settings.py           # Configuration management
│   └── logging.py            # Logging configuration
├── api/
│   ├── __init__.py
│   ├── rest_server.py        # FastAPI/Flask REST endpoints
│   └── mcp_server.py         # MCP server implementation
├── core/
│   ├── __init__.py
│   ├── auth.py               # Authentication management
│   ├── sessions.py           # Session management
│   ├── query_executor.py     # Query execution logic
│   └── formatters.py         # Result formatting
├── models/
│   ├── __init__.py
│   ├── requests.py           # Request/response models
│   └── sessions.py           # Session data models
└── utils/
    ├── __init__.py
    ├── errors.py             # Custom exception classes
    └── validators.py         # Input validation
```

### Configuration Schema
```python
# config/settings.py
from pydantic import BaseSettings
from typing import Optional, List

class RocketgraphConfig(BaseSettings):
    # Server configuration
    rest_host: str = "0.0.0.0"
    rest_port: int = 8000
    mcp_enabled: bool = True

    # Authentication
    auth_methods: List[str] = ["basic", "pki"]
    session_timeout: int = 3600  # seconds
    max_concurrent_sessions: int = 100

    # Query execution
    query_timeout: int = 300  # seconds
    max_result_rows: int = 10000
    enable_query_cache: bool = False

    # Security
    enable_audit_logging: bool = True
    rate_limit_queries: int = 100  # per minute per session

    # Graph SDK configuration
    graph_connection_string: str
    graph_pool_size: int = 10

    class Config:
        env_prefix = "ROCKETGRAPH_"
        case_sensitive = False
```

### MCP Tool Definitions
```python
# api/mcp_server.py
from mcp.server.models import Tool
import mcp.types as types

class RocketgraphMCPServer:
    def get_tool_definitions(self) -> List[Tool]:
        return [
            Tool(
                name="rocketgraph_authenticate",
                description="Authenticate with Rocketgraph and establish a session",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                            "description": "Username for authentication"
                        },
                        "password": {
                            "type": "string",
                            "description": "Password for authentication"
                        },
                        "auth_method": {
                            "type": "string",
                            "enum": ["basic", "pki"],
                            "default": "basic",
                            "description": "Authentication method to use"
                        },
                        "cert_path": {
                            "type": "string",
                            "description": "Path to certificate file (for PKI auth)"
                        },
                        "key_path": {
                            "type": "string",
                            "description": "Path to private key file (for PKI auth)"
                        }
                    },
                    "required": ["username"],
                    "additionalProperties": False
                }
            ),
            Tool(
                name="rocketgraph_query",
                description="Execute a Cypher query against the Rocketgraph database",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "cypher": {
                            "type": "string",
                            "description": "Cypher query to execute",
                            "minLength": 1
                        },
                        "parameters": {
                            "type": "object",
                            "description": "Query parameters as key-value pairs",
                            "default": {}
                        },
                        "session_id": {
                            "type": "string",
                            "description": "Session ID from authentication",
                            "pattern": "^[a-zA-Z0-9-_]+$"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of rows to return",
                            "default": 100,
                            "minimum": 1,
                            "maximum": 10000
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Query timeout in seconds",
                            "default": 60,
                            "minimum": 1,
                            "maximum": 300
                        }
                    },
                    "required": ["cypher", "session_id"],
                    "additionalProperties": False
                }
            ),
            Tool(
                name="rocketgraph_schema",
                description="Get schema information about the graph database",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "Session ID from authentication"
                        },
                        "include_indexes": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include index information"
                        },
                        "include_constraints": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include constraint information"
                        }
                    },
                    "required": ["session_id"],
                    "additionalProperties": False
                }
            )
        ]
```

### Error Handling Strategy
```python
# utils/errors.py
class RocketgraphError(Exception):
    """Base exception for Rocketgraph errors"""
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
        super().__init__(message)

class AuthenticationError(RocketgraphError):
    """Authentication related errors"""
    pass

class QueryError(RocketgraphError):
    """Query execution errors"""
    pass

class SessionError(RocketgraphError):
    """Session management errors"""
    pass

# MCP error response formatting
def format_mcp_error(error: Exception) -> types.TextContent:
    if isinstance(error, AuthenticationError):
        return types.TextContent(
            type="text",
            text=f"Authentication failed: {error.message}"
        )
    elif isinstance(error, QueryError):
        return types.TextContent(
            type="text",
            text=f"Query execution failed: {error.message}"
        )
    elif isinstance(error, SessionError):
        return types.TextContent(
            type="text",
            text=f"Session error: {error.message}"
        )
    else:
        return types.TextContent(
            type="text",
            text=f"Internal error: {str(error)}"
        )
```

### Result Formatting for Claude
```python
# core/formatters.py
class MCPResultFormatter:
    @staticmethod
    def format_query_results(results, execution_time: float, row_count: int) -> str:
        """Format graph query results for optimal Claude consumption"""

        output = f"Query executed successfully in {execution_time:.2f}ms\n"
        output += f"Returned {row_count} rows\n\n"

        if not results.rows:
            return output + "No results returned."

        # Format as structured text for better Claude understanding
        if row_count <= 20:
            # Small result sets: show full table
            return output + MCPResultFormatter._format_as_table(results)
        else:
            # Large result sets: show summary + sample
            output += MCPResultFormatter._format_summary(results)
            output += "\n\nSample rows:\n"
            output += MCPResultFormatter._format_as_table(results, limit=10)
            return output

    @staticmethod
    def _format_as_table(results, limit: int = None) -> str:
        headers = results.columns
        rows = results.rows[:limit] if limit else results.rows

        # Calculate column widths
        col_widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))

        # Build table
        output = ""

        # Header
        header_row = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
        output += header_row + "\n"
        output += "-" * len(header_row) + "\n"

        # Data rows
        for row in rows:
            data_row = " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
            output += data_row + "\n"

        return output

    @staticmethod
    def format_schema_info(schema_data) -> str:
        """Format schema information for Claude"""
        output = "Graph Schema Information\n"
        output += "=" * 25 + "\n\n"

        if "node_labels" in schema_data:
            output += "Node Labels:\n"
            for label in schema_data["node_labels"]:
                output += f"- {label}\n"
            output += "\n"

        if "relationship_types" in schema_data:
            output += "Relationship Types:\n"
            for rel_type in schema_data["relationship_types"]:
                output += f"- {rel_type}\n"
            output += "\n"

        if "property_keys" in schema_data:
            output += "Property Keys:\n"
            for prop in schema_data["property_keys"]:
                output += f"- {prop}\n"

        return output
```

### Startup and Runtime Management
```python
# main.py
import asyncio
import sys
import signal
from typing import Optional
from config.settings import RocketgraphConfig
from api.rest_server import create_rest_app
from api.mcp_server import RocketgraphMCPServer

class RocketgraphApplication:
    def __init__(self, config: RocketgraphConfig):
        self.config = config
        self.rest_server: Optional[uvicorn.Server] = None
        self.mcp_server: Optional[RocketgraphMCPServer] = None
        self.shutdown_event = asyncio.Event()

    async def start(self):
        """Start the application in the appropriate mode"""
        mode = self._determine_mode()

        if mode == "rest":
            await self._run_rest_only()
        elif mode == "mcp":
            await self._run_mcp_only()
        elif mode == "hybrid":
            await self._run_hybrid()
        else:
            raise ValueError(f"Unknown mode: {mode}")

    def _determine_mode(self) -> str:
        """Determine runtime mode from environment/args"""
        if "--mcp-only" in sys.argv:
            return "mcp"
        elif "--rest-only" in sys.argv:
            return "rest"
        elif self.config.mcp_enabled:
            return "hybrid"
        else:
            return "rest"

    async def _run_hybrid(self):
        """Run both REST and MCP servers concurrently"""
        await asyncio.gather(
            self._start_rest_server(),
            self._start_mcp_server(),
            self._wait_for_shutdown()
        )

    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers"""
        for sig in [signal.SIGINT, signal.SIGTERM]:
            signal.signal(sig, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        asyncio.create_task(self._shutdown())

    async def _shutdown(self):
        """Graceful shutdown"""
        self.shutdown_event.set()
        # Cleanup logic here

async def main():
    config = RocketgraphConfig()
    app = RocketgraphApplication(config)
    await app.start()

if __name__ == "__main__":
    asyncio.run(main())
```

## Testing Strategy

### Unit Testing
- Test MCP tool definitions and validation
- Test shared service layer components
- Test error handling and edge cases
- Mock graph SDK for isolated testing

### Integration Testing
- Test MCP server with actual Claude Desktop
- Test authentication flows with both methods
- Test query execution with various Cypher patterns
- Test concurrent session handling

### Performance Testing
- Load test with multiple simultaneous MCP sessions
- Stress test query execution timeouts
- Memory usage profiling for long-running sessions
- Network latency testing for complex queries

## Deployment Considerations

### Environment Configuration
```bash
# Production environment variables
ROCKETGRAPH_REST_HOST=0.0.0.0
ROCKETGRAPH_REST_PORT=8000
ROCKETGRAPH_MCP_ENABLED=true
ROCKETGRAPH_AUTH_METHODS=basic,pki
ROCKETGRAPH_SESSION_TIMEOUT=3600
ROCKETGRAPH_ENABLE_AUDIT_LOGGING=true
ROCKETGRAPH_GRAPH_CONNECTION_STRING=bolt://graph-server:7687
```

### Claude Desktop Configuration
```json
{
  "mcpServers": {
    "rocketgraph": {
      "command": "python",
      "args": ["/opt/rocketgraph/main.py", "--mcp-only"],
      "env": {
        "ROCKETGRAPH_MCP_ENABLED": "true",
        "ROCKETGRAPH_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Docker Deployment
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Support both REST and MCP modes
EXPOSE 8000
ENTRYPOINT ["python", "main.py"]
```

## Security Considerations

### Authentication Security
- Secure session token generation and storage
- Session timeout and cleanup mechanisms
- Rate limiting to prevent brute force attacks
- Audit logging of all authentication attempts

### Query Security
- Input validation and sanitization for Cypher queries
- Query complexity analysis and rejection of expensive queries
- Resource usage monitoring and limits
- Prevention of information disclosure through error messages

### Transport Security
- TLS encryption for REST endpoints
- Secure stdio communication for MCP
- Certificate validation for PKI authentication
- Secrets management for configuration

## Monitoring and Observability

### Metrics
- Authentication success/failure rates
- Query execution times and success rates
- Active session counts
- Resource usage (CPU, memory, network)

### Logging
- Structured logging with correlation IDs
- Separate log streams for REST and MCP activities
- Performance logging for slow queries
- Security event logging

### Health Checks
- REST API health endpoint
- MCP server connectivity validation
- Graph database connection status
- Resource availability checks

## Future Enhancements

### Phase 2 Features
- Query result caching for improved performance
- Query templates and saved queries
- Real-time query result streaming
- Advanced schema introspection tools

### Integration Opportunities
- Integration with graph visualization tools
- Support for additional graph query languages
- Batch query execution capabilities
- Graph algorithm execution through MCP

## Success Criteria

### Functional Requirements
- ✅ Claude can authenticate with Rocketgraph via MCP
- ✅ Claude can execute arbitrary Cypher queries
- ✅ Results are formatted appropriately for Claude consumption
- ✅ Error handling provides useful feedback
- ✅ Existing REST API functionality is preserved

### Performance Requirements
- Query response time: < 5 seconds for typical queries
- Authentication time: < 1 second
- Concurrent session support: 50+ simultaneous sessions
- Memory usage: < 2GB for typical workloads

### Security Requirements
- All authentication methods work correctly
- Session management is secure and reliable
- No information leakage through error messages
- Audit trail for all MCP interactions

This design provides a comprehensive roadmap for integrating MCP capabilities into your existing Rocketgraph Python process while maintaining backward compatibility and ensuring production-ready security and performance characteristics.
