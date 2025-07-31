"""
MCP (Model Context Protocol) server for RocketGraph.

Provides Claude with direct access to RocketGraph's graph analytics platform
through authenticated Cypher queries, using the existing REST API infrastructure.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from ..auth.mcp_auth import get_mcp_auth_service
from ..auth.passthrough_models import AuthenticatedXGTUser
from ..config.app_config import get_settings
from ..core.mcp_formatters import MCPResultFormatter
from ..utils.exceptions import XGTConnectionError, XGTOperationError
from ..utils.xgt_user_operations import create_user_xgt_operations

logger = logging.getLogger(__name__)


class RocketgraphMCPServer:
    """MCP server that integrates with existing RocketGraph REST API infrastructure."""

    def __init__(self):
        self.settings = get_settings()
        self.auth_service = get_mcp_auth_service()
        self.active_sessions: Dict[str, AuthenticatedXGTUser] = {}
        
        # Session cleanup tracking
        self._session_created_times: Dict[str, float] = {}
        
        # Create MCP server instance
        self.server = Server("rocketgraph")
        
        # Register tool handlers
        self._register_tools()

    def _register_tools(self):
        """Register MCP tools with the server."""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            """List available tools."""
            return [
                types.Tool(
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
                                "description": "Password for authentication (for basic auth)"
                            },
                            "auth_method": {
                                "type": "string",
                                "enum": ["basic", "pki", "proxy_pki"],
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
                types.Tool(
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
                types.Tool(
                    name="rocketgraph_schema",
                    description="Get schema information about the graph database",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {
                                "type": "string",
                                "description": "Session ID from authentication"
                            },
                            "dataset_name": {
                                "type": "string",
                                "description": "Optional dataset name to get schema for"
                            },
                            "include_sample_data": {
                                "type": "boolean",
                                "default": False,
                                "description": "Include sample data from frames"
                            }
                        },
                        "required": ["session_id"],
                        "additionalProperties": False
                    }
                ),
                types.Tool(
                    name="rocketgraph_list_graphs",
                    description="List all available graphs/datasets for the authenticated user",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {
                                "type": "string",
                                "description": "Session ID from authentication"
                            }
                        },
                        "required": ["session_id"],
                        "additionalProperties": False
                    }
                ),
                types.Tool(
                    name="rocketgraph_frame_data",
                    description="Get data from a specific frame/table in the graph",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {
                                "type": "string",
                                "description": "Session ID from authentication"
                            },
                            "frame_name": {
                                "type": "string",
                                "description": "Name of the frame to get data from"
                            },
                            "offset": {
                                "type": "integer",
                                "default": 0,
                                "minimum": 0,
                                "description": "Starting offset for pagination"
                            },
                            "limit": {
                                "type": "integer",
                                "default": 100,
                                "minimum": 1,
                                "maximum": 1000,
                                "description": "Maximum number of rows to return"
                            }
                        },
                        "required": ["session_id", "frame_name"],
                        "additionalProperties": False
                    }
                )
            ]

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[types.TextContent]:
            """Handle tool calls."""
            try:
                # Clean up expired sessions before processing
                await self._cleanup_expired_sessions()
                
                if name == "rocketgraph_authenticate":
                    return await self._handle_authenticate(arguments)
                elif name == "rocketgraph_query":
                    return await self._handle_query(arguments)
                elif name == "rocketgraph_schema":
                    return await self._handle_schema(arguments)
                elif name == "rocketgraph_list_graphs":
                    return await self._handle_list_graphs(arguments)
                elif name == "rocketgraph_frame_data":
                    return await self._handle_frame_data(arguments)
                else:
                    raise ValueError(f"Unknown tool: {name}")
                    
            except Exception as e:
                logger.error(f"Error handling tool call {name}: {e}")
                error_msg = MCPResultFormatter.format_error_message(e, f"tool {name}")
                return [types.TextContent(type="text", text=error_msg)]

    async def _handle_authenticate(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle authentication requests."""
        try:
            username = arguments["username"]
            password = arguments.get("password", "")
            auth_method = arguments.get("auth_method", "basic")
            cert_path = arguments.get("cert_path")
            key_path = arguments.get("key_path")
            
            logger.info(f"MCP authentication request for user {username} with method {auth_method}")
            
            # Authenticate user using existing infrastructure
            authenticated_user = await self.auth_service.authenticate_mcp_user(
                username=username,
                password=password,
                auth_method=auth_method,
                cert_path=cert_path,
                key_path=key_path
            )
            
            # Create session ID
            session_id = f"mcp_{hash(username + str(time.time()))}_{int(time.time())}"
            
            # Store session
            self.active_sessions[session_id] = authenticated_user
            self._session_created_times[session_id] = time.time()
            
            # Cleanup old sessions
            await self._cleanup_expired_sessions()
            
            success_msg = f"""Authentication successful!

Session ID: {session_id}
Username: {username}
Authentication Method: {auth_method}
Session Timeout: {self.settings.MCP_SESSION_TIMEOUT} seconds

You can now execute queries using this session ID. The session will automatically expire after the timeout period."""

            logger.info(f"MCP user {username} authenticated successfully with session {session_id}")
            
            return [types.TextContent(type="text", text=success_msg)]
            
        except Exception as e:
            logger.error(f"MCP authentication failed: {e}")
            error_msg = f"Authentication failed: {str(e)}"
            return [types.TextContent(type="text", text=error_msg)]

    async def _handle_query(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle query execution requests."""
        try:
            session_id = arguments["session_id"]
            cypher_query = arguments["cypher"]
            parameters = arguments.get("parameters", {})
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout", 60)
            
            # Validate session
            if session_id not in self.active_sessions:
                return [types.TextContent(type="text", text="Invalid or expired session ID. Please authenticate first.")]
            
            user = self.active_sessions[session_id]
            
            # Check session timeout
            if not self.auth_service.validate_session_timeout(user):
                del self.active_sessions[session_id]
                if session_id in self._session_created_times:
                    del self._session_created_times[session_id]
                return [types.TextContent(type="text", text="Session has expired. Please authenticate again.")]
            
            logger.info(f"Executing MCP query for user {user.username}: {cypher_query[:100]}...")
            
            # Execute query using user's credentials
            start_time = time.time()
            user_xgt_ops = create_user_xgt_operations(user.credentials)
            
            # Apply result limit from MCP settings if needed
            effective_limit = min(limit, self.settings.MCP_MAX_RESULT_ROWS)
            
            # Execute the query
            results = user_xgt_ops.execute_query(cypher_query, parameters)
            
            execution_time_ms = (time.time() - start_time) * 1000
            
            # Format results for Claude
            formatted_results = user_xgt_ops.format_results_for_mcp(
                results, 
                execution_time_ms=execution_time_ms
            )
            
            logger.info(f"MCP query completed in {execution_time_ms:.2f}ms, returned {len(results)} rows")
            
            return [types.TextContent(type="text", text=formatted_results)]
            
        except Exception as e:
            logger.error(f"MCP query execution failed: {e}")
            error_msg = MCPResultFormatter.format_error_message(e, "query execution")
            return [types.TextContent(type="text", text=error_msg)]

    async def _handle_schema(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle schema information requests."""
        try:
            session_id = arguments["session_id"]
            dataset_name = arguments.get("dataset_name")
            include_sample_data = arguments.get("include_sample_data", False)
            
            # Validate session
            if session_id not in self.active_sessions:
                return [types.TextContent(type="text", text="Invalid or expired session ID. Please authenticate first.")]
            
            user = self.active_sessions[session_id]
            
            # Check session timeout
            if not self.auth_service.validate_session_timeout(user):
                del self.active_sessions[session_id]
                if session_id in self._session_created_times:
                    del self._session_created_times[session_id]
                return [types.TextContent(type="text", text="Session has expired. Please authenticate again.")]
            
            logger.info(f"Getting schema info for user {user.username}, dataset: {dataset_name}")
            
            # Get schema using user's credentials
            user_xgt_ops = create_user_xgt_operations(user.credentials)
            formatted_schema = user_xgt_ops.get_schema_for_mcp(dataset_name)
            
            # Add sample data if requested
            if include_sample_data:
                formatted_schema += "\n\nNote: Sample data can be retrieved using the rocketgraph_frame_data tool for specific frames."
            
            return [types.TextContent(type="text", text=formatted_schema)]
            
        except Exception as e:
            logger.error(f"MCP schema request failed: {e}")
            error_msg = MCPResultFormatter.format_error_message(e, "schema retrieval")
            return [types.TextContent(type="text", text=error_msg)]

    async def _handle_list_graphs(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle list graphs/datasets requests."""
        try:
            session_id = arguments["session_id"]
            
            # Validate session
            if session_id not in self.active_sessions:
                return [types.TextContent(type="text", text="Invalid or expired session ID. Please authenticate first.")]
            
            user = self.active_sessions[session_id]
            
            # Check session timeout
            if not self.auth_service.validate_session_timeout(user):
                del self.active_sessions[session_id]
                if session_id in self._session_created_times:
                    del self._session_created_times[session_id]
                return [types.TextContent(type="text", text="Session has expired. Please authenticate again.")]
            
            logger.info(f"Listing graphs for user {user.username}")
            
            # Get datasets using user's credentials
            user_xgt_ops = create_user_xgt_operations(user.credentials)
            datasets = user_xgt_ops.datasets_info()
            
            # Format for Claude
            output_lines = ["Available Graphs/Datasets:", ""]
            
            if not datasets:
                output_lines.append("No graphs found for your user account.")
            else:
                for i, dataset in enumerate(datasets, 1):
                    output_lines.append(f"{i}. {dataset['name']}")
                    
                    # Count vertices and edges
                    vertex_count = len(dataset.get('vertices', []))
                    edge_count = len(dataset.get('edges', []))
                    table_count = len(dataset.get('tables', []))
                    
                    output_lines.append(f"   - Node types: {vertex_count}")
                    output_lines.append(f"   - Relationship types: {edge_count}")
                    if table_count > 0:
                        output_lines.append(f"   - Tables: {table_count}")
                    output_lines.append("")
            
            output_lines.append("Use rocketgraph_schema to get detailed schema information for a specific graph.")
            
            return [types.TextContent(type="text", text="\n".join(output_lines))]
            
        except Exception as e:
            logger.error(f"MCP list graphs failed: {e}")
            error_msg = MCPResultFormatter.format_error_message(e, "graph listing")
            return [types.TextContent(type="text", text=error_msg)]

    async def _handle_frame_data(self, arguments: Dict[str, Any]) -> List[types.TextContent]:
        """Handle frame data requests."""
        try:
            session_id = arguments["session_id"]
            frame_name = arguments["frame_name"]
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            
            # Validate session
            if session_id not in self.active_sessions:
                return [types.TextContent(type="text", text="Invalid or expired session ID. Please authenticate first.")]
            
            user = self.active_sessions[session_id]
            
            # Check session timeout
            if not self.auth_service.validate_session_timeout(user):
                del self.active_sessions[session_id]
                if session_id in self._session_created_times:
                    del self._session_created_times[session_id]
                return [types.TextContent(type="text", text="Session has expired. Please authenticate again.")]
            
            logger.info(f"Getting frame data for user {user.username}, frame: {frame_name}")
            
            # Get frame data using user's credentials
            user_xgt_ops = create_user_xgt_operations(user.credentials)
            formatted_data = user_xgt_ops.get_frame_data_for_mcp(frame_name, offset, limit)
            
            return [types.TextContent(type="text", text=formatted_data)]
            
        except Exception as e:
            logger.error(f"MCP frame data request failed: {e}")
            error_msg = MCPResultFormatter.format_error_message(e, "frame data retrieval")
            return [types.TextContent(type="text", text=error_msg)]

    async def _cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        try:
            current_time = time.time()
            expired_sessions = []
            
            for session_id, created_time in self._session_created_times.items():
                if current_time - created_time > self.settings.MCP_SESSION_TIMEOUT:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                if session_id in self.active_sessions:
                    del self.active_sessions[session_id]
                if session_id in self._session_created_times:
                    del self._session_created_times[session_id]
                logger.info(f"Cleaned up expired MCP session: {session_id}")
            
            # Also check if we have too many active sessions
            if len(self.active_sessions) > self.settings.MCP_MAX_CONCURRENT_SESSIONS:
                # Remove oldest sessions
                sessions_by_age = sorted(
                    self._session_created_times.items(), 
                    key=lambda x: x[1]
                )
                
                sessions_to_remove = len(self.active_sessions) - self.settings.MCP_MAX_CONCURRENT_SESSIONS
                for session_id, _ in sessions_by_age[:sessions_to_remove]:
                    if session_id in self.active_sessions:
                        del self.active_sessions[session_id]
                    if session_id in self._session_created_times:
                        del self._session_created_times[session_id]
                    logger.info(f"Cleaned up old MCP session due to limit: {session_id}")
                        
        except Exception as e:
            logger.error(f"Error cleaning up MCP sessions: {e}")

    async def run_stdio(self):
        """Run the MCP server in stdio mode."""
        logger.info("Starting RocketGraph MCP server in stdio mode")
        
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, 
                write_stream,
                self.server.create_initialization_options()
            )


# Global MCP server instance
_mcp_server: Optional[RocketgraphMCPServer] = None


def get_mcp_server() -> RocketgraphMCPServer:
    """Get the global MCP server instance."""
    global _mcp_server
    if _mcp_server is None:
        _mcp_server = RocketgraphMCPServer()
    return _mcp_server


async def run_mcp_server():
    """Run the MCP server."""
    server = get_mcp_server()
    await server.run_stdio()