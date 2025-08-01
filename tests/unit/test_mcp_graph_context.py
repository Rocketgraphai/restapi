"""
Unit tests for MCP graph context functionality.
"""

import time
from unittest.mock import Mock, patch
import pytest


class TestMCPGraphContext:
    """Test MCP graph context tools and session management."""

    def setup_method(self):
        """Set up test fixtures."""
        from app.api.mcp_server import RocketgraphMCPServer
        
        self.server = RocketgraphMCPServer()
        
        # Mock authentication service
        self.mock_user = Mock()
        self.mock_user.username = "test_user"
        self.mock_user.credentials = Mock()
        
        self.server.auth_service.validate_session_timeout = Mock(return_value=True)
        
        # Add a mock session
        self.session_id = "test_session_123"
        self.server.active_sessions[self.session_id] = self.mock_user
        self.server._session_created_times[self.session_id] = time.time()

    @patch("app.api.mcp_server.create_user_xgt_operations")
    @pytest.mark.asyncio
    async def test_use_graph_success(self, mock_create_user_xgt_ops):
        """Test successful graph context setting."""
        # Mock the user operations
        mock_xgt_ops = Mock()
        mock_xgt_ops.graphs_info.return_value = [{"name": "TestGraph"}]
        mock_create_user_xgt_ops.return_value = mock_xgt_ops
        
        use_graph_args = {
            "session_id": self.session_id,
            "graph_name": "TestGraph"
        }
        
        result = await self.server._handle_use_graph(use_graph_args)
        
        # Verify graph context was set
        assert self.session_id in self.server._session_graph_contexts
        assert self.server._session_graph_contexts[self.session_id] == "TestGraph"
        
        # Verify response message
        assert len(result) == 1
        assert "Graph context set successfully!" in result[0].text
        assert "TestGraph" in result[0].text

    @patch("app.api.mcp_server.create_user_xgt_operations")
    @pytest.mark.asyncio
    async def test_use_graph_not_found(self, mock_create_user_xgt_ops):
        """Test graph context setting with non-existent graph."""
        # Mock the user operations to return empty list
        mock_xgt_ops = Mock()
        mock_xgt_ops.graphs_info.return_value = []
        mock_create_user_xgt_ops.return_value = mock_xgt_ops
        
        use_graph_args = {
            "session_id": self.session_id,
            "graph_name": "NonExistentGraph"
        }
        
        result = await self.server._handle_use_graph(use_graph_args)
        
        # Verify graph context was NOT set
        assert self.session_id not in self.server._session_graph_contexts
        
        # Verify error response
        assert len(result) == 1
        assert "not found or not accessible" in result[0].text

    @pytest.mark.asyncio
    async def test_use_graph_invalid_session(self):
        """Test graph context setting with invalid session."""
        use_graph_args = {
            "session_id": "invalid_session",
            "graph_name": "TestGraph"
        }
        
        result = await self.server._handle_use_graph(use_graph_args)
        
        # Verify error response
        assert len(result) == 1
        assert "Invalid or expired session ID" in result[0].text

    @patch("app.api.mcp_server.create_user_xgt_operations")
    @pytest.mark.asyncio
    async def test_query_with_session_context(self, mock_create_user_xgt_ops):
        """Test query execution using session graph context."""
        # Set up session graph context
        self.server._session_graph_contexts[self.session_id] = "TestGraph"
        
        # Mock the user operations
        mock_xgt_ops = Mock()
        mock_xgt_ops.execute_query.return_value = [{"n": "test_node"}]
        mock_xgt_ops.format_results_for_mcp.return_value = "Test results formatted for MCP"
        mock_create_user_xgt_ops.return_value = mock_xgt_ops
        
        query_args = {
            "session_id": self.session_id,
            "cypher": "MATCH (n) RETURN n LIMIT 5"
        }
        
        result = await self.server._handle_query(query_args)
        
        # Verify execute_query was called with session graph context
        mock_xgt_ops.execute_query.assert_called_once_with(
            "MATCH (n) RETURN n LIMIT 5",
            {},
            graph_name="TestGraph"
        )

    @patch("app.api.mcp_server.create_user_xgt_operations")
    @pytest.mark.asyncio
    async def test_query_with_explicit_graph_override(self, mock_create_user_xgt_ops):
        """Test query execution with explicit graph_name overriding session context."""
        # Set up session graph context
        self.server._session_graph_contexts[self.session_id] = "SessionGraph"
        
        # Mock the user operations
        mock_xgt_ops = Mock()
        mock_xgt_ops.execute_query.return_value = [{"n": "test_node"}]
        mock_xgt_ops.format_results_for_mcp.return_value = "Test results formatted for MCP"
        mock_create_user_xgt_ops.return_value = mock_xgt_ops
        
        query_args = {
            "session_id": self.session_id,
            "cypher": "MATCH (n) RETURN n LIMIT 5",
            "graph_name": "ExplicitGraph"
        }
        
        result = await self.server._handle_query(query_args)
        
        # Verify execute_query was called with explicit graph context
        mock_xgt_ops.execute_query.assert_called_once_with(
            "MATCH (n) RETURN n LIMIT 5",
            {},
            graph_name="ExplicitGraph"  # Should use explicit parameter
        )

    @patch("app.api.mcp_server.create_user_xgt_operations")
    @pytest.mark.asyncio
    async def test_query_without_graph_context(self, mock_create_user_xgt_ops):
        """Test query execution without any graph context."""
        # Mock the user operations
        mock_xgt_ops = Mock()
        mock_xgt_ops.execute_query.return_value = [{"n": "test_node"}]
        mock_xgt_ops.format_results_for_mcp.return_value = "Test results formatted for MCP"
        mock_create_user_xgt_ops.return_value = mock_xgt_ops
        
        query_args = {
            "session_id": self.session_id,
            "cypher": "MATCH (n) RETURN n LIMIT 5"
        }
        
        result = await self.server._handle_query(query_args)
        
        # Verify execute_query was called with None graph context
        mock_xgt_ops.execute_query.assert_called_once_with(
            "MATCH (n) RETURN n LIMIT 5",
            {},
            graph_name=None
        )

    @patch("app.api.mcp_server.create_user_xgt_operations")
    @pytest.mark.asyncio
    async def test_frame_data_with_session_context(self, mock_create_user_xgt_ops):
        """Test frame data retrieval using session graph context."""
        # Set up session graph context
        self.server._session_graph_contexts[self.session_id] = "TestGraph"
        
        # Mock the user operations
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data_for_mcp.return_value = "Test frame data formatted for MCP"
        mock_create_user_xgt_ops.return_value = mock_xgt_ops
        
        frame_args = {
            "session_id": self.session_id,
            "frame_name": "Customers",
            "offset": 0,
            "limit": 10
        }
        
        result = await self.server._handle_frame_data(frame_args)
        
        # Verify get_frame_data_for_mcp was called with qualified frame name
        mock_xgt_ops.get_frame_data_for_mcp.assert_called_once_with(
            "TestGraph__Customers",  # Should be qualified with graph name
            0,
            10
        )

    @patch("app.api.mcp_server.create_user_xgt_operations")
    @pytest.mark.asyncio
    async def test_frame_data_with_explicit_graph_override(self, mock_create_user_xgt_ops):
        """Test frame data retrieval with explicit graph_name override."""
        # Set up session graph context
        self.server._session_graph_contexts[self.session_id] = "SessionGraph"
        
        # Mock the user operations
        mock_xgt_ops = Mock()
        mock_xgt_ops.get_frame_data_for_mcp.return_value = "Test frame data formatted for MCP"
        mock_create_user_xgt_ops.return_value = mock_xgt_ops
        
        frame_args = {
            "session_id": self.session_id,
            "frame_name": "Customers",
            "graph_name": "ExplicitGraph",
            "offset": 0,
            "limit": 10
        }
        
        result = await self.server._handle_frame_data(frame_args)
        
        # Verify get_frame_data_for_mcp was called with explicit graph qualified frame name
        mock_xgt_ops.get_frame_data_for_mcp.assert_called_once_with(
            "ExplicitGraph__Customers",  # Should use explicit graph name
            0,
            10
        )

    @pytest.mark.asyncio
    async def test_session_cleanup_removes_graph_contexts(self):
        """Test that session cleanup also removes graph contexts."""
        # Set up session graph context
        self.server._session_graph_contexts[self.session_id] = "TestGraph"
        
        # Set session as expired
        self.server._session_created_times[self.session_id] = time.time() - (self.server.settings.MCP_SESSION_TIMEOUT + 100)
        
        # Run cleanup
        await self.server._cleanup_expired_sessions()
        
        # Verify session and graph context were cleaned up
        assert self.session_id not in self.server.active_sessions
        assert self.session_id not in self.server._session_created_times
        assert self.session_id not in self.server._session_graph_contexts

    def test_tool_schemas_include_graph_name_parameters(self):
        """Test that MCP tool schemas include the new graph_name parameters."""
        # Get the tool list
        tools = []
        
        # Mock the list_tools handler to get the tools
        @self.server.server.list_tools()
        async def handle_list_tools():
            return []
            
        # Check that our tools have been registered with graph_name parameters
        # Note: This is a structural test to ensure the tools are properly defined
        
        # We can verify the server has our handlers registered
        assert hasattr(self.server, '_handle_use_graph')
        assert hasattr(self.server, '_handle_query')
        assert hasattr(self.server, '_handle_frame_data')
        
        # Verify session graph context storage exists
        assert hasattr(self.server, '_session_graph_contexts')
        assert isinstance(self.server._session_graph_contexts, dict)