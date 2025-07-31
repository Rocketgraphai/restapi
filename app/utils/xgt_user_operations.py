"""
User-specific XGT operations for pass-through authentication.

This module provides XGT database operations using individual user credentials
rather than shared admin credentials. Each instance is tied to a specific user's
authentication context and provides access to their authorized data.

Key Features:
- Pass-through authentication with XGT
- Multiple auth methods: Basic, PKI, Proxy PKI
- Automatic schema detection and conversion
- MCP (Model Context Protocol) integration
- Robust error handling and logging
"""

from contextlib import contextmanager
import logging
from typing import Any, Optional

from ..config.app_config import get_settings
from ..utils.exceptions import XGTConnectionError, XGTOperationError

# XGT imports
try:
    import xgt
except ImportError:
    xgt = None

logger = logging.getLogger(__name__)

# Constants
DEFAULT_FRAME_LIMIT = 1000
DEFAULT_QUERY_TIMEOUT = 300
DATASET_NAME_SEPARATOR = "__"


class UserXGTOperations:
    """
    User-specific XGT operations using pass-through authentication.

    Each instance is tied to a specific user's credentials and creates
    XGT connections using those credentials instead of admin credentials.
    """

    def __init__(self, user_credentials):
        """
        Initialize with user-specific XGT credentials.

        Args:
            user_credentials: Decrypted XGT credentials for the user
        """
        self.user_credentials = user_credentials
        self.settings = get_settings()

    def _create_user_connection(self):
        """
        Create XGT connection using user's credentials.

        Returns:
            XGT connection object using user's auth

        Raises:
            XGTConnectionError: If connection fails
        """
        if xgt is None:
            raise XGTConnectionError("XGT library not available")

        try:
            # Create auth object based on user's auth type
            if self.user_credentials.auth_type.value == "basic":
                auth_obj = xgt.BasicAuth(
                    username=self.user_credentials.auth_data["username"],
                    password=self.user_credentials.auth_data["password"],
                )
                conn_flags = self._get_basic_auth_flags()

            elif self.user_credentials.auth_type.value == "pki":
                auth_obj = self._create_pki_auth_from_credentials()
                conn_flags = self._get_pki_auth_flags()

            elif self.user_credentials.auth_type.value == "proxy_pki":
                auth_obj = xgt.ProxyPKIAuth(
                    user_id=self.user_credentials.auth_data["user_id"],
                    proxy_host=self.user_credentials.auth_data["proxy_host"],
                )
                conn_flags = self._get_proxy_pki_auth_flags()

            else:
                raise XGTConnectionError(f"Unsupported auth type: {self.user_credentials.auth_type}")

            # Create connection
            connection = xgt.Connection(
                host=self.settings.XGT_HOST,
                port=self.settings.XGT_PORT,
                auth=auth_obj,
                flags=conn_flags,
            )

            logger.debug(f"Created user XGT connection for {self.user_credentials.username}")
            return connection

        except Exception as e:
            logger.error(f"Failed to create user XGT connection: {e}")
            raise XGTConnectionError(f"User connection failed: {str(e)}")

    def _get_basic_auth_flags(self) -> dict[str, Any]:
        """Get connection flags for basic auth."""
        flags = {}
        if self.settings.XGT_USE_SSL:
            flags = {
                "ssl": True,
                "ssl_server_cert": self.settings.XGT_SSL_CERT,
                "ssl_server_cn": self.settings.XGT_SERVER_CN,
            }
        return flags

    def _get_pki_auth_flags(self) -> dict[str, Any]:
        """Get connection flags for PKI auth."""
        flags = {"ssl": True}  # PKI always requires SSL

        ssl_server_cn = self.user_credentials.auth_data.get("ssl_server_cn")
        if ssl_server_cn:
            flags["ssl_server_cn"] = ssl_server_cn
        elif self.settings.XGT_SERVER_CN:
            flags["ssl_server_cn"] = self.settings.XGT_SERVER_CN

        return flags

    def _get_proxy_pki_auth_flags(self) -> dict[str, Any]:
        """Get connection flags for proxy PKI auth."""
        return {"ssl": True}  # Proxy PKI always requires SSL

    def _create_pki_auth_from_credentials(self):
        """Recreate PKI auth object from stored credentials."""
        import base64
        import os
        import tempfile

        # Create temporary directory for certificates
        temp_dir = tempfile.mkdtemp(prefix="xgt_user_pki_")

        try:
            # Recreate certificate files
            client_cert_path = os.path.join(temp_dir, "client.cert.pem")
            with open(client_cert_path, "wb") as f:
                f.write(base64.b64decode(self.user_credentials.auth_data["client_cert"]))

            client_key_path = os.path.join(temp_dir, "client.key.pem")
            with open(client_key_path, "wb") as f:
                f.write(base64.b64decode(self.user_credentials.auth_data["client_key"]))

            # CA chain if available
            if self.user_credentials.auth_data.get("ca_chain"):
                ca_chain_path = os.path.join(temp_dir, "ca-chain.cert.pem")
                with open(ca_chain_path, "wb") as f:
                    f.write(base64.b64decode(self.user_credentials.auth_data["ca_chain"]))

                # Use root directory approach
                return xgt.PKIAuth(ssl_root_dir=temp_dir)
            else:
                # Use individual cert/key approach
                return xgt.PKIAuth(
                    ssl_client_cert=client_cert_path,
                    ssl_client_key=client_key_path,
                    ssl_server_cert=self.user_credentials.auth_data.get("ssl_server_cert"),
                )

        except Exception as e:
            # Cleanup on error
            import shutil

            shutil.rmtree(temp_dir, ignore_errors=True)
            raise XGTOperationError(f"PKI auth recreation failed: {e}")

    @contextmanager
    def connection(self):
        """Context manager for user-specific XGT connections."""
        conn = None
        try:
            conn = self._create_user_connection()
            yield conn
        except Exception as e:
            logger.error(f"User XGT connection error: {e}")
            raise
        finally:
            if conn:
                try:
                    if hasattr(conn, "close"):
                        conn.close()
                except Exception:
                    pass  # Ignore errors on close

    def execute_query(self, query: str, parameters: dict = None) -> list:
        """
        Execute a query using user's XGT connection.

        Args:
            query: Cypher query to execute
            parameters: Query parameters

        Returns:
            List of result dictionaries

        Raises:
            XGTOperationError: If query execution fails
        """
        try:
            with self.connection() as conn:
                # Try different XGT API methods based on what's available
                result = None

                try:
                    # Try run_job method first (newer API)
                    if hasattr(conn, "run_job"):
                        job = conn.run_job(query)
                        # Get results from job
                        result = getattr(job, "results", job)
                    else:
                        raise AttributeError("run_job not available")

                except AttributeError:
                    try:
                        # Try run_query method (older API)
                        if hasattr(conn, "run_query"):
                            result = conn.run_query(query)
                        else:
                            raise AttributeError("run_query not available")

                    except AttributeError:
                        # Try run method (alternate API)
                        if hasattr(conn, "run"):
                            if parameters:
                                result = conn.run(query, parameters)
                            else:
                                result = conn.run(query)
                        else:
                            raise XGTOperationError("No supported query execution method found on connection")

                # Convert result to list of dictionaries
                results = []
                if hasattr(result, "records") and result.records:
                    for record in result.records:
                        if hasattr(record, "data"):
                            results.append(record.data())
                        elif hasattr(record, "_fields") and hasattr(record, "_values"):
                            record_dict = dict(zip(record._fields, record._values))
                            results.append(record_dict)
                        else:
                            results.append(dict(record))
                elif hasattr(result, "__iter__") and not isinstance(result, (str, bytes)):
                    # Handle case where result is directly iterable
                    for item in result:
                        if hasattr(item, "data"):
                            results.append(item.data())
                        elif isinstance(item, dict):
                            results.append(item)
                        else:
                            results.append(dict(item))
                else:
                    # Handle case where result is the data itself
                    if isinstance(result, list):
                        results = result
                    elif result is not None:
                        results = [result]

                return results

        except Exception as e:
            logger.error(f"User query execution failed: {e}")
            raise XGTOperationError(f"Query execution error: {str(e)}")

    def get_user_namespace(self) -> str:
        """Get the user's default namespace."""
        try:
            with self.connection() as conn:
                return getattr(conn, "get_default_namespace", lambda: self.user_credentials.username)()
        except Exception as e:
            logger.warning(f"Could not get user namespace: {e}")
            return self.user_credentials.username or "default"

    def list_frames(self, frame_type: Optional[str] = None) -> list:
        """
        List frames accessible to the user.

        Args:
            frame_type: Filter by frame type (node, edge, table)

        Returns:
            List of frame information
        """
        try:
            with self.connection() as conn:
                if frame_type:
                    if frame_type.lower() == "node":
                        frames = conn.get_frames(frame_type="Vertex")
                    elif frame_type.lower() == "edge":
                        frames = conn.get_frames(frame_type="Edge")
                    elif frame_type.lower() == "table":
                        frames = conn.get_frames(frame_type="Table")
                    else:
                        raise XGTOperationError(f"Invalid frame type: {frame_type}")
                else:
                    # Get all frames
                    frames = conn.get_frames()

                # Convert to list of dictionaries
                frame_list = []
                for frame in frames:
                    frame_info = {
                        "name": frame.name,
                        "type": self._determine_frame_type(frame),
                        "num_rows": getattr(frame, "num_rows", 0),
                        "schema": self._convert_schema_to_list(frame),
                    }
                    frame_list.append(frame_info)

                return frame_list

        except Exception as e:
            logger.error(f"Failed to list frames: {e}")
            raise XGTOperationError(f"Frame listing failed: {str(e)}")

    def _determine_frame_type(self, frame) -> str:
        """Determine the type of a frame object."""
        frame_class = frame.__class__.__name__.lower()
        if "vertex" in frame_class or "node" in frame_class:
            return "node"
        elif "edge" in frame_class:
            return "edge"
        elif "table" in frame_class:
            return "table"
        else:
            return "unknown"

    def _extract_frame_schema_properties(self, frame) -> list:
        """
        Extract schema properties from a frame for detailed schema endpoints.

        Returns list of property dictionaries with name, type, leaf_type, depth.
        """
        try:
            properties = []
            if hasattr(frame, "schema"):
                for column in frame.schema:
                    if isinstance(column, (list, tuple)) and len(column) >= 2:
                        # Handle XGT schema format: [name, type, leaf_type, depth]
                        prop_info = {
                            "name": str(column[0]),
                            "type": str(column[1]),
                            "leaf_type": str(column[2]) if len(column) >= 3 else str(column[1]),
                            "depth": int(column[3]) if len(column) >= 4 else 1,
                        }
                        properties.append(prop_info)
                    elif hasattr(column, "name") and hasattr(column, "type"):
                        # Fallback for object-based schema
                        prop_info = {
                            "name": column.name,
                            "type": str(column.type),
                            "leaf_type": str(column.type),
                            "depth": 1,
                        }
                        properties.append(prop_info)
            return properties
        except Exception as e:
            logger.warning(f"Could not extract frame schema properties: {e}")
            return []

    def _extract_frame_attributes(self, frame) -> dict:
        """
        Extract common frame attributes (source, target, key) with robust attribute detection.

        Returns dictionary with source_frame, target_frame, source_key, target_key, key.
        """
        try:
            # Extract source and target frame names
            source_frame = getattr(frame, "source_name", None) or getattr(frame, "source_frame", None) or getattr(frame, "source", None)
            target_frame = getattr(frame, "target_name", None) or getattr(frame, "target_frame", None) or getattr(frame, "target", None)

            # Extract source and target keys
            source_key = getattr(frame, "source_key", None) or getattr(frame, "source_column", None) or "id"
            target_key = getattr(frame, "target_key", None) or getattr(frame, "target_column", None) or "id"

            # Extract primary key
            key = getattr(frame, "key", None) or self._get_primary_key(frame)

            return {
                "source_frame": str(source_frame) if source_frame else None,
                "target_frame": str(target_frame) if target_frame else None,
                "source_key": str(source_key),
                "target_key": str(target_key),
                "key": key
            }
        except Exception as e:
            logger.warning(f"Could not extract frame attributes: {e}")
            return {
                "source_frame": None,
                "target_frame": None,
                "source_key": "id",
                "target_key": "id",
                "key": None
            }

    def datasets_info(self, dataset_name: Optional[str] = None) -> list:
        """
        Get information about datasets (graphs) within the user's namespace.
        Each dataset represents a graph with its own collection of frames.

        Args:
            dataset_name: Optional specific dataset name to retrieve

        Returns:
            List of dataset information dictionaries, each representing a graph
        """
        try:
            with self.connection() as conn:
                # Get all frames from user's namespace
                vertex_frames = list(conn.get_frames(frame_type="Vertex"))
                edge_frames = list(conn.get_frames(frame_type="Edge"))
                table_frames = list(conn.get_frames(frame_type="Table"))

                # Group frames by dataset/graph name
                # This extracts the dataset name from frame names (assumes naming convention)
                datasets = {}

                # Process vertex frames to identify datasets
                for frame in vertex_frames:
                    dataset_name_extracted = self._extract_dataset_name(frame.name)
                    if dataset_name_extracted not in datasets:
                        datasets[dataset_name_extracted] = {"name": dataset_name_extracted, "vertices": [], "edges": [], "tables": []}

                    attributes = self._extract_frame_attributes(frame)
                    frame_info = {
                        "name": frame.name,
                        "schema": self._convert_schema_to_list(frame),
                        "num_rows": getattr(frame, "num_rows", 0),
                        "create_rows": True,
                        "delete_frame": True,
                        "key": attributes["key"],
                    }
                    datasets[dataset_name_extracted]["vertices"].append(frame_info)

                # Process edge frames
                for frame in edge_frames:
                    dataset_name_extracted = self._extract_dataset_name(frame.name)
                    if dataset_name_extracted not in datasets:
                        datasets[dataset_name_extracted] = {"name": dataset_name_extracted, "vertices": [], "edges": [], "tables": []}

                    attributes = self._extract_frame_attributes(frame)
                    frame_info = {
                        "name": frame.name,
                        "schema": self._convert_schema_to_list(frame),
                        "num_rows": getattr(frame, "num_rows", 0),
                        "create_rows": True,
                        "delete_frame": True,
                        "source_frame": attributes["source_frame"] or "unknown_source",
                        "source_key": attributes["source_key"],
                        "target_frame": attributes["target_frame"] or "unknown_target",
                        "target_key": attributes["target_key"],
                    }
                    datasets[dataset_name_extracted]["edges"].append(frame_info)

                # Process table frames
                for frame in table_frames:
                    dataset_name_extracted = self._extract_dataset_name(frame.name)
                    if dataset_name_extracted not in datasets:
                        datasets[dataset_name_extracted] = {"name": dataset_name_extracted, "vertices": [], "edges": [], "tables": []}

                    frame_info = {
                        "name": frame.name,
                        "schema": self._convert_schema_to_list(frame),
                        "num_rows": getattr(frame, "num_rows", 0),
                        "create_rows": True,
                        "delete_frame": True,
                    }
                    datasets[dataset_name_extracted]["tables"].append(frame_info)

                # Filter by specific dataset if requested
                if dataset_name:
                    return [datasets[dataset_name]] if dataset_name in datasets else []

                # Return all datasets as a list
                return list(datasets.values())

        except Exception as e:
            logger.error(f"Failed to get datasets info: {e}")
            raise XGTOperationError(f"Datasets info retrieval failed: {str(e)}")

    def _extract_dataset_name(self, frame_name: str) -> str:
        """
        Extract dataset/graph name from frame name using naming convention.

        Naming convention: DatasetName__FrameName
        Examples:
        - AnonCyber__Devices -> AnonCyber
        - FinTrans__Accounts -> FinTrans
        - SimpleFrameName -> SimpleFrameName (fallback)

        Args:
            frame_name: Full frame name

        Returns:
            Dataset/graph name
        """
        if '__' in frame_name:
            return frame_name.split('__')[0]
        else:
            # Fallback: if no separator, treat entire name as dataset name
            return frame_name

    def _convert_schema_to_list(self, frame) -> list:
        """
        Convert frame schema to simple list format expected by basic API endpoints.

        Returns schema as [["column_name", "column_type"], ...] format.
        """
        try:
            schema_list = []
            if hasattr(frame, "schema") and frame.schema:
                # XGT schema is typically a list of tuples/lists
                for column in frame.schema:
                    if isinstance(column, (list, tuple)) and len(column) >= 2:
                        # Handle case where schema is already a list of [name, type] tuples (most common)
                        schema_list.append([str(column[0]), str(column[1])])
                    elif hasattr(column, "name") and hasattr(column, "type"):
                        schema_list.append([column.name, str(column.type)])
                    elif hasattr(column, "name") and hasattr(column, "data_type"):
                        schema_list.append([column.name, str(column.data_type)])

            elif hasattr(frame, "get_schema"):
                # Alternative: get_schema() method
                schema_info = frame.get_schema()
                if isinstance(schema_info, list):
                    for item in schema_info:
                        if isinstance(item, (list, tuple)) and len(item) >= 2:
                            schema_list.append([str(item[0]), str(item[1])])

            elif hasattr(frame, "columns"):
                # Alternative: columns attribute
                for column in frame.columns:
                    if hasattr(column, "name") and hasattr(column, "type"):
                        schema_list.append([column.name, str(column.type)])

            return schema_list
        except Exception as e:
            logger.error(f"Could not convert frame schema for {getattr(frame, 'name', 'unknown')}: {e}")
            return []

    def _get_primary_key(self, frame) -> Optional[str]:
        """Try to determine the primary key for a frame."""
        try:
            if hasattr(frame, "key") and frame.key:
                return frame.key
            # Try to find 'id' column as fallback
            if hasattr(frame, "schema"):
                for column in frame.schema:
                    if hasattr(column, "name") and column.name.lower() in ["id", "key"]:
                        return column.name
            return None
        except Exception as e:
            logger.warning(f"Could not determine primary key: {e}")
            return None

    def get_frame_data(self, frame_name: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """
        Get data from a specific frame.

        Args:
            frame_name: Name of the frame to retrieve data from
            offset: Starting offset for pagination
            limit: Maximum number of rows to return

        Returns:
            Dictionary with frame data information
        """
        try:
            with self.connection() as conn:
                # Try to find the frame
                frame = None
                frame_type = None

                # Check vertex frames
                for vframe in conn.get_frames(frame_type="Vertex"):
                    if vframe.name == frame_name or f"{self.get_user_namespace()}__{vframe.name}" == frame_name:
                        frame = vframe
                        frame_type = "vertex"
                        break

                # Check edge frames if not found
                if not frame:
                    for eframe in conn.get_frames(frame_type="Edge"):
                        if eframe.name == frame_name or f"{self.get_user_namespace()}__{eframe.name}" == frame_name:
                            frame = eframe
                            frame_type = "edge"
                            break

                # Check table frames if not found
                if not frame:
                    for tframe in conn.get_frames(frame_type="Table"):
                        if tframe.name == frame_name or f"{self.get_user_namespace()}__{tframe.name}" == frame_name:
                            frame = tframe
                            frame_type = "table"
                            break

                if not frame:
                    raise XGTOperationError(f"Frame '{frame_name}' not found")

                # Get column names
                columns = []
                if hasattr(frame, "schema"):
                    columns = [column.name for column in frame.schema if hasattr(column, "name")]

                # Query the frame data
                if columns:
                    column_list = ", ".join(columns)
                    query = f"MATCH (n:{frame.name}) RETURN {column_list} SKIP {offset} LIMIT {limit}"
                else:
                    query = f"MATCH (n:{frame.name}) RETURN n SKIP {offset} LIMIT {limit}"

                result = self.execute_query(query)

                # Convert results to rows format
                rows = []
                if result:
                    for record in result:
                        if isinstance(record, dict):
                            # Extract values in column order
                            row = [record.get(col, None) for col in columns] if columns else list(record.values())
                        else:
                            row = list(record) if hasattr(record, "__iter__") else [record]
                        rows.append(row)

                # Get total row count
                total_rows = getattr(frame, "num_rows", len(rows))

                return {
                    "frame_name": frame_name,
                    "frame_type": frame_type,
                    "namespace": self.get_user_namespace(),
                    "columns": columns,
                    "rows": rows,
                    "total_rows": total_rows,
                    "offset": offset,
                    "limit": limit,
                    "returned_rows": len(rows),
                }

        except Exception as e:
            logger.error(f"Failed to get frame data: {e}")
            raise XGTOperationError(f"Frame data retrieval failed: {str(e)}")

    def format_results_for_mcp(self, results: list, columns: list = None, execution_time_ms: float = None) -> str:
        """
        Format query results for optimal Claude consumption via MCP.

        Args:
            results: Query result data
            columns: Optional column names
            execution_time_ms: Optional execution time in milliseconds

        Returns:
            Formatted string optimized for Claude understanding
        """
        from ..core.mcp_formatters import MCPResultFormatter
        return MCPResultFormatter.format_query_results(results, columns, execution_time_ms)

    def get_schema_for_mcp(self, dataset_name: str = None) -> str:
        """
        Get schema information formatted for Claude via MCP.

        Args:
            dataset_name: Optional dataset name, defaults to user namespace

        Returns:
            Formatted schema string optimized for Claude understanding
        """
        schema = self.get_schema(dataset_name or self.get_user_namespace())
        from ..core.mcp_formatters import MCPResultFormatter
        return MCPResultFormatter.format_schema_info(schema)

    def get_frame_data_for_mcp(self, frame_name: str, offset: int = 0, limit: int = 100) -> str:
        """
        Get frame data formatted for Claude via MCP.

        Args:
            frame_name: Name of the frame to retrieve data from
            offset: Starting offset for pagination (default: 0)
            limit: Maximum number of rows to return (default: 100)

        Returns:
            Formatted frame data string optimized for Claude understanding
        """
        frame_data = self.get_frame_data(frame_name, offset, limit)
        from ..core.mcp_formatters import MCPResultFormatter
        return MCPResultFormatter.format_frame_data(frame_data)

    def get_schema(self, dataset_name: str, fully_qualified: bool = False, add_missing_edge_nodes: bool = False) -> dict[str, Any]:
        """
        Get schema information for a dataset.

        Args:
            dataset_name: Name of the dataset
            fully_qualified: Whether to include namespace in names
            add_missing_edge_nodes: Whether to include missing edge nodes

        Returns:
            Schema information dictionary
        """
        try:
            with self.connection() as conn:
                user_namespace = self.get_user_namespace()

                # Note: Removed restrictive namespace check - let XGT handle access control
                # If the user can access the dataset via other endpoints, they should be able
                # to get its schema too. XGT will enforce proper access control.

                # Get all frames from user's accessible namespace
                all_vertex_frames = list(conn.get_frames(frame_type="Vertex"))
                all_edge_frames = list(conn.get_frames(frame_type="Edge"))

                # Filter frames for the specific dataset using the same logic as datasets_info
                vertex_frames = []
                edge_frames = []

                for frame in all_vertex_frames:
                    frame_dataset = self._extract_dataset_name(frame.name)
                    if frame_dataset == dataset_name:
                        vertex_frames.append(frame)

                for frame in all_edge_frames:
                    frame_dataset = self._extract_dataset_name(frame.name)
                    if frame_dataset == dataset_name:
                        edge_frames.append(frame)

                # Build nodes schema
                nodes = []
                for frame in vertex_frames:
                    properties = self._extract_frame_schema_properties(frame)
                    attributes = self._extract_frame_attributes(frame)

                    node_name = f"{user_namespace}__{frame.name}" if fully_qualified else frame.name
                    node_info = {
                        "name": node_name,
                        "properties": properties,
                        "key": attributes["key"] or "id",
                    }
                    nodes.append(node_info)

                # Build edges schema
                edges = []
                for frame in edge_frames:
                    properties = self._extract_frame_schema_properties(frame)
                    attributes = self._extract_frame_attributes(frame)

                    edge_name = f"{user_namespace}__{frame.name}" if fully_qualified else frame.name

                    # Handle source and target names with proper qualification
                    source_name = attributes["source_frame"] or "unknown"
                    target_name = attributes["target_frame"] or "unknown"

                    if fully_qualified:
                        source_name = f"{user_namespace}__{source_name}" if source_name != "unknown" else source_name
                        target_name = f"{user_namespace}__{target_name}" if target_name != "unknown" else target_name

                    edge_info = {
                        "name": edge_name,
                        "properties": properties,
                        "source": source_name,
                        "target": target_name,
                        "source_key": attributes["source_key"],
                        "target_key": attributes["target_key"],
                    }
                    edges.append(edge_info)

                return {"graph": dataset_name, "nodes": nodes, "edges": edges}

        except Exception as e:
            logger.error(f"Failed to get schema: {e}")
            raise XGTOperationError(f"Schema retrieval failed: {str(e)}")


def create_user_xgt_operations(user_credentials) -> UserXGTOperations:
    """
    Factory function to create user-specific XGT operations.

    Args:
        user_credentials: User's decrypted XGT credentials

    Returns:
        UserXGTOperations instance for the user
    """
    return UserXGTOperations(user_credentials)
