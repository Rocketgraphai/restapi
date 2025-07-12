#
#   Copyright 2024-2025 Trovares Inc. dba Rocketgraph.  All rights reserved.
#
#===------------------------------------------------------------------------===#

"""
XGT Operations for RocketGraph Public API

Stateless XGT database operations adapted from the desktop backend.
Provides core graph database functionality with organization-scoped access.
"""

from contextlib import contextmanager
import logging
import os
import re
import time
from typing import Optional

# XGT imports (will need to be installed)
try:
    import xgt
    from xgt import GraphTypesService_pb2 as graph_proto
except ImportError:
    # Handle gracefully for development
    xgt = None
    graph_proto = None

# Optional XGT connector imports (may have architecture dependencies)
# TODO: Re-enable when compatible XGT connector is available
# try:
#     from xgt_connector import (ODBCConnector, SQLODBCDriver, MongoODBCDriver,
#                                OracleODBCDriver, SAPODBCDriver,
#                                SnowflakeODBCDriver)
#     from arrow_odbc.connect import connect_to_database
#     XGT_CONNECTOR_AVAILABLE = True
# except ImportError as e:
#     # Handle gracefully - these are only needed for some operations
#     print(f"Warning: XGT connector not available - {e}")
XGT_CONNECTOR_AVAILABLE = False

from ..config.app_config import get_settings
from .exceptions import (
    XGTConnectionError,
    XGTOperationError,
)

logger = logging.getLogger(__name__)


def is_parquet_file(file_path: str) -> bool:
    """Check if file is a Parquet file based on extension."""
    _, file_extension = os.path.splitext(file_path)
    return file_extension.lower() == '.parquet'


class XGTOperations:
    """
    Stateless XGT operations for the public API.

    Provides organization-scoped access to XGT graph database operations
    without relying on Flask sessions or user profiles.
    """

    def __init__(self):
        """
        Initialize XGT operations.

        Uses XGT's authentication-based access control and namespacing.
        """
        self.settings = get_settings()

        # INTO pattern for query validation (from original)
        self.INTO_PATTERN = re.compile(
            r"""
            [Ii][Nn][Tt][Oo][\t\n\r ]+                          # Matches 'into' in any case followed by whitespace
            (                                                   # Start of group
              [A-Za-z_][A-Za-z_0-9]*                            # Matches an identifier that starts with a letter or underscore, followed by alphanumeric characters
              |                                                 # OR
              `[A-Za-z_0-9~!@#$%^&*()-=+\[\]{}\\|;:'",.<>?/]*`  # Matches a string within backticks, allowing a variety of characters
            )                                                   # End of group
            [\t\n\r ]*$                                         # Matches trailing whitespace till the end of the line
            """,
            re.VERBOSE
        )

    # Removed _get_namespace() - XGT handles namespacing via authentication

    def _create_connection(self) -> 'xgt.Connection':
        """
        Create a new XGT connection.

        Returns:
            XGT connection object

        Raises:
            XGTConnectionError: If connection fails
        """
        if xgt is None:
            raise XGTConnectionError("XGT library not available - install xgt package for full functionality")

        # Check if XGT credentials are provided
        if not self.settings.XGT_PASSWORD and self.settings.is_production:
            raise XGTConnectionError("XGT password required for production environment")

        try:
            # Get connection settings from configuration
            auth = xgt.BasicAuth(
                username=self.settings.XGT_USERNAME,
                password=self.settings.XGT_PASSWORD
            )

            conn_flags = {}
            if self.settings.XGT_USE_SSL:
                conn_flags = {
                    'ssl': True,
                    'ssl_server_cert': self.settings.XGT_SSL_CERT,
                    'ssl_server_cn': self.settings.XGT_SERVER_CN
                }

            connection = xgt.Connection(
                host=self.settings.XGT_HOST,
                port=self.settings.XGT_PORT,
                auth=auth,
                flags=conn_flags
            )

            # Let XGT set the default namespace based on authentication
            # The default namespace is determined by the authenticated username
            logger.debug("Connected to XGT - using authentication-based default namespace")

            return connection

        except Exception as e:
            logger.error(f"Failed to create XGT connection: {e}")
            if "Connection refused" in str(e):
                raise XGTConnectionError("Cannot connect to XGT server - ensure XGT is running and accessible")
            raise XGTConnectionError(f"Connection failed: {str(e)}")

    @contextmanager
    def connection(self):
        """Context manager for XGT connections."""
        conn = None
        try:
            conn = self._create_connection()
            yield conn
        except Exception as e:
            logger.error(f"XGT connection error: {e}")
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass  # Ignore errors on close

    def _fix_name(self, name: str, fully_qualified: bool, default_namespace: str) -> str:
        """
        Fix frame name based on qualification requirements.

        Args:
            name: The frame name
            fully_qualified: Whether to return fully qualified name
            default_namespace: Default namespace to use

        Returns:
            Fixed frame name
        """
        # This covers the case where a fully qualified name is desired.
        if fully_qualified:
            if "__" not in name:
                return default_namespace + "__" + name
            return name

        # The rest of the function covers the case when the frame name without
        # the namespace is desired.
        if "__" not in name:
            return name

        fields = name.split('__')
        if len(fields) == 2:
            return fields[1]

        return name

    def _get_edge_schema(self, edge_frame, node_set: set,
                        fully_qualified: bool, default_namespace: str) -> dict:
        """
        Extract schema information for an edge frame.

        Args:
            edge_frame: XGT edge frame object
            node_set: Set of available node names
            fully_qualified: Whether to use fully qualified names
            default_namespace: Default namespace

        Returns:
            Dictionary containing edge schema information
        """
        source = self._fix_name(
            edge_frame.source_name,
            fully_qualified or edge_frame.source_name not in node_set,
            default_namespace
        )
        target = self._fix_name(
            edge_frame.target_name,
            fully_qualified or edge_frame.target_name not in node_set,
            default_namespace
        )

        schema_map = {
            'properties': [
                {
                    'name': p[0],
                    'type': p[1],
                    'leaf_type': p[2] if len(p) >= 3 else p[1],
                    'depth': p[3] if len(p) >= 4 else 1
                }
                for p in edge_frame.schema
            ],
            'source': source,
            'target': target,
            'name': self._fix_name(edge_frame.name, fully_qualified, default_namespace),
            'source_key': edge_frame.source_key,
            'target_key': edge_frame.target_key
        }

        return schema_map

    def _get_node_schema(self, node_frame, node_set: set,
                        fully_qualified: bool, default_namespace: str) -> dict:
        """
        Extract schema information for a node frame.

        Args:
            node_frame: XGT node frame object
            node_set: Set of available node names
            fully_qualified: Whether to use fully qualified names
            default_namespace: Default namespace

        Returns:
            Dictionary containing node schema information
        """
        schema_map = {
            'properties': [
                {
                    'name': p[0],
                    'type': p[1],
                    'leaf_type': p[2] if len(p) >= 3 else p[1],
                    'depth': p[3] if len(p) >= 4 else 1
                }
                for p in node_frame.schema
            ],
            'name': self._fix_name(
                node_frame.name,
                fully_qualified or node_frame.name not in node_set,
                default_namespace
            ),
            'key': node_frame.key
        }

        return schema_map

    def get_schema(self, dataset_name: Optional[str] = None,
                   names: Optional[list[str]] = None,
                   add_missing_edge_nodes: bool = False,
                   fully_qualified: bool = False,
                   filter_create_rows: bool = False) -> dict:
        """
        Get schema information for datasets or specific frames.

        Args:
            dataset_name: Name of the dataset/namespace
            names: Specific frame names to include
            add_missing_edge_nodes: Whether to include missing edge nodes
            fully_qualified: Whether to use fully qualified names
            filter_create_rows: Whether to filter by create permission

        Returns:
            Dictionary containing schema information

        Raises:
            XGTOperationError: If operation fails
        """
        try:
            with self.connection() as conn:
                frames = None
                if names is not None:
                    frames = conn.get_frames(names=names)

                default_namespace = conn.get_default_namespace()

                # Get node and edge frames
                if frames is None:
                    node_frames = conn.get_frames(
                        namespace=dataset_name,
                        frame_type='vertex'
                    )
                    edge_frames = conn.get_frames(
                        namespace=dataset_name,
                        frame_type='edge'
                    )
                else:
                    node_frames = [f for f in frames if isinstance(f, xgt.VertexFrame)]
                    edge_frames = [f for f in frames if isinstance(f, xgt.EdgeFrame)]

                # Filter by permissions if requested
                if filter_create_rows:
                    node_frames = [
                        n for n in node_frames
                        if n.user_permissions.get('create_rows', False)
                    ]
                    edge_frames = [
                        e for e in edge_frames
                        if e.user_permissions.get('create_rows', False)
                    ]

                node_set = {n.name for n in node_frames}
                missing_nodes = set()

                # Get edge schemas
                edge_props = [
                    self._get_edge_schema(e, node_set, fully_qualified, default_namespace)
                    for e in edge_frames
                ]

                # Add missing edge nodes if requested
                if add_missing_edge_nodes:
                    for e in edge_frames:
                        if e.source_name not in node_set:
                            missing_nodes.add(e.source_name)
                        if e.target_name not in node_set:
                            missing_nodes.add(e.target_name)

                    if missing_nodes:
                        additional_nodes = conn.get_frames(
                            names=list(missing_nodes),
                            frame_type='vertex'
                        )
                        node_frames.extend(additional_nodes)

                        if filter_create_rows:
                            node_frames = [
                                n for n in node_frames
                                if n.user_permissions.get('create_rows', False)
                            ]

                # Get node schemas
                node_props = [
                    self._get_node_schema(n, node_set, fully_qualified, default_namespace)
                    for n in node_frames
                ]

                # Sort results
                edge_props.sort(key=lambda x: x['name'])
                node_props.sort(key=lambda x: x['name'])

                return {
                    "graph": dataset_name,
                    "nodes": node_props,
                    "edges": edge_props,
                }

        except Exception as e:
            logger.error(f"Failed to get schema: {e}")
            raise XGTOperationError(f"Schema retrieval failed: {str(e)}")

    def datasets_info(self, dataset_name: Optional[str] = None) -> list[dict]:
        """
        Get information about available datasets.

        Args:
            dataset_name: Specific dataset name, or None for all datasets

        Returns:
            List of dataset information dictionaries

        Raises:
            XGTOperationError: If operation fails
        """
        def extract_vertex_metadata(frame) -> dict:
            """Extract metadata from a vertex frame."""
            return {
                'name': self._fix_name(frame.name, False, ""),
                'schema': frame.schema,
                'num_rows': frame.num_rows,
                'create_rows': frame.user_permissions.get('create_rows', False),
                'delete_frame': frame.user_permissions.get('delete_frame', False),
                'key': frame.key
            }

        def extract_edge_metadata(frame) -> dict:
            """Extract metadata from an edge frame."""
            return {
                'name': self._fix_name(frame.name, False, ""),
                'schema': frame.schema,
                'num_rows': frame.num_rows,
                'create_rows': frame.user_permissions.get('create_rows', False),
                'delete_frame': frame.user_permissions.get('delete_frame', False),
                'source_frame': frame.source_name,
                'source_key': frame.source_key,
                'target_frame': frame.target_name,
                'target_key': frame.target_key
            }

        try:
            with self.connection() as conn:
                if dataset_name is None:
                    # Get all namespaces accessible to the authenticated user
                    try:
                        # Try to get list of accessible namespaces
                        available_namespaces = conn.get_namespaces()
                        ds_names = available_namespaces
                    except (AttributeError, Exception):
                        # Fallback: use default namespace if get_namespaces() not available
                        default_ns = conn.get_default_namespace()
                        ds_names = [default_ns] if default_ns else [""]
                else:
                    # Use the specific dataset name as provided
                    ds_names = [dataset_name]

                datasets = []
                for ds_name in ds_names:
                    try:
                        vertex_frames = conn.get_frames(
                            namespace=ds_name,
                            frame_type='vertex'
                        )
                        edge_frames = conn.get_frames(
                            namespace=ds_name,
                            frame_type='edge'
                        )

                        vertex_info = [extract_vertex_metadata(f) for f in vertex_frames]
                        edge_info = [extract_edge_metadata(f) for f in edge_frames]

                        if vertex_info or edge_info:  # Only include if has frames
                            datasets.append({
                                'name': ds_name,
                                'vertices': vertex_info,
                                'edges': edge_info
                            })

                    except Exception as e:
                        logger.warning(f"Failed to get info for dataset {ds_name}: {e}")
                        continue

                return datasets

        except Exception as e:
            logger.error(f"Failed to get datasets info: {e}")
            raise XGTOperationError(f"Dataset info retrieval failed: {str(e)}")

    def memory_footprint(self) -> dict:
        """
        Get memory footprint information from XGT server.

        Returns:
            Dictionary containing memory usage information

        Raises:
            XGTOperationError: If operation fails
        """
        try:
            with self.connection() as conn:
                footprint = conn.get_server_memory_usage()
                return {
                    'memory_usage': footprint
                }
        except Exception as e:
            logger.error(f"Failed to get memory footprint: {e}")
            raise XGTOperationError(f"Memory footprint retrieval failed: {str(e)}")

    def schedule_query(self, query: str, dataset_name: Optional[str] = None) -> dict:
        """
        Schedule a query for execution.

        Args:
            query: Cypher query to execute
            dataset_name: Dataset name for scoping

        Returns:
            Dictionary containing job information

        Raises:
            XGTOperationError: If query scheduling fails
        """
        try:
            with self.connection() as conn:
                # Validate query doesn't contain dangerous patterns
                if self.INTO_PATTERN.search(query):
                    raise XGTOperationError("INTO clauses not allowed in public API")

                # Set namespace if dataset specified
                if dataset_name:
                    conn.set_default_namespace(dataset_name)

                # Run query
                job = conn.run_job(query)

                return {
                    'job_id': job.id,
                    'status': job.status,
                    'query': query,
                    'dataset_name': dataset_name,
                    'submitted_at': time.time()
                }

        except Exception as e:
            logger.error(f"Failed to schedule query: {e}")
            raise XGTOperationError(f"Query scheduling failed: {str(e)}")

    def get_query_answer(self, job_id: int, offset: int = 0,
                        length: int = 10000) -> dict:
        """
        Get results from a completed query job.

        Args:
            job_id: Job ID to get results for
            offset: Starting offset for results
            length: Maximum number of results to return

        Returns:
            Dictionary containing query results

        Raises:
            XGTOperationError: If getting results fails
        """
        try:
            with self.connection() as conn:
                job = conn.get_job(job_id)

                if job.status == 'completed':
                    results = job.get_data(offset=offset, length=length)
                    return {
                        'job_id': job_id,
                        'status': job.status,
                        'results': results,
                        'offset': offset,
                        'length': len(results) if results else 0
                    }
                else:
                    return {
                        'job_id': job_id,
                        'status': job.status,
                        'results': None,
                        'offset': offset,
                        'length': 0
                    }

        except Exception as e:
            logger.error(f"Failed to get query results: {e}")
            raise XGTOperationError(f"Query results retrieval failed: {str(e)}")

    def job_status(self, job_id: int) -> dict:
        """
        Get status of a job.

        Args:
            job_id: Job ID to check

        Returns:
            Dictionary containing job status information

        Raises:
            XGTOperationError: If getting status fails
        """
        try:
            with self.connection() as conn:
                job = conn.get_job(job_id)

                return {
                    'job_id': job_id,
                    'status': job.status,
                    'progress': getattr(job, 'progress', None),
                    'start_time': getattr(job, 'start_time', None),
                    'end_time': getattr(job, 'end_time', None)
                }

        except Exception as e:
            logger.error(f"Failed to get job status: {e}")
            raise XGTOperationError(f"Job status retrieval failed: {str(e)}")


# Factory function for creating XGT operations
def create_xgt_operations() -> XGTOperations:
    """
    Factory function to create XGT operations.

    Returns:
        XGTOperations instance
    """
    return XGTOperations()
