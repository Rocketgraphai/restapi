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

        def extract_table_metadata(frame) -> dict:
            """Extract metadata from a table frame."""
            return {
                'name': self._fix_name(frame.name, False, ""),
                'schema': frame.schema,
                'num_rows': frame.num_rows,
                'create_rows': frame.user_permissions.get('create_rows', False),
                'delete_frame': frame.user_permissions.get('delete_frame', False)
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
                        table_frames = conn.get_frames(
                            namespace=ds_name,
                            frame_type='table'
                        )

                        vertex_info = [extract_vertex_metadata(f) for f in vertex_frames]
                        edge_info = [extract_edge_metadata(f) for f in edge_frames]
                        table_info = [extract_table_metadata(f) for f in table_frames]

                        if vertex_info or edge_info or table_info:  # Only include if has frames
                            datasets.append({
                                'name': ds_name,
                                'vertices': vertex_info,
                                'edges': edge_info,
                                'tables': table_info
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

                # Try to run query - XGT might handle this differently
                try:
                    # Try the run_job method first
                    job = conn.run_job(query)
                    job_id = getattr(job, 'id', hash(query + str(time.time())))
                    job_status = getattr(job, 'status', 'completed')
                    
                    # Store the job for later retrieval (simple in-memory storage)
                    if not hasattr(self, '_jobs'):
                        self._jobs = {}
                    self._jobs[job_id] = {
                        'job': job,
                        'query': query,
                        'dataset_name': dataset_name,
                        'submitted_at': time.time()
                    }
                    
                    return {
                        'job_id': job_id,
                        'status': job_status,
                        'query': query,
                        'dataset_name': dataset_name,
                        'submitted_at': time.time()
                    }
                
                except AttributeError:
                    # If run_job doesn't exist, run query directly and simulate job
                    results = conn.run_query(query)
                    job_id = hash(query + str(time.time()))
                    
                    # Store the results for later retrieval
                    if not hasattr(self, '_jobs'):
                        self._jobs = {}
                    self._jobs[job_id] = {
                        'results': results,
                        'query': query,
                        'dataset_name': dataset_name,
                        'submitted_at': time.time(),
                        'status': 'completed'
                    }
                    
                    return {
                        'job_id': job_id,
                        'status': 'completed',
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
            logger.info(f"Getting query answer for job {job_id}")
            with self.connection() as conn:
                # First try to get job from XGT server
                try:
                    xgt_jobs = conn.get_jobs()
                    logger.info(f"Found {len(xgt_jobs)} jobs from XGT server for job {job_id}")
                    for job in xgt_jobs:
                        # Check if this is the job we're looking for
                        xgt_job_id = getattr(job, 'id', getattr(job, 'job_id', hash(str(job))))
                        if xgt_job_id == job_id:
                            logger.info(f"Found matching job {job_id} on XGT server")
                            # Extract job status information
                            job_status = getattr(job, 'status', 'unknown')
                            
                            if job_status == 'completed':
                                try:
                                    # Try to get data from the job first (for queries without INTO clause)
                                    logger.debug(f"Trying to get data from job {job_id}")
                                    results = job.get_data(offset=offset, length=length)
                                    logger.debug(f"Got results from job.get_data(): {results}")
                                    
                                    # If we got results, return them
                                    if results is not None:
                                        return {
                                            'job_id': job_id,
                                            'status': job_status,
                                            'results': results,
                                            'offset': offset,
                                            'length': len(results) if results else 0
                                        }
                                    else:
                                        # Results are None, fall through to try table frame lookup
                                        logger.debug(f"Job {job_id} get_data() returned None, trying table frame lookup")
                                        
                                except AttributeError as attr_error:
                                    logger.debug(f"AttributeError getting data from job: {attr_error}")
                                
                                # Whether we got None from get_data() or AttributeError, try table frame lookup
                                # For queries with INTO clause, results are stored in table frames
                                try:
                                    # Try to get job information to find associated table frame
                                    job_info = getattr(job, 'info', {})
                                    table_name = job_info.get('result_table') or job_info.get('output_table')
                                    
                                    if not table_name:
                                        # Try to extract table name from the query's INTO clause
                                        query_text = getattr(job, 'query', getattr(job, 'query_text', getattr(job, 'cypher', getattr(job, 'description', ''))))
                                        logger.debug(f"Query text for job {job_id}: {query_text}")
                                        
                                        # If no query text from job object, try to get it from in-memory storage
                                        if not query_text:
                                            logger.debug(f"No query text in job object, trying in-memory storage")
                                            if hasattr(self, '_jobs') and job_id in self._jobs:
                                                job_info = self._jobs[job_id]
                                                query_text = job_info.get('query', '')
                                                logger.debug(f"Found query text from in-memory storage: {query_text}")
                                            else:
                                                logger.debug(f"Job {job_id} not found in in-memory storage")
                                        
                                        if query_text:
                                            # Look for INTO clause in the query
                                            import re
                                            into_match = re.search(r'INTO\s+([^\s;]+)', query_text, re.IGNORECASE)
                                            if into_match:
                                                table_name = into_match.group(1).strip('`"\'')
                                                logger.debug(f"Found table name from INTO clause: {table_name}")
                                                # If table name doesn't have namespace, try current namespace
                                                if '__' not in table_name:
                                                    current_namespace = getattr(job, 'namespace', conn.get_default_namespace())
                                                    if current_namespace:
                                                        table_name = f"{current_namespace}__{table_name}"
                                                        logger.debug(f"Added namespace to table name: {table_name}")
                                            else:
                                                logger.debug(f"No INTO clause found in query")
                                        else:
                                            logger.debug(f"No query text found for job {job_id}")
                                        
                                    if table_name:
                                        logger.debug(f"Trying to get table frame: {table_name}")
                                        # Get data from the table frame
                                        try:
                                            table_frame = conn.get_frame(table_name)
                                            table_data = table_frame.get_data(offset=offset, length=length)
                                            logger.debug(f"Retrieved {len(table_data) if table_data else 0} rows from table frame")
                                            
                                            # Convert table data to results format
                                            if table_data:
                                                # Get column names from job schema first, then fall back to table frame schema
                                                columns = []
                                                try:
                                                    # Try to get columns from job schema first
                                                    logger.debug(f"Job {job_id} has schema attribute: {hasattr(job, 'schema')}")
                                                    if hasattr(job, 'schema'):
                                                        logger.debug(f"Job {job_id} schema value: {job.schema}")
                                                        logger.debug(f"Job {job_id} schema type: {type(job.schema)}")
                                                        
                                                    if hasattr(job, 'schema') and job.schema:
                                                        logger.debug(f"Job {job_id} has schema: {job.schema}")
                                                        if hasattr(job.schema, '__iter__'):
                                                            columns = []
                                                            for col in job.schema:
                                                                if hasattr(col, 'name'):
                                                                    columns.append(col.name)
                                                                elif hasattr(col, '__iter__') and not isinstance(col, str):
                                                                    # Schema might be [column_name, type] tuples
                                                                    columns.append(col[0])
                                                                else:
                                                                    columns.append(str(col))
                                                        else:
                                                            columns = [str(job.schema)]
                                                        logger.debug(f"Extracted columns from job schema: {columns}")
                                                    # Fall back to table frame schema
                                                    elif hasattr(table_frame, 'schema'):
                                                        logger.debug(f"Using table frame schema instead")
                                                        if hasattr(table_frame.schema, '__iter__'):
                                                            columns = []
                                                            for col in table_frame.schema:
                                                                if hasattr(col, 'name'):
                                                                    columns.append(col.name)
                                                                elif hasattr(col, '__iter__') and not isinstance(col, str):
                                                                    # Schema might be [column_name, type] tuples
                                                                    columns.append(col[0])
                                                                else:
                                                                    columns.append(str(col))
                                                        else:
                                                            columns = [f"col_{i}" for i in range(len(table_data[0]))] if table_data else []
                                                    else:
                                                        logger.debug(f"No schema found, using generic column names")
                                                        columns = [f"col_{i}" for i in range(len(table_data[0]))] if table_data else []
                                                except Exception as e:
                                                    logger.debug(f"Exception getting columns: {e}")
                                                    columns = [f"col_{i}" for i in range(len(table_data[0]))] if table_data else []
                                                
                                                # Convert rows to the expected format
                                                rows = []
                                                for row in table_data:
                                                    if hasattr(row, '__iter__') and not isinstance(row, str):
                                                        # Row is already a list/tuple
                                                        rows.append(list(row))
                                                    else:
                                                        # Row is a single value
                                                        rows.append([row])
                                                
                                                return {
                                                    'job_id': job_id,
                                                    'status': job_status,
                                                    'results': rows,
                                                    'columns': columns,
                                                    'offset': offset,
                                                    'length': len(rows),
                                                    'total_rows': getattr(job, 'num_rows', None)
                                                }
                                        except Exception as frame_error:
                                            logger.warning(f"Failed to get data from table frame {table_name}: {frame_error}")
                                    else:
                                        logger.debug(f"No table name found for job {job_id}")
                                    
                                    # If no table frame found, return empty results
                                    return {
                                        'job_id': job_id,
                                        'status': job_status,
                                        'results': [],
                                        'offset': offset,
                                        'length': 0,
                                        'total_rows': getattr(job, 'num_rows', None)
                                    }
                                except Exception as e:
                                    logger.warning(f"Failed to get results from table frame: {e}")
                                    return {
                                        'job_id': job_id,
                                        'status': job_status,
                                        'results': [],
                                        'offset': offset,
                                        'length': 0,
                                        'total_rows': getattr(job, 'num_rows', None)
                                    }
                            else:
                                # Job not completed yet
                                return {
                                    'job_id': job_id,
                                    'status': job_status,
                                    'results': None,
                                    'offset': offset,
                                    'length': 0
                                }
                except (AttributeError, Exception) as e:
                    logger.warning(f"Failed to get job results from XGT server: {e}")
                
                # Fallback to in-memory job storage
                logger.info(f"Falling back to in-memory job storage for job {job_id}")
                if hasattr(self, '_jobs') and job_id in self._jobs:
                    job_info = self._jobs[job_id]
                    logger.info(f"Found job {job_id} in in-memory storage")
                    
                    # If we have a job object, try to get its results
                    if 'job' in job_info:
                        job = job_info['job']
                        job_status = getattr(job, 'status', 'completed')
                        
                        if job_status == 'completed':
                            try:
                                # Try to get data from the job first (for queries without INTO clause)
                                results = job.get_data(offset=offset, length=length)
                                return {
                                    'job_id': job_id,
                                    'status': job_status,
                                    'results': results,
                                    'offset': offset,
                                    'length': len(results) if results else 0
                                }
                            except AttributeError:
                                # Job doesn't have get_data method, try to find associated table frame
                                # For queries with INTO clause, results are stored in table frames
                                try:
                                    # Try to get job information to find associated table frame
                                    job_info_attr = getattr(job, 'info', {})
                                    table_name = job_info_attr.get('result_table') or job_info_attr.get('output_table')
                                    
                                    if not table_name:
                                        # Try to extract table name from the query's INTO clause
                                        query_text = getattr(job, 'query', getattr(job, 'query_text', getattr(job, 'cypher', getattr(job, 'description', job_info.get('query', '')))))
                                        if query_text:
                                            # Look for INTO clause in the query
                                            import re
                                            into_match = re.search(r'INTO\s+([^\s;]+)', query_text, re.IGNORECASE)
                                            if into_match:
                                                table_name = into_match.group(1).strip('`"\'')
                                                # If table name doesn't have namespace, try current namespace
                                                if '__' not in table_name:
                                                    current_namespace = getattr(job, 'namespace', job_info.get('dataset_name', conn.get_default_namespace()))
                                                    if current_namespace:
                                                        table_name = f"{current_namespace}__{table_name}"
                                    
                                    if table_name:
                                        # Get data from the table frame
                                        table_frame = conn.get_frame(table_name)
                                        table_data = table_frame.get_data(offset=offset, length=length)
                                        
                                        # Convert table data to results format
                                        if table_data:
                                            # Get column names from job schema first, then fall back to table frame schema
                                            columns = []
                                            try:
                                                # Try to get columns from job schema first
                                                if hasattr(job, 'schema') and job.schema:
                                                    if hasattr(job.schema, '__iter__'):
                                                        columns = []
                                                        for col in job.schema:
                                                            if hasattr(col, 'name'):
                                                                columns.append(col.name)
                                                            elif hasattr(col, '__iter__') and not isinstance(col, str):
                                                                # Schema might be [column_name, type] tuples
                                                                columns.append(col[0])
                                                            else:
                                                                columns.append(str(col))
                                                    else:
                                                        columns = [str(job.schema)]
                                                # Fall back to table frame schema
                                                elif hasattr(table_frame, 'schema'):
                                                    if hasattr(table_frame.schema, '__iter__'):
                                                        columns = []
                                                        for col in table_frame.schema:
                                                            if hasattr(col, 'name'):
                                                                columns.append(col.name)
                                                            elif hasattr(col, '__iter__') and not isinstance(col, str):
                                                                # Schema might be [column_name, type] tuples
                                                                columns.append(col[0])
                                                            else:
                                                                columns.append(str(col))
                                                    else:
                                                        columns = [f"col_{i}" for i in range(len(table_data[0]))] if table_data else []
                                                else:
                                                    columns = [f"col_{i}" for i in range(len(table_data[0]))] if table_data else []
                                            except:
                                                columns = [f"col_{i}" for i in range(len(table_data[0]))] if table_data else []
                                            
                                            # Convert rows to the expected format
                                            rows = []
                                            for row in table_data:
                                                if hasattr(row, '__iter__') and not isinstance(row, str):
                                                    # Row is already a list/tuple
                                                    rows.append(list(row))
                                                else:
                                                    # Row is a single value
                                                    rows.append([row])
                                            
                                            return {
                                                'job_id': job_id,
                                                'status': job_status,
                                                'results': rows,
                                                'columns': columns,
                                                'offset': offset,
                                                'length': len(rows),
                                                'total_rows': getattr(job, 'num_rows', None)
                                            }
                                    
                                    # If no table frame found, return empty results
                                    return {
                                        'job_id': job_id,
                                        'status': job_status,
                                        'results': [],
                                        'offset': offset,
                                        'length': 0,
                                        'total_rows': getattr(job, 'num_rows', None)
                                    }
                                except Exception as e:
                                    logger.warning(f"Failed to get results from table frame: {e}")
                                    return {
                                        'job_id': job_id,
                                        'status': job_status,
                                        'results': [],
                                        'offset': offset,
                                        'length': 0,
                                        'total_rows': getattr(job, 'num_rows', None)
                                    }
                        else:
                            # Job not completed yet
                            return {
                                'job_id': job_id,
                                'status': job_status,
                                'results': None,
                                'offset': offset,
                                'length': 0
                            }
                    
                    # If we have direct results stored
                    elif 'results' in job_info:
                        results = job_info['results']
                        # Apply offset and length
                        if results:
                            paginated_results = results[offset:offset + length]
                        else:
                            paginated_results = []
                        
                        return {
                            'job_id': job_id,
                            'status': job_info.get('status', 'completed'),
                            'results': paginated_results,
                            'offset': offset,
                            'length': len(paginated_results)
                        }
                
                # If job not found in either XGT server or storage, it doesn't exist
                raise XGTOperationError(f"Job {job_id} not found")

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
                # First try to get job from XGT server
                try:
                    xgt_jobs = conn.get_jobs()
                    for job in xgt_jobs:
                        # Check if this is the job we're looking for
                        xgt_job_id = getattr(job, 'id', getattr(job, 'job_id', hash(str(job))))
                        if xgt_job_id == job_id:
                            # Extract job status information
                            job_status = getattr(job, 'status', 'unknown')
                            progress = getattr(job, 'progress', 1.0 if job_status == 'completed' else 0.0)
                            
                            # Get timing information
                            submitted_at = getattr(job, 'submitted_at', getattr(job, 'create_time', time.time()))
                            start_time = getattr(job, 'start_time', getattr(job, 'started_at', submitted_at))
                            end_time = getattr(job, 'end_time', getattr(job, 'finished_at', None))
                            
                            # Convert to timestamp if needed
                            if hasattr(submitted_at, 'timestamp'):
                                submitted_at = submitted_at.timestamp()
                            if hasattr(start_time, 'timestamp'):
                                start_time = start_time.timestamp()
                            if hasattr(end_time, 'timestamp'):
                                end_time = end_time.timestamp()
                            
                            return {
                                'job_id': job_id,
                                'status': job_status,
                                'progress': progress,
                                'start_time': start_time,
                                'end_time': end_time
                            }
                except (AttributeError, Exception) as e:
                    logger.warning(f"Failed to get job status from XGT server: {e}")
                
                # Fallback to in-memory job storage
                if hasattr(self, '_jobs') and job_id in self._jobs:
                    job_info = self._jobs[job_id]
                    
                    # If we have a job object, try to get its status
                    if 'job' in job_info:
                        job = job_info['job']
                        return {
                            'job_id': job_id,
                            'status': getattr(job, 'status', job_info.get('status', 'completed')),
                            'progress': getattr(job, 'progress', 1.0),
                            'start_time': getattr(job, 'start_time', job_info['submitted_at']),
                            'end_time': getattr(job, 'end_time', None)
                        }
                    else:
                        # Direct result storage
                        return {
                            'job_id': job_id,
                            'status': job_info.get('status', 'completed'),
                            'progress': 1.0,
                            'start_time': job_info['submitted_at'],
                            'end_time': job_info['submitted_at']
                        }
                
                # If job not found in either XGT server or storage, it doesn't exist
                raise XGTOperationError(f"Job {job_id} not found")

        except Exception as e:
            logger.error(f"Failed to get job status: {e}")
            raise XGTOperationError(f"Job status retrieval failed: {str(e)}")

    def get_job_history(self, page: int = 1, per_page: int = 50, 
                       status_filter: Optional[str] = None, 
                       dataset_filter: Optional[str] = None) -> dict:
        """
        Get paginated job history with optional filtering.

        Args:
            page: Page number (1-based)
            per_page: Number of jobs per page
            status_filter: Filter by job status
            dataset_filter: Filter by dataset name

        Returns:
            Dictionary containing paginated job history

        Raises:
            XGTOperationError: If getting job history fails
        """
        try:
            with self.connection() as conn:
                # Get jobs from XGT server using get_jobs method
                try:
                    # Try to get jobs from XGT server
                    xgt_jobs = conn.get_jobs()
                    logger.debug(f"Retrieved {len(xgt_jobs)} jobs from XGT server")
                except (AttributeError, Exception) as e:
                    logger.warning(f"Failed to get jobs from XGT server: {e}")
                    # Fallback to in-memory storage if XGT doesn't support get_jobs
                    if not hasattr(self, '_jobs'):
                        self._jobs = {}
                    xgt_jobs = []
                
                # Convert XGT jobs to our format
                all_jobs = []
                for job in xgt_jobs:
                    try:
                        # Extract job information from XGT job object
                        job_id = getattr(job, 'id', getattr(job, 'job_id', hash(str(job))))
                        job_status = getattr(job, 'status', 'unknown')
                        
                        # Try to get query text from job
                        query = getattr(job, 'query', getattr(job, 'query_text', getattr(job, 'cypher', getattr(job, 'description', ''))))
                        if not query:
                            # Try to extract from job description or command
                            query = getattr(job, 'description', getattr(job, 'command', 'Query not available'))
                        
                        # Get timing information
                        submitted_at = getattr(job, 'submitted_at', getattr(job, 'create_time', time.time()))
                        start_time = getattr(job, 'start_time', getattr(job, 'started_at', submitted_at))
                        end_time = getattr(job, 'end_time', getattr(job, 'finished_at', None))
                        
                        # Convert to timestamp if needed
                        if hasattr(submitted_at, 'timestamp'):
                            submitted_at = submitted_at.timestamp()
                        if hasattr(start_time, 'timestamp'):
                            start_time = start_time.timestamp()
                        if hasattr(end_time, 'timestamp'):
                            end_time = end_time.timestamp()
                        
                        # Try to determine dataset name from job context
                        dataset_name = getattr(job, 'namespace', getattr(job, 'dataset', None))
                        
                        # Create job history item
                        job_item = {
                            'job_id': job_id,
                            'status': job_status,
                            'query': query,
                            'dataset_name': dataset_name,
                            'submitted_at': submitted_at,
                            'start_time': start_time,
                            'end_time': end_time
                        }
                        
                        # Apply filters
                        if status_filter and job_status != status_filter:
                            continue
                        if dataset_filter and dataset_name != dataset_filter:
                            continue
                        
                        all_jobs.append(job_item)
                        
                    except Exception as e:
                        logger.warning(f"Failed to process job {job}: {e}")
                        continue
                
                # If no jobs from XGT server, fall back to in-memory storage
                if not all_jobs and hasattr(self, '_jobs'):
                    logger.debug("No jobs from XGT server, using in-memory storage")
                    for job_id, job_info in self._jobs.items():
                        # Extract job status from job object or stored status
                        job_status = job_info.get('status', 'completed')
                        if 'job' in job_info:
                            job_status = getattr(job_info['job'], 'status', job_status)
                        
                        # Get timing information
                        start_time = job_info.get('start_time')
                        end_time = job_info.get('end_time')
                        
                        # If we have a job object, try to get its timing
                        if 'job' in job_info:
                            job = job_info['job']
                            start_time = getattr(job, 'start_time', start_time)
                            end_time = getattr(job, 'end_time', end_time)
                        
                        # Create job history item
                        job_item = {
                            'job_id': job_id,
                            'status': job_status,
                            'query': job_info['query'],
                            'dataset_name': job_info.get('dataset_name'),
                            'submitted_at': job_info['submitted_at'],
                            'start_time': start_time,
                            'end_time': end_time
                        }
                        
                        # Apply filters
                        if status_filter and job_status != status_filter:
                            continue
                        if dataset_filter and job_info.get('dataset_name') != dataset_filter:
                            continue
                        
                        all_jobs.append(job_item)
                
                # Sort by submission time (newest first)
                all_jobs.sort(key=lambda x: x['submitted_at'], reverse=True)
                
                # Apply pagination
                total_count = len(all_jobs)
                start_idx = (page - 1) * per_page
                end_idx = start_idx + per_page
                paginated_jobs = all_jobs[start_idx:end_idx]
                
                has_more = end_idx < total_count
                
                return {
                    'jobs': paginated_jobs,
                    'total_count': total_count,
                    'page': page,
                    'per_page': per_page,
                    'has_more': has_more
                }
            
        except Exception as e:
            logger.error(f"Failed to get job history: {e}")
            raise XGTOperationError(f"Job history retrieval failed: {str(e)}")

    def get_frame_data(self, frame_name: str, offset: int = 0, limit: int = 1000) -> dict:
        """
        Get data from a specific frame.

        Args:
            frame_name: Name of the frame (can be fully qualified like 'ns__frameName' or just 'frameName')
            offset: Starting offset for data retrieval
            limit: Maximum number of rows to return

        Returns:
            Dictionary containing frame data and metadata

        Raises:
            XGTOperationError: If frame not found or operation fails
        """
        try:
            with self.connection() as conn:
                # Get the frame - XGT handles namespace resolution automatically
                try:
                    frames = conn.get_frames(names=[frame_name])
                    if not frames:
                        raise XGTOperationError(f"Frame '{frame_name}' not found")
                    
                    frame = frames[0]
                except Exception:
                    raise XGTOperationError(f"Frame '{frame_name}' not found or not accessible")

                # Get frame data - different frame types have different get_data signatures
                try:
                    # Try with num_rows first (VertexFrame and EdgeFrame)
                    data = frame.get_data(offset=offset, num_rows=limit)
                except TypeError:
                    # Fallback for TableFrame which uses 'length' instead of 'num_rows'
                    try:
                        data = frame.get_data(offset=offset, length=limit)
                    except TypeError:
                        # Last resort - try with just offset
                        data = frame.get_data(offset=offset)
                        # If we got more data than requested, slice it
                        if data and len(data) > limit:
                            data = data[:limit]
                
                # Convert data to list format for JSON serialization
                if data is not None:
                    # Get column names from schema
                    columns = [prop[0] for prop in frame.schema]
                    
                    # Convert data to list of lists
                    rows = []
                    for row in data:
                        # Handle different data types that might not be JSON serializable
                        json_row = []
                        for value in row:
                            if value is None:
                                json_row.append(None)
                            elif hasattr(value, 'isoformat'):  # datetime objects
                                json_row.append(value.isoformat())
                            else:
                                json_row.append(value)
                        rows.append(json_row)
                else:
                    columns = []
                    rows = []

                # Determine frame type more robustly
                frame_type = "unknown"
                frame_class_name = frame.__class__.__name__
                
                if 'EdgeFrame' in frame_class_name or hasattr(frame, 'source_name'):
                    frame_type = "edge"
                elif 'VertexFrame' in frame_class_name or hasattr(frame, 'key'):
                    frame_type = "vertex"
                elif 'TableFrame' in frame_class_name:
                    frame_type = "table"
                else:
                    # Fallback detection
                    if hasattr(frame, 'source_name') and hasattr(frame, 'target_name'):
                        frame_type = "edge"
                    elif hasattr(frame, 'key'):
                        frame_type = "vertex"
                    else:
                        frame_type = "table"

                # Extract namespace from frame name if present
                namespace = None
                if "__" in frame_name:
                    namespace = frame_name.split("__")[0]

                return {
                    "frame_name": frame_name,
                    "frame_type": frame_type,
                    "namespace": namespace,
                    "columns": columns,
                    "rows": rows,
                    "total_rows": frame.num_rows,
                    "offset": offset,
                    "limit": limit,
                    "returned_rows": len(rows)
                }

        except XGTOperationError:
            # Re-raise XGT operation errors
            raise
        except Exception as e:
            logger.error(f"Failed to get frame data: {e}")
            raise XGTOperationError(f"Frame data retrieval failed: {str(e)}")


# Factory function for creating XGT operations
def create_xgt_operations() -> XGTOperations:
    """
    Factory function to create XGT operations.

    Returns:
        XGTOperations instance
    """
    return XGTOperations()
