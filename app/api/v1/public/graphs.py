"""
Graph discovery endpoints for the RocketGraph Public API.

Provides read-only access to discover available graphs and their metadata.
"""

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from ....auth.passthrough_middleware import require_xgt_authentication
from ....auth.passthrough_models import AuthenticatedXGTUser
from ....config.app_config import get_settings
from ....utils.exceptions import XGTConnectionError, XGTOperationError
from ....utils.xgt_user_operations import create_user_xgt_operations

router = APIRouter()
logger = logging.getLogger(__name__)


class FrameInfo(BaseModel):
    """Information about a frame (vertex or edge) in a graph."""

    name: str = Field(..., description="Frame name")
    schema_definition: list[list[Any]] = Field(..., description="Frame schema definition")
    num_rows: int = Field(..., description="Number of rows in the frame")
    create_rows: bool = Field(..., description="Whether user can create rows")
    delete_frame: bool = Field(..., description="Whether user can delete frame")


class VertexFrameInfo(FrameInfo):
    """Information about a vertex frame."""

    key: str = Field(..., description="Primary key column name")


class EdgeFrameInfo(FrameInfo):
    """Information about an edge frame."""

    source_frame: str = Field(..., description="Source vertex frame name")
    source_key: str = Field(..., description="Source key column name")
    target_frame: str = Field(..., description="Target vertex frame name")
    target_key: str = Field(..., description="Target key column name")


class GraphInfo(BaseModel):
    """Information about a graph (namespace)."""

    name: str = Field(..., description="Graph name")
    vertices: list[VertexFrameInfo] = Field(..., description="Vertex frames in the graph")
    edges: list[EdgeFrameInfo] = Field(..., description="Edge frames in the graph")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "social_network",
                "vertices": [
                    {
                        "name": "users",
                        "schema_definition": [["id", "TEXT"], ["name", "TEXT"], ["age", "INTEGER"]],
                        "num_rows": 1000,
                        "create_rows": True,
                        "delete_frame": False,
                        "key": "id",
                    }
                ],
                "edges": [
                    {
                        "name": "friendships",
                        "schema_definition": [["created_at", "DATETIME"], ["weight", "FLOAT"]],
                        "num_rows": 5000,
                        "create_rows": True,
                        "delete_frame": False,
                        "source_frame": "users",
                        "source_key": "id",
                        "target_frame": "users",
                        "target_key": "id",
                    }
                ],
            }
        }
    )


class GraphsResponse(BaseModel):
    """Response for graphs listing."""

    graphs: list[GraphInfo] = Field(..., description="Available graphs")
    total_count: int = Field(..., description="Total number of graphs")


class SchemaProperty(BaseModel):
    """Schema property information."""

    name: str = Field(..., description="Property name")
    type: str = Field(..., description="Property type")
    leaf_type: str = Field(..., description="Leaf type for complex types")
    depth: int = Field(..., description="Type depth")


class NodeSchema(BaseModel):
    """Node frame schema information."""

    name: str = Field(..., description="Node frame name")
    properties: list[SchemaProperty] = Field(..., description="Node properties")
    key: str = Field(..., description="Primary key property")


class EdgeSchema(BaseModel):
    """Edge frame schema information."""

    name: str = Field(..., description="Edge frame name")
    properties: list[SchemaProperty] = Field(..., description="Edge properties")
    source: str = Field(..., description="Source node frame name")
    target: str = Field(..., description="Target node frame name")
    source_key: str = Field(..., description="Source key property")
    target_key: str = Field(..., description="Target key property")


class SchemaResponse(BaseModel):
    """Schema information response."""

    graph: str = Field(..., description="Graph name")
    nodes: list[NodeSchema] = Field(..., description="Node schemas")
    edges: list[EdgeSchema] = Field(..., description="Edge schemas")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "graph": "customer_graph",
                "nodes": [
                    {
                        "name": "Customer",
                        "properties": [
                            {"name": "id", "type": "TEXT", "leaf_type": "TEXT", "depth": 1},
                            {"name": "name", "type": "TEXT", "leaf_type": "TEXT", "depth": 1},
                            {"name": "age", "type": "INTEGER", "leaf_type": "INTEGER", "depth": 1},
                        ],
                        "key": "id",
                    }
                ],
                "edges": [
                    {
                        "name": "PURCHASED",
                        "properties": [
                            {"name": "amount", "type": "FLOAT", "leaf_type": "FLOAT", "depth": 1},
                            {
                                "name": "date",
                                "type": "DATETIME",
                                "leaf_type": "DATETIME",
                                "depth": 1,
                            },
                        ],
                        "source": "Customer",
                        "target": "Product",
                        "source_key": "id",
                        "target_key": "id",
                    }
                ],
            }
        }
    )


@router.get("/graphs", response_model=GraphsResponse)
async def list_graphs(
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    include_empty: bool = Query(default=False, description="Include graphs with no frames"),
):
    """
    List all graphs available to the organization.

    Returns metadata about graphs that contain graph data.
    Each graph contains vertex frames (nodes) and edge frames (relationships).

    Args:
        include_empty: Whether to include graphs that have no frames

    Returns:
        List of graphs with their frame information

    Raises:
        HTTPException: If XGT connection fails or operation errors occur
    """
    try:
        logger.info("Listing graphs from XGT server")

        # Create user-specific XGT operations instance
        user_xgt_ops = create_user_xgt_operations(current_user.credentials)

        # Get graphs accessible to user (their namespace)
        graphs_raw = user_xgt_ops.graphs_info()

        # Transform the raw data into our response format
        graphs = []
        for graph_raw in graphs_raw:
            # Skip empty graphs if not requested
            if not include_empty and not graph_raw.get("vertices") and not graph_raw.get("edges"):
                continue

            # Convert vertex frames
            vertices = []
            for vertex_raw in graph_raw.get("vertices", []):
                vertices.append(
                    VertexFrameInfo(
                        name=vertex_raw["name"],
                        schema_definition=vertex_raw["schema"],
                        num_rows=vertex_raw["num_rows"],
                        create_rows=vertex_raw["create_rows"],
                        delete_frame=vertex_raw["delete_frame"],
                        key=vertex_raw["key"],
                    )
                )

            # Convert edge frames
            edges = []
            for edge_raw in graph_raw.get("edges", []):
                edges.append(
                    EdgeFrameInfo(
                        name=edge_raw["name"],
                        schema_definition=edge_raw["schema"],
                        num_rows=edge_raw["num_rows"],
                        create_rows=edge_raw["create_rows"],
                        delete_frame=edge_raw["delete_frame"],
                        source_frame=edge_raw["source_frame"],
                        source_key=edge_raw["source_key"],
                        target_frame=edge_raw["target_frame"],
                        target_key=edge_raw["target_key"],
                    )
                )

            graphs.append(GraphInfo(name=graph_raw["name"], vertices=vertices, edges=edges))

        logger.info(f"Found {len(graphs)} graphs")

        return GraphsResponse(graphs=graphs, total_count=len(graphs))

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server",
                "details": str(e),
            },
        )
    except XGTOperationError as e:
        logger.error(f"XGT operation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "XGT_OPERATION_ERROR",
                "message": "Failed to retrieve graphs",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected error listing graphs: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )


@router.get("/graphs/{graph_name}/schema", response_model=SchemaResponse)
async def get_graph_schema(
    graph_name: str,
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    fully_qualified: bool = Query(default=False, description="Include namespace information in frame names"),
    add_missing_edge_nodes: bool = Query(default=False, description="Include missing edge nodes in the schema"),
):
    """
    Get schema information for a specific graph.

    Returns detailed schema information including node and edge frame definitions,
    their properties, types, and relationships.

    Args:
        graph_name: Name of the graph to get schema for
        fully_qualified: Whether to include namespace information
        add_missing_edge_nodes: Whether to include missing edge nodes

    Returns:
        Schema information for the graph

    Raises:
        HTTPException: If graph not found or XGT operation fails
    """
    try:
        logger.info(f"Getting schema for graph: {graph_name}")

        # Create user-specific XGT operations instance
        user_xgt_ops = create_user_xgt_operations(current_user.credentials)

        # Get schema information from XGT
        # Get schema using the graph name
        schema_raw = user_xgt_ops.get_schema(
            graph_name=graph_name,
            fully_qualified=fully_qualified,
            add_missing_edge_nodes=add_missing_edge_nodes,
        )

        # Convert nodes to response format
        nodes = []
        for node_raw in schema_raw.get("nodes", []):
            properties = [
                SchemaProperty(
                    name=prop["name"],
                    type=prop["type"],
                    leaf_type=prop["leaf_type"],
                    depth=prop["depth"],
                )
                for prop in node_raw["properties"]
            ]

            nodes.append(NodeSchema(name=node_raw["name"], properties=properties, key=node_raw["key"]))

        # Convert edges to response format
        edges = []
        for edge_raw in schema_raw.get("edges", []):
            properties = [
                SchemaProperty(
                    name=prop["name"],
                    type=prop["type"],
                    leaf_type=prop["leaf_type"],
                    depth=prop["depth"],
                )
                for prop in edge_raw["properties"]
            ]

            edges.append(
                EdgeSchema(
                    name=edge_raw["name"],
                    properties=properties,
                    source=edge_raw["source"],
                    target=edge_raw["target"],
                    source_key=edge_raw["source_key"],
                    target_key=edge_raw["target_key"],
                )
            )

        logger.info(f"Retrieved schema for {graph_name}: {len(nodes)} nodes, {len(edges)} edges")

        return SchemaResponse(graph=schema_raw.get("graph", graph_name), nodes=nodes, edges=edges)

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server",
                "details": str(e),
            },
        )
    except XGTOperationError as e:
        logger.error(f"XGT operation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "XGT_OPERATION_ERROR",
                "message": f"Failed to retrieve schema for graph '{graph_name}'",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected error getting schema for {graph_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )


@router.get("/graphs/{graph_name}", response_model=GraphInfo)
async def get_graph_info(
    graph_name: str,
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
):
    """
    Get detailed information about a specific graph.

    Returns comprehensive metadata about a graph including all vertex and edge frames,
    their schemas, row counts, and permissions.

    Args:
        graph_name: Name of the graph to retrieve

    Returns:
        Detailed graph information

    Raises:
        HTTPException: If graph not found or XGT operation fails
    """
    try:
        logger.info(f"Getting graph info for: {graph_name}")

        # Create user-specific XGT operations instance
        user_xgt_ops = create_user_xgt_operations(current_user.credentials)

        # Get specific graph information
        # Get specific graph information
        graphs_raw = user_xgt_ops.graphs_info(graph_name=graph_name)

        if not graphs_raw:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "GRAPH_NOT_FOUND",
                    "message": f"Graph '{graph_name}' not found",
                    "details": f"No graph named '{graph_name}' exists",
                },
            )

        graph_raw = graphs_raw[0]  # Should only be one graph

        # Convert to response format (same logic as list_graphs)
        vertices = []
        for vertex_raw in graph_raw.get("vertices", []):
            vertices.append(
                VertexFrameInfo(
                    name=vertex_raw["name"],
                    schema_definition=vertex_raw["schema"],
                    num_rows=vertex_raw["num_rows"],
                    create_rows=vertex_raw["create_rows"],
                    delete_frame=vertex_raw["delete_frame"],
                    key=vertex_raw["key"],
                )
            )

        edges = []
        for edge_raw in graph_raw.get("edges", []):
            edges.append(
                EdgeFrameInfo(
                    name=edge_raw["name"],
                    schema_definition=edge_raw["schema"],
                    num_rows=edge_raw["num_rows"],
                    create_rows=edge_raw["create_rows"],
                    delete_frame=edge_raw["delete_frame"],
                    source_frame=edge_raw["source_frame"],
                    source_key=edge_raw["source_key"],
                    target_frame=edge_raw["target_frame"],
                    target_key=edge_raw["target_key"],
                )
            )

        return GraphInfo(name=graph_raw["name"], vertices=vertices, edges=edges)

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server",
                "details": str(e),
            },
        )
    except XGTOperationError as e:
        logger.error(f"XGT operation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "XGT_OPERATION_ERROR",
                "message": f"Failed to retrieve graph '{graph_name}'",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected error getting graph {graph_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )