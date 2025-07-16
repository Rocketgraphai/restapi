"""
Dataset discovery endpoints for the RocketGraph Public API.

Provides read-only access to discover available datasets and their metadata.
"""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ....config.app_config import get_settings
from ....utils.exceptions import XGTConnectionError, XGTOperationError
from ....utils.xgt_operations import create_xgt_operations

router = APIRouter()
logger = logging.getLogger(__name__)


class DatasetFrameInfo(BaseModel):
    """Information about a frame (vertex or edge) in a dataset."""
    name: str = Field(..., description="Frame name")
    schema: list[list[Any]] = Field(..., description="Frame schema definition")
    num_rows: int = Field(..., description="Number of rows in the frame")
    create_rows: bool = Field(..., description="Whether user can create rows")
    delete_frame: bool = Field(..., description="Whether user can delete frame")


class VertexFrameInfo(DatasetFrameInfo):
    """Information about a vertex frame."""
    key: str = Field(..., description="Primary key column name")


class EdgeFrameInfo(DatasetFrameInfo):
    """Information about an edge frame."""
    source_frame: str = Field(..., description="Source vertex frame name")
    source_key: str = Field(..., description="Source key column name")
    target_frame: str = Field(..., description="Target vertex frame name")
    target_key: str = Field(..., description="Target key column name")


class DatasetInfo(BaseModel):
    """Information about a dataset (namespace)."""
    name: str = Field(..., description="Dataset name")
    vertices: list[VertexFrameInfo] = Field(..., description="Vertex frames in the dataset")
    edges: list[EdgeFrameInfo] = Field(..., description="Edge frames in the dataset")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "social_network",
                "vertices": [
                    {
                        "name": "users",
                        "schema": [["id", "TEXT"], ["name", "TEXT"], ["age", "INTEGER"]],
                        "num_rows": 1000,
                        "create_rows": True,
                        "delete_frame": False,
                        "key": "id"
                    }
                ],
                "edges": [
                    {
                        "name": "friendships",
                        "schema": [["created_at", "DATETIME"], ["weight", "FLOAT"]],
                        "num_rows": 5000,
                        "create_rows": True,
                        "delete_frame": False,
                        "source_frame": "users",
                        "source_key": "id",
                        "target_frame": "users",
                        "target_key": "id"
                    }
                ]
            }
        }


class DatasetsResponse(BaseModel):
    """Response for datasets listing."""
    datasets: list[DatasetInfo] = Field(..., description="Available datasets")
    total_count: int = Field(..., description="Total number of datasets")


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
    graph: str = Field(..., description="Dataset/graph name")
    nodes: list[NodeSchema] = Field(..., description="Node schemas")
    edges: list[EdgeSchema] = Field(..., description="Edge schemas")

    class Config:
        json_schema_extra = {
            "example": {
                "graph": "customer_graph",
                "nodes": [
                    {
                        "name": "Customer",
                        "properties": [
                            {"name": "id", "type": "TEXT", "leaf_type": "TEXT", "depth": 1},
                            {"name": "name", "type": "TEXT", "leaf_type": "TEXT", "depth": 1},
                            {"name": "age", "type": "INTEGER", "leaf_type": "INTEGER", "depth": 1}
                        ],
                        "key": "id"
                    }
                ],
                "edges": [
                    {
                        "name": "PURCHASED",
                        "properties": [
                            {"name": "amount", "type": "FLOAT", "leaf_type": "FLOAT", "depth": 1},
                            {"name": "date", "type": "DATETIME", "leaf_type": "DATETIME", "depth": 1}
                        ],
                        "source": "Customer",
                        "target": "Product",
                        "source_key": "id",
                        "target_key": "id"
                    }
                ]
            }
        }


@router.get("/datasets", response_model=DatasetsResponse)
async def list_datasets(
    include_empty: bool = Query(
        default=False,
        description="Include datasets with no frames"
    )
):
    """
    List all datasets available to the organization.

    Returns metadata about datasets (namespaces) that contain graph data.
    Each dataset contains vertex frames (nodes) and edge frames (relationships).

    Args:
        include_empty: Whether to include datasets that have no frames

    Returns:
        List of datasets with their frame information

    Raises:
        HTTPException: If XGT connection fails or operation errors occur
    """
    try:
        logger.info("Listing datasets from XGT server")

        # Create XGT operations instance
        xgt_ops = create_xgt_operations()

        # Get datasets information from XGT
        datasets_raw = xgt_ops.datasets_info()

        # Transform the raw data into our response format
        datasets = []
        for dataset_raw in datasets_raw:
            # Skip empty datasets if not requested
            if not include_empty and not dataset_raw.get('vertices') and not dataset_raw.get('edges'):
                continue

            # Convert vertex frames
            vertices = []
            for vertex_raw in dataset_raw.get('vertices', []):
                vertices.append(VertexFrameInfo(
                    name=vertex_raw['name'],
                    schema=vertex_raw['schema'],
                    num_rows=vertex_raw['num_rows'],
                    create_rows=vertex_raw['create_rows'],
                    delete_frame=vertex_raw['delete_frame'],
                    key=vertex_raw['key']
                ))

            # Convert edge frames
            edges = []
            for edge_raw in dataset_raw.get('edges', []):
                edges.append(EdgeFrameInfo(
                    name=edge_raw['name'],
                    schema=edge_raw['schema'],
                    num_rows=edge_raw['num_rows'],
                    create_rows=edge_raw['create_rows'],
                    delete_frame=edge_raw['delete_frame'],
                    source_frame=edge_raw['source_frame'],
                    source_key=edge_raw['source_key'],
                    target_frame=edge_raw['target_frame'],
                    target_key=edge_raw['target_key']
                ))

            datasets.append(DatasetInfo(
                name=dataset_raw['name'],
                vertices=vertices,
                edges=edges
            ))

        logger.info(f"Found {len(datasets)} datasets")

        return DatasetsResponse(
            datasets=datasets,
            total_count=len(datasets)
        )

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server",
                "details": str(e)
            }
        )
    except XGTOperationError as e:
        logger.error(f"XGT operation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "XGT_OPERATION_ERROR",
                "message": "Failed to retrieve datasets",
                "details": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Unexpected error listing datasets: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error"
            }
        )


@router.get("/datasets/{dataset_name}/schema", response_model=SchemaResponse)
async def get_dataset_schema(
    dataset_name: str,
    fully_qualified: bool = Query(
        default=False,
        description="Include namespace information in frame names"
    ),
    add_missing_edge_nodes: bool = Query(
        default=False,
        description="Include missing edge nodes in the schema"
    )
):
    """
    Get schema information for a specific dataset.

    Returns detailed schema information including node and edge frame definitions,
    their properties, types, and relationships.

    Args:
        dataset_name: Name of the dataset to get schema for
        fully_qualified: Whether to include namespace information
        add_missing_edge_nodes: Whether to include missing edge nodes

    Returns:
        Schema information for the dataset

    Raises:
        HTTPException: If dataset not found or XGT operation fails
    """
    try:
        logger.info(f"Getting schema for dataset: {dataset_name}")

        # Create XGT operations instance
        xgt_ops = create_xgt_operations()

        # Get schema information from XGT
        schema_raw = xgt_ops.get_schema(
            dataset_name=dataset_name,
            fully_qualified=fully_qualified,
            add_missing_edge_nodes=add_missing_edge_nodes
        )

        # Convert nodes to response format
        nodes = []
        for node_raw in schema_raw.get('nodes', []):
            properties = [
                SchemaProperty(
                    name=prop['name'],
                    type=prop['type'],
                    leaf_type=prop['leaf_type'],
                    depth=prop['depth']
                )
                for prop in node_raw['properties']
            ]

            nodes.append(NodeSchema(
                name=node_raw['name'],
                properties=properties,
                key=node_raw['key']
            ))

        # Convert edges to response format
        edges = []
        for edge_raw in schema_raw.get('edges', []):
            properties = [
                SchemaProperty(
                    name=prop['name'],
                    type=prop['type'],
                    leaf_type=prop['leaf_type'],
                    depth=prop['depth']
                )
                for prop in edge_raw['properties']
            ]

            edges.append(EdgeSchema(
                name=edge_raw['name'],
                properties=properties,
                source=edge_raw['source'],
                target=edge_raw['target'],
                source_key=edge_raw['source_key'],
                target_key=edge_raw['target_key']
            ))

        logger.info(f"Retrieved schema for {dataset_name}: {len(nodes)} nodes, {len(edges)} edges")

        return SchemaResponse(
            graph=schema_raw.get('graph', dataset_name),
            nodes=nodes,
            edges=edges
        )

    except XGTConnectionError as e:
        logger.error(f"XGT connection failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={
                "error": "XGT_CONNECTION_ERROR",
                "message": "Cannot connect to XGT server",
                "details": str(e)
            }
        )
    except XGTOperationError as e:
        logger.error(f"XGT operation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "XGT_OPERATION_ERROR",
                "message": f"Failed to retrieve schema for dataset '{dataset_name}'",
                "details": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Unexpected error getting schema for {dataset_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error"
            }
        )


@router.get("/datasets/{dataset_name}", response_model=DatasetInfo)
async def get_dataset_info(
    dataset_name: str
):
    """
    Get detailed information about a specific dataset.

    Returns comprehensive metadata about a dataset including all vertex and edge frames,
    their schemas, row counts, and permissions.

    Args:
        dataset_name: Name of the dataset to retrieve

    Returns:
        Detailed dataset information

    Raises:
        HTTPException: If dataset not found or XGT operation fails
    """
    try:
        logger.info(f"Getting dataset info for: {dataset_name}")

        # Create XGT operations instance
        xgt_ops = create_xgt_operations()

        # Get specific dataset information
        datasets_raw = xgt_ops.datasets_info(dataset_name=dataset_name)

        if not datasets_raw:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "DATASET_NOT_FOUND",
                    "message": f"Dataset '{dataset_name}' not found",
                    "details": f"No dataset named '{dataset_name}' exists"
                }
            )

        dataset_raw = datasets_raw[0]  # Should only be one dataset

        # Convert to response format (same logic as list_datasets)
        vertices = []
        for vertex_raw in dataset_raw.get('vertices', []):
            vertices.append(VertexFrameInfo(
                name=vertex_raw['name'],
                schema=vertex_raw['schema'],
                num_rows=vertex_raw['num_rows'],
                create_rows=vertex_raw['create_rows'],
                delete_frame=vertex_raw['delete_frame'],
                key=vertex_raw['key']
            ))

        edges = []
        for edge_raw in dataset_raw.get('edges', []):
            edges.append(EdgeFrameInfo(
                name=edge_raw['name'],
                schema=edge_raw['schema'],
                num_rows=edge_raw['num_rows'],
                create_rows=edge_raw['create_rows'],
                delete_frame=edge_raw['delete_frame'],
                source_frame=edge_raw['source_frame'],
                source_key=edge_raw['source_key'],
                target_frame=edge_raw['target_frame'],
                target_key=edge_raw['target_key']
            ))

        return DatasetInfo(
            name=dataset_raw['name'],
            vertices=vertices,
            edges=edges
        )

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
                "details": str(e)
            }
        )
    except XGTOperationError as e:
        logger.error(f"XGT operation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "XGT_OPERATION_ERROR",
                "message": f"Failed to retrieve dataset '{dataset_name}'",
                "details": str(e)
            }
        )
    except Exception as e:
        logger.error(f"Unexpected error getting dataset {dataset_name}: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error"
            }
        )
