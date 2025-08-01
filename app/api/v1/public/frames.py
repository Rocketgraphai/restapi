"""
Frame data endpoints for the RocketGraph Public API.

Provides access to frame data with pagination support.
Frames can be vertex frames, edge frames, or table frames.
"""

import logging
from typing import Annotated, Any, Optional

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
    """Information about a frame."""

    name: str = Field(..., description="Frame name")
    full_name: str = Field(..., description="Fully qualified frame name")
    namespace: str = Field(..., description="Namespace of the frame")
    frame_type: str = Field(..., description="Type of frame (vertex, edge, table)")
    num_rows: int = Field(..., description="Number of rows in the frame")
    schema_definition: list[list[Any]] = Field(..., description="Frame schema definition")

    # Additional fields for vertex frames
    key: Optional[str] = Field(None, description="Primary key column (vertex frames only)")

    # Additional fields for edge frames
    source_name: Optional[str] = Field(None, description="Source frame name (edge frames only)")
    target_name: Optional[str] = Field(None, description="Target frame name (edge frames only)")
    source_key: Optional[str] = Field(None, description="Source key column (edge frames only)")
    target_key: Optional[str] = Field(None, description="Target key column (edge frames only)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "customers",
                "full_name": "ecommerce__customers",
                "namespace": "ecommerce",
                "frame_type": "vertex",
                "num_rows": 10000,
                "schema_definition": [["id", "TEXT"], ["name", "TEXT"], ["email", "TEXT"]],
                "key": "id",
                "source_name": None,
                "target_name": None,
                "source_key": None,
                "target_key": None,
            }
        }
    )


class FramesListResponse(BaseModel):
    """Response for frames listing."""

    frames: list[FrameInfo] = Field(..., description="List of frames")
    total_count: int = Field(..., description="Total number of frames")
    graphs: list[str] = Field(..., description="Graph names included in the results")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "frames": [
                    {
                        "name": "customers",
                        "full_name": "ecommerce__customers",
                        "namespace": "ecommerce",
                        "frame_type": "vertex",
                        "num_rows": 10000,
                        "schema_definition": [["id", "TEXT"], ["name", "TEXT"]],
                        "key": "id",
                        "source_name": None,
                        "target_name": None,
                        "source_key": None,
                        "target_key": None,
                    },
                    {
                        "name": "purchases",
                        "full_name": "ecommerce__purchases",
                        "namespace": "ecommerce",
                        "frame_type": "edge",
                        "num_rows": 50000,
                        "schema_definition": [["amount", "FLOAT"], ["date", "DATETIME"]],
                        "key": None,
                        "source_name": "customers",
                        "target_name": "products",
                        "source_key": "id",
                        "target_key": "id",
                    },
                ],
                "total_count": 2,
                "namespaces": ["ecommerce"],
            }
        }
    )


class FrameDataResponse(BaseModel):
    """Response for frame data retrieval."""

    frame_name: str = Field(..., description="Name of the frame")
    frame_type: str = Field(..., description="Type of frame (vertex, edge, table)")
    namespace: Optional[str] = Field(None, description="Namespace of the frame")
    columns: list[str] = Field(..., description="Column names")
    rows: list[list[Any]] = Field(..., description="Data rows")
    total_rows: int = Field(..., description="Total rows in the frame")
    offset: int = Field(..., description="Starting offset")
    limit: int = Field(..., description="Requested limit")
    returned_rows: int = Field(..., description="Number of rows returned")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "frame_name": "ecommerce__customers",
                "frame_type": "vertex",
                "namespace": "ecommerce",
                "columns": ["id", "name", "email", "created_at"],
                "rows": [
                    ["cust_001", "John Doe", "john@example.com", "2024-01-15T10:30:00"],
                    ["cust_002", "Jane Smith", "jane@example.com", "2024-01-16T14:20:00"],
                ],
                "total_rows": 10000,
                "offset": 0,
                "limit": 100,
                "returned_rows": 2,
            }
        }
    )


@router.get("/frames", response_model=FramesListResponse)
async def list_frames(
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    graph_name: Optional[str] = Query(
        default=None,
        description="Filter frames by graph name (if not specified, all graphs except xgt__)",
    ),
    frame_type: Optional[str] = Query(default=None, description="Filter frames by type (vertex, edge, table)"),
):
    """
    List all frames across all graphs.

    Returns information about all frames (vertex, edge, and table frames)
    across all accessible graphs, excluding the system xgt__ graph.
    Useful for discovering available data structures before querying.

    Args:
        graph_name: Filter frames by specific graph name (optional)
        frame_type: Filter frames by type (vertex, edge, table) (optional)

    Returns:
        List of frames with their metadata

    Raises:
        HTTPException: If XGT connection fails or operation errors occur
    """
    try:
        logger.info("Listing all frames from XGT server")

        # Create user-specific XGT operations instance
        user_xgt_ops = create_user_xgt_operations(current_user.credentials)

        # Get graphs information from XGT (this includes frame info)
        graphs_raw = user_xgt_ops.graphs_info()

        frames = []
        graphs_found = set()

        for graph_raw in graphs_raw:
            current_graph_name = graph_raw["name"]

            # Skip the xgt__ graph
            if current_graph_name == "xgt__":
                continue

            # Apply graph name filter if specified
            if graph_name and current_graph_name != graph_name:
                continue

            graphs_found.add(current_graph_name)

            # Process vertex frames
            for vertex_raw in graph_raw.get("vertices", []):
                # Apply frame type filter if specified
                if frame_type and frame_type != "vertex":
                    continue

                frame_info = FrameInfo(
                    name=vertex_raw["name"],
                    full_name=f"{current_graph_name}__{vertex_raw['name']}",
                    namespace=current_graph_name,
                    frame_type="vertex",
                    num_rows=vertex_raw["num_rows"],
                    schema_definition=vertex_raw["schema"],
                    key=vertex_raw["key"],
                    source_name=None,
                    target_name=None,
                    source_key=None,
                    target_key=None,
                )
                frames.append(frame_info)

            # Process edge frames
            for edge_raw in graph_raw.get("edges", []):
                # Apply frame type filter if specified
                if frame_type and frame_type != "edge":
                    continue

                frame_info = FrameInfo(
                    name=edge_raw["name"],
                    full_name=f"{current_graph_name}__{edge_raw['name']}",
                    namespace=current_graph_name,
                    frame_type="edge",
                    num_rows=edge_raw["num_rows"],
                    schema_definition=edge_raw["schema"],
                    key=None,
                    source_name=edge_raw["source_frame"],
                    target_name=edge_raw["target_frame"],
                    source_key=edge_raw["source_key"],
                    target_key=edge_raw["target_key"],
                )
                frames.append(frame_info)

            # Process table frames
            for table_raw in graph_raw.get("tables", []):
                # Apply frame type filter if specified
                if frame_type and frame_type != "table":
                    continue

                frame_info = FrameInfo(
                    name=table_raw["name"],
                    full_name=f"{current_graph_name}__{table_raw['name']}",
                    namespace=current_graph_name,
                    frame_type="table",
                    num_rows=table_raw["num_rows"],
                    schema_definition=table_raw["schema"],
                    key=None,  # Table frames don't have keys
                    source_name=None,
                    target_name=None,
                    source_key=None,
                    target_key=None,
                )
                frames.append(frame_info)

        # Sort frames by graph name, then by frame name
        frames.sort(key=lambda f: (f.namespace, f.name))

        logger.info(f"Found {len(frames)} frames across {len(graphs_found)} graphs")

        return FramesListResponse(frames=frames, total_count=len(frames), graphs=sorted(graphs_found))

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
                "message": "Failed to retrieve frames",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected error listing frames: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )


@router.get("/frames/{frame_name}/data", response_model=FrameDataResponse)
async def get_frame_data(
    frame_name: str,
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    offset: int = Query(default=0, ge=0, description="Starting offset for data retrieval"),
    limit: int = Query(default=100, ge=1, le=10000, description="Maximum number of rows to return (max 10,000)"),
):
    """
    Get data rows from a specific frame.

    Retrieves data from a vertex, edge, or table frame with support for
    offset-based pagination. Useful for exploring frame contents before
    writing complex queries.

    Frame names can be:
    - Simple names like 'users' (uses default namespace)
    - Fully qualified names like 'ecommerce__users'

    Args:
        frame_name: Name of the frame (simple or fully qualified)
        offset: Starting row offset (0-based)
        limit: Maximum number of rows to return

    Returns:
        Frame data with columns and rows

    Raises:
        HTTPException: If frame not found or operation fails
    """
    try:
        logger.info(f"Getting data from frame: {frame_name}")

        # Create user-specific XGT operations instance
        user_xgt_ops = create_user_xgt_operations(current_user.credentials)

        # Get frame data from XGT
        frame_data = user_xgt_ops.get_frame_data(frame_name=frame_name, offset=offset, limit=limit)

        logger.info(f"Retrieved {frame_data['returned_rows']} rows from {frame_name}")

        return FrameDataResponse(**frame_data)

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
        # Check if it's a frame not found error
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "FRAME_NOT_FOUND",
                    "message": f"Frame '{frame_name}' not found or not accessible",
                    "details": str(e),
                },
            )
        else:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "XGT_OPERATION_ERROR",
                    "message": f"Failed to retrieve data from frame '{frame_name}'",
                    "details": str(e),
                },
            )
    except Exception as e:
        logger.error(f"Unexpected error getting frame data: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )
