"""
Frame data endpoints for the RocketGraph Public API.

Provides access to frame data with pagination support.
Frames can be vertex frames, edge frames, or table frames.
"""

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ....config.app_config import get_settings
from ....utils.exceptions import XGTConnectionError, XGTOperationError
from ....utils.xgt_operations import create_xgt_operations

router = APIRouter()
logger = logging.getLogger(__name__)


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

    class Config:
        json_schema_extra = {
            "example": {
                "frame_name": "ecommerce__customers",
                "frame_type": "vertex",
                "namespace": "ecommerce",
                "columns": ["id", "name", "email", "created_at"],
                "rows": [
                    ["cust_001", "John Doe", "john@example.com", "2024-01-15T10:30:00"],
                    ["cust_002", "Jane Smith", "jane@example.com", "2024-01-16T14:20:00"]
                ],
                "total_rows": 10000,
                "offset": 0,
                "limit": 100,
                "returned_rows": 2
            }
        }


@router.get("/frames/{frame_name}/data", response_model=FrameDataResponse)
async def get_frame_data(
    frame_name: str,
    offset: int = Query(
        default=0,
        ge=0,
        description="Starting offset for data retrieval"
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=10000,
        description="Maximum number of rows to return (max 10,000)"
    )
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

        # Create XGT operations instance
        xgt_ops = create_xgt_operations()

        # Get frame data from XGT
        frame_data = xgt_ops.get_frame_data(
            frame_name=frame_name,
            offset=offset,
            limit=limit
        )

        logger.info(f"Retrieved {frame_data['returned_rows']} rows from {frame_name}")

        return FrameDataResponse(**frame_data)

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
        # Check if it's a frame not found error
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "FRAME_NOT_FOUND",
                    "message": f"Frame '{frame_name}' not found or not accessible",
                    "details": str(e)
                }
            )
        else:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "XGT_OPERATION_ERROR",
                    "message": f"Failed to retrieve data from frame '{frame_name}'",
                    "details": str(e)
                }
            )
    except Exception as e:
        logger.error(f"Unexpected error getting frame data: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error"
            }
        )