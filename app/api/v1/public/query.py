"""
Query execution endpoints for the RocketGraph Public API.

Provides async Cypher query execution with job management.
"""

import logging
import time
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


class QueryRequest(BaseModel):
    """Request model for executing queries."""

    query: str = Field(..., description="Cypher query to execute", min_length=1)
    parameters: Optional[dict[str, Any]] = Field(
        default=None, description="Query parameters for substitution"
    )
    format: str = Field(
        default="json",
        description="Result format (json, csv, parquet)",
        pattern="^(json|csv|parquet)$",
    )
    limit: Optional[int] = Field(
        default=None, ge=1, le=1000000, description="Maximum number of results to return"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "query": (
                    "MATCH (c:Customer)-[p:PURCHASED]->(pr:Product) "
                    "WHERE pr.category = $category "
                    "RETURN c.name, p.amount, pr.name LIMIT $limit"
                ),
                "parameters": {"category": "electronics", "limit": 100},
                "format": "json",
                "limit": 1000,
            }
        }
    )


class QueryResponse(BaseModel):
    """Response for query execution."""

    job_id: int = Field(..., description="Job ID for tracking query execution")
    status: str = Field(..., description="Current job status")
    query: str = Field(..., description="The executed query")
    dataset_name: str = Field(..., description="Dataset the query was executed against")
    submitted_at: float = Field(..., description="Unix timestamp when query was submitted")
    estimated_completion: Optional[str] = Field(
        None, description="Estimated completion time (ISO 8601)"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "job_id": 12345,
                "status": "queued",
                "query": "MATCH (c:Customer) RETURN c.name LIMIT 10",
                "dataset_name": "ecommerce",
                "submitted_at": 1642248000.0,
                "estimated_completion": "2024-01-15T10:32:00Z",
            }
        }
    )


class QueryStatusResponse(BaseModel):
    """Response for query status."""

    job_id: int = Field(..., description="Job ID")
    status: str = Field(..., description="Current job status")
    progress: Optional[float] = Field(None, description="Completion progress (0.0-1.0)")
    start_time: Optional[float] = Field(None, description="Unix timestamp when job started")
    end_time: Optional[float] = Field(None, description="Unix timestamp when job completed")
    processing_time_ms: Optional[int] = Field(None, description="Processing time in milliseconds")
    error_message: Optional[str] = Field(None, description="Error message if job failed")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "job_id": 12345,
                "status": "completed",
                "progress": 1.0,
                "start_time": 1642248000.0,
                "end_time": 1642248045.0,
                "processing_time_ms": 45000,
                "error_message": None,
            }
        }
    )


class QueryResultsResponse(BaseModel):
    """Response for query results."""

    job_id: int = Field(..., description="Job ID")
    status: str = Field(..., description="Job status")
    columns: Optional[list[str]] = Field(None, description="Column names")
    rows: Optional[list[list[Any]]] = Field(None, description="Result rows")
    offset: int = Field(..., description="Starting offset")
    limit: int = Field(..., description="Number of results requested")
    returned_rows: int = Field(..., description="Number of rows returned")
    total_rows: Optional[int] = Field(None, description="Total number of result rows")
    result_metadata: Optional[dict[str, Any]] = Field(
        None, description="Additional result metadata"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "job_id": 12345,
                "status": "completed",
                "columns": ["customer_name", "amount", "product_name"],
                "rows": [["John Doe", 299.99, "Smartphone"], ["Jane Smith", 1299.99, "Laptop"]],
                "offset": 0,
                "limit": 1000,
                "returned_rows": 2,
                "total_rows": 1250,
                "result_metadata": {"execution_time_ms": 45000, "query_hash": "sha256_abc123..."},
            }
        }
    )


class JobHistoryItem(BaseModel):
    """Individual job in history listing."""

    job_id: int = Field(..., description="Job ID")
    status: str = Field(..., description="Job status")
    query: str = Field(..., description="Query that was executed")
    dataset_name: Optional[str] = Field(None, description="Dataset the query was executed against")
    submitted_at: float = Field(..., description="Unix timestamp when query was submitted")
    start_time: Optional[float] = Field(None, description="Unix timestamp when job started")
    end_time: Optional[float] = Field(None, description="Unix timestamp when job completed")
    processing_time_ms: Optional[int] = Field(None, description="Processing time in milliseconds")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "job_id": 12345,
                "status": "completed",
                "query": "MATCH (c:Customer) RETURN c.name LIMIT 10",
                "dataset_name": "ecommerce",
                "submitted_at": 1642248000.0,
                "start_time": 1642248000.0,
                "end_time": 1642248045.0,
                "processing_time_ms": 45000,
            }
        }
    )


class JobHistoryResponse(BaseModel):
    """Response for job history listing."""

    jobs: list[JobHistoryItem] = Field(..., description="List of jobs in history")
    total_count: int = Field(..., description="Total number of jobs")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Number of jobs per page")
    has_more: bool = Field(..., description="Whether there are more jobs available")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "jobs": [
                    {
                        "job_id": 12345,
                        "status": "completed",
                        "query": "MATCH (c:Customer) RETURN c.name LIMIT 10",
                        "dataset_name": "ecommerce",
                        "submitted_at": 1642248000.0,
                        "start_time": 1642248000.0,
                        "end_time": 1642248045.0,
                        "processing_time_ms": 45000,
                    }
                ],
                "total_count": 1,
                "page": 1,
                "per_page": 50,
                "has_more": False,
            }
        }
    )


@router.get("/query/jobs", response_model=JobHistoryResponse)
async def list_job_history(
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    per_page: int = Query(
        default=50, ge=1, le=200, description="Number of jobs per page (max 200)"
    ),
    status: Optional[str] = Query(default=None, description="Filter by job status"),
    dataset_name: Optional[str] = Query(default=None, description="Filter by dataset name"),
):
    """
    List all jobs in the query history.

    Returns a paginated list of all query jobs that have been executed,
    including their status, execution times, and metadata. Useful for
    monitoring and debugging query activity.

    Args:
        page: Page number for pagination (1-based)
        per_page: Number of jobs per page
        status: Filter jobs by status (queued, running, completed, failed)
        dataset_name: Filter jobs by dataset name

    Returns:
        Paginated list of job history with metadata

    Raises:
        HTTPException: If operation fails
    """
    try:
        logger.info(f"Listing job history - page {page}, per_page {per_page}")

        # For now, return a basic job history structure
        # TODO: Implement proper job history retrieval using user credentials
        # user_xgt_ops = create_user_xgt_operations(current_user.credentials)
        job_history = {"jobs": [], "total_count": 0, "has_more": False}

        logger.info(f"Retrieved {len(job_history['jobs'])} jobs from history")

        # Convert to response format
        jobs = []
        for job_info in job_history["jobs"]:
            # Calculate processing time if available
            processing_time_ms = None
            if job_info.get("start_time") and job_info.get("end_time"):
                processing_time_ms = int((job_info["end_time"] - job_info["start_time"]) * 1000)

            jobs.append(
                JobHistoryItem(
                    job_id=job_info["job_id"],
                    status=job_info["status"],
                    query=job_info["query"],
                    dataset_name=job_info.get("dataset_name"),
                    submitted_at=job_info["submitted_at"],
                    start_time=job_info.get("start_time"),
                    end_time=job_info.get("end_time"),
                    processing_time_ms=processing_time_ms,
                )
            )

        return JobHistoryResponse(
            jobs=jobs,
            total_count=job_history["total_count"],
            page=page,
            per_page=per_page,
            has_more=job_history.get("has_more", False),
        )

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
                "message": "Failed to retrieve job history",
                "details": str(e),
            },
        )
    except Exception as e:
        logger.error(f"Unexpected error getting job history: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )


@router.post("/datasets/{dataset_name}/query", response_model=QueryResponse)
async def execute_query(
    dataset_name: str,
    query_request: QueryRequest,
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
):
    """
    Execute a Cypher query against a dataset.

    Submits a query for asynchronous execution. The query is validated
    and queued for processing. Use the returned job_id to check status
    and retrieve results.

    Args:
        dataset_name: Name of the dataset to query
        query_request: Query details including Cypher query and parameters

    Returns:
        Query job information with job_id for tracking

    Raises:
        HTTPException: If query validation fails or submission errors occur
    """
    try:
        logger.info(f"Executing query on dataset {dataset_name}")
        logger.debug(f"Query: {query_request.query}")

        # Create a mock job response for now
        # TODO: Implement proper job scheduling with user credentials
        # user_xgt_ops = create_user_xgt_operations(current_user.credentials)
        # results = user_xgt_ops.execute_query(query_request.query)
        job_info = {
            "job_id": hash(query_request.query + str(time.time())) % 1000000,
            "status": "completed",
            "query": query_request.query,
            "dataset_name": dataset_name,
            "submitted_at": time.time(),
        }

        logger.info(f"Query scheduled with job ID: {job_info['job_id']}")

        return QueryResponse(
            job_id=job_info["job_id"],
            status=job_info["status"],
            query=job_info["query"],
            dataset_name=job_info["dataset_name"],
            submitted_at=job_info["submitted_at"],
            estimated_completion=None,  # XGT doesn't provide this yet
        )

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
        # Check for specific query validation errors
        if "INTO clauses not allowed" in str(e):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "INVALID_QUERY",
                    "message": "Query contains forbidden operations",
                    "details": str(e),
                },
            )
        else:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "XGT_OPERATION_ERROR",
                    "message": "Failed to execute query",
                    "details": str(e),
                },
            )
    except Exception as e:
        logger.error(f"Unexpected error executing query: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )


@router.get("/query/{job_id}/status", response_model=QueryStatusResponse)
async def get_query_status(
    job_id: int, current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)]
):
    """
    Get the status of a query job.

    Returns current execution status, progress information, and timing
    details for a previously submitted query job.

    Args:
        job_id: ID of the query job to check

    Returns:
        Query job status information

    Raises:
        HTTPException: If job not found or status check fails
    """
    try:
        logger.info(f"Checking status for job ID: {job_id}")

        # For now, return a mock status
        # TODO: Implement proper job status retrieval using user credentials
        # user_xgt_ops = create_user_xgt_operations(current_user.credentials)
        status_info = {
            "job_id": job_id,
            "status": "completed",
            "progress": 1.0,
            "start_time": time.time() - 60,
            "end_time": time.time(),
        }

        # Calculate processing time if available
        processing_time_ms = None
        if status_info.get("start_time") and status_info.get("end_time"):
            processing_time_ms = int((status_info["end_time"] - status_info["start_time"]) * 1000)

        return QueryStatusResponse(
            job_id=status_info["job_id"],
            status=status_info["status"],
            progress=status_info.get("progress"),
            start_time=status_info.get("start_time"),
            end_time=status_info.get("end_time"),
            processing_time_ms=processing_time_ms,
            error_message=None,  # XGT doesn't provide error details in status
        )

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
        # Check if it's a job not found error
        if "not found" in str(e).lower() or "invalid" in str(e).lower():
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "JOB_NOT_FOUND",
                    "message": f"Query job {job_id} not found",
                    "details": str(e),
                },
            )
        else:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "XGT_OPERATION_ERROR",
                    "message": "Failed to get job status",
                    "details": str(e),
                },
            )
    except Exception as e:
        logger.error(f"Unexpected error getting job status: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )


@router.get("/query/{job_id}/results", response_model=QueryResultsResponse)
async def get_query_results(
    job_id: int,
    current_user: Annotated[AuthenticatedXGTUser, Depends(require_xgt_authentication)],
    offset: int = 0,
    limit: int = 1000,
):
    """
    Get results from a completed query job.

    Retrieves the results of a query job with pagination support.
    The job must be in 'completed' status to return results.

    Args:
        job_id: ID of the query job to get results for
        offset: Starting offset for results pagination
        limit: Maximum number of results to return

    Returns:
        Query results with data and pagination information

    Raises:
        HTTPException: If job not found, not completed, or results retrieval fails
    """
    try:
        logger.info(f"Getting results for job ID: {job_id}")

        # Create user-specific XGT operations instance
        user_xgt_ops = create_user_xgt_operations(current_user.credentials)

        # Get query results from XGT using user's credentials
        results = user_xgt_ops.execute_query(
            f"/* Get results for job {job_id} with offset {offset} limit {limit} */"
        )

        # For now, return a simplified response structure
        # TODO: Implement proper job result retrieval from XGT using user credentials
        results_info = {
            "status": "completed",
            "results": results,
            "columns": [f"col_{i}" for i in range(len(results[0]))] if results else [],
            "total_rows": len(results),
        }

        # Parse results based on job status
        if results_info["status"] == "completed":
            results = results_info.get("results", [])

            # Extract columns and rows from results
            columns = results_info.get("columns", [])
            rows = results_info.get("results", [])

            # If no columns provided, try to extract from results
            if not columns and results:
                # Assume first row contains column info or is data
                if isinstance(results[0], dict):
                    # Results are dictionaries
                    columns = list(results[0].keys())
                    rows = [[row[col] for col in columns] for row in results]
                else:
                    # Results are lists - need to infer columns
                    rows = results
                    columns = [f"col_{i}" for i in range(len(rows[0]))] if rows else []

            return QueryResultsResponse(
                job_id=job_id,
                status=results_info["status"],
                columns=columns,
                rows=rows,
                offset=offset,
                limit=limit,
                returned_rows=len(rows),
                total_rows=results_info.get("total_rows"),
                result_metadata={"query_execution_completed": True},
            )
        else:
            # Job not completed yet
            return QueryResultsResponse(
                job_id=job_id,
                status=results_info["status"],
                columns=None,
                rows=None,
                offset=offset,
                limit=limit,
                returned_rows=0,
                total_rows=None,
                result_metadata={"query_execution_completed": False},
            )

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
        # Check if it's a job not found error
        if "not found" in str(e).lower() or "invalid" in str(e).lower():
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "JOB_NOT_FOUND",
                    "message": f"Query job {job_id} not found",
                    "details": str(e),
                },
            )
        else:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "XGT_OPERATION_ERROR",
                    "message": "Failed to get query results",
                    "details": str(e),
                },
            )
    except Exception as e:
        logger.error(f"Unexpected error getting query results: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred",
                "details": str(e) if get_settings().DEBUG else "Internal server error",
            },
        )
