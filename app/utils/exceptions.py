"""
Custom exceptions for the RocketGraph Public API.

Provides structured error handling with proper HTTP status codes
and detailed error information for API consumers.
"""

from typing import Optional, Dict, Any


class BaseAPIException(Exception):
    """Base exception for all API errors."""
    
    def __init__(self, message: str, error_code: str = None, 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}


class XGTConnectionError(BaseAPIException):
    """Raised when XGT connection fails."""
    
    def __init__(self, message: str = "Failed to connect to XGT database", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "XGT_CONNECTION_ERROR", details)


class XGTOperationError(BaseAPIException):
    """Raised when XGT operation fails."""
    
    def __init__(self, message: str = "XGT operation failed", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "XGT_OPERATION_ERROR", details)


class DatasetNotFoundError(BaseAPIException):
    """Raised when requested dataset is not found."""
    
    def __init__(self, dataset_name: str = None, 
                 details: Optional[Dict[str, Any]] = None):
        message = f"Dataset '{dataset_name}' not found" if dataset_name else "Dataset not found"
        super().__init__(message, "DATASET_NOT_FOUND", details)


class UnauthorizedError(BaseAPIException):
    """Raised when user lacks required permissions."""
    
    def __init__(self, message: str = "Unauthorized access", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "UNAUTHORIZED", details)


class ValidationError(BaseAPIException):
    """Raised when input validation fails."""
    
    def __init__(self, message: str = "Input validation failed", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "VALIDATION_ERROR", details)


class RateLimitExceededError(BaseAPIException):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", 
                 retry_after: Optional[int] = None,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "RATE_LIMIT_EXCEEDED", details)
        self.retry_after = retry_after


class APIKeyError(BaseAPIException):
    """Raised when API key validation fails."""
    
    def __init__(self, message: str = "Invalid API key", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "INVALID_API_KEY", details)


class QueryError(BaseAPIException):
    """Raised when query execution fails."""
    
    def __init__(self, message: str = "Query execution failed", 
                 query: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "QUERY_ERROR", details)
        self.query = query


class SchemaError(BaseAPIException):
    """Raised when schema operations fail."""
    
    def __init__(self, message: str = "Schema operation failed", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "SCHEMA_ERROR", details)


class ConfigurationError(BaseAPIException):
    """Raised when configuration is invalid."""
    
    def __init__(self, message: str = "Configuration error", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFIGURATION_ERROR", details)