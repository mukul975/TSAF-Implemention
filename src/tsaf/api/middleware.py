"""
API Middleware
Security, monitoring, and utility middleware for TSAF API.
"""

import time
import json
import uuid
from typing import Callable, Dict, Any, Optional
from datetime import datetime

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

import structlog

logger = structlog.get_logger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for API protection."""

    def __init__(
        self,
        app: ASGIApp,
        api_keys: Optional[Dict[str, str]] = None,
        rate_limit: int = 1000,
        rate_window: int = 3600
    ):
        super().__init__(app)
        self.api_keys = api_keys or {}
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.request_counts = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with security checks."""
        start_time = time.time()

        try:
            # Skip security for health checks and docs
            if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
                return await call_next(request)

            # API Key validation
            if self.api_keys:
                api_key = request.headers.get("X-API-Key")
                if not api_key or api_key not in self.api_keys:
                    return JSONResponse(
                        status_code=401,
                        content={"error": "Invalid or missing API key"}
                    )

            # Rate limiting
            client_ip = self._get_client_ip(request)
            if not self._check_rate_limit(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded"}
                )

            # Content-Type validation for POST/PUT requests
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if not content_type.startswith("application/json"):
                    return JSONResponse(
                        status_code=400,
                        content={"error": "Content-Type must be application/json"}
                    )

            # Process request
            response = await call_next(request)

            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

            # Log security events
            processing_time = time.time() - start_time
            logger.info(
                "API request processed",
                method=request.method,
                path=request.url.path,
                client_ip=client_ip,
                status_code=response.status_code,
                processing_time=processing_time
            )

            return response

        except Exception as e:
            logger.error("Security middleware error", error=str(e))
            return JSONResponse(
                status_code=500,
                content={"error": "Internal security error"}
            )

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to client host
        return request.client.host if request.client else "unknown"

    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limit."""
        now = int(time.time())
        window_start = now - self.rate_window

        # Clean old entries
        if client_ip in self.request_counts:
            self.request_counts[client_ip] = [
                timestamp for timestamp in self.request_counts[client_ip]
                if timestamp > window_start
            ]
        else:
            self.request_counts[client_ip] = []

        # Check rate limit
        if len(self.request_counts[client_ip]) >= self.rate_limit:
            return False

        # Record this request
        self.request_counts[client_ip].append(now)
        return True


class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware for request tracking and monitoring."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Track request metrics and performance."""
        request_id = str(uuid.uuid4())
        start_time = time.time()

        # Add request ID to request state
        request.state.request_id = request_id

        # Log request start
        logger.info(
            "Request started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query_params=str(request.query_params),
            user_agent=request.headers.get("user-agent"),
            content_length=request.headers.get("content-length")
        )

        try:
            # Process request
            response = await call_next(request)

            # Calculate metrics
            processing_time = time.time() - start_time
            response_size = response.headers.get("content-length", "0")

            # Add tracking headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Processing-Time"] = f"{processing_time:.4f}"

            # Log request completion
            logger.info(
                "Request completed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                processing_time=processing_time,
                response_size=response_size
            )

            # Record metrics (could send to metrics system)
            await self._record_metrics(request, response, processing_time)

            return response

        except Exception as e:
            processing_time = time.time() - start_time

            logger.error(
                "Request failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                processing_time=processing_time,
                error=str(e)
            )

            raise

    async def _record_metrics(self, request: Request, response: Response, processing_time: float):
        """Record request metrics."""
        try:
            # Here you could send metrics to a metrics system like Prometheus
            # For now, we'll just log key metrics
            metrics = {
                "request_duration_seconds": processing_time,
                "request_size_bytes": int(request.headers.get("content-length", "0")),
                "response_size_bytes": int(response.headers.get("content-length", "0")),
                "status_code": response.status_code,
                "method": request.method,
                "endpoint": request.url.path
            }

            logger.debug("Request metrics", **metrics)

        except Exception as e:
            logger.error("Failed to record metrics", error=str(e))


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware for centralized error handling."""

    def __init__(self, app: ASGIApp, include_debug_info: bool = False):
        super().__init__(app)
        self.include_debug_info = include_debug_info

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle errors and format responses consistently."""
        try:
            response = await call_next(request)
            return response

        except HTTPException as e:
            # FastAPI HTTPExceptions are handled properly
            raise

        except ValueError as e:
            logger.warning("Validation error", error=str(e), path=request.url.path)
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Validation Error",
                    "message": str(e),
                    "request_id": getattr(request.state, "request_id", None)
                }
            )

        except PermissionError as e:
            logger.warning("Permission denied", error=str(e), path=request.url.path)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Permission Denied",
                    "message": "Insufficient permissions",
                    "request_id": getattr(request.state, "request_id", None)
                }
            )

        except Exception as e:
            logger.error(
                "Unhandled error",
                error=str(e),
                path=request.url.path,
                method=request.method
            )

            error_response = {
                "error": "Internal Server Error",
                "message": "An unexpected error occurred",
                "request_id": getattr(request.state, "request_id", None),
                "timestamp": datetime.utcnow().isoformat()
            }

            if self.include_debug_info:
                error_response["debug_info"] = {
                    "exception_type": type(e).__name__,
                    "exception_message": str(e)
                }

            return JSONResponse(
                status_code=500,
                content=error_response
            )


class CORSMiddleware(BaseHTTPMiddleware):
    """CORS middleware for cross-origin requests."""

    def __init__(
        self,
        app: ASGIApp,
        allow_origins: list = None,
        allow_methods: list = None,
        allow_headers: list = None,
        allow_credentials: bool = True
    ):
        super().__init__(app)
        self.allow_origins = allow_origins or ["*"]
        self.allow_methods = allow_methods or ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        self.allow_headers = allow_headers or ["*"]
        self.allow_credentials = allow_credentials

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle CORS headers."""
        origin = request.headers.get("origin")

        # Handle preflight requests
        if request.method == "OPTIONS":
            response = Response(status_code=200)
        else:
            response = await call_next(request)

        # Add CORS headers
        if origin and (self.allow_origins == ["*"] or origin in self.allow_origins):
            response.headers["Access-Control-Allow-Origin"] = origin
        elif self.allow_origins == ["*"]:
            response.headers["Access-Control-Allow-Origin"] = "*"

        response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allow_methods)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allow_headers)

        if self.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"

        return response


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Middleware for additional request validation."""

    def __init__(self, app: ASGIApp, max_content_length: int = 10 * 1024 * 1024):  # 10MB
        super().__init__(app)
        self.max_content_length = max_content_length

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Validate request before processing."""
        try:
            # Check content length
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.max_content_length:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request too large"}
                )

            # Validate JSON content for appropriate methods
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if content_type.startswith("application/json"):
                    try:
                        # Attempt to parse JSON to validate it
                        body = await request.body()
                        if body:
                            json.loads(body)

                        # Create new request with the body (since it's consumed)
                        from starlette.requests import Request as StarletteRequest

                        # Create new request with preserved body for downstream processing

                    except json.JSONDecodeError:
                        return JSONResponse(
                            status_code=400,
                            content={"error": "Invalid JSON format"}
                        )

            return await call_next(request)

        except Exception as e:
            logger.error("Request validation error", error=str(e))
            return JSONResponse(
                status_code=400,
                content={"error": "Request validation failed"}
            )


def setup_middleware(app, config: Dict[str, Any] = None):
    """Set up all middleware for the application."""
    config = config or {}

    # Error handling (first - catches all errors)
    app.add_middleware(
        ErrorHandlingMiddleware,
        include_debug_info=config.get("debug", False)
    )

    # Request tracking
    app.add_middleware(RequestTrackingMiddleware)

    # Security middleware
    app.add_middleware(
        SecurityMiddleware,
        api_keys=config.get("api_keys"),
        rate_limit=config.get("rate_limit", 1000),
        rate_window=config.get("rate_window", 3600)
    )

    # Request validation
    app.add_middleware(
        RequestValidationMiddleware,
        max_content_length=config.get("max_content_length", 10 * 1024 * 1024)
    )

    # CORS (if needed)
    if config.get("enable_cors", False):
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.get("cors_origins", ["*"]),
            allow_methods=config.get("cors_methods", ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]),
            allow_headers=config.get("cors_headers", ["*"]),
            allow_credentials=config.get("cors_credentials", True)
        )