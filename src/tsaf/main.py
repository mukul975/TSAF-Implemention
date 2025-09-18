"""
TSAF Main Application
FastAPI application with integrated security analysis framework.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from tsaf.api.routes import create_api_router
from tsaf.api.middleware import setup_middleware
from tsaf.database.connection import initialize_database_manager, close_database_manager
from tsaf.core.config import load_config
from tsaf.core.engine import TSAFEngine

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    logger.info("Starting TSAF application")

    try:
        # Load configuration
        config = load_config()
        app.state.config = config

        # Initialize database
        db_manager = initialize_database_manager(config.database)
        await db_manager.initialize()
        app.state.db_manager = db_manager

        # Initialize TSAF Engine
        tsaf_engine = TSAFEngine(config)
        await tsaf_engine.initialize()
        app.state.tsaf_engine = tsaf_engine

        logger.info("TSAF application startup completed")

        # Yield control to the application
        yield

    except Exception as e:
        logger.error("TSAF application startup failed", error=str(e))
        raise

    finally:
        # Cleanup on shutdown
        logger.info("Shutting down TSAF application")

        try:
            # Shutdown TSAF Engine
            if hasattr(app.state, 'tsaf_engine'):
                await app.state.tsaf_engine.shutdown()

            # Close database connections
            await close_database_manager()

            logger.info("TSAF application shutdown completed")

        except Exception as e:
            logger.error("TSAF application shutdown failed", error=str(e))


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    # Create FastAPI app with lifespan management
    app = FastAPI(
        title="TSAF - Translation Security Analysis Framework",
        description="Advanced security analysis framework for multi-agent communication protocols",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan
    )

    # Setup middleware
    middleware_config = {
        "debug": False,  # Set to True for development
        "enable_cors": True,
        "cors_origins": ["*"],  # Configure appropriately for production
        "rate_limit": 1000,
        "rate_window": 3600
    }
    setup_middleware(app, middleware_config)

    # Include API routes
    api_router = create_api_router()
    app.include_router(api_router)

    # Root endpoint
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            "message": "TSAF - Translation Security Analysis Framework",
            "version": "1.0.0",
            "status": "operational",
            "docs": "/docs",
            "api": "/api/v1"
        }

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Simple health check endpoint."""
        try:
            # Check database health
            from tsaf.database.connection import get_database_manager
            db_manager = get_database_manager()
            db_health = await db_manager.get_health_status()

            return {
                "status": "healthy" if db_health["status"] == "healthy" else "degraded",
                "version": "1.0.0",
                "components": {
                    "database": db_health
                }
            }

        except Exception as e:
            logger.error("Health check failed", error=str(e))
            return {
                "status": "unhealthy",
                "error": str(e)
            }

    return app


# Create the application instance
app = create_app()

if __name__ == "__main__":
    import uvicorn

    # Run the application
    uvicorn.run(
        "tsaf.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # Set to True for development
        access_log=True,
        log_config=None  # Use structlog configuration
    )