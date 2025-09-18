"""
Database Connection Management
Handles database connections, sessions, and initialization.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import structlog
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from tsaf.core.config import DatabaseConfig
from tsaf.core.exceptions import TSAFException
from tsaf.database.models import Base

logger = structlog.get_logger(__name__)


class DatabaseManager:
    """
    Database connection and session management.

    Provides both async and sync database sessions for TSAF components.
    """

    def __init__(self, config: DatabaseConfig):
        self.config = config
        self._async_engine = None
        self._sync_engine = None
        self._async_session_factory = None
        self._sync_session_factory = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize database connections and create tables."""
        if self._initialized:
            return

        logger.info("Initializing database connections")

        try:
            # Create async engine
            self._async_engine = create_async_engine(
                self.config.async_url,
                echo=self.config.echo_sql,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                poolclass=NullPool if self.config.disable_pool else None,
                connect_args=self._get_connect_args()
            )

            # Create sync engine for migrations and admin tasks
            self._sync_engine = create_engine(
                self.config.sync_url,
                echo=self.config.echo_sql,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                poolclass=NullPool if self.config.disable_pool else None,
                connect_args=self._get_connect_args()
            )

            # Create session factories
            self._async_session_factory = async_sessionmaker(
                self._async_engine,
                class_=AsyncSession,
                expire_on_commit=False
            )

            self._sync_session_factory = sessionmaker(
                self._sync_engine,
                expire_on_commit=False
            )

            # Test connections
            await self._test_async_connection()
            await self._test_sync_connection()

            # Create tables if needed
            if self.config.create_tables:
                await self.create_tables()

            self._initialized = True
            logger.info("Database initialization completed successfully")

        except Exception as e:
            logger.error("Database initialization failed", error=str(e))
            raise TSAFException(f"Database initialization failed: {str(e)}")

    def _get_connect_args(self) -> dict:
        """Get database-specific connection arguments."""
        connect_args = {}

        if "sqlite" in self.config.database_url:
            connect_args["check_same_thread"] = False

        if "postgresql" in self.config.database_url:
            connect_args.update({
                "server_settings": {
                    "jit": "off",  # Disable JIT for better performance in some cases
                }
            })

        return connect_args

    async def _test_async_connection(self) -> None:
        """Test async database connection."""
        try:
            async with self._async_engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            logger.debug("Async database connection test successful")
        except Exception as e:
            logger.error("Async database connection test failed", error=str(e))
            raise

    async def _test_sync_connection(self) -> None:
        """Test sync database connection."""
        try:
            def test_sync():
                with self._sync_engine.begin() as conn:
                    conn.execute(text("SELECT 1"))

            await asyncio.get_event_loop().run_in_executor(None, test_sync)
            logger.debug("Sync database connection test successful")
        except Exception as e:
            logger.error("Sync database connection test failed", error=str(e))
            raise

    async def create_tables(self) -> None:
        """Create database tables."""
        logger.info("Creating database tables")

        try:
            def create_tables_sync():
                Base.metadata.create_all(self._sync_engine)

            await asyncio.get_event_loop().run_in_executor(None, create_tables_sync)
            logger.info("Database tables created successfully")

        except Exception as e:
            logger.error("Failed to create database tables", error=str(e))
            raise TSAFException(f"Failed to create database tables: {str(e)}")

    async def drop_tables(self) -> None:
        """Drop all database tables."""
        logger.warning("Dropping all database tables")

        try:
            def drop_tables_sync():
                Base.metadata.drop_all(self._sync_engine)

            await asyncio.get_event_loop().run_in_executor(None, drop_tables_sync)
            logger.warning("All database tables dropped")

        except Exception as e:
            logger.error("Failed to drop database tables", error=str(e))
            raise TSAFException(f"Failed to drop database tables: {str(e)}")

    @asynccontextmanager
    async def get_async_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get async database session context manager.

        Usage:
            async with db_manager.get_async_session() as session:
                # Use session
                pass
        """
        if not self._initialized:
            raise TSAFException("Database not initialized")

        async with self._async_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    @asynccontextmanager
    async def get_sync_session(self):
        """
        Get sync database session context manager.

        Usage:
            async with db_manager.get_sync_session() as session:
                # Use session
                pass
        """
        if not self._initialized:
            raise TSAFException("Database not initialized")

        def get_session():
            return self._sync_session_factory()

        session = await asyncio.get_event_loop().run_in_executor(None, get_session)
        try:
            yield session
            await asyncio.get_event_loop().run_in_executor(None, session.commit)
        except Exception:
            await asyncio.get_event_loop().run_in_executor(None, session.rollback)
            raise
        finally:
            await asyncio.get_event_loop().run_in_executor(None, session.close)

    async def execute_raw_async(self, query: str, parameters: Optional[dict] = None) -> any:
        """Execute raw SQL query asynchronously."""
        if not self._initialized:
            raise TSAFException("Database not initialized")

        async with self.get_async_session() as session:
            result = await session.execute(text(query), parameters or {})
            return result

    async def get_health_status(self) -> dict:
        """Get database health status."""
        try:
            start_time = asyncio.get_event_loop().time()

            # Test async connection
            async with self._async_engine.begin() as conn:
                await conn.execute(text("SELECT 1 as health_check"))

            response_time = (asyncio.get_event_loop().time() - start_time) * 1000

            # Get connection pool status
            pool = self._async_engine.pool
            pool_status = {
                "size": pool.size(),
                "checked_in": pool.checkedin(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
            }

            return {
                "status": "healthy",
                "response_time_ms": response_time,
                "pool_status": pool_status,
                "initialized": self._initialized
            }

        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return {
                "status": "unhealthy",
                "error": str(e)
            }

    async def get_metrics(self) -> dict:
        """Get database performance metrics."""
        try:
            metrics = {}

            if self._async_engine:
                pool = self._async_engine.pool
                metrics.update({
                    "pool_size": pool.size(),
                    "checked_in_connections": pool.checkedin(),
                    "checked_out_connections": pool.checkedout(),
                    "overflow_connections": pool.overflow(),
                    "total_connections": pool.size() + pool.overflow(),
                })

            # Get database-specific metrics
            async with self.get_async_session() as session:
                if "postgresql" in self.config.database_url:
                    result = await session.execute(text("""
                        SELECT
                            COUNT(*) as active_connections,
                            SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END) as active_queries
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                    """))
                    row = result.first()
                    if row:
                        metrics.update({
                            "active_connections": row.active_connections,
                            "active_queries": row.active_queries
                        })

            return metrics

        except Exception as e:
            logger.error("Failed to get database metrics", error=str(e))
            return {"error": str(e)}

    async def shutdown(self) -> None:
        """Shutdown database connections."""
        logger.info("Shutting down database connections")

        try:
            if self._async_engine:
                await self._async_engine.dispose()

            if self._sync_engine:
                await asyncio.get_event_loop().run_in_executor(
                    None, self._sync_engine.dispose
                )

            self._initialized = False
            logger.info("Database shutdown completed")

        except Exception as e:
            logger.error("Database shutdown failed", error=str(e))
            raise TSAFException(f"Database shutdown failed: {str(e)}")


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_database_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    global _db_manager
    if _db_manager is None:
        raise TSAFException("Database manager not initialized")
    return _db_manager


def initialize_database_manager(config: DatabaseConfig) -> DatabaseManager:
    """Initialize the global database manager."""
    global _db_manager
    _db_manager = DatabaseManager(config)
    return _db_manager


async def close_database_manager() -> None:
    """Close the global database manager."""
    global _db_manager
    if _db_manager:
        await _db_manager.shutdown()
        _db_manager = None