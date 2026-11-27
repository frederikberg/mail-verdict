"""
Database connection management.

Async engine, session factory, and pool configuration.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, AsyncIterator

from sqlalchemy import NullPool, text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

if TYPE_CHECKING:
    from mail_verdict.config import DatabaseConfig

logger = logging.getLogger(__name__)


class DatabaseConnection:
    """
    Manages async database connections.

    Provides session factory and lifecycle management.
    """

    def __init__(self, config: DatabaseConfig) -> None:
        """
        Initialize database connection.

        Args:
            config: Database configuration with URL and pool settings
        """
        self._config = config
        self._engine: AsyncEngine | None = None
        self._lock_engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    @property
    def engine(self) -> AsyncEngine:
        """Get the async engine, raising if not initialized."""
        if self._engine is None:
            raise RuntimeError("Database not initialized. Call init() first.")
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Get the session factory."""
        if self._session_factory is None:
            raise RuntimeError("Database not initialized. Call init() first.")
        return self._session_factory

    @property
    def pool_capacity(self) -> int:
        """Maximum sessions this connection can hand out at once.

        `pool_size + max_overflow` -- the real ceiling on how many workers
        can hold a session concurrently, independent of whatever a caller
        asks a queue's concurrency setting to be.
        """
        return self._config.pool_size + self._config.max_overflow

    async def init(self) -> None:
        """Initialize the database engine and session factory."""
        self._engine = create_async_engine(
            self._config.url,
            echo=False,
            pool_size=self._config.pool_size,
            max_overflow=self._config.max_overflow,
            pool_pre_ping=True,
        )
        # Session-level advisory locks (queue/notify.py) are held for as long
        # as their connection is open. Taking them from the pool above would
        # let the many timers that fire together at startup hold every
        # pooled connection, leaving their own callbacks and the requests
        # with none. These connections stay out of the pool and last as long
        # as the lock does.
        self._lock_engine = create_async_engine(self._config.url, echo=False, poolclass=NullPool)
        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        url_safe = self._config.url.split("@")[-1] if "@" in self._config.url else "***"
        logger.info("Database initialized", extra={"url": url_safe})

    async def close(self) -> None:
        """Close the database connection and dispose of the pool."""
        if self._lock_engine:
            await self._lock_engine.dispose()
            self._lock_engine = None
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
            logger.info("Database connection closed")

    @asynccontextmanager
    async def lock_connection(self) -> AsyncIterator[AsyncConnection]:
        """
        A connection outside the pool, for holding a session-level advisory
        lock across a long piece of work. Closed on exit, which also
        releases any lock still held on it.
        """
        if self._lock_engine is None:
            raise RuntimeError("Database not initialized. Call init() first.")
        async with self._lock_engine.connect() as conn:
            yield conn

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """
        Get an async session context manager.

        Commits on success, rolls back on exception.

        Yields:
            AsyncSession for database operations
        """
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    @asynccontextmanager
    async def session_or(self, existing: AsyncSession | None) -> AsyncIterator[AsyncSession]:
        """Reuse `existing` if given, otherwise open (and commit) a fresh
        session -- lets a caller collapse several repository calls onto one
        session it already holds, without every repository method needing
        two separate code paths of its own."""
        if existing is not None:
            yield existing
        else:
            async with self.session() as session:
                yield session

    async def health_check(self) -> bool:
        """
        Check database connectivity.

        Returns:
            True if database is reachable, False otherwise
        """
        try:
            async with self.session() as session:
                await session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.warning("Database health check failed", extra={"error": str(e)})
            return False


_db_connection: DatabaseConnection | None = None


def get_db_connection() -> DatabaseConnection:
    """
    Get the global database connection.

    Raises:
        RuntimeError: If database not initialized
    """
    if _db_connection is None:
        raise RuntimeError("Database not initialized")
    return _db_connection


async def init_database(config: DatabaseConfig) -> DatabaseConnection:
    """
    Initialize the global database connection.

    Args:
        config: Database configuration

    Returns:
        Initialized DatabaseConnection
    """
    global _db_connection
    _db_connection = DatabaseConnection(config)
    await _db_connection.init()
    return _db_connection


async def close_database() -> None:
    """Close the global database connection."""
    global _db_connection
    if _db_connection:
        await _db_connection.close()
        _db_connection = None
