"""Database engines and session factories.

The API talks to Postgres over asyncpg; Celery workers and Alembic use the
synchronous psycopg driver. Both share the same declarative ``Base`` so the
ORM models are defined exactly once.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import settings

# --- Declarative base -------------------------------------------------------


class Base(DeclarativeBase):
    """Shared declarative base for every ORM model."""


# --- Async (FastAPI) --------------------------------------------------------

async_engine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_timeout=settings.db_pool_timeout,
    pool_recycle=settings.db_pool_recycle,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an async session with rollback-on-error."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


# --- Sync (Celery workers, Alembic) ----------------------------------------

sync_engine = create_engine(
    settings.sync_database_url,
    echo=settings.db_echo,
    pool_size=settings.db_worker_pool_size,
    max_overflow=settings.db_worker_max_overflow,
    pool_timeout=settings.db_pool_timeout,
    pool_recycle=settings.db_pool_recycle,
    pool_pre_ping=True,
)

SyncSessionLocal = sessionmaker(bind=sync_engine, expire_on_commit=False, autoflush=False)


def dispose_inherited_pools() -> None:
    """Drop pool connections inherited across a fork.

    Celery's default prefork pool imports this module in the parent, forks its
    children, and only then starts running tasks. Every child therefore begins
    life holding *the same* open sockets the parent has in its pool — two
    processes, one TCP connection each believes it owns exclusively. The first
    time both use it the Postgres wire protocol desynchronises, and the symptom
    is not a clean error but a task that reads another task's result set or
    fails with an unexplained "connection already closed" hours later.

    ``close=False`` is the important argument: the child must forget the
    inherited handles without closing them, because closing sends a Terminate
    down a socket the parent is still using and takes the parent's connection
    with it. The child builds a fresh pool on first use.

    Called from the worker_process_init signal in workers.celery_app. Uvicorn
    runs a single process by default here (see the compose command) so the API
    has no equivalent need; it would want the same call if it were ever run
    with --workers > 1.
    """
    sync_engine.dispose(close=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for worker code: commits on success, rolls back on error."""
    session = SyncSessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
