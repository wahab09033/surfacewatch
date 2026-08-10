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
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)

SyncSessionLocal = sessionmaker(bind=sync_engine, expire_on_commit=False, autoflush=False)


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
