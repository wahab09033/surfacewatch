"""Test harness: real Postgres, in-process Redis, no live Celery broker.

The database is real because the isolation guarantees under test are enforced
in SQL. Redis and Celery are faked so the suite needs no external services:
tests assert on API behaviour, not on scan results.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

# Must be set before config/settings is imported anywhere.
os.environ.setdefault("JWT_SECRET", "test-only-secret-key-not-for-production-1234567890")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("POSTGRES_HOST", "127.0.0.1")
os.environ.setdefault("POSTGRES_PORT", "55432")
os.environ.setdefault("POSTGRES_DB", "surfacewatch_test")
os.environ.setdefault("POSTGRES_USER", "postgres")
os.environ.setdefault("POSTGRES_PASSWORD", "postgres")
os.environ.setdefault("ALLOW_ARBITRARY_TARGETS", "true")


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def _fake_redis():
    """Route every Redis client at a single in-process fake.

    core.events builds its clients via redis.ConnectionPool.from_url (sync) and
    redis.asyncio.from_url (async), and caches both in module globals. Patching
    Redis.from_url alone would miss them, so the factories themselves are
    replaced and the cached globals cleared.
    """
    import fakeredis
    import fakeredis.aioredis

    from core import events

    server = fakeredis.FakeServer()

    events._sync_pool = None
    events._async_client = None

    def _sync_redis():
        return fakeredis.FakeRedis(server=server, decode_responses=True)

    def _async_redis():
        # Deliberately NOT cached. The real implementation memoises its client,
        # which is right in production (one long-lived loop) but wrong here:
        # TestClient runs each test in a fresh event loop, and a fakeredis
        # client bound to a closed loop raises "Event loop is closed". All
        # instances share one FakeServer, so state is still consistent.
        return fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)

    orig_sync, orig_async = events.sync_redis, events.async_redis
    events.sync_redis = _sync_redis
    events.async_redis = _async_redis

    # main.py imported async_redis by name at import time, so rebind its copy.
    import main

    main.async_redis = _async_redis

    try:
        yield server
    finally:
        events.sync_redis, events.async_redis = orig_sync, orig_async
        events._async_client = None


@pytest.fixture(scope="session", autouse=True)
def _eager_celery(_fake_redis):
    """Run tasks inline and swallow failures.

    Without this, POST /api/scans would enqueue to a broker nobody is draining
    and the request would appear to succeed while the scan never moved. Eager
    mode keeps the API contract honest without doing real network scanning.
    """
    from workers.celery_app import celery_app

    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = False
    yield


@pytest.fixture(scope="session", autouse=True)
def _null_pool():
    """Stop the app's async engine from reusing connections across event loops.

    Each test gets a fresh event loop, but the engine in db.database is created
    once at import time. A pooled asyncpg connection opened under one loop and
    reused under another raises "attached to a different loop" / "Event loop is
    closed". NullPool opens and closes per checkout: slower, but correct here.
    Production keeps its real pool.

    Several modules do `from db.database import AsyncSessionLocal` at import
    time, so they hold their own references. Every one of those has to be
    rebound or it keeps using the original pooled engine.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    import db
    from config import get_settings
    from db import database

    settings = get_settings()
    original = database.async_engine

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    session_local = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

    database.async_engine = engine
    database.AsyncSessionLocal = session_local

    import core.deps
    import main

    for module in (db, core.deps, main):
        if hasattr(module, "AsyncSessionLocal"):
            module.AsyncSessionLocal = session_local
        if hasattr(module, "async_engine"):
            module.async_engine = engine

    # Drop the original engine's pool so it cannot leak a connection into a
    # later test's event loop during garbage collection.
    original.sync_engine.pool.dispose()

    yield engine


@pytest.fixture(scope="session", autouse=True)
def _schema(_fake_redis):
    """Create the test database from the models, once per session."""
    import sqlalchemy as sa

    import models  # noqa: F401  (registers every table on Base.metadata)
    from config import get_settings
    from db.database import Base

    settings = get_settings()
    admin_url = settings.sync_database_url.rsplit("/", 1)[0] + "/postgres"

    admin = sa.create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{settings.postgres_db}" WITH (FORCE)'))
        conn.execute(sa.text(f'CREATE DATABASE "{settings.postgres_db}"'))
    admin.dispose()

    engine = sa.create_engine(settings.sync_database_url)
    Base.metadata.create_all(engine)
    engine.dispose()
    yield


@pytest.fixture(autouse=True)
def _clean_redis(_fake_redis):
    """Reset Redis between tests, for the same reason the tables are truncated.

    The FakeServer is session-scoped while the database truncates per test, so
    without this the rate-limit counters accumulate across the whole run: the
    sixth test to call /register trips the per-IP registration cap and fails
    with a 429 that has nothing to do with what it was testing. Restoring
    ``connected`` on both sides also stops a test that simulates a Redis outage
    from leaving the rest of the suite talking to a dead server.
    """
    import fakeredis

    _fake_redis.connected = True
    fakeredis.FakeRedis(server=_fake_redis, decode_responses=True).flushall()
    yield
    _fake_redis.connected = True


@pytest.fixture(autouse=True)
def _clean_tables(_schema):
    """Truncate between tests so each one starts from an empty tenant space.

    Sync on purpose: it uses a sync engine, and making it async would attach an
    extra event loop to tests that drive the app through TestClient's own loop.
    """
    import sqlalchemy as sa

    from config import get_settings
    from db.database import Base

    settings = get_settings()
    engine = sa.create_engine(settings.sync_database_url)
    tables = ", ".join(f'"{t.name}"' for t in reversed(Base.metadata.sorted_tables))
    with engine.begin() as conn:
        conn.execute(sa.text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    engine.dispose()
    yield


@pytest.fixture
async def client(_clean_tables):
    """An httpx client wired straight to the ASGI app (no socket needed)."""
    import httpx

    from main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as ac:
        yield ac
