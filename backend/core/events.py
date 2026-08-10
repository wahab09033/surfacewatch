"""Redis pub/sub contract for live scan output.

Workers publish to ``scan:{scan_id}:logs``; the WebSocket endpoint subscribes
to the same channel. Keeping the channel name and event envelope in one module
stops the two sides from drifting apart.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import redis
import redis.asyncio as aioredis

from config import settings

# --- Channel naming ---------------------------------------------------------


def scan_channel(scan_id: uuid.UUID | str) -> str:
    return f"scan:{scan_id}:logs"


def scan_history_key(scan_id: uuid.UUID | str) -> str:
    """Capped list mirroring the channel, so a late subscriber can catch up
    even if the DB write lags behind."""
    return f"scan:{scan_id}:history"


HISTORY_MAX_EVENTS = 2_000
HISTORY_TTL_SECONDS = 60 * 60 * 24  # keep replay data for a day


# --- Event envelopes --------------------------------------------------------


def log_event(
    scan_id: uuid.UUID | str,
    message: str,
    *,
    level: str = "info",
    stage: str | None = None,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    return {
        "type": "log",
        "scan_id": str(scan_id),
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "level": level,
        "stage": stage,
        "message": message,
    }


def status_event(
    scan_id: uuid.UUID | str,
    status: str,
    *,
    stage: str | None = None,
    progress: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "type": "status",
        "scan_id": str(scan_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "stage": stage,
        "progress": progress,
        **extra,
    }


def result_event(scan_id: uuid.UUID | str, kind: str, payload: Any) -> dict[str, Any]:
    """Structured mid-scan result (a discovered host, a new finding, ...)."""
    return {
        "type": "result",
        "scan_id": str(scan_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "payload": payload,
    }


# Sentinel telling subscribers no further events will arrive.
def terminal_event(scan_id: uuid.UUID | str, status: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "end",
        "scan_id": str(scan_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        **extra,
    }


# --- Sync publisher (Celery workers) ----------------------------------------

_sync_pool: redis.ConnectionPool | None = None


def sync_redis() -> redis.Redis:
    global _sync_pool
    if _sync_pool is None:
        _sync_pool = redis.ConnectionPool.from_url(
            settings.redis_url, decode_responses=True, max_connections=20
        )
    return redis.Redis(connection_pool=_sync_pool)


def publish(scan_id: uuid.UUID | str, event: dict[str, Any]) -> None:
    """Publish an event and append it to the replay list.

    Streaming is best-effort: a Redis hiccup must never fail the scan itself,
    since the authoritative log lives in Postgres.
    """
    payload = json.dumps(event, default=str)
    channel = scan_channel(scan_id)
    try:
        client = sync_redis()
        pipe = client.pipeline()
        pipe.publish(channel, payload)
        pipe.rpush(scan_history_key(scan_id), payload)
        pipe.ltrim(scan_history_key(scan_id), -HISTORY_MAX_EVENTS, -1)
        pipe.expire(scan_history_key(scan_id), HISTORY_TTL_SECONDS)
        pipe.execute()
    except redis.RedisError:
        pass


# --- Async subscriber (WebSocket endpoint) ----------------------------------

_async_client: aioredis.Redis | None = None


def async_redis() -> aioredis.Redis:
    global _async_client
    if _async_client is None:
        _async_client = aioredis.from_url(
            settings.redis_url, decode_responses=True, max_connections=50
        )
    return _async_client


async def close_async_redis() -> None:
    global _async_client
    if _async_client is not None:
        await _async_client.aclose()
        _async_client = None


async def read_history(scan_id: uuid.UUID | str, limit: int = 500) -> list[dict[str, Any]]:
    """Replay recent events for a client that connected mid-scan."""
    try:
        raw = await async_redis().lrange(scan_history_key(scan_id), -limit, -1)
    except Exception:
        return []
    events: list[dict[str, Any]] = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except json.JSONDecodeError:
            continue
    return events


__all__ = [
    "async_redis",
    "close_async_redis",
    "log_event",
    "publish",
    "read_history",
    "result_event",
    "scan_channel",
    "scan_history_key",
    "status_event",
    "sync_redis",
    "terminal_event",
]
