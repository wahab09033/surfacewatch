"""SurfaceWatch API.

Run with:  uvicorn main:app --reload
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import redis.exceptions
from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select, text

from config import settings
from core.deps import authenticate_websocket
from core.events import async_redis, close_async_redis, read_history, scan_channel
from core.security_headers import SecurityHeadersMiddleware
from db.database import AsyncSessionLocal, async_engine
from models import Scan
from routes import assets, auth, findings, reports, scans

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("surfacewatch")

# WebSocket close codes (RFC 6455 private range).
WS_UNAUTHORIZED = 4401
WS_FORBIDDEN = 4403
WS_NOT_FOUND = 4404


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("SurfaceWatch API starting (environment=%s)", settings.environment)
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Database connection established")
    except Exception:
        # Do not abort startup: the container should come up and report
        # unhealthy rather than crash-loop while Postgres is still booting.
        logger.exception("Database unreachable at startup")

    yield

    await close_async_redis()
    await async_engine.dispose()
    logger.info("SurfaceWatch API stopped")


app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description=(
        "Attack Surface Management API. Every endpoint is scoped to the "
        "authenticated user's organisation."
    ),
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Added after CORS, so it runs *outside* it. add_middleware prepends, and the
# outermost layer is the last to touch the response — which means these headers
# land on CORS preflight replies and on responses CORS rejects too.
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(assets.router)
app.include_router(findings.router)
app.include_router(reports.router)


# --- Health -----------------------------------------------------------------


@app.get("/health", tags=["system"], summary="Liveness probe")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": settings.api_version}


@app.get("/health/ready", tags=["system"], summary="Readiness probe")
async def readiness() -> JSONResponse:
    """Reports dependency health; returns 503 if anything the API needs is down."""
    checks: dict[str, str] = {}

    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {type(exc).__name__}"

    try:
        await async_redis().ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {type(exc).__name__}"

    healthy = all(v == "ok" for v in checks.values())
    return JSONResponse(
        content={"status": "ready" if healthy else "degraded", "checks": checks},
        status_code=200 if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
    )


# --- WebSocket: live scan log stream ----------------------------------------


@app.websocket("/ws/scan/{scan_id}")
async def scan_log_stream(
    websocket: WebSocket,
    scan_id: uuid.UUID,
    token: str | None = Query(default=None, description="JWT access token"),
    replay: int = Query(default=200, ge=0, le=2000, description="Historical events to replay"),
) -> None:
    """Stream a scan's log lines in real time.

    The browser WebSocket API cannot set an Authorization header, so the access
    token arrives as a query parameter. It is validated exactly like an HTTP
    request, and the scan is then checked against the caller's organisation —
    a scan belonging to another tenant is indistinguishable from one that does
    not exist.
    """
    user = await authenticate_websocket(token)
    if user is None:
        await websocket.close(code=WS_UNAUTHORIZED, reason="Invalid or missing token")
        return

    async with AsyncSessionLocal() as db:
        scan = await db.scalar(
            select(Scan).where(Scan.id == scan_id, Scan.org_id == user.org_id)
        )
        if scan is None:
            await websocket.close(code=WS_NOT_FOUND, reason="Scan not found")
            return
        already_finished = scan.status.is_terminal
        snapshot = {
            "type": "snapshot",
            "scan_id": str(scan.id),
            "status": scan.status.value,
            "target": scan.target,
            "stage": scan.current_stage,
            "progress": scan.progress,
            "assets_discovered": scan.assets_discovered,
            "findings_count": scan.findings_count,
        }

    await websocket.accept()
    channel = scan_channel(scan_id)
    pubsub = None

    try:
        await websocket.send_json(snapshot)

        # Subscribe *before* replaying history so events emitted during replay
        # are buffered by Redis rather than lost in the gap.
        pubsub = async_redis().pubsub(ignore_subscribe_messages=True)
        await pubsub.subscribe(channel)

        if replay:
            for event in await read_history(scan_id, limit=replay):
                await websocket.send_json(event)

        if already_finished:
            # Nothing more will be published; let the client close cleanly.
            await websocket.send_json(
                {"type": "end", "scan_id": str(scan_id), "status": snapshot["status"]}
            )
            return

        while True:
            try:
                message = await asyncio.wait_for(
                    pubsub.get_message(timeout=1.0), timeout=30.0
                )
            except asyncio.TimeoutError:
                # No traffic for 30s — ping so dead peers and idle proxies are
                # detected instead of hanging the connection open forever.
                await websocket.send_json({"type": "ping"})
                continue

            if message is None:
                continue

            data = message.get("data")
            if not data:
                continue

            try:
                event: dict[str, Any] = json.loads(data)
            except json.JSONDecodeError:
                logger.warning("dropping malformed event on %s", channel)
                continue

            await websocket.send_json(event)

            if event.get("type") == "end":
                break

    except WebSocketDisconnect:
        logger.debug("client disconnected from %s", channel)
    except redis.exceptions.RedisError:
        logger.exception("redis error while streaming %s", channel)
        try:
            await websocket.send_json(
                {"type": "error", "message": "Live stream interrupted; reload to resume"}
            )
        except Exception:
            pass
    except Exception:
        logger.exception("unexpected error streaming %s", channel)
    finally:
        if pubsub is not None:
            try:
                await pubsub.unsubscribe(channel)
                await pubsub.aclose()
            except Exception:
                pass
        # Close explicitly rather than leaving it to the framework, so a client
        # that has been sent the terminal "end" event sees the socket shut with
        # a normal close code instead of waiting on a half-open connection.
        try:
            await websocket.close()
        except Exception:
            pass


# --- Error handling ---------------------------------------------------------


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Log the detail, return a generic message.

    Stack traces and driver errors can disclose schema and infrastructure, so
    they stay in the logs.
    """
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


@app.get("/", tags=["system"], include_in_schema=False)
async def root() -> dict[str, str]:
    return {
        "name": settings.api_title,
        "version": settings.api_version,
        "docs": "/docs" if not settings.is_production else "disabled",
    }
