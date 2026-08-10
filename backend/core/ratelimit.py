"""Redis-backed rate limiting for the authentication endpoints.

Without this, ``POST /api/auth/login`` will answer as fast as an attacker can
ask. That is the whole precondition for credential stuffing (many passwords
against one account) and password spraying (one common password against many
accounts), and neither is theoretical against an internet-facing security tool.

Three decisions here are load-bearing:

**Two dimensions, not one.** A per-IP limit alone is defeated by a botnet
spreading attempts across thousands of addresses; a per-account limit alone is
defeated by spraying one password across thousands of accounts. Both are
enforced, so an attacker has to stay under both ceilings at once.

**Failure counters key on the submitted email, existing or not.** Counting only
real accounts would turn the lockout into exactly the enumeration oracle that
``/login`` and ``/register`` go out of their way to avoid: "this address got
throttled, therefore it exists". An unknown address consumes budget identically.

**Fail open when Redis is down.** A rate limiter that fails closed converts a
cache outage into a total authentication outage — it hands an attacker a much
cheaper denial of service than the one it prevents. Redis errors are logged and
the request proceeds; ``/health/ready`` already reports Redis as degraded.

Fixed windows rather than a sliding log: an attacker can burst across a window
boundary and briefly get 2x the nominal rate, which for a threshold measured in
tens of attempts is not the difference between safe and unsafe, and the counter
costs one INCR instead of a sorted set per client.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from config import settings
from core import events

logger = logging.getLogger(__name__)

__all__ = [
    "RateLimit",
    "RateLimitRule",
    "account_identity",
    "assert_under",
    "clear_failures",
    "client_ip",
    "enforce",
    "record_failure",
]


@dataclass(frozen=True)
class RateLimitRule:
    """One ceiling: ``limit`` events per ``window`` seconds, under ``bucket``."""

    bucket: str
    limit: int
    window: int


def client_ip(request: Request) -> str:
    """The caller's address, honouring X-Forwarded-For only when it is trustworthy.

    Trusting the header unconditionally is the standard way to render a rate
    limiter useless: an attacker sets ``X-Forwarded-For: <random>`` per request
    and every attempt lands in its own bucket. Trusting it never is also wrong
    once there is a load balancer in front, because then every request appears
    to come from the proxy and one noisy tenant throttles everyone.

    So it is opt-in via ``TRUSTED_PROXY_COUNT``: with N trusted hops, the client
    is the Nth entry from the right — the last value the outermost proxy we
    control appended, and the first one the client could not have forged.
    """
    hops = settings.trusted_proxy_count
    if hops > 0:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if parts:
                index = len(parts) - hops
                # A chain shorter than configured means the request did not come
                # through the expected proxies. Take the leftmost value rather
                # than indexing off the front of the list.
                return parts[index] if 0 <= index < len(parts) else parts[0]
    return request.client.host if request.client else "unknown"


def _hash(value: str) -> str:
    """Key material for Redis, so raw emails do not sit in keyspace dumps.

    Not a security boundary — the space of email addresses is guessable — but
    ``KEYS *``, slow-log entries and metrics exporters all surface key names,
    and none of those are places user identifiers belong.
    """
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()[:32]


def _key(rule: RateLimitRule, identity: str) -> str:
    return f"ratelimit:{rule.bucket}:{identity}"


async def _incr(key: str, window: int) -> int | None:
    """Increment a fixed-window counter. Returns None when Redis is unavailable."""
    try:
        client = events.async_redis()
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = await pipe.execute()
        # A fresh key has no expiry yet, and a key whose TTL was somehow lost
        # would otherwise count forever. Both are repaired the same way.
        if ttl is None or ttl < 0:
            await client.expire(key, window)
        return int(count)
    except Exception:
        logger.warning("rate limiter unavailable; allowing request", exc_info=True)
        return None


async def _peek(key: str) -> tuple[int, int]:
    """Current count and seconds remaining, without consuming budget."""
    try:
        client = events.async_redis()
        pipe = client.pipeline()
        pipe.get(key)
        pipe.ttl(key)
        raw, ttl = await pipe.execute()
        return int(raw or 0), max(int(ttl or 0), 0)
    except Exception:
        logger.warning("rate limiter unavailable; allowing request", exc_info=True)
        return 0, 0


def _too_many(retry_after: int) -> HTTPException:
    """The 429 every path returns.

    One message for every rule, deliberately. If the per-account ceiling said
    something different from the per-IP ceiling, the difference would be the
    enumeration signal the counters were designed not to emit.
    """
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many attempts. Please wait and try again.",
        headers={"Retry-After": str(max(retry_after, 1))},
    )


async def enforce(rule: RateLimitRule, identity: str) -> None:
    """Consume one unit of budget for ``identity``; raise 429 when it is spent."""
    if not settings.rate_limit_enabled:
        return

    key = _key(rule, identity)
    count = await _incr(key, rule.window)
    if count is None or count <= rule.limit:
        return

    _, ttl = await _peek(key)
    logger.warning(
        "rate limit exceeded: bucket=%s count=%d limit=%d", rule.bucket, count, rule.limit
    )
    raise _too_many(ttl or rule.window)


async def assert_under(rule: RateLimitRule, identity: str) -> None:
    """Raise 429 if ``identity`` is already over budget, without consuming any.

    Separate from ``enforce`` because failure counters are only incremented on
    an actual failure — a user typing the right password on their sixth attempt
    should succeed, not be charged for the check.
    """
    if not settings.rate_limit_enabled:
        return

    key = _key(rule, identity)
    count, ttl = await _peek(key)
    if count > rule.limit:
        logger.warning(
            "locked out: bucket=%s count=%d limit=%d", rule.bucket, count, rule.limit
        )
        raise _too_many(ttl or rule.window)


async def record_failure(rule: RateLimitRule, identity: str) -> None:
    """Charge one failed attempt against ``identity``."""
    if not settings.rate_limit_enabled:
        return
    await _incr(_key(rule, identity), rule.window)


async def clear_failures(rule: RateLimitRule, identity: str) -> None:
    """Reset a failure counter after a legitimate success."""
    if not settings.rate_limit_enabled:
        return
    try:
        await events.async_redis().delete(_key(rule, identity))
    except Exception:
        logger.warning("could not clear rate limit counter", exc_info=True)


# --- Rules ------------------------------------------------------------------
#
# Failure ceilings are what an attacker hits; the per-IP request ceilings
# alongside them stop someone from burning through those failures in one second.
# Thresholds come from settings so a deployment behind a corporate NAT (where
# hundreds of real users share one address) can raise them without a code change.

_WINDOW = settings.rate_limit_window_seconds

LOGIN_IP = RateLimitRule("login:ip", settings.rate_limit_login_per_ip, _WINDOW)
LOGIN_ACCOUNT = RateLimitRule(
    "login:account", settings.rate_limit_login_failures_per_account, _WINDOW
)
REGISTER_IP = RateLimitRule("register:ip", settings.rate_limit_register_per_ip, _WINDOW)
REFRESH_IP = RateLimitRule("refresh:ip", settings.rate_limit_refresh_per_ip, _WINDOW)
PASSWORD_USER = RateLimitRule(
    "password:user", settings.rate_limit_login_failures_per_account, _WINDOW
)


# --- FastAPI plumbing -------------------------------------------------------


def RateLimit(rule: RateLimitRule):  # noqa: N802 — used like a dependency class
    """Dependency enforcing a per-IP ceiling on one endpoint."""

    async def dependency(request: Request) -> None:
        await enforce(rule, client_ip(request))

    return dependency


def account_identity(email: str) -> str:
    """Bucket key for one login identity. Hashed; see ``_hash``."""
    return _hash(email)
