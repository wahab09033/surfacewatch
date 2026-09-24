"""Application configuration.

All settings are read from environment variables (or a local ``.env`` file).
See ``.env.example`` for the full list.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _dotenv_path() -> str | None:
    """Return ``.env`` only if this process can actually read it.

    Running in compose, ``backend/`` is bind-mounted into a container whose app
    user is uid 10001, while ``.env`` on the host is mode 600 owned by the
    developer's uid. The bind mount preserves host ownership, so opening it
    raises PermissionError and the process dies before it can report why —
    even though compose has already supplied every one of those settings as a
    real environment variable.

    Loosening the mode on a file holding JWT_SECRET and the database password
    is the wrong trade. Skipping an unreadable dotenv file is the right one:
    the environment wins either way, since env vars take precedence over
    dotenv values in pydantic-settings.
    """
    path = Path(".env")
    if not path.is_file():
        return None
    return ".env" if os.access(path, os.R_OK) else None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_dotenv_path(),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- General -----------------------------------------------------------
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    api_title: str = "SurfaceWatch API"
    api_version: str = "1.0.0"

    # --- Database ----------------------------------------------------------
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "surfacewatch"
    postgres_user: str = "surfacewatch"
    postgres_password: str = "surfacewatch"

    # API pool. Sized per process, so with API_WORKERS=2 and the defaults the
    # fleet can hold 2 x (10 + 20) = 60 connections; Postgres' own default
    # max_connections is 100 and the workers need some of it. Raising these
    # without raising max_connections turns load into "too many clients
    # already" rather than into more throughput.
    db_pool_size: int = 10
    db_max_overflow: int = 20
    # Celery workers and Alembic. Smaller because a worker's concurrency is
    # bound by --concurrency, not by the pool — a pool bigger than the number
    # of tasks that can run at once only holds idle connections open.
    db_worker_pool_size: int = 5
    db_worker_max_overflow: int = 10

    # Seconds a connection may sit idle before it is recycled. This is not
    # redundant with pool_pre_ping: pre_ping checks a connection is alive
    # *before* handing it out, which costs a round trip and still cannot save a
    # connection the server kills mid-query. What it protects against is a
    # connection that looks fine at checkout and is dropped while in use.
    #
    # 1800s is below the idle timeout of every managed Postgres worth naming
    # (RDS's default is unset but its proxy sits at 350s; Neon, Supabase and
    # most poolers close at 300–600s) and below the typical 350s idle timeout
    # of a cloud load balancer. Direct connections to a local Postgres never hit
    # it, and recycling costs one reconnect per connection per half hour.
    db_pool_recycle: int = 1800
    # How long a request waits for a free connection before failing. Without a
    # bound, exhausting the pool turns into requests that hang until the client
    # gives up, which looks like a dead API; with it, the request fails fast and
    # the 500 says PoolTimeout, which names the actual problem.
    db_pool_timeout: float = 30.0
    db_echo: bool = False

    # --- Redis / Celery ----------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # --- Auth --------------------------------------------------------------
    jwt_secret: str = "insecure-development-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 14
    bcrypt_rounds: int = 12

    # --- CORS --------------------------------------------------------------
    cors_origins: str = "http://localhost:3000"

    # --- Rate limiting -----------------------------------------------------
    # Ceilings on the unauthenticated endpoints. Defaults are generous enough
    # that a person fumbling a password never notices, and tight enough that
    # online guessing is not viable: 10 failures/15min against one account
    # allows roughly 960 guesses a day, against a keyspace where that is
    # nothing.
    rate_limit_enabled: bool = True
    rate_limit_window_seconds: int = 900  # 15 minutes
    rate_limit_login_per_ip: int = 30
    rate_limit_login_failures_per_account: int = 10
    rate_limit_register_per_ip: int = 5
    rate_limit_refresh_per_ip: int = 60
    # Each verification attempt triggers outbound DNS queries against a
    # user-supplied domain, so an unthrottled endpoint is a DNS amplification
    # vector pointed at third parties from our address. Keyed per organisation
    # rather than per IP: the caller is authenticated, so the org is the
    # accountable identity, and per-IP would let one org spread attempts across
    # a team's addresses.
    rate_limit_domain_verify_per_org: int = 20
    # Number of reverse proxies in front of the app whose X-Forwarded-For
    # entries can be trusted. 0 means the header is ignored entirely, which is
    # correct when the app is directly exposed — otherwise anyone can forge a
    # fresh client address per request and walk straight through the limiter.
    # Set to 1 behind a single load balancer, 2 behind an LB plus a CDN.
    trusted_proxy_count: int = 0

    # --- Password policy ---------------------------------------------------
    # The offline checks in core.passwords always run. This adds the Have I
    # Been Pwned range API on top, which is the only way to say "nobody else
    # has already chosen this" with any authority — no bundled list gets near
    # its ~850M entries. Off by default because it makes registration depend on
    # a third party; on is the better setting for a real deployment.
    password_hibp_check_enabled: bool = False
    password_hibp_timeout: float = 3.0
    # Appearances in the corpus before the password is refused. 1 is the strict
    # reading; a small allowance absorbs a strong passphrase that one other
    # person also happened to pick.
    password_hibp_max_appearances: int = 1

    # --- Security headers --------------------------------------------------
    # Only emitted when is_production. See core.security_headers for why
    # sending HSTS from a localhost dev server is a self-inflicted outage.
    hsts_max_age: int = 31_536_000  # 1 year

    # --- Scanning ----------------------------------------------------------
    allow_arbitrary_targets: bool = False
    scan_max_concurrency: int = 200
    scan_connect_timeout: float = 2.0
    scan_rate_limit_per_host: int = 50
    http_user_agent: str = "SurfaceWatch/1.0 (+https://surfacewatch.local/scanner)"

    # Concurrent QUEUED/RUNNING scans one organisation may hold. A ceiling
    # rather than a queue: scans are long and hold sockets, so letting one org
    # enqueue fifty starves every other tenant on the same workers.
    #
    # Lives here rather than as a constant in routes.scans because the scheduled
    # scan dispatcher in workers.scheduler enforces the same limit, and a worker
    # importing from a routes module would be wrong-direction coupling.
    max_concurrent_scans_per_org: int = 5

    # --- Domain verification ------------------------------------------------
    # Scanning authority comes only from a domain proven via DNS TXT. See
    # core.dns_verify and models.DomainVerification.
    #
    # The cap is a blast-radius limit on a public-registration deployment: each
    # verified domain authorises every subdomain under it, and each pending claim
    # is a row anyone who registers can create.
    max_verified_domains_per_org: int = 25

    # --- Scheduled scans ----------------------------------------------------
    # Recurring scans live in scan_schedules; workers.scheduler fires them.
    #
    # How many dispatches in a row may fail before the schedule switches itself
    # off. Failures here are broker failures, not scan failures — a scan that
    # runs and finds nothing is a success. Retrying forever would mean a tenant
    # whose schedule cannot queue wakes up to a disabled schedule with no
    # explanation, so the reason is written to disabled_reason and shown.
    schedule_max_consecutive_failures: int = 5

    # Re-run the DNS challenge for already-verified domains, weekly.
    #
    # Off by default, and deliberately so: revocation is the one action here
    # that *removes* a customer's ability to scan. A DNS provider outage, a
    # resolver problem on our side, or a temporary nameserver change all look
    # identical to a domain that has changed hands, and the cost of being wrong
    # is an outage the customer did not cause and cannot immediately fix.
    domain_reverify_enabled: bool = True
    # How many checks in a row must fail before a domain is revoked. 0 means
    # never revoke automatically, which is the default.
    #
    # Checking is always safe — it only updates last_checked_at and
    # consecutive_failures, both of which the settings UI shows. Revoking is
    # not: it takes away a customer's ability to scan, and every cause we can
    # actually observe from here (a DNS provider outage, a resolver failure on
    # our side, a nameserver move that has not propagated) is indistinguishable
    # from a domain that genuinely changed hands. So the sweep reports, and a
    # human decides. Raise this only where an unverified domain left scannable
    # is the larger risk.
    domain_reverify_failure_threshold: int = 0

    # --- Retention ----------------------------------------------------------
    # Log lines are the highest-volume, lowest-value rows in the schema: one
    # per progress message, per scan, forever. Kept for a month because that is
    # how far back anyone reads a scan log; a failed scan from six weeks ago is
    # diagnosed from its findings, not its stdout.
    retention_scan_log_days: int = 30

    # Whole scans, with their findings and assets. 0 disables the sweep.
    #
    # Off by default and it should stay off unless you have decided otherwise:
    # findings cascade with their scan, so enabling this deletes the security
    # history the product exists to keep. It is here for deployments with a
    # contractual data-retention limit, where the alternative is a manual job
    # somebody forgets to run.
    retention_scan_days: int = 0

    # Generated PDF/HTML reports. 0 disables. Deleting a Report row is not
    # enough — the file on disk outlives it, so the sweep unlinks first and
    # only then deletes the row, or a failed unlink leaves an orphan with no
    # record that it exists.
    retention_report_days: int = 0

    # --- CVE enrichment ----------------------------------------------------
    nvd_api_key: str = ""
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_cache_ttl_seconds: int = 86_400

    # --- AI remediation ----------------------------------------------------
    # Generic "upgrade to a patched version" advice is what every scanner
    # already prints and what an engineer already knows. The value here is
    # advice grounded in *this* host's stack — the reverse proxy in front of it,
    # the ports actually exposed, the version actually running. That needs a
    # model call per finding, so it is off unless a key is present.
    #
    # Deliberately NOT named ANTHROPIC_API_KEY / ANTHROPIC_MODEL. Those are the
    # SDK's own conventional variable names and are very often already exported
    # in a developer shell or CI runner for something unrelated — Claude Code
    # exports both, for instance. With case_sensitive=False, pydantic-settings
    # would bind them, and the failure is silent in the worst direction: the
    # feature switches itself on and bills a key nobody meant to point at this
    # app, or quietly runs a different model than the one configured here.
    # The AI_REMEDIATION_ prefix cannot collide with anything.
    ai_remediation_api_key: str = ""
    # Sonnet rather than Opus: this is a bounded grounding-and-summarising task
    # over facts we supply, not open-ended reasoning, and it runs once per
    # finding across a scan that can produce hundreds.
    ai_remediation_model: str = "claude-sonnet-5"
    ai_remediation_enabled: bool = True
    ai_remediation_max_tokens: int = 1_200
    ai_remediation_timeout: float = 45.0
    # Cap per scan. A large estate can generate thousands of findings, and an
    # unbounded fan-out turns one scan into an unbounded bill.
    ai_remediation_max_per_scan: int = 60
    # Same CVE against the same product/version yields the same advice, so the
    # cache is keyed on that rather than on the finding.
    ai_remediation_cache_ttl_seconds: int = 604_800  # 7 days

    # --- Notifications -----------------------------------------------------
    # Per-organisation webhooks live on the organisations row; these are the
    # transport-level knobs that apply to all of them.
    slack_notifications_enabled: bool = True
    slack_timeout_seconds: float = 10.0
    # Only these severities page anyone. Alerting on medium findings trains
    # people to ignore the channel, which costs more than the alert is worth.
    slack_min_severity: Literal["critical", "high", "medium", "low", "info"] = "critical"

    # --- Reports -----------------------------------------------------------
    report_output_dir: str = "/var/lib/surfacewatch/reports"

    # ----------------------------------------------------------------------
    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def _dsn_credentials(self) -> str:
        """``user:password`` with both percent-encoded.

        A generated Postgres password routinely contains @ / : / # / ?, every
        one of which is structural in a URL. Interpolated raw, an @ truncates
        the host and the driver connects somewhere else (or, on a good day,
        fails with an error naming a host that does not exist); a # silently
        discards the rest of the string. `quote` with an empty safe set is what
        keeps the credential opaque to the URL parser.
        """
        return f"{quote(self.postgres_user, safe='')}:{quote(self.postgres_password, safe='')}"

    @property
    def database_url(self) -> str:
        """Async URL used by the FastAPI application."""
        return (
            f"postgresql+asyncpg://{self._dsn_credentials}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_url(self) -> str:
        """Sync URL used by Celery workers and Alembic."""
        return (
            f"postgresql+psycopg://{self._dsn_credentials}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def ai_remediation_active(self) -> bool:
        """AI remediation runs only when it is both enabled and configured.

        Two conditions rather than one so the feature can be switched off for a
        run without unsetting the key, and so a missing key degrades to the
        template advice instead of raising on every finding.
        """
        return self.ai_remediation_enabled and bool(self.ai_remediation_api_key.strip())


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.is_production and "change-me" in settings.jwt_secret:
        raise RuntimeError("JWT_SECRET must be set to a real secret in production")
    return settings


settings = get_settings()
