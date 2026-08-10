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
    db_pool_size: int = 10
    db_max_overflow: int = 20
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
