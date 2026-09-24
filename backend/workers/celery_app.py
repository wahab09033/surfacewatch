"""Celery application.

Each scan module is a separate task so it can be retried, rate-limited and
scaled independently. The orchestrator chains them per scan.
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from celery.signals import setup_logging, worker_process_init

from config import settings

# Imported for its side effect, not its names. core.request_context installs a
# logging record factory, and the format string below interpolates
# %(request_id)s. Without the import every record reaching that formatter is
# missing the attribute, logging swallows the resulting error and prints
# "--- Logging error ---" instead of the line — the worker would run correctly
# and appear to log nothing at all. The API is covered because main.py imports
# it directly; the worker has no path to it otherwise.
from core import request_context  # noqa: F401

celery_app = Celery(
    "surfacewatch",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "workers.orchestrator",
        "workers.subdomain_enum",
        "workers.port_scanner",
        "workers.fingerprinter",
        "workers.cve_correlator",
        "workers.ai_remediation",
        "workers.change_detector",
        "workers.report_builder",
        "workers.notifier",
        "workers.scheduler",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Workers hold long-running network scans; prefetching more than one would
    # leave tasks queued behind a slow scan on an otherwise idle worker.
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
    result_expires=60 * 60 * 24,
    # A scan that has not finished in an hour is stuck; kill it rather than
    # letting it hold a worker slot forever.
    task_soft_time_limit=3_300,
    task_time_limit=3_600,
    broker_transport_options={"visibility_timeout": 3_600},
    task_routes={
        # Network-bound scanning work is isolated from report rendering, which
        # is CPU/memory heavy (WeasyPrint) and would otherwise stall scans.
        "workers.orchestrator.*": {"queue": "scans"},
        "workers.subdomain_enum.*": {"queue": "scans"},
        "workers.port_scanner.*": {"queue": "scans"},
        "workers.fingerprinter.*": {"queue": "scans"},
        "workers.cve_correlator.*": {"queue": "enrich"},
        # Model calls sit alongside NVD lookups: both are slow, external, and
        # tolerant of being retried later.
        "workers.ai_remediation.*": {"queue": "enrich"},
        "workers.change_detector.*": {"queue": "scans"},
        "workers.report_builder.*": {"queue": "reports"},
        # Its own queue so an alert is not stuck behind a half-hour CVE
        # enrichment run. A notification that arrives after the incident is
        # over has no value, and this queue's work is always sub-second.
        "workers.notifier.*": {"queue": "notify"},
        # Beat's own queue. Kept separate so a dispatcher tick is never stuck
        # behind the scans it just queued — on a shared queue the tick that
        # creates work would wait for that work to drain, and the next tick
        # would overlap it. The retention sweep also runs here, and its bulk
        # DELETEs must not land in front of a scan's first task.
        "workers.scheduler.*": {"queue": "schedule"},
    },
    # Everything Celery beat fires. Beat is the only producer of work with no
    # user behind it, so this list is deliberately short and its failure modes
    # are the ones worth reasoning about: a tick that raises produces no scan
    # and no error anyone reads.
    beat_schedule={
        "dispatch-due-scans": {
            "task": "workers.scheduler.dispatch_due_scans",
            # Every minute. This is the resolution of every cadence, so hourly
            # schedules fire within a minute of the hour and a scan created at
            # 03:00:30 still starts at 04:00. A longer interval would make the
            # other two cadences drift by however much it was.
            "schedule": 60.0,
        },
        "prune-old-data": {
            "task": "workers.scheduler.prune_old_data",
            # 03:30 UTC — half an hour after the default daily-scan hour, so the
            # sweep is not competing with the scans it would otherwise delete
            # logs out from under.
            "schedule": crontab(hour=3, minute=30),
        },
        "reverify-domains": {
            "task": "workers.scheduler.reverify_domains",
            # Monday 04:15 UTC. Weekly, and clear of both the daily dispatch and
            # the retention sweep. Named rather than numeric: Celery's
            # day_of_week follows cron's convention where 0 is Sunday, which is
            # one off from the Monday-is-0 used everywhere else in this codebase.
            "schedule": crontab(hour=4, minute=15, day_of_week="monday"),
        },
    },
)


# Make this the process-wide default app.
#
# Tasks are declared with @shared_task, which does not bind to an app at import
# time — it resolves through celery.current_app on every call. current_app is
# *thread-local*, and only the thread that constructed the app has it set; any
# other thread falls back to Celery's blank "default" app, whose broker_url is
# None and therefore defaults to amqp://localhost. Dispatching a scan from a
# sync endpoint (Starlette runs those in an anyio worker thread) would then
# publish to a RabbitMQ that does not exist instead of our Redis broker, and
# the scan would vanish with no error the user could see.
celery_app.set_default()


@setup_logging.connect
def _configure_logging(**_kwargs) -> None:
    """Let Celery use the app's logging config rather than hijacking the root
    logger, so worker output matches the API's format."""
    import logging

    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)-8s [%(request_id)s] %(name)s: %(message)s",
    )


@worker_process_init.connect
def _dispose_inherited_db_connections(**_kwargs) -> None:
    """Drop the database sockets this worker inherited from its parent.

    Fires in each forked child before it runs any task. Without it every child
    shares the parent's pooled connections, and the first time two processes use
    the same socket the Postgres protocol desynchronises. See
    db.database.dispose_inherited_pools for why the handles are abandoned rather
    than closed. Imported here rather than at module scope so that importing
    this module — which Alembic and the test suite both do — does not drag the
    engine in before the settings are ready.
    """
    from db.database import dispose_inherited_pools

    dispose_inherited_pools()


__all__ = ["celery_app"]
