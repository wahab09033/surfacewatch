"""Celery application.

Each scan module is a separate task so it can be retried, rate-limited and
scaled independently. The orchestrator chains them per scan.
"""

from __future__ import annotations

from celery import Celery
from celery.signals import setup_logging

from config import settings

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
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )


__all__ = ["celery_app"]
