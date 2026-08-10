"""Celery workers.

Each scanning module is an independent task; ``orchestrator`` chains them.
Import ``celery_app`` from here when starting a worker:

    celery -A workers.celery_app worker -Q scans,enrich,reports --loglevel=info
"""

from workers.celery_app import celery_app

__all__ = ["celery_app"]
