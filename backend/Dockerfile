# syntax=docker/dockerfile:1
#
# SurfaceWatch backend.
#
# The API and the Celery workers run the same image — they share config.py,
# models and db/, and splitting them would mean maintaining two dependency
# sets that must stay in lockstep. They differ only in their command.
#
# Targets:
#   dev   — source is bind-mounted, uvicorn --reload / watchmedo restart
#   prod  — source baked in, no reload tooling
#
# Python 3.12 rather than 3.13: every pin in requirements.txt ships a 3.12
# wheel, so nothing has to compile from source at build time. The code is
# `from __future__ import annotations` throughout and uses no 3.13 feature.

FROM python:3.12-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# WeasyPrint renders the PDF reports and links against Pango/HarfBuzz at
# runtime, not build time — so these are needed in the final image, not just a
# builder stage. Without them `import weasyprint` raises OSError on library
# load and every report task fails at import.
#
# fonts-dejavu-core is not optional either: with no font installed, WeasyPrint
# produces a PDF of blank boxes rather than an error.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libfribidi0 \
        libffi8 \
        libjpeg62-turbo \
        fontconfig \
        fonts-dejavu-core \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies are installed into the system site-packages, deliberately not a
# virtualenv under /app: the dev target bind-mounts the host's ./backend over
# /app, which would shadow a venv living there and leave the container with no
# packages at all.
COPY requirements.txt ./
RUN pip install -r requirements.txt

# An unprivileged user. The port scanner uses asyncio TCP connect scans rather
# than raw sockets, so nothing here needs root or CAP_NET_RAW.
RUN useradd --create-home --uid 10001 app

# Created here, with app ownership, so that the named volume compose mounts at
# this path inherits that ownership on first use. Docker seeds an empty named
# volume from the image directory including its uid/gid — create it only in
# compose and it would come up root-owned and unwritable.
RUN mkdir -p /var/lib/surfacewatch/reports && chown -R app:app /var/lib/surfacewatch

EXPOSE 8000


# --- dev --------------------------------------------------------------------
FROM base AS dev

# Celery has had no built-in reloader since 3.x, so the worker gets restarted
# by watchmedo on source change. Dev-only: it is not in requirements.txt
# because production should never be restarting workers on file writes.
RUN pip install "watchdog[watchmedo]==6.0.0"

USER app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


# --- prod -------------------------------------------------------------------
FROM base AS prod

COPY --chown=app:app . .
USER app

# No --reload, and no worker count: concurrency is the orchestrator's job here
# (multiple replicas), not uvicorn's, so a crash-looping process is visible to
# the platform rather than silently restarted inside the container.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
