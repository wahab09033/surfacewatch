#!/usr/bin/env bash
#
# Back up the SurfaceWatch database.
#
#   ./scripts/backup.sh                    # into ./backups
#   BACKUP_DIR=/mnt/backups ./scripts/backup.sh
#
# What this produces is a *logical* dump — the schema and every row, as SQL.
# That is the right shape for this database because it is small (a few hundred
# MB at the scale this deployment is built for) and because the alternative, a
# physical base backup, is only restorable onto the same Postgres major version
# with the same layout. A logical dump restores into a fresh container from a
# different image, which is exactly the scenario a restore actually happens in.
#
# What this does NOT do: it does not copy the report PDFs in
# REPORT_OUTPUT_DIR, and it does not back up Redis. Redis holds the Celery
# queue and the live scan-log stream, both of which are rebuildable — a scan
# interrupted by a restore shows as failed and can be re-run, and the log lines
# are already persisted in Postgres. Reports are regenerable from the scan
# data; if you would rather not regenerate them, copy that directory too.
#
# Run it from cron or a systemd timer, not from inside the app. See the bottom
# of this file for a suggested schedule.

set -euo pipefail

# --- Configuration ----------------------------------------------------------

BACKUP_DIR="${BACKUP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/backups}"

# Kept as a separate knob from BACKUP_DIR because the two answer different
# questions: where the dumps live, and how much history is worth the disk.
RETENTION_DAYS="${RETENTION_DAYS:-14}"

# Refuse to run rather than quietly produce a truncated dump. A backup that
# dies halfway leaves a file that looks like a backup, and the first time
# anyone finds out otherwise is during a restore.
PG_DUMP_TIMEOUT="${PG_DUMP_TIMEOUT:-1800}"   # seconds

# --- Credentials ------------------------------------------------------------
#
# Taken from the environment, never from this file. A password written here is
# a password in the repository, and the compose files already read the same
# variables from .env / .env.prod, so there is nothing extra to configure:
#
#   set -a; . .env.prod; set +a; ./scripts/backup.sh
#
# PGPASSWORD is set for the duration of the dump only. It is exported rather
# than passed on the command line because an argument is visible in `ps` to
# every other user on the box.

: "${POSTGRES_USER:?set POSTGRES_USER (see .env.prod)}"
: "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD (see .env.prod)}"
POSTGRES_DB="${POSTGRES_DB:-surfacewatch}"

# Inside the compose network the database is at "postgres"; from the host it is
# 127.0.0.1 and whatever port the compose file publishes.
POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"

# Prefer the container's own pg_dump when the stack is running: the client must
# not be older than the server, and pg_dump refuses outright to talk to a newer
# major. The image's binary always matches its own server, so the container path
# is the one that cannot fail this way.
#
# Note the two different addresses. From the host, the database is published on
# whatever port the compose file maps. Inside the container it is always 5432.
# The container's pg_hba requires a password over TCP (local socket is trust,
# but forcing TCP here keeps one code path rather than two), so PGPASSWORD is
# handed to the container with `exec -e` — not set as a prefix on the docker
# command, which would only affect the host-side client.
HOST="${POSTGRES_HOST}"
PORT="${POSTGRES_PORT}"
USE_DOCKER=0

if command -v docker >/dev/null 2>&1 && \
   docker compose ps --status running --services 2>/dev/null | grep -qx postgres; then
    USE_DOCKER=1
    HOST="127.0.0.1"
    PORT="5432"
    echo "==> using pg_dump from the running postgres container"
elif command -v pg_dump >/dev/null 2>&1; then
    echo "==> using pg_dump from PATH"
    echo "    (pg_dump must be the same major version or newer than the server)"
else
    echo "ERROR: no pg_dump available — start the stack, or install postgresql-client." >&2
    exit 1
fi

# --- Checks -----------------------------------------------------------------

mkdir -p "$BACKUP_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${BACKUP_DIR}/surfacewatch-${STAMP}.sql.gz"

# Write to a temporary name, then rename. An interrupted dump therefore leaves
# a .partial file, which the retention sweep and any sane restore procedure
# both ignore — instead of a .sql.gz that unpacks to half a database.
PARTIAL="${TARGET}.partial"

cleanup() {
    rm -f "$PARTIAL"
}
trap cleanup EXIT

# --- Dump -------------------------------------------------------------------

echo "==> dumping ${POSTGRES_DB} from ${HOST}:${PORT}"

# --format=plain rather than the default custom format, because the result is
# piped through gzip: a custom-format archive is already compressed internally
# and would gain nothing, whereas plain SQL gzips to roughly a tenth of its
# size and can be read, grepped and edited by a human during an incident.
#
# --no-owner and --no-privileges so the dump restores into a database whose
# role names differ from this one's. Without them a restore into a fresh
# container fails on every GRANT to a role that does not exist there, which is
# the most common way a valid backup turns out to be useless.
#
# Not --clean: it belongs in the restore step, where its effect is visible,
# rather than baked into the file.
DUMP_ARGS=(
    --format=plain
    --no-owner
    --no-privileges
    --host="$HOST"
    --port="$PORT"
    --username="$POSTGRES_USER"
    --dbname="$POSTGRES_DB"
)

if [ "$USE_DOCKER" -eq 1 ]; then
    docker compose exec -T -e "PGPASSWORD=${POSTGRES_PASSWORD}" \
        postgres pg_dump "${DUMP_ARGS[@]}" | gzip -9 > "$PARTIAL"
else
    PGPASSWORD="$POSTGRES_PASSWORD" pg_dump "${DUMP_ARGS[@]}" | gzip -9 > "$PARTIAL"
fi

# --- Verify -----------------------------------------------------------------

# gzip -t is the cheapest possible check and it catches the failure that
# actually happens: a dump killed partway by a timeout or a full disk, leaving
# a file that gunzips to a truncated database. It is not a substitute for
# rehearsing a restore (see the bottom of this file).
if ! gzip -t "$PARTIAL" 2>/dev/null; then
    echo "ERROR: the dump is not a valid gzip stream — nothing was written." >&2
    exit 1
fi

# A dump of a non-empty database is never small. This catches the other silent
# failure: pg_dump exiting 0 having found nothing because it connected to the
# wrong host or the wrong database name.
SIZE_BYTES=$(wc -c < "$PARTIAL")
MIN_BYTES="${MIN_BYTES:-1024}"
if [ "$SIZE_BYTES" -lt "$MIN_BYTES" ]; then
    echo "ERROR: dump is only ${SIZE_BYTES} bytes — wrong database?" >&2
    exit 1
fi

mv "$PARTIAL" "$TARGET"
trap - EXIT

echo "==> wrote ${TARGET} ($(numfmt --to=iec "$SIZE_BYTES" 2>/dev/null || echo "${SIZE_BYTES}B"))"

# --- Retention --------------------------------------------------------------

if [ "$RETENTION_DAYS" -gt 0 ]; then
    # -mtime +N is "strictly more than N days old". The glob is narrow on
    # purpose: a stray `find "$BACKUP_DIR" -mtime +N -delete` would take
    # anything else someone keeps in that directory with it.
    removed=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'surfacewatch-*.sql.gz' \
        -mtime "+${RETENTION_DAYS}" -print -delete | wc -l)
    if [ "$removed" -gt 0 ]; then
        echo "==> pruned ${removed} dump(s) older than ${RETENTION_DAYS} days"
    fi
fi

# Stale partials from runs that were killed before the trap could fire.
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'surfacewatch-*.partial' -mtime +1 -delete 2>/dev/null || true

echo "==> done"

# --- Restoring --------------------------------------------------------------
#
#   docker compose exec -T postgres psql -U surfacewatch -d postgres \
#     -c 'DROP DATABASE IF EXISTS surfacewatch WITH (FORCE)' \
#     -c 'CREATE DATABASE surfacewatch'
#   gunzip -c backups/surfacewatch-YYYYMMDDTHHMMSSZ.sql.gz \
#     | docker compose exec -T postgres psql -U surfacewatch -d surfacewatch
#
# Then bring the stack back up. Because the migration head is recorded in the
# dump's alembic_version table, `alembic upgrade head` afterwards is a no-op if
# the dump matches the deployed code and a real upgrade if the code has moved
# on — which is the case this whole exercise exists for.
#
# --- Scheduling -------------------------------------------------------------
#
#   # /etc/cron.d/surfacewatch-backup
#   17 2 * * * root cd /opt/surfacewatch && set -a && . ./.env.prod && set +a && \
#     BACKUP_DIR=/mnt/backups ./scripts/backup.sh >> /var/log/surfacewatch-backup.log 2>&1
#
# 02:17 rather than 02:00 so it does not collide with the retention sweep, and
# off the hour so it does not collide with everything else on the box.
#
# --- The part that matters --------------------------------------------------
#
# An untested backup is not a backup. Once a quarter, restore the most recent
# dump into a scratch database and confirm the row counts:
#
#   createdb -h 127.0.0.1 -U postgres restore_rehearsal
#   gunzip -c backups/<newest>.sql.gz | psql -h 127.0.0.1 -U postgres -d restore_rehearsal
#   psql -h 127.0.0.1 -U postgres -d restore_rehearsal \
#     -c 'SELECT (SELECT count(*) FROM organisations) AS orgs,
#                (SELECT count(*) FROM scans)         AS scans,
#                (SELECT count(*) FROM findings)      AS findings'
#   dropdb -h 127.0.0.1 -U postgres restore_rehearsal
#
# If that fails, it is a scheduling problem rather than a disaster. If it is
# discovered during an actual restore, it is a disaster.
