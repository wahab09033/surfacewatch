"""``scripts/backup.sh`` does what it says.

A backup script is the single piece of this codebase whose failure is only
discovered at the worst possible moment, and it is not covered by anything else
— it is not imported by the app, not exercised by the API tests, and on a
machine without a database it exits before doing anything. The parts most likely
to rot silently are the ones this module pins down:

* a dump that is written, verified and then *renamed*, so an interrupted run
  cannot leave a file that looks like a backup;
* the size check, which catches the failure where pg_dump exits 0 having
  connected to the wrong database and dumped nothing;
* the retention sweep, whose glob must match the dumps and nothing else in the
  directory — a `find -delete` that is one character too broad is a script that
  deletes something irreplaceable on a schedule, unattended.

The real pg_dump is replaced by a stub on PATH. That is the point: the test is
about this script's control flow, not about Postgres, and a stub is the only way
to make the failure branches (empty dump, gzip that does not verify) reachable
at all.
"""

from __future__ import annotations

import gzip
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "backup.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="backup.sh is a bash script"
)

# How much SQL the stub emits. It is pseudo-random rather than repeated because
# the script's floor is on the *compressed* size: a few thousand identical
# "SELECT 1;" lines gzip to a couple of hundred bytes and would trip the guard
# the happy-path test is trying not to trip.
REAL_DUMP_LINES = 200


@pytest.fixture
def stub_bin(tmp_path: Path) -> Path:
    """A directory holding a fake pg_dump, to be prepended to PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    return bindir


def _write_stub(bindir: Path, lines: int) -> None:
    # The emitter lives beside the stub rather than inline, so the stub stays a
    # one-line shell script and the quoting does not have to survive two levels
    # of nesting.
    (bindir / "emit.py").write_text(
        "import random, string, sys\n"
        "random.seed(1234)\n"
        f"for _ in range({lines}):\n"
        "    sys.stdout.write(''.join(random.choices(string.hexdigits, k=64)) + '\\n')\n"
    )
    stub = bindir / "pg_dump"
    stub.write_text(
        "#!/bin/sh\n"
        # Echoed so a test can assert on the arguments the script chose.
        'echo "stub-args: $*" >&2\n'
        'exec python3 "$(dirname "$0")/emit.py"\n'
    )
    stub.chmod(0o755)


def _run(
    tmp_path: Path,
    stub_bin: Path,
    *,
    lines: int = REAL_DUMP_LINES,
    retention_days: str = "14",
    timeout: int = 90,
) -> subprocess.CompletedProcess:
    _write_stub(stub_bin, lines)
    backup_dir = tmp_path / "backups"

    env = dict(os.environ)
    env.update(
        POSTGRES_USER="surfacewatch",
        POSTGRES_PASSWORD="not-a-real-password",
        POSTGRES_DB="surfacewatch",
        POSTGRES_HOST="127.0.0.1",
        POSTGRES_PORT="55432",
        BACKUP_DIR=str(backup_dir),
        RETENTION_DAYS=retention_days,
    )
    # The stub shadows any real pg_dump; docker is left alone, and the empty
    # cwd below means `docker compose ps` finds no compose file and the script
    # falls through to the pg_dump branch.
    env["PATH"] = f"{stub_bin}{os.pathsep}{env.get('PATH', '')}"

    return subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=timeout,
    )


def _produced(tmp_path: Path) -> list[Path]:
    backup_dir = tmp_path / "backups"
    return sorted(backup_dir.glob("surfacewatch-*.sql.gz")) if backup_dir.exists() else []


# --- credential guards ------------------------------------------------------


def test_missing_credentials_stop_before_writing_anything(tmp_path, stub_bin):
    """The script is meant to be run from cron with the environment sourced
    from .env.prod. If that sourcing is forgotten, the failure must be loud and
    must happen before a file is created — an exit-0 run that wrote a dump of
    nothing is the failure mode that matters."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("POSTGRES_")}
    env["PATH"] = f"{stub_bin}{os.pathsep}{env.get('PATH', '')}"
    env["BACKUP_DIR"] = str(tmp_path / "backups")

    result = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60
    )

    assert result.returncode != 0
    assert "POSTGRES_USER" in result.stderr
    assert _produced(tmp_path) == []


# --- the happy path ---------------------------------------------------------


def test_a_dump_is_written_verified_and_named(tmp_path, stub_bin):
    result = _run(tmp_path, stub_bin)

    assert result.returncode == 0, result.stdout + result.stderr
    produced = _produced(tmp_path)
    assert len(produced) == 1

    # It must actually be a gzip stream that decompresses, not merely a file
    # with .gz on the end.
    with gzip.open(produced[0], "rt") as fh:
        assert fh.read().strip(), "the dump decompressed to nothing"


def test_no_partial_file_survives_a_successful_run(tmp_path, stub_bin):
    """The write goes to *.partial and is renamed only after it verifies. A
    .partial left behind means the rename or the trap is wrong."""
    _run(tmp_path, stub_bin)
    assert list((tmp_path / "backups").glob("*.partial")) == []


def test_the_dump_is_restorable_sql(tmp_path, stub_bin):
    """--no-owner and --no-privileges are what let the dump restore into a fresh
    container whose roles were created by a different initdb. If they are
    dropped, the failure only shows up during a restore."""
    result = _run(tmp_path, stub_bin)
    args = [line for line in result.stderr.splitlines() if line.startswith("stub-args:")]
    assert args, "the stub never ran, so nothing about the arguments was checked"
    joined = " ".join(args)
    assert "--format=plain" in joined
    assert "--no-owner" in joined
    assert "--no-privileges" in joined
    assert "--dbname=surfacewatch" in joined


# --- the guards -------------------------------------------------------------


def test_an_empty_dump_is_rejected(tmp_path, stub_bin):
    """pg_dump exits 0 when it connects successfully to the wrong database. The
    size floor is the only thing standing between that and a nightly rotation
    of empty backups overwriting the real ones."""
    result = _run(tmp_path, stub_bin, lines=0)

    assert result.returncode != 0
    assert "bytes" in result.stderr
    assert _produced(tmp_path) == [], "a dump of nothing was kept"


def test_a_corrupt_dump_is_rejected(tmp_path, stub_bin):
    """A dump killed partway by a timeout or a full disk gunzips to a truncated
    database. gzip -t is cheap and catches exactly that."""
    stub = stub_bin / "pg_dump"
    stub.write_text("#!/bin/sh\nprintf 'this is not gzip at all'\n")
    stub.chmod(0o755)

    env = dict(os.environ)
    env.update(
        POSTGRES_USER="u",
        POSTGRES_PASSWORD="p",
        POSTGRES_DB="surfacewatch",
        BACKUP_DIR=str(tmp_path / "backups"),
    )
    env["PATH"] = f"{stub_bin}{os.pathsep}{env.get('PATH', '')}"

    result = subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60
    )

    assert result.returncode != 0
    assert _produced(tmp_path) == []


# --- retention --------------------------------------------------------------


def test_retention_prunes_dumps_and_nothing_else(tmp_path, stub_bin):
    """The sweep runs unattended and deletes by glob. An over-broad pattern here
    destroys something nobody gets back, so the negative case is the assertion
    that matters: a non-dump file in the same directory must survive, and so
    must a dump that is inside the retention window."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    old_dump = backup_dir / "surfacewatch-20200101T000000Z.sql.gz"
    old_dump.write_text("old")
    bystander = backup_dir / "keep-me.txt"
    bystander.write_text("somebody's notes")
    stale_partial = backup_dir / "surfacewatch-20200101T000000Z.sql.gz.partial"
    stale_partial.write_text("interrupted")

    five_days_ago = old_dump.stat().st_mtime - 5 * 86400
    os.utime(old_dump, (five_days_ago, five_days_ago))
    os.utime(stale_partial, (five_days_ago, five_days_ago))
    # The bystander has to be *old* too. Left at its creation time it is inside
    # the retention window, so an over-broad glob would not match it and the
    # test would pass while asserting nothing — which is exactly what happened
    # the first time this was checked against a deliberately widened pattern.
    os.utime(bystander, (five_days_ago, five_days_ago))

    result = _run(tmp_path, stub_bin, retention_days="1")
    assert result.returncode == 0, result.stdout + result.stderr

    remaining = {p.name for p in backup_dir.iterdir()}
    assert bystander.name in remaining, "the sweep deleted a file that was not a dump"
    assert old_dump.name not in remaining, "an expired dump survived"
    assert stale_partial.name not in remaining, "a stale .partial survived"
    assert "pruned" in result.stdout
    # The run's own fresh dump is inside the window and must still be there.
    assert len(_produced(tmp_path)) == 1


def test_retention_can_be_disabled(tmp_path, stub_bin):
    """RETENTION_DAYS=0 must mean "keep everything", not "delete everything" —
    the two are one comparison apart."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    old_dump = backup_dir / "surfacewatch-20200101T000000Z.sql.gz"
    old_dump.write_text("old")
    old_mtime = old_dump.stat().st_mtime - 400 * 86400
    os.utime(old_dump, (old_mtime, old_mtime))

    result = _run(tmp_path, stub_bin, retention_days="0")
    assert result.returncode == 0, result.stdout + result.stderr
    assert old_dump.exists(), "RETENTION_DAYS=0 deleted a dump"
    assert "pruned" not in result.stdout
