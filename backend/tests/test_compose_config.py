"""The compose files and the application agree about configuration.

Two invariants, both of which fail silently in production and neither of which
anything else in this suite can see:

1. **Every setting is reachable.** ``config.py`` defines a setting; the compose
   anchors hand the container its environment. A setting that exists in the code
   and in ``.env.example`` but is absent from the anchor is the worst of the
   three states — it is documented, it looks like it works, and setting it does
   nothing. Thirty-four of them were in exactly that state when this module was
   written, including every pool-size knob.

2. **The duplicates do not drift.** The anchors spell out each default so a
   container comes up correctly without a ``.env``. That is a second copy of a
   number that lives in ``config.py``, which is only safe if something checks
   the copies against each other. That is what the second test does.

A third invariant lives here because it belongs to the same failure family:

3. **Every Celery queue that is routed to is listened on.** ``celery_app.py``
   sends each task to a named queue and the worker's ``-Q`` decides which it
   consumes. A queue in one and not the other means those tasks are published
   into a void: the worker comes up healthy, logs nothing, and the work never
   happens. There is no error anywhere to find.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent

COMPOSE_FILES = [
    REPO / "docker-compose.yml",
    REPO / "docker-compose.prod.yml",
]

# Set on the compose anchor as a literal rather than a ${VAR:-default}, because
# it is a filesystem path inside the container and there is nothing sensible for
# an operator to substitute.
NOT_TEMPLATED = {"REPORT_OUTPUT_DIR"}


def _settings_defaults() -> dict[str, object]:
    """Every field of ``config.Settings`` with its declared default.

    Read from the AST rather than by importing the class: instantiating
    Settings here would read whatever .env the developer has, so the defaults
    being compared would be the machine's values rather than the code's.
    """
    tree = ast.parse((BACKEND / "config.py").read_text())
    defaults: dict[str, object] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Settings":
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    name = stmt.target.id
                    try:
                        defaults[name.upper()] = ast.literal_eval(stmt.value)
                    except (ValueError, TypeError):
                        # A field with no default, or one built by a call
                        # (default_factory, a computed validator). Reported as
                        # missing rather than guessed at.
                        defaults[name.upper()] = _NO_DEFAULT
    return defaults


class _NoDefault:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<no literal default>"


_NO_DEFAULT = _NoDefault()

_TEMPLATE = re.compile(r"^\$\{([A-Z0-9_]+):-(.*)\}$", re.DOTALL)


def _anchor(path: Path) -> dict[str, str]:
    document = yaml.safe_load(path.read_text())
    anchor = document.get("x-backend-env")
    assert anchor, f"{path.name} has no x-backend-env anchor"
    return anchor


@pytest.fixture(params=COMPOSE_FILES, ids=lambda p: p.name)
def compose(request) -> tuple[Path, dict[str, str]]:
    return request.param, _anchor(request.param)


# --- 1. every setting reaches the container ---------------------------------


def test_every_setting_is_passed_through_to_the_container(compose):
    path, anchor = compose
    missing = sorted(set(_settings_defaults()) - set(anchor))

    assert not missing, (
        f"{path.name} does not pass these settings to the container, so setting "
        f"them in the environment file has no effect: {missing}"
    )


def test_the_anchor_does_not_invent_settings_that_do_not_exist(compose):
    """The other direction. A variable in the anchor that config.py does not
    define is a typo or a leftover — pydantic-settings ignores it, so it is a
    line of configuration that reads as live and is not."""
    path, anchor = compose
    defined = set(_settings_defaults())
    # PYTHONUNBUFFERED etc. would go here if the anchor ever carried them.
    unknown = sorted(set(anchor) - defined)

    assert not unknown, f"{path.name} sets variables config.py does not define: {unknown}"


# --- 2. the duplicated defaults have not drifted ----------------------------


def _comparable(compose_value: str) -> str | None:
    match = _TEMPLATE.match(compose_value.strip())
    return match.group(2) if match else None


def _coerce(code_default: object, text: str) -> object:
    """Compare on value, not on spelling: True / 'true', 30.0 / '30.0'."""
    if isinstance(code_default, bool):
        return text.strip().lower() in ("true", "1", "yes")
    if isinstance(code_default, int):
        return int(text)
    if isinstance(code_default, float):
        return float(text)
    return text


# Values the production anchor sets differently from config.py's defaults on
# purpose, each with the reason. The assertion below is not "prod must equal the
# code" — that would be wrong, because a free-tier VM genuinely should not run
# the development scan rates. It is "prod must equal the code, or differ in a
# way somebody decided and wrote down here". An undeclared difference fails.
PROD_OVERRIDES: dict[str, tuple[str, str]] = {
    "DB_POOL_SIZE": ("4", "free-tier managed Postgres often allows 20-25 connections total"),
    "DB_MAX_OVERFLOW": ("2", "same ceiling; the API runs API_WORKERS copies of this pool"),
    "DB_WORKER_POOL_SIZE": ("2", "same ceiling"),
    "DB_WORKER_MAX_OVERFLOW": ("1", "same ceiling"),
    "SCAN_MAX_CONCURRENCY": ("50", "a shared-core VM cannot sustain 200 sockets"),
    "SCAN_CONNECT_TIMEOUT": ("3.0", "a slower box needs a longer connect budget"),
    "SCAN_RATE_LIMIT_PER_HOST": ("20", "50 req/host resembles an attack to the provider"),
    # Caddy is the single proxy in front of the API in the production stack, so
    # unlike development there is exactly one X-Forwarded-For entry to believe.
    "TRUSTED_PROXY_COUNT": ("1", "Caddy is the one proxy in front of the API"),
}


def _drift(path: Path, anchor: dict[str, str]) -> list[str]:
    code = _settings_defaults()
    overrides = PROD_OVERRIDES if path.name == "docker-compose.prod.yml" else {}
    drifted = []

    for name, value in sorted(anchor.items()):
        if name in NOT_TEMPLATED or name not in code:
            continue
        expected = code[name]
        text = _comparable(str(value))
        if text is None or expected is _NO_DEFAULT:
            # A literal, or a field whose default is not a literal — nothing in
            # the code to compare against.
            continue
        if name in overrides:
            declared, reason = overrides[name]
            if text != declared:
                drifted.append(
                    f"{name}: {path.name} says {text!r} but the override table "
                    f"declares {declared!r} ({reason}) — update one of them"
                )
            continue
        try:
            matched = _coerce(expected, text) == expected
        except (ValueError, TypeError):
            matched = False
        if not matched:
            drifted.append(
                f"{name}: compose says {text!r}, config.py says {expected!r} "
                f"(add it to PROD_OVERRIDES if the difference is intended)"
            )

    return drifted


def test_the_defaults_in_the_anchor_match_the_defaults_in_the_code(compose):
    """There is no way to reference config.py's default from a compose file, so
    it is written twice. This is the check that the second copy is still right —
    without it, changing a default in config.py leaves the container silently
    running the old value, and the two disagree only under load or in prod.

    Development must match the code exactly. Production may differ, but only
    where PROD_OVERRIDES records the difference and the reason for it.
    """
    path, anchor = compose
    drifted = _drift(path, anchor)

    assert not drifted, f"{path.name} has drifted from config.py:\n  " + "\n  ".join(drifted)


def test_the_override_table_does_not_go_stale():
    """An entry left behind after prod was changed back to the code default is a
    comment that lies about what production runs. Checked in both directions:
    every declared override must still be a real difference."""
    anchor = _anchor(REPO / "docker-compose.prod.yml")
    code = _settings_defaults()

    for name, (declared, _reason) in PROD_OVERRIDES.items():
        assert name in anchor, f"PROD_OVERRIDES names {name}, which prod does not set"
        actual = _comparable(str(anchor[name]))
        assert actual == declared, (
            f"PROD_OVERRIDES says {name}={declared!r}, prod sets {actual!r}"
        )
        assert _coerce(code[name], declared) != code[name], (
            f"PROD_OVERRIDES claims {name} differs from config.py, but both are "
            f"{code[name]!r} — the entry is stale"
        )


def test_the_container_paths_are_the_paths_the_code_uses(compose):
    """REPORT_OUTPUT_DIR is the one value that cannot be a ${VAR:-default}: the
    API and the worker must agree on it or every download is a 404 for a file
    that exists on the other container. Asserted literally so a change to the
    compose value without the matching volume is caught."""
    _path, anchor = compose
    assert anchor["REPORT_OUTPUT_DIR"] == "/var/lib/surfacewatch/reports"


# --- 3. routed queues are listened on ---------------------------------------


def _routed_queues() -> set[str]:
    source = (BACKEND / "workers" / "celery_app.py").read_text()
    return set(re.findall(r'"queue":\s*"([^"]+)"', source))


def _listened_queues(command: list[str]) -> set[str]:
    """The queues a `celery worker -Q a,b,c` command subscribes to."""
    assert "-Q" in command, f"no -Q in the worker command: {command}"
    return set(command[command.index("-Q") + 1].split(","))


@pytest.mark.parametrize("compose_path", COMPOSE_FILES, ids=lambda p: p.name)
def test_every_routed_queue_is_consumed_by_the_worker(compose_path):
    """A queue in task_routes but not in -Q is published into a void: no error,
    no log line, the work simply never happens. This is the check that the two
    lists in two different files still describe the same set."""
    document = yaml.safe_load(compose_path.read_text())
    command = document["services"]["worker"]["command"]
    listened = _listened_queues(list(command))

    routed = _routed_queues()
    assert routed, "no task_routes found — the regex has rotted"
    assert routed <= listened, (
        f"{compose_path.name}: tasks are routed to {sorted(routed - listened)}, "
        f"which the worker does not consume"
    )


@pytest.mark.parametrize("compose_path", COMPOSE_FILES, ids=lambda p: p.name)
def test_the_worker_does_not_listen_on_queues_nothing_routes_to(compose_path):
    """The converse. Harmless in itself, but it is how a queue that was renamed
    in one file and not the other is found: the old name lingers here while the
    tasks go to the new one."""
    document = yaml.safe_load(compose_path.read_text())
    command = document["services"]["worker"]["command"]

    orphaned = _listened_queues(list(command)) - _routed_queues()
    assert not orphaned, (
        f"{compose_path.name}: the worker listens on {sorted(orphaned)}, "
        f"which no task is routed to"
    )


@pytest.mark.parametrize("compose_path", COMPOSE_FILES, ids=lambda p: p.name)
def test_the_beat_schedule_only_references_tasks_that_exist(compose_path):
    """beat fires tasks by name. A renamed task leaves beat publishing to a name
    nothing is registered under, on a schedule, forever, with no error."""
    source = (BACKEND / "workers" / "celery_app.py").read_text()
    scheduled = set(re.findall(r'"task":\s*"([^"]+)"', source))
    assert scheduled, "no beat_schedule entries found — the regex has rotted"

    named_tasks = set(re.findall(r'@shared_task\(\s*name="([^"]+)"', _all_worker_source()))
    missing = scheduled - named_tasks
    assert not missing, (
        f"beat_schedule fires {sorted(missing)}, which no @shared_task declares — "
        f"check the task names in workers/"
    )


def _all_worker_source() -> str:
    return "\n".join(
        path.read_text() for path in sorted((BACKEND / "workers").glob("*.py"))
    )
