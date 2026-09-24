"""The CI workflow's environment names actually exist.

A typo in a workflow's ``env:`` block is invisible. GitHub sets the variable,
the application's settings loader ignores a name it does not define, and the
step runs with the default it was supposed to override. The build is green and
the configuration the file appears to apply is not applied — the same failure
mode ``test_compose_config.py`` guards against for the compose anchors, in the
third file that carries configuration.

The check is deliberately one-directional. Every name CI sets must be a real
setting; CI is not required to set every setting, because unlike the compose
anchors it is not how anyone deploys.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

BACKEND = Path(__file__).resolve().parents[1]
WORKFLOWS = BACKEND.parent / ".github" / "workflows"

# Read by the frontend build, not by config.py. NEXT_PUBLIC_* values are
# inlined into the browser bundle by Next, and NEXT_TELEMETRY_DISABLED is read
# by Next itself — neither is a backend setting, and neither should ever
# become one.
FRONTEND_VARIABLES = {"NEXT_PUBLIC_API_URL", "NEXT_TELEMETRY_DISABLED"}


def _workflow_files() -> list[Path]:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    assert files, f"no workflows found under {WORKFLOWS}"
    return files


def _settings_fields() -> set[str]:
    tree = ast.parse((BACKEND / "config.py").read_text())
    fields: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Settings":
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    fields.add(stmt.target.id.upper())
    assert fields, "no Settings fields found — config.py has been restructured"
    return fields


def _env_names(document: dict) -> set[str]:
    """Every name set in any `env:` block, at job or step level."""
    names: set[str] = set()
    for job in (document.get("jobs") or {}).values():
        names |= set(job.get("env") or {})
        for step in job.get("steps") or []:
            names |= set(step.get("env") or {})
    return names


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_no_workflow_sets_a_variable_that_is_not_a_setting(path):
    declared = _settings_fields() | FRONTEND_VARIABLES
    unknown = sorted(_env_names(yaml.safe_load(path.read_text())) - declared)

    assert not unknown, (
        f"{path.name} sets {unknown}, which config.py does not define. A typo here "
        f"is silent: the variable is exported, the settings loader ignores it, and "
        f"the step runs with the default it was meant to override."
    )


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_every_workflow_parses_and_has_jobs(path):
    """A workflow that does not parse is not a failing check — GitHub reports it
    as a broken workflow file on the default branch, which is easy to miss on a
    branch that only ever runs on pull_request."""
    document = yaml.safe_load(path.read_text())
    assert document.get("jobs"), f"{path.name} declares no jobs"


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_env_values_are_strings(path):
    """GitHub Actions requires env values to be strings; a bare `5432` is
    accepted by the parser and rejected by the runner, or worse, coerced."""
    document = yaml.safe_load(path.read_text())
    offenders = []
    for job_name, job in document["jobs"].items():
        for scope, block in [("job", job.get("env") or {})] + [
            (step.get("name", "<unnamed>"), step.get("env") or {})
            for step in job.get("steps") or []
        ]:
            for key, value in block.items():
                if not isinstance(value, str):
                    offenders.append(f"{job_name}/{scope}: {key}={value!r}")
    assert not offenders, f"{path.name} has non-string env values: {offenders}"
