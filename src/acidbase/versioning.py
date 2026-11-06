"""Shared project-version bump command for uv-managed Python repositories.

This module is intentionally separate from :mod:`acidbase.security`.  A
project-version bump advances ``[project].version`` for a release; the
security patch workflow changes dependency requirements across repositories.
"""

from __future__ import annotations

import subprocess
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import click
from packaging.version import InvalidVersion, Version

from acidbase.workflow import compose_command, find_project_root

BUMP_KINDS: tuple[str, ...] = (
    "alpha",
    "beta",
    "dev",
    "major",
    "minor",
    "patch",
    "post",
    "rc",
    "stable",
)
_VERSION_PATHS: tuple[str, ...] = ("pyproject.toml", "uv.lock")


@dataclass(frozen=True)
class ProjectVersion:
    """Static project identity read from ``pyproject.toml``."""

    name: str
    version: str


def _load_project_version(root: Path) -> ProjectVersion:
    """Loads and validates a static PEP 621 project version."""
    pyproject = root / "pyproject.toml"
    try:
        with pyproject.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise click.ClickException(f"Cannot read {pyproject}: {exc}") from exc

    project = data.get("project")
    if not isinstance(project, dict):
        raise click.ClickException("pyproject.toml has no [project] table.")

    dynamic = project.get("dynamic", [])
    if isinstance(dynamic, list) and "version" in dynamic:
        raise click.ClickException(
            "Cannot bump a dynamic project version; configure the owning version provider instead."
        )

    version = project.get("version")
    if not isinstance(version, str) or not version.strip():
        raise click.ClickException("[project].version must be a non-empty static string.")
    try:
        Version(version)
    except InvalidVersion as exc:
        raise click.ClickException(f"[project].version is not a valid PEP 440 version: {version}") from exc

    name = project.get("name")
    project_name = name.strip() if isinstance(name, str) and name.strip() else root.name
    return ProjectVersion(name=project_name, version=version)


def _run_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Runs one resolved, shell-free command and captures its UTF-8 output."""
    command = compose_command(tool, *arguments)
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
    )


def _ensure_version_files_clean(root: Path) -> None:
    """Refuses to mix a bump with existing changes to its two output files."""
    result = _run_process(
        "git",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        *_VERSION_PATHS,
        cwd=root,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        suffix = f"\n{detail}" if detail else ""
        raise click.ClickException(f"Could not verify Git state for pyproject.toml and uv.lock.{suffix}")

    changes = [line for line in result.stdout.splitlines() if line.strip()]
    if changes:
        rendered = "\n".join(f"  {line}" for line in changes)
        raise click.ClickException(
            f"Refusing to bump because pyproject.toml or uv.lock already has uncommitted changes:\n{rendered}"
        )


def _version_arguments(values: Sequence[str], *, dry_run: bool) -> tuple[str, ...]:
    """Translates bump components or one explicit version into uv argv."""
    requested = tuple(value.strip() for value in values if value.strip())
    if not requested:
        raise click.ClickException("Provide at least one bump kind or an explicit PEP 440 version.")

    bump_kinds = tuple(value.lower() for value in requested)
    if all(value in BUMP_KINDS for value in bump_kinds):
        if len(set(bump_kinds)) != len(bump_kinds):
            raise click.ClickException("Each bump kind may be specified only once.")
        arguments: list[str] = ["version"]
        for bump_kind in bump_kinds:
            arguments.extend(("--bump", bump_kind))
    elif len(requested) == 1:
        try:
            Version(requested[0])
        except InvalidVersion as exc:
            choices = ", ".join(BUMP_KINDS)
            raise click.ClickException(f"VALUE must be an explicit PEP 440 version or one of: {choices}.") from exc
        arguments = ["version", requested[0]]
    else:
        raise click.ClickException("An explicit PEP 440 version cannot be combined with bump kinds.")

    arguments.extend(("--no-sync", "--short"))
    if dry_run:
        arguments.append("--dry-run")
    return tuple(arguments)


def _reported_version(output: str) -> str:
    """Returns the final version line emitted by ``uv version --short``."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        raise click.ClickException("uv version succeeded but did not report the resulting version.")
    reported = lines[-1]
    try:
        Version(reported)
    except InvalidVersion as exc:
        raise click.ClickException(f"uv version reported an invalid version: {reported}") from exc
    return reported


def _echo_failure(result: subprocess.CompletedProcess[str]) -> None:
    """Relays captured child output without duplicating empty lines."""
    if result.stdout.strip():
        click.echo(result.stdout.rstrip())
    if result.stderr.strip():
        click.echo(result.stderr.rstrip(), err=True)


def run_bump(
    value: str,
    *additional_values: str,
    dry_run: bool = False,
    root: Path | None = None,
) -> None:
    """Validates and applies one project-version change through ``uv version``."""
    project_root = find_project_root(root)
    before = _load_project_version(project_root)
    _ensure_version_files_clean(project_root)

    values = (value, *additional_values)
    result = _run_process("uv", *_version_arguments(values, dry_run=dry_run), cwd=project_root)
    if result.returncode != 0:
        _echo_failure(result)
        raise SystemExit(result.returncode)

    reported = _reported_version(result.stdout)
    if dry_run:
        after_version = reported
    else:
        after = _load_project_version(project_root)
        if Version(after.version) != Version(reported):
            raise click.ClickException(
                "uv version reported success, but pyproject.toml does not contain the reported version."
            )
        after_version = after.version

    click.echo(f"{before.name}: {before.version} -> {after_version}")
    if dry_run:
        click.echo("Dry run: pyproject.toml and uv.lock were not changed.")
    else:
        click.echo("Updated pyproject.toml and uv.lock; the project environment was not synchronized.")


@click.command("bump")
@click.argument("values", nargs=-1, required=True)
@click.option("--dry-run", is_flag=True, help="Calculate and report the new version without changing files.")
def bump_command(values: tuple[str, ...], dry_run: bool) -> None:
    """Advance the version by one or more KINDs, or set explicit VALUE.

    KIND may be alpha, beta, dev, major, minor, patch, post, rc, or stable.
    Combine release and prerelease kinds, for example ``patch beta``. An
    explicit VALUE must follow PEP 440 and cannot be combined with KINDs. The
    command updates project metadata and the uv lockfile without synchronizing
    the virtual environment.
    """
    run_bump(*values, dry_run=dry_run)
