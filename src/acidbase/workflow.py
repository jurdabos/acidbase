"""Reusable mechanics for project-owned command-line workflows.

Child repositories decide what commands such as ``clean``, ``dev``, and
``render`` mean.  This module supplies the mechanics those commands should not
have to reimplement: strict project-root discovery, executable lookup,
argv-only command composition, project-local working-directory validation,
and subprocess exit-code propagation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import click

DEFAULT_ROOT_MARKERS = ("pyproject.toml",)


def find_project_root(
    start: str | Path | None = None,
    *,
    markers: Sequence[str] = DEFAULT_ROOT_MARKERS,
) -> Path:
    """Returns the nearest ancestor containing one of ``markers``.

    Discovery is strict because silently treating an arbitrary current working
    directory as a project root can make maintenance commands act on the wrong
    tree.  ``start`` may name either a file or a directory.
    """
    if not markers or any(
        not marker or Path(marker).is_absolute() or Path(marker) == Path(".") or ".." in Path(marker).parts
        for marker in markers
    ):
        raise ValueError("markers must contain relative, non-empty paths")

    candidate = Path.cwd() if start is None else Path(start).expanduser()
    candidate = candidate.resolve()
    if candidate.is_file():
        candidate = candidate.parent

    for directory in (candidate, *candidate.parents):
        if any((directory / marker).exists() for marker in markers):
            return directory
    marker_text = ", ".join(markers)
    raise click.ClickException(f"Could not find a project root containing any of: {marker_text}")


def project_path(root: str | Path, relative: str | Path = ".") -> Path:
    """Resolves ``relative`` inside ``root`` and rejects path traversal."""
    project_root = Path(root).expanduser().resolve()
    requested = Path(relative)
    if requested.is_absolute():
        resolved = requested.expanduser().resolve()
    else:
        resolved = (project_root / requested).resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError as exc:
        raise click.ClickException(f"Path escapes the project root: {relative}") from exc
    return resolved


def require_tool(name: str | Path) -> str:
    """Returns an executable path or raises a concise user-facing error."""
    raw = os.fspath(name)
    if not raw or "\x00" in raw:
        raise click.ClickException("Tool name must be a non-empty executable name or path.")

    looks_like_path = Path(raw).is_absolute() or any(separator in raw for separator in ("/", "\\"))
    if looks_like_path:
        executable = Path(raw).expanduser()
        if executable.is_file():
            return str(executable.resolve())
    else:
        resolved = shutil.which(raw)
        if resolved:
            return resolved
    raise click.ClickException(f"Required tool is unavailable: {raw}")


def compose_command(tool: str | Path, *arguments: object) -> tuple[str, ...]:
    """Builds a shell-free argv tuple after resolving ``tool``.

    Each argument remains one token.  Shell metacharacters therefore have no
    special meaning, which avoids the quoting and command-injection hazards of
    composing a command string.
    """
    argv = [require_tool(tool)]
    for argument in arguments:
        if argument is None:
            raise TypeError("command arguments cannot be None")
        token = os.fspath(argument) if isinstance(argument, os.PathLike) else str(argument)
        if "\x00" in token:
            raise ValueError("command arguments cannot contain NUL bytes")
        argv.append(token)
    return tuple(argv)


def run_command(
    argv: Sequence[str | os.PathLike[str]],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Runs an argv sequence without a shell and propagates a failing exit code."""
    if isinstance(argv, (str, bytes)) or not argv:
        raise TypeError("argv must be a non-empty sequence of tokens, not a command string")
    command = [os.fspath(token) for token in argv]
    if any("\x00" in token for token in command):
        raise ValueError("command tokens cannot contain NUL bytes")

    working_directory = None if cwd is None else Path(cwd).expanduser().resolve()
    if working_directory is not None and not working_directory.is_dir():
        raise click.ClickException(f"Working directory does not exist: {working_directory}")

    try:
        result = subprocess.run(
            command,
            cwd=working_directory,
            env=None if env is None else dict(env),
            shell=False,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise click.ClickException(f"Required tool is unavailable: {command[0]}") from exc
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    return result


@dataclass(frozen=True)
class ProjectRunner:
    """Runs shell-free commands from one validated project root."""

    root: Path

    @classmethod
    def discover(
        cls,
        start: str | Path | None = None,
        *,
        markers: Sequence[str] = DEFAULT_ROOT_MARKERS,
    ) -> "ProjectRunner":
        """Builds a runner for the nearest marked project root."""
        return cls(find_project_root(start, markers=markers))

    def path(self, relative: str | Path = ".") -> Path:
        """Returns a path guaranteed to remain within this project."""
        return project_path(self.root, relative)

    def command(self, tool: str | Path, *arguments: object) -> tuple[str, ...]:
        """Returns an argv tuple with a resolved executable."""
        return compose_command(tool, *arguments)

    def run(
        self,
        tool: str | Path,
        *arguments: object,
        cwd: str | Path = ".",
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Runs a command from a validated project-local directory."""
        return run_command(self.command(tool, *arguments), cwd=self.path(cwd), env=env)
