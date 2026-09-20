"""Tests for reusable, project-owned workflow mechanics."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import click
import pytest

from acidbase.workflow import ProjectRunner, compose_command, find_project_root, project_path, require_tool, run_command


def test_find_project_root_walks_up_from_file(tmp_path: Path) -> None:
    """The nearest marked ancestor wins when discovery starts at a file."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    source = tmp_path / "src" / "demo" / "cli.py"
    source.parent.mkdir(parents=True)
    source.write_text("", encoding="utf-8")

    assert find_project_root(source) == tmp_path


def test_find_project_root_is_strict_when_marker_is_absent(tmp_path: Path) -> None:
    """Discovery never guesses that an unmarked working directory is a project."""
    with pytest.raises(click.ClickException, match="Could not find a project root"):
        find_project_root(tmp_path)


def test_find_project_root_rejects_invalid_markers(tmp_path: Path) -> None:
    """Absolute and empty markers cannot redirect discovery outside the tree."""
    with pytest.raises(ValueError, match="relative, non-empty"):
        find_project_root(tmp_path, markers=("",))
    with pytest.raises(ValueError, match="relative, non-empty"):
        find_project_root(tmp_path, markers=(str(tmp_path / "marker"),))
    with pytest.raises(ValueError, match="relative, non-empty"):
        find_project_root(tmp_path, markers=("../pyproject.toml",))


def test_project_path_rejects_escape(tmp_path: Path) -> None:
    """Project-local working directories cannot traverse above the root."""
    with pytest.raises(click.ClickException, match="escapes the project root"):
        project_path(tmp_path, "../outside")


def test_require_tool_resolves_path_lookup() -> None:
    """A bare tool name is resolved once through the executable search path."""
    with patch("shutil.which", return_value="/tools/uv"):
        assert require_tool("uv") == "/tools/uv"


def test_require_tool_reports_missing_executable() -> None:
    """Missing tools fail before subprocess dispatch with a useful name."""
    with patch("shutil.which", return_value=None), pytest.raises(click.ClickException, match="missing-tool"):
        require_tool("missing-tool")


def test_compose_command_keeps_each_argument_as_one_token() -> None:
    """Shell punctuation remains data because commands are represented as argv."""
    with patch("shutil.which", return_value="/tools/demo"):
        command = compose_command("demo", "value; still-one-token", Path("two words"))
    assert command == ("/tools/demo", "value; still-one-token", "two words")


def test_run_command_rejects_command_strings() -> None:
    """Callers must supply argv and cannot accidentally opt into shell parsing."""
    with pytest.raises(TypeError, match="sequence of tokens"):
        run_command("uv run pytest")


def test_run_command_propagates_exit_code(tmp_path: Path) -> None:
    """A child failure becomes the CLI process exit status."""
    completed = subprocess.CompletedProcess(["demo"], 17)
    with patch("subprocess.run", return_value=completed) as mocked, pytest.raises(SystemExit) as raised:
        run_command(["demo"], cwd=tmp_path)

    assert raised.value.code == 17
    assert mocked.call_args.kwargs["shell"] is False


def test_project_runner_validates_local_working_directory(tmp_path: Path) -> None:
    """The convenience runner applies the project-root boundary to cwd."""
    runner = ProjectRunner(tmp_path)
    with pytest.raises(click.ClickException, match="escapes the project root"):
        runner.path("../outside")
