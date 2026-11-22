"""
Tests the shared development-cache cleaner.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from acidbase import clean
from acidbase.clean import clean_command, find_dev_caches, run_clean
from acidbase.cli import main

CACHES = (
    ".coverage",
    ".coverage.kulcs.1234.567890",
    ".hypothesis/examples/a",
    ".mypy_cache/3.12/demo.data.json",
    ".pytest_cache/v/cache/lastfailed",
    ".ruff_cache/0.16.0/123",
    "coverage.xml",
    "htmlcov/index.html",
    "src/demo/__pycache__/cli.cpython-312.pyc",
    "src/demo/stray.pyc",
    "tests/unit/__pycache__/test_cli.cpython-312.pyc",
)
KEEPERS = (
    ".coveragerc",
    ".env",
    "artifact/export.json",
    "backup.log",
    "data/raw.csv",
    "src/demo/cli.py",
    "state/last_run.json",
)


def _write(root: Path, relative: str, content: str = "x") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _make_project(root: Path) -> Path:
    _write(root, "pyproject.toml", '[project]\nname = "demo"\nversion = "0.1.0"\n')
    for relative in (*CACHES, *KEEPERS):
        _write(root, relative)
    return root


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True)


def test_run_clean_removes_the_inventory_and_nothing_else(tmp_path: Path) -> None:
    """Every named cache goes, while ignored-looking state, data and source stay."""
    project = _make_project(tmp_path / "demo")

    run_clean(root=project)

    for relative in CACHES:
        assert not (project / relative).exists(), relative
    for relative in ("src/demo/__pycache__", "htmlcov", ".pytest_cache", ".hypothesis"):
        assert not (project / relative).exists(), relative
    for relative in KEEPERS:
        assert (project / relative).is_file(), relative


def test_walk_skips_virtual_environments_dependency_trees_and_nested_repositories(tmp_path: Path) -> None:
    """Caches inside trees the project does not own stay where they are."""
    project = _make_project(tmp_path / "demo")
    foreign = (
        ".venv/Lib/site-packages/pkg/__pycache__/a.pyc",
        "env/__pycache__/b.pyc",
        "frontend/node_modules/lib/__pycache__/c.pyc",
        "vendor/other/__pycache__/d.pyc",
    )
    for relative in foreign:
        _write(project, relative)
    _write(project, "env/pyvenv.cfg", "home = C:\\Python312\n")
    (project / "vendor" / "other" / ".git").mkdir()

    run_clean(root=project)

    for relative in foreign:
        assert (project / relative).is_file(), relative


def test_tracked_cache_named_paths_are_kept_and_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A cache-named path Git tracks is a fixture or a published report, not a cache."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    project = _make_project(tmp_path / "demo")
    _git(project, "init", "-q")
    _write(project, "tests/fixture/htmlcov/index.html")
    _write(project, "tests/fixture/coverage.xml")
    _git(project, "add", "tests/fixture")

    run_clean(root=project)

    assert (project / "tests/fixture/htmlcov/index.html").is_file()
    assert (project / "tests/fixture/coverage.xml").is_file()
    assert not (project / "htmlcov").exists()
    output = capsys.readouterr().out
    assert "Kept tests/fixture/coverage.xml: Git tracks it." in output
    assert "Kept tests/fixture/htmlcov: Git tracks it." in output


def test_failing_git_inside_a_work_tree_removes_nothing(tmp_path: Path) -> None:
    """Without the list of tracked files, guessing would put them at risk, so the clean stops."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    project = _make_project(tmp_path / "demo")
    (project / ".git").mkdir()

    with pytest.raises(click.ClickException, match="Could not list the files Git tracks"):
        run_clean(root=project)

    for relative in CACHES:
        assert (project / relative).exists(), relative


def test_dry_run_lists_sizes_and_removes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A dry run names each cache with its size and leaves the tree as it was."""
    project = _make_project(tmp_path / "demo")
    _write(project, "htmlcov/big.html", "y" * 2048)

    run_clean(dry_run=True, root=project)

    for relative in CACHES:
        assert (project / relative).exists(), relative
    output = capsys.readouterr().out
    assert "  htmlcov  2.0 KiB" in output
    assert "demo: would remove 11 items" in output
    assert "Dry run: nothing was removed." in output


def test_one_stuck_cache_is_reported_and_the_rest_still_go(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A cache held open by another process does not stop the others."""
    project = _make_project(tmp_path / "demo")
    real_remove = clean._remove

    def remove(entry: clean.CacheEntry) -> None:
        if entry.relative == "htmlcov":
            raise PermissionError(13, "Access is denied")
        real_remove(entry)

    monkeypatch.setattr(clean, "_remove", remove)

    run_clean(root=project)

    assert (project / "htmlcov").is_dir()
    assert not (project / ".pytest_cache").exists()
    captured = capsys.readouterr()
    assert "Could not remove htmlcov: Access is denied" in captured.err
    assert "1 item could not be removed." in captured.out


def test_every_removal_failing_fails_the_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When nothing can be removed, the run is a failure, not a quiet success."""
    project = _make_project(tmp_path / "demo")

    def remove(entry: clean.CacheEntry) -> None:
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(clean, "_remove", remove)

    with pytest.raises(click.ClickException, match="Could not remove any of the 11 items"):
        run_clean(root=project)


def test_a_linked_cache_folder_is_neither_followed_nor_removed(tmp_path: Path) -> None:
    """A link named like a cache may point anywhere, so the walk leaves it alone."""
    project = _make_project(tmp_path / "demo")
    outside = _write(tmp_path, "outside/keep.txt").parent
    try:
        os.symlink(outside, project / "src" / "__pycache__", target_is_directory=True)
    except OSError:
        pytest.skip("creating a symbolic link needs Developer Mode or elevation here")

    run_clean(root=project)

    assert (outside / "keep.txt").is_file()
    assert (project / "src" / "__pycache__").is_symlink()


def test_clean_project_reports_nothing_to_do(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A second run finds nothing and says so."""
    project = _make_project(tmp_path / "demo")
    run_clean(root=project)
    capsys.readouterr()

    run_clean(root=project)

    assert capsys.readouterr().out == "demo: no development caches found.\n"
    assert find_dev_caches(project).found == ()


def test_clean_command_works_from_a_subdirectory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The command finds the project root from wherever it starts, as bump does."""
    project = _make_project(tmp_path / "demo")
    monkeypatch.chdir(project / "src" / "demo")

    result = CliRunner().invoke(clean_command, [])

    assert result.exit_code == 0, result.output
    assert "demo: removed 11 items" in result.stdout
    assert not (project / ".pytest_cache").exists()


def test_acidbase_cli_exports_clean_command() -> None:
    """The shared command is mounted in acidbase itself as well as in child CLIs."""
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert main.commands["clean"] is clean_command
