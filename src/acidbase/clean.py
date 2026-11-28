"""
Shared development-cache cleaner for Python repositories.

``clean`` removes one fixed inventory of reproducible caches that Python tools
leave in a project: bytecode, test, lint and type-check caches, and coverage
output. The inventory names what may go, so a ``.gitignore`` never decides it:
an ignored path can be a ``.env``, run state or data, and only a named cache is
safe to delete. Anything Git tracks stays, as do virtual environments,
``node_modules`` and nested repositories.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import click

from acidbase.workflow import compose_command, find_project_root

CACHE_DIRECTORIES: frozenset[str] = frozenset(
    {".hypothesis", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "htmlcov"}
)
CACHE_FILES: tuple[str, ...] = ("*.pyc", "*.pyo", ".coverage", ".coverage.*", "coverage.xml")
PRUNED_DIRECTORIES: frozenset[str] = frozenset({".git", ".venv", "node_modules"})


@dataclass(frozen=True)
class CacheEntry:
    """
    Describes one cache found below the project root.
    """

    path: Path
    relative: str
    size: int


@dataclass(frozen=True)
class CacheScan:
    """
    Holds the caches to remove and the cache-named paths kept because Git tracks them.
    """

    found: tuple[CacheEntry, ...]
    kept: tuple[str, ...]


def _inside_git_work_tree(root: Path) -> bool:
    """
    Tells whether ``root`` or one of its ancestors holds a ``.git`` folder or file.
    """
    return any((directory / ".git").exists() for directory in (root, *root.parents))


def _tracked_paths(root: Path) -> tuple[frozenset[str], frozenset[str]]:
    """
    Returns the files Git tracks below ``root`` and the folders holding them, relative to ``root``.

    A cache-named path that Git tracks is a fixture or a published report, so it stays. Outside a work
    tree nothing is tracked. Inside one, a failing ``git`` stops the clean, because guessing would put
    tracked files at risk.
    """
    if not _inside_git_work_tree(root):
        return frozenset(), frozenset()
    result = subprocess.run(
        compose_command("git", "ls-files", "-z"),
        cwd=root,
        capture_output=True,
        shell=False,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        suffix = f"\n{detail}" if detail else ""
        raise click.ClickException(f"Could not list the files Git tracks, so nothing was removed.{suffix}")
    files = frozenset(item for item in result.stdout.decode("utf-8", errors="surrogateescape").split("\0") if item)
    folders = frozenset(
        parent.as_posix() for item in files for parent in PurePosixPath(item).parents if parent != PurePosixPath(".")
    )
    return files, folders


def _size(path: Path) -> int:
    """
    Returns the bytes a file or folder holds, without following links.
    """
    if not path.is_dir() or path.is_symlink():
        return path.lstat().st_size
    total = 0
    for directory, _folders, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(directory, name)).st_size
            except OSError:
                continue  # to skip a file that vanished mid-scan
    return total


def _is_link(path: Path) -> bool:
    """
    Tells whether ``path`` is a symbolic link or a Windows junction.
    """
    return path.is_symlink() or os.path.isjunction(path)


def _is_foreign_tree(path: Path) -> bool:
    """
    Tells whether ``path`` is a virtual environment, a dependency tree or a nested repository.
    """
    return path.name in PRUNED_DIRECTORIES or (path / "pyvenv.cfg").is_file() or (path / ".git").exists()


def find_dev_caches(root: Path) -> CacheScan:
    """
    Returns the development caches below ``root`` in a stable, name-ordered walk.

    The walk never enters a link, a junction, a virtual environment, ``node_modules`` or a nested
    repository, so it touches only this project's own tree.
    """
    tracked_files, tracked_folders = _tracked_paths(root)
    found: list[CacheEntry] = []
    kept: list[str] = []
    for directory, folders, files in os.walk(root):
        here = Path(directory)
        descend: list[str] = []
        for name in sorted(folders):
            path = here / name
            if _is_link(path):
                continue
            relative = path.relative_to(root).as_posix()
            if name in CACHE_DIRECTORIES:
                if relative in tracked_folders:
                    kept.append(relative)
                else:
                    found.append(CacheEntry(path=path, relative=relative, size=_size(path)))
                continue
            if not _is_foreign_tree(path):
                descend.append(name)
        folders[:] = descend
        for name in sorted(files):
            if not any(fnmatch.fnmatchcase(name, pattern) for pattern in CACHE_FILES):
                continue
            path = here / name
            relative = path.relative_to(root).as_posix()
            if relative in tracked_files:
                kept.append(relative)
            else:
                found.append(CacheEntry(path=path, relative=relative, size=_size(path)))
    return CacheScan(found=tuple(found), kept=tuple(kept))


def _remove(entry: CacheEntry) -> None:
    """
    Deletes one cache, removing a link itself rather than its target.
    """
    if entry.path.is_dir() and not _is_link(entry.path):
        shutil.rmtree(entry.path)
    else:
        entry.path.unlink()


def _format_size(size: int) -> str:
    """
    Returns ``size`` in the largest binary unit that keeps it at or above one.
    """
    for unit, factor in (("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
        if size >= factor:
            return f"{size / factor:.1f} {unit}"
    return f"{size} B"


def _items(count: int) -> str:
    """
    Returns ``count`` with the matching form of "item".
    """
    return f"{count} item" if count == 1 else f"{count} items"


def run_clean(*, dry_run: bool = False, root: Path | None = None) -> None:
    """
    Finds and removes the development caches of the project around ``root`` or the working directory.

    A cache that cannot be removed, for example because a running process holds it open, is reported
    and skipped. The command fails only when every removal fails.
    """
    project_root = find_project_root(root)
    scan = find_dev_caches(project_root)
    for relative in scan.kept:
        click.echo(f"Kept {relative}: Git tracks it.")
    if not scan.found:
        click.echo(f"{project_root.name}: no development caches found.")
        return
    total = sum(entry.size for entry in scan.found)
    if dry_run:
        for entry in scan.found:
            click.echo(f"  {entry.relative}  {_format_size(entry.size)}")
        click.echo(f"{project_root.name}: would remove {_items(len(scan.found))}, {_format_size(total)}.")
        click.echo("Dry run: nothing was removed.")
        return
    failed: list[CacheEntry] = []
    for entry in scan.found:
        try:
            _remove(entry)
        except OSError as exc:
            failed.append(entry)
            click.echo(f"Could not remove {entry.relative}: {exc.strerror or exc}", err=True)
    removed = [entry for entry in scan.found if entry not in failed]
    if not removed:
        raise click.ClickException(f"Could not remove any of the {_items(len(scan.found))}.")
    freed = sum(entry.size for entry in removed)
    summary = f"{project_root.name}: removed {_items(len(removed))}, {_format_size(freed)}."
    if failed:
        summary += f" {_items(len(failed))} could not be removed."
    click.echo(summary)


@click.command("clean")
@click.option("--dry-run", is_flag=True, help="List the caches and their sizes without removing anything.")
def clean_command(dry_run: bool) -> None:
    """
    Removes Python development caches from this project.

    The caches are bytecode (__pycache__, *.pyc), the pytest, Hypothesis, ruff and mypy caches, and
    coverage output (.coverage, coverage.xml, htmlcov). Virtual environments, node_modules, nested
    repositories and anything Git tracks stay, and so does every other file, ignored or not.
    """
    run_clean(dry_run=dry_run)
