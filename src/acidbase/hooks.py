"""Report whether a repository's ruff pre-commit hook agrees with its uv.lock.

The a6a ecosystem treats ``uv.lock`` as the single source of truth for the
ruff version: CI runs ``uv run ruff`` and the canonical pre-commit hook runs
``uv run --frozen python -m ruff``. A remote ``astral-sh/ruff-pre-commit``
hook carries its own ``rev:`` pin and therefore a second, independently
drifting copy of ruff. ``acidbase hooks`` classifies each repository so that
drift is visible in a census and fails CI when asked to.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import click
import yaml
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from acidbase.security.profiles import list_skipped, load_config

_RUFF_REMOTE_MARKER = "ruff-pre-commit"
_RUFF_ENTRY_PATTERN = re.compile(r"(^|[\s/\\])ruff(\s|$)")
_UV_RUN_PATTERN = re.compile(r"(^|\s)uv\s+run(\s|$)")


class Severity(str, Enum):
    """How a state should affect the exit code."""

    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class HookState(str, Enum):
    """Relationship between the ruff hook and the locked ruff version."""

    LOCAL = "LOCAL"
    LOCAL_UNLOCKED = "LOCAL-UNLOCKED"
    LOCAL_NOT_SYNCED = "LOCAL-NOT-SYNCED"
    LOCAL_UNPINNED = "LOCAL-UNPINNED"
    ALIGNED = "ALIGNED"
    DRIFT = "DRIFT"
    REMOTE_UNLOCKED = "REMOTE-UNLOCKED"
    NO_RUFF_HOOK = "NO-RUFF-HOOK"
    NO_PRECOMMIT = "NO-PRECOMMIT"
    NO_LOCK = "NO-LOCK"
    UNREADABLE = "UNREADABLE"

    @property
    def severity(self) -> Severity:
        """Returns how seriously to take this state."""
        return _SEVERITIES[self]


_SEVERITIES: dict[HookState, Severity] = {
    # The hook resolves ruff through uv.lock; nothing can drift.
    HookState.LOCAL: Severity.OK,
    # The hook says `uv run ruff` but uv.lock has no ruff: the hook will fail.
    HookState.LOCAL_UNLOCKED: Severity.ERROR,
    # ruff is locked, but only as an extra or in a non-default group, so a plain
    # `uv sync` leaves it uninstalled and the hook fails on a fresh checkout.
    HookState.LOCAL_NOT_SYNCED: Severity.ERROR,
    # A local hook that calls a PATH ruff bypasses uv.lock entirely.
    HookState.LOCAL_UNPINNED: Severity.WARNING,
    # Remote pin happens to match today; it will not tomorrow.
    HookState.ALIGNED: Severity.WARNING,
    # Two copies of ruff disagree; hook and CI will fight.
    HookState.DRIFT: Severity.ERROR,
    # Only one ruff exists (the hook's), so no conflict, but ruff is unmanaged.
    HookState.REMOTE_UNLOCKED: Severity.INFO,
    HookState.NO_RUFF_HOOK: Severity.INFO,
    HookState.NO_PRECOMMIT: Severity.INFO,
    HookState.NO_LOCK: Severity.INFO,
    HookState.UNREADABLE: Severity.ERROR,
}


@dataclass(frozen=True)
class RemotePin:
    """One ``repo:``/``rev:`` pair found in a pre-commit config."""

    repo: str
    rev: str

    @property
    def label(self) -> str:
        """Returns a short ``<name>@<rev>`` label for reports."""
        return f"{self.repo.rstrip('/').rsplit('/', 1)[-1].removesuffix('.git')}@{self.rev}"


@dataclass(frozen=True)
class HookReport:
    """The classification of one repository."""

    path: Path
    state: HookState
    locked_ruff: str | None
    hook_ruff: str | None
    remote_pins: tuple[RemotePin, ...]
    detail: str = ""

    @property
    def name(self) -> str:
        """Returns the repository directory name."""
        return self.path.name

    @property
    def severity(self) -> Severity:
        """Returns the severity of the state."""
        return self.state.severity


def _normalize_rev(rev: Any) -> str:
    """Strips whitespace, a stray CR, and a leading ``v`` from a hook rev."""
    return str(rev).strip().removeprefix("v")


def locked_ruff_version(lock_path: Path) -> str | None:
    """Returns the ruff version pinned in ``uv.lock``, or None when ruff is absent."""
    with lock_path.open("rb") as handle:
        data = tomllib.load(handle)
    for package in data.get("package", []) or []:
        if isinstance(package, dict) and package.get("name") == "ruff":
            version = package.get("version")
            return str(version) if version is not None else None
    return None


def _requirement_name(value: Any) -> str | None:
    """Returns the canonical distribution name of a PEP 508 string, or None."""
    if not isinstance(value, str):
        return None
    try:
        return canonicalize_name(Requirement(value).name)
    except InvalidRequirement:
        return None


def ruff_in_default_groups(pyproject_path: Path) -> bool | None:
    """Returns whether ``ruff`` is reachable from what a plain ``uv sync`` installs.

    That is ``[project].dependencies`` (odd home for a linter, but installed) plus
    the default dependency groups: follows ``{include-group = ...}`` entries and
    honours ``tool.uv.default-groups`` (``"all"`` or a list; ``dev`` when unset).
    Extras under ``[project.optional-dependencies]`` do not count; ``uv sync``
    skips them unless asked. Returns None when pyproject.toml is missing or
    unreadable so the caller does not guess.
    """
    if not pyproject_path.is_file():
        return None
    try:
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8-sig"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    runtime = project.get("dependencies") if isinstance(project, dict) else None
    if any(_requirement_name(entry) == "ruff" for entry in (runtime if isinstance(runtime, list) else [])):
        return True
    groups = data.get("dependency-groups")
    groups = groups if isinstance(groups, dict) else {}
    uv_table = (data.get("tool") or {}).get("uv") or {}
    configured = uv_table.get("default-groups", ["dev"]) if isinstance(uv_table, dict) else ["dev"]
    pending = list(groups) if configured == "all" else [g for g in (configured or []) if isinstance(g, str)]
    seen: set[str] = set()
    while pending:
        group = pending.pop()
        if group in seen:
            continue
        seen.add(group)
        for entry in groups.get(group) or []:
            if isinstance(entry, dict) and isinstance(entry.get("include-group"), str):
                pending.append(entry["include-group"])
            elif _requirement_name(entry) == "ruff":
                return True
    return False


def _load_precommit(config_path: Path) -> list[dict[str, Any]]:
    """Returns the ``repos`` list of a pre-commit config, tolerating CRLF and BOMs."""
    text = config_path.read_text(encoding="utf-8-sig")
    data = yaml.safe_load(text)
    if data is None:
        return []
    if not isinstance(data, dict):
        raise click.ClickException(f"{config_path}: top level is not a mapping")
    repos = data.get("repos") or []
    if not isinstance(repos, list):
        raise click.ClickException(f"{config_path}: 'repos' is not a list")
    return [repo for repo in repos if isinstance(repo, dict)]


def _is_ruff_hook(hook: dict[str, Any]) -> bool:
    """Returns whether a local hook invokes ruff."""
    entry = str(hook.get("entry", ""))
    identifier = str(hook.get("id", ""))
    return identifier in {"ruff", "ruff-format"} or bool(_RUFF_ENTRY_PATTERN.search(entry))


def classify(repo_root: Path) -> HookReport:
    """Classifies one repository's ruff hook against its lockfile."""
    lock_path = repo_root / "uv.lock"
    config_path = repo_root / ".pre-commit-config.yaml"

    locked: str | None = None
    if lock_path.is_file():
        try:
            locked = locked_ruff_version(lock_path)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            return HookReport(repo_root, HookState.UNREADABLE, None, None, (), f"uv.lock: {exc}")

    if not config_path.is_file():
        state = HookState.NO_PRECOMMIT if lock_path.is_file() else HookState.NO_LOCK
        return HookReport(repo_root, state, locked, None, (), _locked_detail(locked))

    try:
        repos = _load_precommit(config_path)
    except (OSError, yaml.YAMLError, click.ClickException) as exc:
        return HookReport(repo_root, HookState.UNREADABLE, locked, None, (), f".pre-commit-config.yaml: {exc}")

    remote_pins: list[RemotePin] = []
    remote_ruff_rev: str | None = None
    local_ruff_entries: list[str] = []
    for repo in repos:
        url = str(repo.get("repo", ""))
        hooks = [hook for hook in (repo.get("hooks") or []) if isinstance(hook, dict)]
        if url == "local":
            local_ruff_entries.extend(str(hook.get("entry", "")) for hook in hooks if _is_ruff_hook(hook))
            continue
        rev = repo.get("rev")
        if rev is not None:
            remote_pins.append(RemotePin(url, str(rev).strip()))
        if _RUFF_REMOTE_MARKER in url and rev is not None:
            remote_ruff_rev = _normalize_rev(rev)

    pins = tuple(remote_pins)
    if local_ruff_entries:
        hook_ruff = "uv.lock" if all(_UV_RUN_PATTERN.search(entry) for entry in local_ruff_entries) else "PATH"
        if hook_ruff == "PATH":
            return HookReport(repo_root, HookState.LOCAL_UNPINNED, locked, hook_ruff, pins, _locked_detail(locked))
        if not lock_path.is_file():
            return HookReport(repo_root, HookState.NO_LOCK, locked, hook_ruff, pins, "local hook but no uv.lock")
        if locked is None:
            return HookReport(repo_root, HookState.LOCAL_UNLOCKED, locked, hook_ruff, pins, "ruff not in uv.lock")
        if ruff_in_default_groups(repo_root / "pyproject.toml") is False:
            return HookReport(
                repo_root,
                HookState.LOCAL_NOT_SYNCED,
                locked,
                hook_ruff,
                pins,
                f"locked={locked} but ruff is not in a default dependency group; `uv sync` will not install it",
            )
        return HookReport(repo_root, HookState.LOCAL, locked, hook_ruff, pins, f"locked={locked}")

    if remote_ruff_rev is None:
        if not lock_path.is_file():
            return HookReport(repo_root, HookState.NO_LOCK, locked, None, pins, "")
        return HookReport(repo_root, HookState.NO_RUFF_HOOK, locked, None, pins, _locked_detail(locked))

    if not lock_path.is_file():
        return HookReport(repo_root, HookState.NO_LOCK, locked, remote_ruff_rev, pins, f"hook={remote_ruff_rev}")
    if locked is None:
        return HookReport(
            repo_root, HookState.REMOTE_UNLOCKED, locked, remote_ruff_rev, pins, f"hook={remote_ruff_rev}"
        )
    if remote_ruff_rev == locked:
        return HookReport(
            repo_root, HookState.ALIGNED, locked, remote_ruff_rev, pins, f"hook={remote_ruff_rev}, locked={locked}"
        )
    return HookReport(
        repo_root,
        HookState.DRIFT,
        locked,
        remote_ruff_rev,
        pins,
        f"hook={remote_ruff_rev} {_relation(remote_ruff_rev, locked)} locked={locked}",
    )


def _locked_detail(locked: str | None) -> str:
    """Formats the locked-version fragment of a report line."""
    return f"locked={locked}" if locked else "ruff not locked"


def _relation(hook: str, locked: str) -> str:
    """Returns ``<``, ``>``, or ``!=`` describing how the hook rev compares to the lock."""
    try:
        hook_version, locked_version = Version(hook), Version(locked)
    except InvalidVersion:
        return "!="
    if hook_version < locked_version:
        return "<"
    if hook_version > locked_version:
        return ">"
    return "!="


def discover_repositories(roots: list[Path], skip: set[str]) -> list[Path]:
    """Returns every immediate child of ``roots`` that is a Python project."""
    found: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir(), key=lambda p: p.name.casefold()):
            if not child.is_dir() or child.name in skip or child.name.startswith("."):
                continue
            if (child / "pyproject.toml").is_file():
                found.append(child)
    return found


def _configured_roots(config_path: Path | None) -> tuple[list[Path], set[str]]:
    """Returns the ``defaults.roots`` and ``defaults.skip`` lists from the security config."""
    config = load_config(config_path)
    defaults = config.get("defaults") or {}
    raw_roots = defaults.get("roots") or []
    roots = [Path(str(root)).expanduser() for root in raw_roots]
    return roots, set(list_skipped(config))


def _format_report(report: HookReport, *, show_pins: bool) -> str:
    """Formats one fixed-width report line."""
    line = f"{report.name:<26} {report.state.value:<16} {report.detail}".rstrip()
    if show_pins and report.remote_pins:
        line += f"  | pins: {', '.join(pin.label for pin in report.remote_pins)}"
    return line


def _exit_code(reports: list[HookReport], *, strict: bool) -> int:
    """Returns 1 when any report is an error (or a warning under --strict)."""
    failing = {Severity.ERROR, Severity.WARNING} if strict else {Severity.ERROR}
    return 1 if any(report.severity in failing for report in reports) else 0


@click.command("hooks")
@click.argument("targets", nargs=-1, type=click.Path(path_type=Path, file_okay=False, exists=True))
@click.option(
    "--all",
    "scan_all",
    is_flag=True,
    help="Scan every Python project directly under the roots in config/security_patch.toml.",
)
@click.option("--config", "config_path", type=click.Path(path_type=Path, dir_okay=False), help="Alternate roots file.")
@click.option("--strict", is_flag=True, help="Also fail on warnings (remote pin that merely happens to match).")
@click.option("--no-pins", is_flag=True, help="Hide the trailing list of remaining remote rev pins.")
def hooks_command(
    targets: tuple[Path, ...], scan_all: bool, config_path: Path | None, strict: bool, no_pins: bool
) -> None:
    """Report whether ruff pre-commit hooks agree with uv.lock.

    TARGETS are repository roots (default: the current directory). With --all
    the roots in config/security_patch.toml are enumerated instead. Exit code 1
    means at least one DRIFT, LOCAL-UNLOCKED, LOCAL-NOT-SYNCED, or UNREADABLE
    repository (plus ALIGNED/LOCAL-UNPINNED under --strict); everything else
    is informational.
    """
    if scan_all and targets:
        raise click.UsageError("Pass either TARGETS or --all, not both.")
    if scan_all:
        roots, skip = _configured_roots(config_path)
        if not roots:
            raise click.ClickException("No defaults.roots configured; pass TARGETS or --config.")
        repositories = discover_repositories(roots, skip)
    else:
        repositories = [target.resolve() for target in (targets or (Path("."),))]
    if not repositories:
        raise click.ClickException("No Python projects found under the configured roots.")

    reports = [classify(repo) for repo in repositories]
    for report in reports:
        click.echo(_format_report(report, show_pins=not no_pins))

    counts: dict[HookState, int] = {}
    for report in reports:
        counts[report.state] = counts.get(report.state, 0) + 1
    summary = ", ".join(f"{state.value}={count}" for state, count in sorted(counts.items(), key=lambda kv: kv[0].value))
    click.echo(f"Summary: {summary}")

    code = _exit_code(reports, strict=strict)
    if code:
        raise SystemExit(code)
