"""Keep the fleet manifest: which repositories consume acidbase, where they live, and how to call them.

The manifest is a TOML file (``config/fleet.toml`` in a metarepo checkout) with one ``[[repo]]`` table
per consumer: its name, host, path, CLI name, and optional mypy target and note. It describes a
portfolio, so the file itself belongs to the private side; this module is the tooling around it:

* ``acidbase fleet add`` registers a repository, inferring name, host, path, and CLI. Repo-creation
  scripts call it as their last step, so new repositories join without hand edits.
* ``acidbase fleet census`` re-derives the fleet from disk (every registration plus the immediate
  children of ``[census.roots]``) and reports drift in both directions.
* ``acidbase fleet list`` renders the manifest for runbook loops (JSON, TSV) or for people (table,
  Markdown).
* ``acidbase fleet remove`` drops a registration, e.g. before re-adding a repository that moved.

Paths are stored the way their own host spells them (``C:\\repos\\x`` on Windows, ``~/x`` under WSL)
and translated when the other host reads them, through the optional ``[hosts]`` table. Entries are
kept in abecedarian order of names (:func:`acidbase.collation.abc_key`); writes go through tomlkit,
so comments and hand formatting survive.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sys
import tomllib
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any, TypeVar

import click
import tomlkit
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from acidbase.cli_utils import group
from acidbase.collation import abc_key

FLEET_FILE_ENV = "ACIDBASE_FLEET_FILE"
WINDOWS = "windows"
WSL = "wsl"
_RELATIVE_FLEET_FILE = Path("config") / "fleet.toml"
_COMMAND_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_PUSH_ALIAS = "push"
_FORMATS = ("table", "json", "tsv", "markdown")

_F = TypeVar("_F", bound=Callable[..., Any])


@dataclass(frozen=True)
class FleetEntry:
    """One registered consumer repository."""

    name: str
    host: str
    path: str
    cli: str
    mypy: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class Fleet:
    """A parsed fleet manifest together with the tomlkit document it was read from."""

    path: Path
    document: tomlkit.TOMLDocument
    entries: tuple[FleetEntry, ...]
    roots: dict[str, tuple[str, ...]]
    ignore: frozenset[str]
    hosts: dict[str, dict[str, str]]


class CensusState(str, Enum):
    """What the census concluded about one repository."""

    OK = "OK"
    UNREGISTERED = "UNREGISTERED"
    MISSING = "MISSING"
    NOT_A_CONSUMER = "NOT-A-CONSUMER"
    CLI_MISMATCH = "CLI-MISMATCH"
    UNREADABLE = "UNREADABLE"
    UNREACHABLE = "UNREACHABLE"

    @property
    def failing(self) -> bool:
        """Returns whether the state is drift (unreachable hosts are informational)."""
        return self not in {CensusState.OK, CensusState.UNREACHABLE}


@dataclass(frozen=True)
class CensusRow:
    """One line of a census report."""

    name: str
    host: str
    path: str
    state: CensusState
    detail: str = ""


def current_host() -> str:
    """
    Returns the host label of the running interpreter.
    Returns:
        ``windows``, ``wsl``, or ``sys.platform`` for any other system
    """
    if os.name == "nt":
        return WINDOWS
    if sys.platform.startswith("linux") and (
        os.environ.get("WSL_DISTRO_NAME") or "microsoft" in platform.release().lower()
    ):
        return WSL
    return sys.platform


def resolve_fleet_file(option: Path | None = None, *, start: Path | None = None) -> Path:
    """
    Returns the fleet manifest to use.
    The order is: the explicit option, then ``$ACIDBASE_FLEET_FILE``, then ``config/fleet.toml`` found
    by walking up from ``start`` (the current directory by default).
    Raises:
        click.ClickException: If an explicit location does not exist or nothing is found
    """
    if option is not None:
        if not option.is_file():
            raise click.ClickException(f"Fleet manifest not found: {option}")
        return option
    env_value = os.environ.get(FLEET_FILE_ENV)
    if env_value:
        candidate = Path(env_value).expanduser()
        if not candidate.is_file():
            raise click.ClickException(f"${FLEET_FILE_ENV} points to a missing file: {candidate}")
        return candidate
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / _RELATIVE_FLEET_FILE
        if candidate.is_file():
            return candidate
    raise click.ClickException(
        f"No fleet manifest found: pass --fleet-file, set ${FLEET_FILE_ENV}, or run inside the metarepo checkout."
    )


def _require_text(raw: Mapping[str, Any], key: str, where: str) -> str:
    """Returns a required, non-empty string field of a manifest table."""
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise click.ClickException(f"{where}: '{key}' must be a non-empty string.")
    return value.strip()


def _optional_text(raw: Mapping[str, Any], key: str, where: str) -> str | None:
    """Returns an optional string field of a manifest table, None when absent or blank."""
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise click.ClickException(f"{where}: '{key}' must be a string.")
    return value.strip() or None


def _parse_entry(raw: Any, index: int, source: Path) -> FleetEntry:
    """Validates one ``[[repo]]`` table."""
    where = f"{source} [[repo]] #{index}"
    if not isinstance(raw, Mapping):
        raise click.ClickException(f"{where}: expected a table.")
    cli = _require_text(raw, "cli", where)
    if not _COMMAND_NAME.fullmatch(cli):
        raise click.ClickException(f"{where}: invalid CLI name {cli!r}.")
    return FleetEntry(
        name=_require_text(raw, "name", where),
        host=_require_text(raw, "host", where),
        path=_require_text(raw, "path", where),
        cli=cli,
        mypy=_optional_text(raw, "mypy", where),
        note=_optional_text(raw, "note", where),
    )


def _string_lists(raw: Any, where: str) -> dict[str, tuple[str, ...]]:
    """Validates a ``{host: [path, ...]}`` table."""
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise click.ClickException(f"{where} must be a table of host = [paths].")
    result: dict[str, tuple[str, ...]] = {}
    for host, values in raw.items():
        if not isinstance(values, list) or not all(isinstance(value, str) and value for value in values):
            raise click.ClickException(f"{where}.{host} must be a list of non-empty strings.")
        result[str(host)] = tuple(values)
    return result


def load_fleet(path: Path) -> Fleet:
    """
    Parses and validates a fleet manifest.
    Raises:
        click.ClickException: If the file cannot be read or violates the schema
    """
    try:
        document = tomlkit.parse(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, tomlkit.exceptions.ParseError) as exc:
        raise click.ClickException(f"Cannot read fleet manifest {path}: {exc}") from exc
    data = document.unwrap()
    raw_entries = data.get("repo", [])
    if not isinstance(raw_entries, list):
        raise click.ClickException(f"{path}: 'repo' must be an array of tables ([[repo]]).")
    entries: list[FleetEntry] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_entries, 1):
        entry = _parse_entry(raw, index, path)
        key = (entry.name.casefold(), entry.host)
        if key in seen:
            raise click.ClickException(f"{path}: {entry.name} ({entry.host}) is registered twice.")
        seen.add(key)
        entries.append(entry)
    census = data.get("census") or {}
    if not isinstance(census, Mapping):
        raise click.ClickException(f"{path}: [census] must be a table.")
    ignore = census.get("ignore") or []
    if not isinstance(ignore, list) or not all(isinstance(name, str) for name in ignore):
        raise click.ClickException(f"{path}: census.ignore must be a list of directory names.")
    hosts_raw = data.get("hosts") or {}
    if not isinstance(hosts_raw, Mapping) or not all(isinstance(value, Mapping) for value in hosts_raw.values()):
        raise click.ClickException(f"{path}: [hosts] must contain one table per host.")
    hosts = {str(host): {str(k): str(v) for k, v in table.items()} for host, table in hosts_raw.items()}
    return Fleet(
        path=path,
        document=document,
        entries=tuple(entries),
        roots=_string_lists(census.get("roots"), f"{path}: census.roots"),
        ignore=frozenset(name.casefold() for name in ignore),
        hosts=hosts,
    )


def save_fleet(fleet: Fleet) -> None:
    """Writes the manifest atomically with LF line endings."""
    text = tomlkit.dumps(fleet.document).replace("\r\n", "\n")
    temporary = fleet.path.with_name(f".{fleet.path.name}.acidbase-{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(text.encode("utf-8"))
        os.replace(temporary, fleet.path)
    finally:
        temporary.unlink(missing_ok=True)


def _toml_path(value: str) -> Any:
    """Returns a literal TOML string for paths (no doubled backslashes) when the value allows it."""
    return tomlkit.string(value, literal=True) if "'" not in value and "\n" not in value else value


def _entry_table(entry: FleetEntry) -> Any:
    """Renders an entry as a tomlkit table followed by a blank line."""
    table = tomlkit.table()
    table["name"] = entry.name
    table["host"] = entry.host
    table["path"] = _toml_path(entry.path)
    table["cli"] = entry.cli
    if entry.mypy:
        table["mypy"] = entry.mypy
    if entry.note:
        table["note"] = entry.note
    table.add(tomlkit.nl())
    return table


def _same_path(left: str, right: str, host: str) -> bool:
    """Compares two stored paths the way their host would (case-insensitively on Windows)."""
    if host == WINDOWS:
        return PureWindowsPath(left) == PureWindowsPath(right)
    return PurePosixPath(left) == PurePosixPath(right)


def add_entry(fleet: Fleet, entry: FleetEntry) -> bool:
    """
    Inserts ``entry`` into the document at its abecedarian position.
    Returns:
        False when the same repository is already registered, True when the document changed
    Raises:
        click.ClickException: If the name is registered on that host with another path or CLI
    """
    for existing in fleet.entries:
        if existing.name.casefold() != entry.name.casefold() or existing.host != entry.host:
            continue
        if _same_path(existing.path, entry.path, entry.host) and existing.cli == entry.cli:
            return False
        raise click.ClickException(
            f"{existing.name} ({existing.host}) is already registered at {existing.path} with CLI {existing.cli!r}; "
            f"run `acidbase fleet remove {existing.name} --host {existing.host}` first if it moved."
        )
    aot = fleet.document.get("repo")
    if aot is None:
        aot = tomlkit.aot()
        fleet.document.append("repo", aot)
    position = next(
        (index for index, other in enumerate(fleet.entries) if abc_key(other.name) > abc_key(entry.name)),
        len(fleet.entries),
    )
    aot.insert(position, _entry_table(entry))
    return True


def remove_entry(fleet: Fleet, name: str, host: str | None = None) -> FleetEntry:
    """
    Deletes one registration from the document and returns it.
    Raises:
        click.ClickException: If nothing matches or the name is ambiguous across hosts
    """
    matches = [
        index
        for index, entry in enumerate(fleet.entries)
        if entry.name.casefold() == name.casefold() and (host is None or entry.host == host)
    ]
    if not matches:
        suffix = f" on {host}" if host else ""
        raise click.ClickException(f"{name} is not registered{suffix}.")
    if len(matches) > 1:
        hosts = ", ".join(fleet.entries[index].host for index in matches)
        raise click.ClickException(f"{name} is registered on several hosts ({hosts}); pass --host.")
    del fleet.document["repo"][matches[0]]
    return fleet.entries[matches[0]]


def stored_path(local: PurePath, host: str, home: PurePath | None = None) -> str:
    """
    Returns how the manifest spells ``local`` for ``host``.
    Windows paths are stored absolute; other hosts store paths under the home directory as ``~/...``.
    """
    if host == WINDOWS:
        return str(PureWindowsPath(local))
    posix = PurePosixPath(local.as_posix())
    base = PurePosixPath((home if home is not None else Path.home()).as_posix())
    try:
        relative = posix.relative_to(base)
    except ValueError:
        return str(posix)
    return f"~/{relative.as_posix()}" if relative.parts else "~"


def native_location(
    local: PurePath,
    here: str,
    hosts: Mapping[str, Mapping[str, str]],
    home: PurePath | None = None,
) -> tuple[str, str]:
    """
    Returns the ``(host, stored path)`` that owns a repository seen at ``local`` from ``here``.
    A repository on a Windows drive belongs to ``windows`` even when WSL registers it through
    ``/mnt/<drive>``, and one under ``hosts.windows.wsl_home`` belongs to ``wsl`` even when Windows
    registers it, so each host can later translate the other's registrations.
    """
    if here == WSL:
        mount = PurePosixPath(hosts.get(WSL, {}).get("windows_mount", "/mnt"))
        posix = PurePosixPath(local.as_posix())
        try:
            relative = posix.relative_to(mount)
        except ValueError:
            relative = None
        if relative is not None and relative.parts and re.fullmatch(r"[A-Za-z]", relative.parts[0]):
            drive = f"{relative.parts[0].upper()}:\\"
            return WINDOWS, str(PureWindowsPath(drive, *relative.parts[1:]))
        return WSL, stored_path(local, WSL, home)
    if here == WINDOWS:
        wsl_home = hosts.get(WINDOWS, {}).get("wsl_home")
        if wsl_home:
            try:
                relative_windows = PureWindowsPath(local).relative_to(PureWindowsPath(wsl_home))
            except ValueError:
                relative_windows = None
            if relative_windows is not None:
                return WSL, f"~/{relative_windows.as_posix()}" if relative_windows.parts else "~"
        return WINDOWS, stored_path(local, WINDOWS)
    return here, stored_path(local, here, home)


def _home_relative(path: str) -> PurePosixPath | None:
    """Returns the part after ``~/`` (empty for ``~``), or None for other spellings."""
    if path == "~":
        return PurePosixPath()
    if path.startswith("~/"):
        return PurePosixPath(path[2:])
    return None


def localize(
    path: str,
    host: str,
    here: str,
    hosts: Mapping[str, Mapping[str, str]],
    home: PurePath | None = None,
) -> str | None:
    """
    Returns ``path`` (as spelled on ``host``) in a form the running host ``here`` can open.
    Same-host paths only get ``~`` expanded. Windows sees WSL home paths through
    ``hosts.windows.wsl_home``; WSL sees Windows drives under ``hosts.wsl.windows_mount`` (``/mnt``).
    Returns:
        The local spelling, or None when there is no route between the two hosts
    """
    relative = _home_relative(path)
    if host == here:
        if relative is None:
            return path
        base = home if home is not None else Path.home()
        return str(Path(base, *relative.parts))
    if here == WINDOWS and host == WSL:
        wsl_home = hosts.get(WINDOWS, {}).get("wsl_home")
        if not wsl_home or relative is None:
            return None
        return str(PureWindowsPath(wsl_home, *relative.parts))
    if here == WSL and host == WINDOWS:
        windows_path = PureWindowsPath(path)
        if not re.fullmatch(r"[A-Za-z]:", windows_path.drive):
            return None
        mount = hosts.get(WSL, {}).get("windows_mount", "/mnt")
        return str(PurePosixPath(mount, windows_path.drive[0].lower(), *windows_path.parts[1:]))
    return None


def _requirement_name(value: Any) -> str | None:
    """Returns the canonical distribution name of a PEP 508 string, or None."""
    if not isinstance(value, str):
        return None
    try:
        return canonicalize_name(Requirement(value).name)
    except InvalidRequirement:
        return None


def read_project(root: Path) -> dict[str, Any] | None:
    """
    Returns the parsed ``pyproject.toml`` of ``root``.
    Raises:
        ValueError: If the file exists but cannot be parsed
    Returns:
        The parsed table, or None when there is no pyproject.toml
    """
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return None
    try:
        return tomllib.loads(pyproject.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"pyproject.toml: {exc}") from exc


def _project_table(data: Mapping[str, Any]) -> Mapping[str, Any]:
    """Returns ``[project]`` or an empty mapping."""
    project = data.get("project")
    return project if isinstance(project, Mapping) else {}


def is_metarepo(data: Mapping[str, Any]) -> bool:
    """Returns whether the project is acidbase itself (never a fleet member)."""
    name = _project_table(data).get("name")
    return isinstance(name, str) and canonicalize_name(name) == "acidbase"


def consumes_acidbase(data: Mapping[str, Any]) -> bool:
    """
    Returns whether a parsed pyproject declares acidbase as a real dependency.
    Runtime dependencies, extras, and dependency groups count; comments and the metarepo itself do not.
    """
    if is_metarepo(data):
        return False
    project = _project_table(data)
    candidates: list[Any] = list(project.get("dependencies") or [])
    extras = project.get("optional-dependencies") or {}
    if isinstance(extras, Mapping):
        for values in extras.values():
            candidates.extend(values if isinstance(values, list) else [])
    groups = data.get("dependency-groups") or {}
    if isinstance(groups, Mapping):
        for values in groups.values():
            candidates.extend(values if isinstance(values, list) else [])
    return any(_requirement_name(candidate) == "acidbase" for candidate in candidates)


def project_scripts(data: Mapping[str, Any]) -> dict[str, str]:
    """Returns ``[project.scripts]`` as a plain name-to-target mapping."""
    scripts = _project_table(data).get("scripts")
    if not isinstance(scripts, Mapping):
        return {}
    return {str(name): str(target) for name, target in scripts.items()}


def infer_cli(scripts: Mapping[str, str]) -> str | None:
    """
    Returns the project CLI among ``scripts``, ignoring a bare ``push`` alias.
    A single remaining script wins; otherwise the single one pointing at a ``main`` function does.
    """
    candidates = {name: target for name, target in scripts.items() if name != _PUSH_ALIAS}
    if len(candidates) == 1:
        return next(iter(candidates))
    mains = [name for name, target in candidates.items() if target.strip().endswith(":main")]
    return mains[0] if len(mains) == 1 else None


def _path_key(local: str) -> str:
    """Normalizes a local path for registration lookups."""
    return os.path.normcase(os.path.normpath(local))


def _check_entry(entry: FleetEntry, local: str) -> CensusRow:
    """Classifies one registered repository found at ``local``."""
    root = Path(local)
    if not root.is_dir():
        return CensusRow(entry.name, entry.host, entry.path, CensusState.MISSING, "directory not found")
    try:
        data = read_project(root)
    except ValueError as exc:
        return CensusRow(entry.name, entry.host, entry.path, CensusState.UNREADABLE, str(exc))
    if data is None:
        return CensusRow(entry.name, entry.host, entry.path, CensusState.NOT_A_CONSUMER, "no pyproject.toml")
    if not consumes_acidbase(data):
        return CensusRow(entry.name, entry.host, entry.path, CensusState.NOT_A_CONSUMER, "no acidbase dependency")
    scripts = project_scripts(data)
    if entry.cli not in scripts:
        declared = ", ".join(sorted(scripts, key=abc_key)) or "none"
        return CensusRow(
            entry.name, entry.host, entry.path, CensusState.CLI_MISMATCH, f"cli={entry.cli}; declared: {declared}"
        )
    return CensusRow(entry.name, entry.host, entry.path, CensusState.OK, f"cli={entry.cli}")


def _join_stored(root: str, name: str, host: str) -> str:
    """Joins a stored root and a child name in the host's own spelling."""
    if host == WINDOWS:
        return str(PureWindowsPath(root, name))
    return f"{root.rstrip('/')}/{name}"


def run_census(
    fleet: Fleet,
    here: str | None = None,
    *,
    local_only: bool = False,
    home: PurePath | None = None,
) -> list[CensusRow]:
    """
    Compares the manifest with the disk as seen from ``here`` (the current host by default).
    Every registration is checked, then the immediate children of each ``[census.roots]`` entry are
    scanned for acidbase consumers that are not registered.
    """
    here = here or current_host()
    rows: list[CensusRow] = []
    registered: set[str] = set()
    for entry in fleet.entries:
        if local_only and entry.host != here:
            continue
        local = localize(entry.path, entry.host, here, fleet.hosts, home)
        if local is None:
            rows.append(CensusRow(entry.name, entry.host, entry.path, CensusState.UNREACHABLE, f"no route from {here}"))
            continue
        registered.add(_path_key(local))
        rows.append(_check_entry(entry, local))
    for host, roots in fleet.roots.items():
        if local_only and host != here:
            continue
        for root in roots:
            local_root = localize(root, host, here, fleet.hosts, home)
            if local_root is None or not Path(local_root).is_dir():
                reason = f"no route from {here}" if local_root is None else "root directory not found"
                rows.append(CensusRow(f"[root] {root}", host, root, CensusState.UNREACHABLE, reason))
                continue
            for child in sorted(Path(local_root).iterdir(), key=lambda p: abc_key(p.name)):
                if not child.is_dir() or child.name.startswith(".") or child.name.casefold() in fleet.ignore:
                    continue
                if _path_key(str(child)) in registered:
                    continue
                try:
                    data = read_project(child)
                except ValueError as exc:
                    stored = _join_stored(root, child.name, host)
                    rows.append(CensusRow(child.name, host, stored, CensusState.UNREADABLE, str(exc)))
                    continue
                if data is None or not consumes_acidbase(data):
                    continue
                stored = _join_stored(root, child.name, host)
                hint = infer_cli(project_scripts(data)) or "?"
                rows.append(
                    CensusRow(
                        child.name,
                        host,
                        stored,
                        CensusState.UNREGISTERED,
                        f"cli={hint}; register with `acidbase fleet add {child}`",
                    )
                )
    return rows


def _display_path(entry: FleetEntry) -> str:
    """Returns the Host/path cell of the Markdown inventory."""
    return f"`{entry.path}`" if entry.host == WINDOWS else f"{entry.host.upper()} `{entry.path}`"


def _markdown_row(cells: list[str]) -> str:
    """Joins table cells into one Markdown row, escaping pipes inside cells."""
    return "| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |"


def render_entries(rows: list[tuple[FleetEntry, str | None]], output_format: str) -> str:
    """
    Renders ``(entry, local path)`` pairs as ``table``, ``json``, ``tsv``, or ``markdown``.
    The local path is the entry's spelling on the running host (None when unreachable). TSV columns are
    name, host, path, local path, cli, mypy.
    """
    if output_format == "json":
        records = [
            {
                "name": entry.name,
                "host": entry.host,
                "path": entry.path,
                "local_path": local,
                "cli": entry.cli,
                "mypy": entry.mypy,
                "note": entry.note,
            }
            for entry, local in rows
        ]
        return json.dumps(records, ensure_ascii=False, indent=2)
    if output_format == "tsv":
        # Using "-" for empty cells: with IFS=$'\t', bash `read` would merge consecutive tabs.
        return "\n".join(
            "\t".join((entry.name, entry.host, entry.path, local or "-", entry.cli, entry.mypy or "-"))
            for entry, local in rows
        )
    if output_format == "markdown":
        lines = [_markdown_row(["Repo", "Host/path", "CLI name", "mypy", "Note"]), "| --- | --- | --- | --- | --- |"]
        for entry, _local in rows:
            mypy = f"`{entry.mypy}`" if entry.mypy else "—"
            lines.append(_markdown_row([entry.name, _display_path(entry), f"`{entry.cli}`", mypy, entry.note or ""]))
        return "\n".join(line.replace("|  |", "| |") for line in lines)
    return "\n".join(
        f"{entry.name:<26} {entry.host:<8} {entry.cli:<20} {entry.mypy or '-':<12} {entry.path}" for entry, _ in rows
    )


def _fleet_file_option(function: _F) -> _F:
    """Adds the shared --fleet-file option to a subcommand."""
    return click.option(
        "--fleet-file",
        type=click.Path(path_type=Path, dir_okay=False),
        help=f"Fleet manifest to use; defaults to ${FLEET_FILE_ENV}, then config/fleet.toml above the cwd.",
    )(function)


@group("fleet")
def fleet_command() -> None:
    """Register, list, and census the repositories that consume acidbase."""


@fleet_command.command("add")
@click.argument("repository", type=click.Path(path_type=Path, file_okay=False, exists=True), default=".")
@click.option("--cli", "cli_name", help="CLI name; inferred from [project.scripts] when omitted.")
@click.option("--mypy", "mypy_target", help="Type-check target for runbook loops, e.g. 'src tests'.")
@click.option("--name", "repo_name", help="Registered name; defaults to the directory name.")
@click.option("--note", help="Free-text remark shown in the Markdown inventory.")
@click.option("--dry-run", is_flag=True, help="Report the decision without writing the manifest.")
@_fleet_file_option
def add_command(
    repository: Path,
    cli_name: str | None,
    mypy_target: str | None,
    repo_name: str | None,
    note: str | None,
    dry_run: bool,
    fleet_file: Path | None,
) -> None:
    """Register a consumer repository in the fleet manifest.

    REPOSITORY defaults to the current directory and must declare acidbase as a
    dependency. The owning host follows the path (a Windows drive seen from WSL
    is still windows), and the path is stored the way that host spells it.
    Registering the same repository again is a no-op, so repo-creation scripts
    can call this unconditionally.
    """
    root = repository.resolve()
    try:
        data = read_project(root)
    except ValueError as exc:
        raise click.ClickException(f"{root}: {exc}") from exc
    if data is None:
        raise click.ClickException(f"{root} has no pyproject.toml.")
    if is_metarepo(data):
        raise click.ClickException("The acidbase metarepo itself is not a fleet member.")
    if not consumes_acidbase(data):
        raise click.ClickException(
            f"{root.name} does not declare acidbase as a dependency; adopt it first (acidbase scaffold --wire-cli)."
        )
    scripts = project_scripts(data)
    cli = cli_name or infer_cli(scripts)
    declared = ", ".join(sorted(scripts, key=abc_key)) or "none"
    if cli is None:
        raise click.ClickException(f"Cannot infer the CLI of {root.name} (scripts: {declared}); pass --cli.")
    if cli not in scripts:
        raise click.ClickException(f"{cli!r} is not in [project.scripts] of {root.name} (scripts: {declared}).")
    fleet = load_fleet(resolve_fleet_file(fleet_file))
    host, path = native_location(root, current_host(), fleet.hosts)
    entry = FleetEntry(
        name=(repo_name or root.name).strip(),
        host=host,
        path=path,
        cli=cli,
        mypy=(mypy_target or "").strip() or None,
        note=(note or "").strip() or None,
    )
    changed = add_entry(fleet, entry)
    label = f"{entry.name} ({entry.host}, {entry.path}, cli={entry.cli})"
    if not changed:
        click.echo(f"Already registered: {label} in {fleet.path}")
    elif dry_run:
        click.echo(f"Would register: {label} in {fleet.path}")
    else:
        save_fleet(fleet)
        click.echo(f"Registered: {label} in {fleet.path}")


@fleet_command.command("census")
@click.option("--local-only", is_flag=True, help="Skip registrations and roots that belong to other hosts.")
@_fleet_file_option
def census_command(local_only: bool, fleet_file: Path | None) -> None:
    """Compare the fleet manifest with what is on disk.

    Checks every registration (still there, still an acidbase consumer, CLI
    still declared) and scans the immediate children of [census.roots] for
    consumers that are not registered. Exit code 1 means drift; anything on a
    host this machine cannot reach is reported as UNREACHABLE and does not fail.
    """
    fleet = load_fleet(resolve_fleet_file(fleet_file))
    rows = run_census(fleet, local_only=local_only)
    for row in rows:
        click.echo(f"{row.name:<26} {row.host:<8} {row.state.value:<15} {row.detail}".rstrip())
    counts: dict[CensusState, int] = {}
    for row in rows:
        counts[row.state] = counts.get(row.state, 0) + 1
    summary = ", ".join(f"{state.value}={count}" for state, count in sorted(counts.items(), key=lambda kv: kv[0].value))
    click.echo(f"Summary: {summary or 'empty manifest'}")
    if any(row.state.failing for row in rows):
        raise SystemExit(1)


@fleet_command.command("list")
@click.option("--host", help="Only show repositories registered on this host (e.g. windows, wsl).")
@click.option(
    "--format", "output_format", type=click.Choice(_FORMATS), default="table", show_default=True, help="Output format."
)
@_fleet_file_option
def list_command(host: str | None, output_format: str, fleet_file: Path | None) -> None:
    """Print the fleet manifest.

    JSON and TSV carry each repository's path on the running host as well
    (local_path; '-' in TSV when the other host is unreachable), so runbook
    loops can iterate without translating paths themselves.
    """
    fleet = load_fleet(resolve_fleet_file(fleet_file))
    here = current_host()
    rows = [
        (entry, localize(entry.path, entry.host, here, fleet.hosts))
        for entry in fleet.entries
        if host is None or entry.host == host
    ]
    rendered = render_entries(rows, output_format)
    if rendered:
        click.echo(rendered)


@fleet_command.command("remove")
@click.argument("name")
@click.option("--host", help="Host of the registration; needed only when NAME is registered on several hosts.")
@_fleet_file_option
def remove_command(name: str, host: str | None, fleet_file: Path | None) -> None:
    """Remove a registration from the fleet manifest (e.g. before re-adding a moved repository)."""
    fleet = load_fleet(resolve_fleet_file(fleet_file))
    removed = remove_entry(fleet, name, host)
    save_fleet(fleet)
    click.echo(f"Removed: {removed.name} ({removed.host}, {removed.path}) from {fleet.path}")
