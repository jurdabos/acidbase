"""Plan and apply the acidbase baseline without overwriting local work."""

from __future__ import annotations

import importlib.resources
import keyword
import os
import re
import tomllib
import uuid
from collections.abc import MutableMapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

import click
import tomlkit
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from acidbase.workflow import project_path

_ACIDBASE_REQUIREMENT = "acidbase @ git+https://github.com/jurdabos/acidbase.git"
_CHECKOUT_TEMPLATE_ROOT = Path(__file__).resolve().parents[2] / "templates"
_TEMPLATE_ASSETS = (
    (PurePosixPath(".github/workflows/lint.yml"), PurePosixPath(".github/workflows/lint.yml")),
    (PurePosixPath(".gitleaks.toml"), PurePosixPath(".gitleaks.toml")),
    (PurePosixPath(".pre-commit-config.yaml"), PurePosixPath(".pre-commit-config.yaml")),
)


class ChangeKind(str, Enum):
    """Describes what applying one scaffold action would do."""

    ADD = "add"
    EXTEND = "extend"
    KEEP = "keep"
    PRESERVE = "preserve"


@dataclass(frozen=True)
class ScaffoldAction:
    """One deterministic file decision in a scaffold plan."""

    relative_path: PurePosixPath
    kind: ChangeKind
    reason: str
    content: bytes | None = None
    original: bytes | None = None

    @property
    def changes_disk(self) -> bool:
        """Returns whether applying the action writes a file."""
        return self.kind in {ChangeKind.ADD, ChangeKind.EXTEND}


@dataclass(frozen=True)
class ScaffoldPlan:
    """A complete, preflighted baseline-adoption plan."""

    target: Path
    package: str
    actions: tuple[ScaffoldAction, ...]
    notes: tuple[str, ...]

    @property
    def changes(self) -> tuple[ScaffoldAction, ...]:
        """Returns actions that will write files."""
        return tuple(action for action in self.actions if action.changes_disk)

    def apply(self) -> None:
        """Applies additions and extensions after checking for plan-time races."""
        for action in self.changes:
            destination = project_path(self.target, Path(*action.relative_path.parts))
            if destination.is_symlink():
                raise click.ClickException(f"Refusing to write through a symbolic link: {destination}")
            if action.kind is ChangeKind.ADD and destination.exists():
                raise click.ClickException(f"Scaffold plan is stale; path now exists: {destination}")
            if action.kind is ChangeKind.EXTEND:
                if not destination.is_file() or destination.read_bytes() != action.original:
                    raise click.ClickException(f"Scaffold plan is stale; file changed: {destination}")
            _validate_parent(self.target, destination)

        staged: list[tuple[Path, Path]] = []
        try:
            for action in self.changes:
                destination = project_path(self.target, Path(*action.relative_path.parts))
                destination.parent.mkdir(parents=True, exist_ok=True)
                temporary = destination.parent / f".{destination.name}.acidbase-{uuid.uuid4().hex}.tmp"
                temporary.write_bytes(action.content or b"")
                staged.append((temporary, destination))
            for temporary, destination in staged:
                os.replace(temporary, destination)
        finally:
            for temporary, _destination in staged:
                temporary.unlink(missing_ok=True)


def _validate_parent(root: Path, destination: Path) -> None:
    """Rejects a destination whose existing parent chain escapes through a link."""
    resolved_root = root.resolve()
    resolved_parent = destination.parent.resolve()
    try:
        resolved_parent.relative_to(resolved_root)
    except ValueError as exc:
        raise click.ClickException(f"Destination escapes the project root: {destination}") from exc


def _template_bytes(relative_path: PurePosixPath) -> bytes:
    """Reads a template from an installed wheel or a source checkout."""
    packaged = importlib.resources.files("acidbase").joinpath("template", *relative_path.parts)
    if packaged.is_file():
        return packaged.read_bytes()
    checkout = _CHECKOUT_TEMPLATE_ROOT.joinpath(*relative_path.parts)
    if checkout.is_file():
        return checkout.read_bytes()
    raise click.ClickException(f"Acidbase installation is missing template: {relative_path.as_posix()}")


def _same_text(left: bytes, right: bytes) -> bool:
    """Compares UTF-8 template files while ignoring newline convention."""
    try:
        left_text = left.decode("utf-8-sig").replace("\r\n", "\n")
        right_text = right.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError:
        return left == right
    return left_text == right_text


def _load_pyproject(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Loads a UTF-8 pyproject and returns its bytes and parsed data."""
    if path.is_symlink() or not path.is_file():
        raise click.ClickException(f"Target must contain a regular pyproject.toml: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
        data = tomllib.loads(text)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise click.ClickException(f"Cannot safely read {path}: {exc}") from exc
    return raw, data


def _normalize_package(value: str) -> str:
    """Converts a distribution-like name to a valid top-level package name."""
    package = re.sub(r"[-.]+", "_", value.strip())
    if not package.isidentifier() or keyword.iskeyword(package):
        raise click.ClickException(
            f"Cannot infer a valid Python package from {value!r}; pass --package with an importable name."
        )
    return package


def _infer_package(target: Path, data: dict[str, Any], requested: str | None) -> str:
    """Infers the package from entry points or layout, then project name."""
    if requested:
        return _normalize_package(requested)

    project = data.get("project")
    project_data = project if isinstance(project, dict) else {}
    scripts = project_data.get("scripts")
    script_values = scripts.values() if isinstance(scripts, dict) else ()
    script_packages = sorted(
        {
            value.partition(":")[0].partition(".")[0]
            for value in script_values
            if isinstance(value, str) and ":" in value
        }
    )
    valid_script_packages = [package for package in script_packages if package.isidentifier()]
    if len(valid_script_packages) == 1:
        return valid_script_packages[0]

    source = target / "src"
    if source.is_dir():
        candidates = sorted(
            child.name
            for child in source.iterdir()
            if child.is_dir() and (child / "__init__.py").is_file() and child.name.isidentifier()
        )
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            joined = ", ".join(candidates)
            raise click.ClickException(f"Multiple src packages found ({joined}); select one with --package.")

    ignored_flat_directories = {"doc", "docs", "script", "scripts", "test", "tests"}
    flat_candidates = sorted(
        child.name
        for child in target.iterdir()
        if child.is_dir()
        and child.name not in ignored_flat_directories
        and (child / "__init__.py").is_file()
        and child.name.isidentifier()
    )
    if len(flat_candidates) == 1:
        return flat_candidates[0]
    if len(flat_candidates) > 1:
        joined = ", ".join(flat_candidates)
        raise click.ClickException(f"Multiple flat packages found ({joined}); select one with --package.")

    name = project_data.get("name")
    return _normalize_package(name if isinstance(name, str) and name.strip() else target.name)


def _package_root(target: Path, package: str) -> PurePosixPath:
    """Returns the existing src/ or flat package root, defaulting to src/."""
    src_package = target / "src" / package
    flat_package = target / package
    if src_package.is_dir() and flat_package.is_dir():
        raise click.ClickException(
            f"Both src/{package} and {package} exist; pass a repository-specific package layout manually."
        )
    if flat_package.is_dir():
        return PurePosixPath(package)
    return PurePosixPath("src") / package


def _append_ruff_config(raw: bytes, text: str) -> bytes:
    """Appends the canonical ruff tables without rewriting existing TOML."""
    newline = "\r\n" if "\r\n" in text else "\n"
    template = _template_bytes(PurePosixPath("pyproject.lint.toml")).decode("utf-8-sig")
    template = template.replace("\r\n", "\n").replace("\n", newline).rstrip("\r\n")
    separator = newline if text.endswith(("\n", "\r")) else newline * 2
    prefix = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
    return prefix + f"{text}{separator}{template}{newline}".encode("utf-8")


def _has_dependency(data: dict[str, Any], name: str) -> bool:
    """Returns whether PEP 621 dependencies declare ``name``."""
    project = data.get("project")
    dependencies = project.get("dependencies", []) if isinstance(project, dict) else []
    for dependency in dependencies if isinstance(dependencies, list) else []:
        if not isinstance(dependency, str):
            continue
        try:
            if canonicalize_name(Requirement(dependency).name) == canonicalize_name(name):
                return True
        except InvalidRequirement:
            continue
    return False


def _table(container: MutableMapping[str, Any], key: str) -> MutableMapping[str, Any]:
    """Returns or creates a TOML table under ``container``."""
    existing = container.get(key)
    if existing is None:
        created = tomlkit.table()
        container[key] = created
        return created
    if not isinstance(existing, MutableMapping):
        raise click.ClickException(f"Cannot wire CLI because {key!r} is not a TOML table.")
    return existing


def _validate_command_name(value: str) -> str:
    """Returns a conservative executable name suitable for project.scripts."""
    command_name = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", command_name):
        raise click.ClickException(
            f"Invalid command name {value!r}; use letters, digits, period, underscore, or hyphen."
        )
    return command_name


def _wire_cli_pyproject(
    content: bytes,
    *,
    package: str,
    package_root: PurePosixPath,
    requested_command_name: str | None,
) -> tuple[bytes, str]:
    """Adds the canonical dependency, entry point, and Hatch package metadata."""
    had_bom = content.startswith(b"\xef\xbb\xbf")
    text = content.decode("utf-8-sig")
    newline = "\r\n" if "\r\n" in text else "\n"
    try:
        document = tomlkit.parse(text)
    except tomlkit.exceptions.ParseError as exc:
        raise click.ClickException(f"Cannot safely wire pyproject.toml: {exc}") from exc

    project = document.get("project")
    if not isinstance(project, MutableMapping):
        raise click.ClickException("Cannot wire CLI because pyproject.toml has no [project] table.")
    project_name = project.get("name")
    if not isinstance(project_name, str) or not project_name:
        raise click.ClickException("Cannot wire CLI because [project].name is missing.")
    command_name = _validate_command_name(requested_command_name or project_name)

    build_system = document.get("build-system")
    if build_system is not None:
        if not isinstance(build_system, MutableMapping) or build_system.get("build-backend") != "hatchling.build":
            raise click.ClickException(
                "Cannot wire CLI automatically because the existing build backend is not Hatchling; "
                "its package-discovery rules are project-owned."
            )
    else:
        build_system = tomlkit.table()
        build_system["requires"] = ["hatchling>=1,<2"]
        build_system["build-backend"] = "hatchling.build"
        document["build-system"] = build_system

    scripts = project.get("scripts")
    expected_entry_point = f"{package}.cli:main"
    if scripts is None:
        scripts = tomlkit.table()
        project["scripts"] = scripts
    elif not isinstance(scripts, MutableMapping):
        raise click.ClickException("Cannot wire CLI because [project.scripts] is not a TOML table.")
    elif scripts and expected_entry_point not in scripts.values():
        existing_names = ", ".join(sorted(str(name) for name in scripts))
        raise click.ClickException(
            f"Existing project scripts are locally owned ({existing_names}); refusing to add a parallel CLI."
        )
    existing_entry_point = scripts.get(command_name)
    if existing_entry_point not in (None, expected_entry_point):
        raise click.ClickException(
            f"Command {command_name!r} already points to {existing_entry_point!r}; refusing to replace it."
        )
    scripts[command_name] = expected_entry_point

    parsed = tomllib.loads(text)
    if not _has_dependency(parsed, "acidbase") and canonicalize_name(project_name) != "acidbase":
        dependencies = project.get("dependencies")
        if dependencies is None:
            dependencies = tomlkit.array().multiline(True)
            project["dependencies"] = dependencies
        if not hasattr(dependencies, "append"):
            raise click.ClickException("Cannot wire CLI because [project].dependencies is not an array.")
        dependencies.append(_ACIDBASE_REQUIREMENT)

    tool = _table(document, "tool")
    hatch = _table(tool, "hatch")
    metadata = _table(hatch, "metadata")
    metadata["allow-direct-references"] = True
    build = _table(hatch, "build")
    targets = _table(build, "targets")
    wheel = _table(targets, "wheel")
    packages = wheel.get("packages")
    expected_package = package_root.as_posix()
    if packages is None:
        wheel["packages"] = [expected_package]
    elif expected_package not in packages:
        raise click.ClickException(
            f"Existing Hatch wheel packages do not include {expected_package!r}; package discovery is locally owned."
        )

    rendered = tomlkit.dumps(document).replace("\r\n", "\n").replace("\n", newline)
    prefix = b"\xef\xbb\xbf" if had_bom else b""
    return prefix + rendered.encode("utf-8"), command_name


def _scaffold_cli(data: dict[str, Any], package: str) -> bool:
    """Returns whether this project already declares the acidbase CLI shape."""
    project = data.get("project")
    project_data = project if isinstance(project, dict) else {}
    scripts = project_data.get("scripts")
    return isinstance(scripts, dict) and f"{package}.cli:main" in scripts.values()


def _contract_notes(
    data: dict[str, Any],
    package: str,
    *,
    scaffold_cli: bool,
    wire_cli: bool,
    wire_changed: bool,
) -> tuple[str, ...]:
    """Reports project-owned pyproject wiring that scaffolding does not guess."""
    notes: list[str] = []
    project = data.get("project")
    project_data = project if isinstance(project, dict) else {}
    project_name = project_data.get("name")
    script_name = project_name if isinstance(project_name, str) and project_name else package.replace("_", "-")

    if wire_cli and wire_changed:
        return ("After applying: run uv lock, then uv sync --frozen.",)
    if wire_cli:
        return ()
    if not scaffold_cli:
        scripts = project_data.get("scripts")
        if isinstance(scripts, dict) and scripts:
            notes.append("Existing [project.scripts] entries are locally owned; no parallel CLI was scaffolded.")
        else:
            notes.append("No CLI is declared; rerun with --wire-cli to create and package one explicitly.")
        return tuple(notes)

    if not _has_dependency(data, "acidbase") and canonicalize_name(str(project_name)) != "acidbase":
        notes.append("Declare acidbase as a project dependency; the generated CLI imports its shared mechanics.")

    scripts = project_data.get("scripts")
    expected = f"{package}.cli:main"
    actual = scripts.get(script_name) if isinstance(scripts, dict) else None
    if actual != expected:
        notes.append(f'Wire the CLI in [project.scripts]: {script_name} = "{expected}"')
    return tuple(sorted(notes))


def build_scaffold_plan(
    target: str | Path,
    *,
    package: str | None = None,
    wire_cli: bool = False,
    command_name: str | None = None,
) -> ScaffoldPlan:
    """Builds a deterministic, non-mutating plan for a uv/Python repository."""
    requested_target = Path(target).expanduser()
    if requested_target.is_symlink():
        raise click.ClickException(f"Refusing a symbolic-link project root: {requested_target}")
    project_root = requested_target.resolve()
    if not project_root.is_dir():
        raise click.ClickException(f"Target directory does not exist: {project_root}")

    pyproject = project_root / "pyproject.toml"
    pyproject_raw, data = _load_pyproject(pyproject)
    package_name = _infer_package(project_root, data, package)
    package_root = _package_root(project_root, package_name)
    scaffold_cli = wire_cli or _scaffold_cli(data, package_name)

    assets = list(_TEMPLATE_ASSETS)
    if scaffold_cli:
        assets.append((PurePosixPath("cli.py"), package_root / "cli.py"))
    actions: list[ScaffoldAction] = []
    for source, relative_destination in assets:
        content = _template_bytes(source)
        destination = project_path(project_root, Path(*relative_destination.parts))
        _validate_parent(project_root, destination)
        if destination.is_symlink():
            actions.append(ScaffoldAction(relative_destination, ChangeKind.PRESERVE, "symbolic link is locally owned"))
        elif not destination.exists():
            actions.append(ScaffoldAction(relative_destination, ChangeKind.ADD, "baseline file is missing", content))
        elif destination.is_file() and _same_text(destination.read_bytes(), content):
            actions.append(ScaffoldAction(relative_destination, ChangeKind.KEEP, "already matches acidbase"))
        else:
            actions.append(
                ScaffoldAction(relative_destination, ChangeKind.PRESERVE, "existing local content is never overwritten")
            )

    if wire_cli:
        initializer = package_root / "__init__.py"
        initializer_path = project_path(project_root, Path(*initializer.parts))
        _validate_parent(project_root, initializer_path)
        if initializer_path.is_symlink():
            actions.append(ScaffoldAction(initializer, ChangeKind.PRESERVE, "symbolic link is locally owned"))
        elif not initializer_path.exists():
            actions.append(ScaffoldAction(initializer, ChangeKind.ADD, "package initializer is missing", b""))
        elif initializer_path.is_file():
            actions.append(ScaffoldAction(initializer, ChangeKind.KEEP, "package initializer already exists"))
        else:
            raise click.ClickException(f"Package initializer path is not a regular file: {initializer_path}")

    tool = data.get("tool")
    has_ruff = isinstance(tool, dict) and "ruff" in tool
    pyproject_content = pyproject_raw
    reasons: list[str] = []
    wire_changed = False
    if wire_cli:
        before_wiring = pyproject_content
        pyproject_content, resolved_command_name = _wire_cli_pyproject(
            pyproject_content,
            package=package_name,
            package_root=package_root,
            requested_command_name=command_name,
        )
        wire_changed = not _same_text(pyproject_content, before_wiring)
        reasons.append(f"wire {resolved_command_name} CLI")
    if not has_ruff:
        current_text = pyproject_content.decode("utf-8-sig")
        pyproject_content = _append_ruff_config(pyproject_content, current_text)
        reasons.append("append canonical ruff tables")

    if _same_text(pyproject_content, pyproject_raw):
        reason = "CLI wiring and ruff are already configured" if wire_cli else "ruff is already configured"
        actions.append(ScaffoldAction(PurePosixPath("pyproject.toml"), ChangeKind.KEEP, reason))
    else:
        actions.append(
            ScaffoldAction(
                PurePosixPath("pyproject.toml"),
                ChangeKind.EXTEND,
                "; ".join(reasons),
                pyproject_content,
                pyproject_raw,
            )
        )

    actions.sort(key=lambda action: action.relative_path.as_posix())
    return ScaffoldPlan(
        project_root,
        package_name,
        tuple(actions),
        _contract_notes(
            data,
            package_name,
            scaffold_cli=scaffold_cli,
            wire_cli=wire_cli,
            wire_changed=wire_changed,
        ),
    )


def _print_plan(plan: ScaffoldPlan, *, applied: bool) -> None:
    """Prints one stable, ASCII-ordered scaffold report."""
    click.echo(f"Target:  {plan.target}")
    click.echo(f"Package: {plan.package}")
    click.echo("Files:")
    for action in plan.actions:
        click.echo(f"  {action.kind.value:<8} {action.relative_path.as_posix()}  ({action.reason})")

    counts = {kind: 0 for kind in ChangeKind}
    for action in plan.actions:
        counts[action.kind] += 1
    summary = ", ".join(f"{kind.value}={counts[kind]}" for kind in ChangeKind)
    click.echo(f"Summary: {summary}")

    if plan.notes:
        click.echo("Project-owned follow-up:")
        for note in plan.notes:
            click.echo(f"  - {note}")
    if applied:
        click.echo(f"Applied {len(plan.changes)} change(s); preserved every divergent local file.")
    elif plan.changes:
        click.echo("Plan only; rerun with --apply to make the listed add/extend changes.")
    else:
        click.echo("No scaffold changes are needed.")


@click.command("scaffold")
@click.argument("target", type=click.Path(path_type=Path, file_okay=False), default=".")
@click.option("--package", help="Import package receiving the shared cli.py; inferred when omitted.")
@click.option(
    "--wire-cli", is_flag=True, help="Also wire dependency, entry point, initializer, and packaging metadata."
)
@click.option("--command-name", help="Executable name for --wire-cli; defaults to [project].name.")
@click.option("--apply", "apply_changes", is_flag=True, help="Apply the plan; the default is read-only.")
def scaffold_command(
    target: Path,
    package: str | None,
    wire_cli: bool,
    command_name: str | None,
    apply_changes: bool,
) -> None:
    """Plan or safely adopt the acidbase baseline in an initialized repository.

    TARGET must contain pyproject.toml. Existing divergent files are reported
    and preserved. Ordinary adoption writes only missing baseline files and an
    absent ruff configuration; --wire-cli explicitly adds the coupled metadata
    needed for a new installable project CLI.
    """
    if command_name and not wire_cli:
        raise click.UsageError("--command-name requires --wire-cli")
    plan = build_scaffold_plan(target, package=package, wire_cli=wire_cli, command_name=command_name)
    if apply_changes:
        plan.apply()
    _print_plan(plan, applied=apply_changes)
