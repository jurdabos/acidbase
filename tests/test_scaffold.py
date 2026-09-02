"""Tests for plan-first, non-overwriting scaffold adoption."""

from __future__ import annotations

import runpy
import tomllib
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from acidbase.cli import main
from acidbase.push import push_command
from acidbase.scaffold import ChangeKind, build_scaffold_plan, scaffold_command
from acidbase.versioning import bump_command


def _make_project(root: Path, *, name: str = "demo-project", package: str = "demo_project") -> Path:
    """Creates the initialized repository shape required by the scaffold contract."""
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                f'name = "{name}"',
                'version = "0.1.0"',
                "dependencies = []",
                "",
            ]
        ),
        encoding="utf-8",
    )
    package_root = root / "src" / package
    package_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    return root


def _action(plan, relative_path: str):
    """Returns one action by its rendered relative path."""
    return next(action for action in plan.actions if action.relative_path.as_posix() == relative_path)


def test_plan_is_read_only_by_default(tmp_path: Path) -> None:
    """Invoking the CLI without --apply reports changes and writes nothing."""
    project = _make_project(tmp_path / "project")

    result = CliRunner().invoke(scaffold_command, [str(project)])

    assert result.exit_code == 0, result.output
    assert "Plan only" in result.output
    assert not (project / ".gitleaks.toml").exists()
    assert "[tool.ruff]" not in (project / "pyproject.toml").read_text(encoding="utf-8")


def test_apply_adds_missing_files_and_extends_pyproject(tmp_path: Path) -> None:
    """The apply phase installs only planned additions and the absent ruff tables."""
    project = _make_project(tmp_path / "project")

    result = CliRunner().invoke(scaffold_command, [str(project), "--apply"])

    assert result.exit_code == 0, result.output
    assert (project / ".github" / "workflows" / "lint.yml").is_file()
    assert (project / ".gitleaks.toml").is_file()
    assert (project / ".pre-commit-config.yaml").is_file()
    assert not (project / "src" / "demo_project" / "cli.py").exists()
    parsed = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    assert parsed["tool"]["ruff"]["line-length"] == 120
    assert "Applied 4 change(s)" in result.output


def test_apply_is_idempotent(tmp_path: Path) -> None:
    """A second adoption recognizes every acidbase-owned file and makes no writes."""
    project = _make_project(tmp_path / "project")
    first = build_scaffold_plan(project)
    first.apply()

    second = build_scaffold_plan(project)

    assert not second.changes
    assert all(action.kind is ChangeKind.KEEP for action in second.actions)


def test_existing_divergent_cli_is_preserved_while_missing_files_are_added(tmp_path: Path) -> None:
    """Project-specific command implementations survive baseline adoption byte-for-byte."""
    project = _make_project(tmp_path / "project")
    pyproject = project / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8") + '\n[project.scripts]\ndemo-project = "demo_project.cli:main"\n',
        encoding="utf-8",
    )
    cli = project / "src" / "demo_project" / "cli.py"
    local_content = b"# locally owned commands\n"
    cli.write_bytes(local_content)

    plan = build_scaffold_plan(project)
    assert _action(plan, "src/demo_project/cli.py").kind is ChangeKind.PRESERVE
    plan.apply()

    assert cli.read_bytes() == local_content
    assert (project / ".gitleaks.toml").is_file()


def test_existing_divergent_security_config_is_preserved(tmp_path: Path) -> None:
    """A repository-specific secret allowlist is never replaced by the canonical file."""
    project = _make_project(tmp_path / "project")
    config = project / ".gitleaks.toml"
    config.write_text("# project-specific allowlist\n", encoding="utf-8")

    plan = build_scaffold_plan(project)
    plan.apply()

    assert _action(plan, ".gitleaks.toml").kind is ChangeKind.PRESERVE
    assert config.read_text(encoding="utf-8") == "# project-specific allowlist\n"


def test_existing_ruff_configuration_is_locally_owned(tmp_path: Path) -> None:
    """Scaffolding does not append or replace ruff when the project already configures it."""
    project = _make_project(tmp_path / "project")
    pyproject = project / "pyproject.toml"
    pyproject.write_text(pyproject.read_text(encoding="utf-8") + "\n[tool.ruff]\nline-length = 88\n", encoding="utf-8")
    before = pyproject.read_bytes()

    plan = build_scaffold_plan(project)
    plan.apply()

    assert _action(plan, "pyproject.toml").kind is ChangeKind.KEEP
    assert pyproject.read_bytes() == before


def test_package_override_rejects_path_shaped_value(tmp_path: Path) -> None:
    """The CLI destination cannot be redirected with a package path."""
    project = _make_project(tmp_path / "project")
    with pytest.raises(click.ClickException, match="valid Python package"):
        build_scaffold_plan(project, package="../outside")


def test_existing_flat_layout_cli_is_inferred_and_preserved(tmp_path: Path) -> None:
    """An established Typer-style entry point prevents a parallel src-layout CLI."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "demo-ai"',
                'version = "0.1.0"',
                "dependencies = []",
                "",
                "[project.scripts]",
                'demo = "demo.cli.commands:app"',
                "",
                "[tool.ruff]",
                "line-length = 100",
                "",
            ]
        ),
        encoding="utf-8",
    )
    package = project / "demo"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")

    plan = build_scaffold_plan(project)

    assert plan.package == "demo"
    assert all(action.relative_path.as_posix() != "src/demo/cli.py" for action in plan.actions)
    assert plan.notes == ("Existing [project.scripts] entries are locally owned; no parallel CLI was scaffolded.",)


def test_wire_cli_plans_complete_entrypoint_and_packaging_contract(tmp_path: Path) -> None:
    """Explicit wiring couples the source template to installable project metadata."""
    project = _make_project(tmp_path / "project")

    plan = build_scaffold_plan(project, wire_cli=True)

    initializer = _action(plan, "src/demo_project/__init__.py")
    pyproject = _action(plan, "pyproject.toml")
    assert initializer.kind is ChangeKind.KEEP
    assert pyproject.kind is ChangeKind.EXTEND
    assert pyproject.content is not None
    rendered = pyproject.content.decode("utf-8-sig")
    parsed = tomllib.loads(rendered)
    assert any(dependency.startswith("acidbase @ git+") for dependency in parsed["project"]["dependencies"])
    assert parsed["project"]["scripts"]["demo-project"] == "demo_project.cli:main"
    assert parsed["build-system"]["build-backend"] == "hatchling.build"
    assert parsed["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/demo_project"]
    assert parsed["tool"]["hatch"]["metadata"]["allow-direct-references"] is True
    assert rendered.index("[project.scripts]") < rendered.index("# Append this block")
    assert rendered.index("# Append this block") < rendered.index("[tool.ruff]")
    assert plan.notes == ("After applying: run uv lock, then uv sync --frozen.",)

    plan.apply()
    cli_text = (project / "src" / "demo_project" / "cli.py").read_text(encoding="utf-8")
    assert "from acidbase.versioning import bump_command" in cli_text
    assert cli_text.index("cli.add_command(bump_command)") < cli_text.index("cli.add_command(push_command)")
    generated = runpy.run_path(str(project / "src" / "demo_project" / "cli.py"), run_name="template_contract_test")
    assert generated["cli"].commands["bump"] is bump_command
    assert generated["cli"].commands["push"] is push_command

    second = build_scaffold_plan(project, wire_cli=True)
    assert not second.changes
    assert second.notes == ()

    pyproject_path = project / "pyproject.toml"
    normalized_newlines = pyproject_path.read_bytes().replace(b"\r\n", b"\n")
    mixed_newlines = normalized_newlines.replace(b"\n", b"\r\n", 1)
    pyproject_path.write_bytes(mixed_newlines)
    third = build_scaffold_plan(project, wire_cli=True)
    assert not third.changes


def test_wire_cli_uses_existing_flat_package_root(tmp_path: Path) -> None:
    """A flat-layout project remains flat when it has no existing executable."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = []\n',
        encoding="utf-8",
    )
    package = project / "demo"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")

    plan = build_scaffold_plan(project, wire_cli=True)

    assert _action(plan, "demo/cli.py").kind is ChangeKind.ADD
    parsed = tomllib.loads(_action(plan, "pyproject.toml").content.decode("utf-8-sig"))
    assert parsed["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["demo"]


def test_wire_cli_refuses_parallel_cli_for_existing_scripts(tmp_path: Path) -> None:
    """Even explicit wiring does not reinterpret an established application CLI."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "demo"',
                'version = "0.1.0"',
                "dependencies = []",
                "",
                "[project.scripts]",
                'demo = "demo.commands:app"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    package = project / "demo"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")

    with pytest.raises(click.ClickException, match="refusing to add a parallel CLI"):
        build_scaffold_plan(project, wire_cli=True)


def test_wire_cli_refuses_non_hatch_build_backend(tmp_path: Path) -> None:
    """Package discovery stays project-owned when another build backend is established."""
    project = _make_project(tmp_path / "project")
    pyproject = project / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8")
        + '\n[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n',
        encoding="utf-8",
    )

    with pytest.raises(click.ClickException, match="existing build backend is not Hatchling"):
        build_scaffold_plan(project, wire_cli=True)


def test_command_name_requires_wire_cli(tmp_path: Path) -> None:
    """The executable-name option cannot silently broaden ordinary adoption."""
    project = _make_project(tmp_path / "project")

    result = CliRunner().invoke(scaffold_command, [str(project), "--command-name", "demo"])

    assert result.exit_code != 0
    assert "--command-name requires --wire-cli" in result.output


def test_missing_pyproject_is_rejected_without_creating_files(tmp_path: Path) -> None:
    """The command adopts initialized repositories and never guesses a build contract."""
    project = tmp_path / "project"
    project.mkdir()

    result = CliRunner().invoke(scaffold_command, [str(project), "--apply"])

    assert result.exit_code != 0
    assert "must contain a regular pyproject.toml" in result.output
    assert list(project.iterdir()) == []


def test_changed_pyproject_invalidates_plan_before_any_write(tmp_path: Path) -> None:
    """A plan-time race aborts before additions are installed."""
    project = _make_project(tmp_path / "project")
    plan = build_scaffold_plan(project)
    pyproject = project / "pyproject.toml"
    pyproject.write_text(pyproject.read_text(encoding="utf-8") + "# concurrent edit\n", encoding="utf-8")

    with pytest.raises(click.ClickException, match="plan is stale"):
        plan.apply()

    assert not (project / ".gitleaks.toml").exists()


def test_report_paths_are_ascii_sorted(tmp_path: Path) -> None:
    """Inventory output uses deterministic filename order, independent of procedure order."""
    project = _make_project(tmp_path / "project")
    result = CliRunner().invoke(scaffold_command, [str(project)])
    rendered_paths = [
        line.split()[1]
        for line in result.output.splitlines()
        if line.startswith(("  add", "  extend", "  keep", "  preserve"))
    ]
    assert rendered_paths == sorted(rendered_paths)


def test_scaffold_is_registered_on_public_cli(tmp_path: Path) -> None:
    """The installed acidbase entry point exposes the plan-first command."""
    project = _make_project(tmp_path / "project")

    result = CliRunner().invoke(main, ["scaffold", str(project)])

    assert result.exit_code == 0, result.output
    assert "Plan only" in result.output
