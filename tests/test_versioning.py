"""Tests for the shared project-version bump command."""

from __future__ import annotations

import subprocess
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from acidbase import versioning
from acidbase.cli import main
from acidbase.versioning import BUMP_KINDS, bump_command, run_bump


def _make_project(root: Path, *, version: str = "0.1.0", dynamic: bool = False) -> Path:
    root.mkdir()
    version_line = 'dynamic = ["version"]' if dynamic else f'version = "{version}"'
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "demo"\n{version_line}\n',
        encoding="utf-8",
    )
    (root / "uv.lock").write_text('version = 1\nrevision = 3\nrequires-python = ">=3.12"\n', encoding="utf-8")
    return root


def _completed(
    tool: str, returncode: int = 0, *, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([tool], returncode, stdout=stdout, stderr=stderr)


def _install_successful_process(
    monkeypatch: pytest.MonkeyPatch, project: Path, new_version: str
) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def fake_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        assert cwd == project
        calls.append((tool, *arguments))
        if tool == "git":
            return _completed(tool)
        if "--dry-run" not in arguments:
            pyproject = project / "pyproject.toml"
            text = pyproject.read_text(encoding="utf-8")
            pyproject.write_text(text.replace('version = "0.1.0"', f'version = "{new_version}"'), encoding="utf-8")
        return _completed(tool, stdout=f"{new_version}\n")

    monkeypatch.setattr(versioning, "_run_process", fake_process)
    return calls


@pytest.mark.parametrize("kind", BUMP_KINDS)
def test_every_uv_bump_kind_is_forwarded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """Major, minor, patch, pre-release, post, and development forms use uv semantics."""
    project = _make_project(tmp_path / "project")
    calls = _install_successful_process(monkeypatch, project, "0.1.1")

    run_bump(kind, root=project)

    assert calls[-1] == ("uv", "version", "--bump", kind, "--no-sync", "--short")


def test_explicit_pep440_version_is_forwarded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit version is passed positionally rather than treated as a bump kind."""
    project = _make_project(tmp_path / "project")
    calls = _install_successful_process(monkeypatch, project, "1.0.0")

    run_bump("1.0.0", root=project)

    assert calls[-1] == ("uv", "version", "1.0.0", "--no-sync", "--short")


def test_combined_release_and_prerelease_bumps_are_forwarded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A new prerelease line can advance its release segment in one operation."""
    project = _make_project(tmp_path / "project")
    calls = _install_successful_process(monkeypatch, project, "0.1.1b1")

    run_bump("patch", "beta", root=project)

    assert calls[-1] == (
        "uv",
        "version",
        "--bump",
        "patch",
        "--bump",
        "beta",
        "--no-sync",
        "--short",
    )


def test_explicit_version_cannot_be_combined_with_bump_kind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Mixed explicit and calculated requests fail before invoking uv."""
    project = _make_project(tmp_path / "project")
    calls: list[str] = []

    def fake_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        calls.append(tool)
        return _completed(tool)

    monkeypatch.setattr(versioning, "_run_process", fake_process)

    with pytest.raises(click.ClickException, match="cannot be combined"):
        run_bump("1.0.0", "beta", root=project)

    assert calls == ["git"]


def test_click_command_accepts_combined_bump_kinds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The public command accepts the complete stable-to-prerelease request."""
    project = _make_project(tmp_path / "project")
    _install_successful_process(monkeypatch, project, "0.1.1b1")
    monkeypatch.chdir(project)

    result = CliRunner().invoke(bump_command, ["patch", "beta", "--dry-run"])

    assert result.exit_code == 0
    assert "demo: 0.1.0 -> 0.1.1b1" in result.output


def test_duplicate_bump_kinds_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated components cannot create an ambiguous version request."""
    project = _make_project(tmp_path / "project")
    monkeypatch.setattr(versioning, "_run_process", lambda tool, *arguments, cwd: _completed(tool))

    with pytest.raises(click.ClickException, match="only once"):
        run_bump("patch", "patch", root=project)


def test_dry_run_reports_versions_without_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The dry-run flag reaches uv and leaves both managed files byte-identical."""
    project = _make_project(tmp_path / "project")
    before = {path.name: path.read_bytes() for path in (project / "pyproject.toml", project / "uv.lock")}
    calls = _install_successful_process(monkeypatch, project, "0.1.1")
    monkeypatch.chdir(project)

    result = CliRunner().invoke(bump_command, ["patch", "--dry-run"], catch_exceptions=False, obj=None)
    after = {path.name: path.read_bytes() for path in (project / "pyproject.toml", project / "uv.lock")}

    assert result.exit_code == 0
    assert calls[-1] == ("uv", "version", "--bump", "patch", "--no-sync", "--short", "--dry-run")
    assert after == before


def test_click_command_prints_old_and_new_versions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The public command has concise output and does not hide dry-run status."""
    project = _make_project(tmp_path / "project")
    _install_successful_process(monkeypatch, project, "0.2.0")
    monkeypatch.chdir(project)

    result = CliRunner().invoke(bump_command, ["minor", "--dry-run"])

    assert result.exit_code == 0
    assert "demo: 0.1.0 -> 0.2.0" in result.output
    assert "were not changed" in result.output


def test_dynamic_version_is_refused_before_processes_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A version-provider-owned project cannot be rewritten as static metadata."""
    project = _make_project(tmp_path / "project", dynamic=True)
    called = False

    def fake_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return _completed(tool)

    monkeypatch.setattr(versioning, "_run_process", fake_process)

    with pytest.raises(click.ClickException, match="dynamic project version"):
        run_bump("patch", root=project)

    assert called is False


def test_missing_static_version_is_refused_before_processes_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project without either static or declared dynamic version metadata fails clearly."""
    project = _make_project(tmp_path / "project")
    (project / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")

    def unexpected_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        pytest.fail(f"unexpected process: {tool} {arguments}")

    monkeypatch.setattr(versioning, "_run_process", unexpected_process)

    with pytest.raises(click.ClickException, match="non-empty static string"):
        run_bump("patch", root=project)


@pytest.mark.parametrize("status", [" M pyproject.toml\n", "M  uv.lock\n", "?? uv.lock\n"])
def test_dirty_version_metadata_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    """Staged, unstaged, and untracked edits to either output file block the bump."""
    project = _make_project(tmp_path / "project")
    calls: list[str] = []

    def fake_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        calls.append(tool)
        return _completed(tool, stdout=status)

    monkeypatch.setattr(versioning, "_run_process", fake_process)

    with pytest.raises(click.ClickException, match="already has uncommitted changes"):
        run_bump("patch", root=project)

    assert calls == ["git"]


def test_unrelated_git_changes_do_not_block_bump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The Git query scopes cleanliness to pyproject.toml and uv.lock."""
    project = _make_project(tmp_path / "project")
    calls = _install_successful_process(monkeypatch, project, "0.1.1")

    run_bump("patch", root=project)

    assert calls[0] == (
        "git",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        "pyproject.toml",
        "uv.lock",
    )


def test_invalid_value_is_refused_before_uv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo cannot be interpreted as an arbitrary uv argument."""
    project = _make_project(tmp_path / "project")
    calls: list[str] = []

    def fake_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        calls.append(tool)
        return _completed(tool)

    monkeypatch.setattr(versioning, "_run_process", fake_process)

    with pytest.raises(click.ClickException, match="explicit PEP 440 version"):
        run_bump("banana", root=project)

    assert calls == ["git"]


def test_uv_exit_code_and_output_are_propagated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """A failed uv invocation remains the command's process status."""
    project = _make_project(tmp_path / "project")

    def fake_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        if tool == "git":
            return _completed(tool)
        return _completed(tool, 23, stdout="uv context\n", stderr="uv failed\n")

    monkeypatch.setattr(versioning, "_run_process", fake_process)

    with pytest.raises(SystemExit) as raised:
        run_bump("patch", root=project)

    captured = capsys.readouterr()
    assert raised.value.code == 23
    assert "uv context" in captured.out
    assert "uv failed" in captured.err


def test_success_requires_pyproject_to_contain_reported_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zero uv exit code is insufficient when the declared version did not change as reported."""
    project = _make_project(tmp_path / "project")

    def fake_process(tool: str, *arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        return _completed(tool, stdout="0.1.1\n" if tool == "uv" else "")

    monkeypatch.setattr(versioning, "_run_process", fake_process)

    with pytest.raises(click.ClickException, match="does not contain the reported version"):
        run_bump("patch", root=project)


def test_acidbase_cli_exports_bump_command() -> None:
    """The complete command is available from acidbase as well as child CLIs."""
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "bump" in result.output
