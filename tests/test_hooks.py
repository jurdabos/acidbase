"""Tests for the ruff hook / uv.lock alignment report."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from acidbase.cli import main
from acidbase.hooks import (
    HookState,
    Severity,
    classify,
    discover_repositories,
    hooks_command,
    ruff_in_default_groups,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_TEMPLATE_PRECOMMIT = _REPO_ROOT / "templates" / ".pre-commit-config.yaml"
_OWN_PRECOMMIT = _REPO_ROOT / ".pre-commit-config.yaml"

_LOCAL_RUFF_BLOCK = """\
repos:
  - repo: local
    hooks:
      - id: ruff
        name: ruff check
        entry: uv run --frozen python -m ruff check --fix --force-exclude
        language: system
      - id: ruff-format
        name: ruff format
        entry: uv run --frozen python -m ruff format --force-exclude
        language: system
"""


def _remote_block(rev: str, *, gitleaks_rev: str | None = None) -> str:
    """Returns a pre-commit config carrying the historical remote ruff hook."""
    text = f"""\
repos:
  - repo: https://github.com/astral-sh/uv-pre-commit
    rev: 0.8.15
    hooks:
      - id: uv-lock
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: {rev}
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
"""
    if gitleaks_rev:
        text += f"""\
  - repo: https://github.com/gitleaks/gitleaks
    rev: {gitleaks_rev}
    hooks:
      - id: gitleaks
"""
    return text


def _lock(ruff: str | None) -> str:
    """Returns a minimal uv.lock, optionally locking ruff."""
    packages = ['[[package]]\nname = "click"\nversion = "8.3.0"\n']
    if ruff:
        packages.append(f'[[package]]\nname = "ruff"\nversion = "{ruff}"\n')
    return 'version = 1\nrequires-python = ">=3.12"\n\n' + "\n".join(packages)


_DEV_GROUP = '[dependency-groups]\ndev = ["pytest>=8", "ruff>=0.16"]\n'


def _repo(
    root: Path,
    name: str,
    *,
    precommit: str | None,
    lock: str | None,
    newline: str = "\n",
    pyproject_extra: str = _DEV_GROUP,
) -> Path:
    """Materializes one fake repository under ``root``."""
    repo = root / name
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "0.1.0"\n\n{pyproject_extra}', encoding="utf-8"
    )
    if precommit is not None:
        (repo / ".pre-commit-config.yaml").write_bytes(precommit.replace("\n", newline).encode("utf-8"))
    if lock is not None:
        (repo / "uv.lock").write_bytes(lock.replace("\n", newline).encode("utf-8"))
    return repo


@pytest.mark.parametrize(
    ("precommit", "lock", "expected", "severity"),
    [
        (_LOCAL_RUFF_BLOCK, _lock("0.16.8"), HookState.LOCAL, Severity.OK),
        (_LOCAL_RUFF_BLOCK, _lock(None), HookState.LOCAL_UNLOCKED, Severity.ERROR),
        (_remote_block("v0.16.8"), _lock("0.16.8"), HookState.ALIGNED, Severity.WARNING),
        (_remote_block("v0.8.0"), _lock("0.16.4"), HookState.DRIFT, Severity.ERROR),
        (_remote_block("v0.16.8"), _lock("0.15.0"), HookState.DRIFT, Severity.ERROR),
        (_remote_block("v0.8.6"), _lock(None), HookState.REMOTE_UNLOCKED, Severity.INFO),
        (
            "repos:\n  - repo: local\n    hooks:\n      - id: gitleaks\n        entry: gitleaks\n",
            _lock("0.15.0"),
            HookState.NO_RUFF_HOOK,
            Severity.INFO,
        ),
        (None, _lock("0.15.0"), HookState.NO_PRECOMMIT, Severity.INFO),
        (_remote_block("v0.8.0"), None, HookState.NO_LOCK, Severity.INFO),
        (_LOCAL_RUFF_BLOCK, None, HookState.NO_LOCK, Severity.INFO),
    ],
)
def test_classify_states(tmp_path: Path, precommit, lock, expected: HookState, severity: Severity) -> None:
    """Every combination of hook shape and lock content maps to one stable state."""
    repo = _repo(tmp_path, "demo", precommit=precommit, lock=lock)

    report = classify(repo)

    assert report.state is expected
    assert report.severity is severity


def test_classify_tolerates_crlf_files(tmp_path: Path) -> None:
    """A Windows checkout with CRLF endings does not produce a phantom mismatch."""
    repo = _repo(tmp_path, "crlf", precommit=_remote_block("v0.16.8"), lock=_lock("0.16.8"), newline="\r\n")

    report = classify(repo)

    assert report.state is HookState.ALIGNED
    assert report.hook_ruff == "0.16.8"
    assert report.locked_ruff == "0.16.8"


def test_drift_detail_reports_direction(tmp_path: Path) -> None:
    """The DRIFT line says whether the hook is behind or ahead of the lock."""
    older = _repo(tmp_path, "older", precommit=_remote_block("v0.8.0"), lock=_lock("0.16.4"))
    newer = _repo(tmp_path, "newer", precommit=_remote_block("v0.16.8"), lock=_lock("0.15.0"))

    assert classify(older).detail == "hook=0.8.0 < locked=0.16.4"
    assert classify(newer).detail == "hook=0.16.8 > locked=0.15.0"


@pytest.mark.parametrize(
    ("pyproject_extra", "expected"),
    [
        # ruff only as an optional-dependencies extra: `uv sync` skips it (the CanonFodder case).
        ('[project.optional-dependencies]\ndev = ["ruff>=0.9"]\n', HookState.LOCAL_NOT_SYNCED),
        # ruff in a group that is not a default group.
        ('[dependency-groups]\ndev = ["pytest"]\nlint = ["ruff"]\n', HookState.LOCAL_NOT_SYNCED),
        # ... unless tool.uv.default-groups says so.
        (
            '[dependency-groups]\ndev = ["pytest"]\nlint = ["ruff"]\n\n[tool.uv]\ndefault-groups = ["dev", "lint"]\n',
            HookState.LOCAL,
        ),
        # ... or via include-group from a default group.
        ('[dependency-groups]\ndev = ["pytest", {include-group = "lint"}]\nlint = ["ruff"]\n', HookState.LOCAL),
        # ... or default-groups = "all".
        ('[dependency-groups]\nlint = ["ruff==0.16.8"]\n\n[tool.uv]\ndefault-groups = "all"\n', HookState.LOCAL),
        # ruff as a runtime dependency: an odd home, but `uv sync` installs it (the email case).
        ('dependencies = ["click>=8", "ruff>=0.15.13"]\n\n[dependency-groups]\ndev = ["pytest"]\n', HookState.LOCAL),
        # No groups at all.
        ("", HookState.LOCAL_NOT_SYNCED),
    ],
)
def test_local_hook_requires_ruff_in_a_default_group(tmp_path: Path, pyproject_extra: str, expected: HookState) -> None:
    """A locked ruff that a plain `uv sync` would not install is an error, not LOCAL."""
    repo = _repo(tmp_path, "grp", precommit=_LOCAL_RUFF_BLOCK, lock=_lock("0.16.8"), pyproject_extra=pyproject_extra)

    report = classify(repo)

    assert report.state is expected
    if expected is HookState.LOCAL_NOT_SYNCED:
        assert report.severity is Severity.ERROR
        assert "uv sync" in report.detail


def test_ruff_in_default_groups_returns_none_without_pyproject(tmp_path: Path) -> None:
    """Missing or unreadable pyproject.toml is reported as unknown, not as a verdict."""
    assert ruff_in_default_groups(tmp_path / "pyproject.toml") is None
    (tmp_path / "pyproject.toml").write_text("[broken", encoding="utf-8")
    assert ruff_in_default_groups(tmp_path / "pyproject.toml") is None


def test_local_hook_calling_path_ruff_is_unpinned(tmp_path: Path) -> None:
    """A local hook that runs a PATH ruff bypasses uv.lock and is flagged."""
    precommit = (
        "repos:\n  - repo: local\n    hooks:\n      - id: ruff\n        entry: ruff check\n        language: system\n"
    )
    repo = _repo(tmp_path, "path-ruff", precommit=precommit, lock=_lock("0.16.8"))

    report = classify(repo)

    assert report.state is HookState.LOCAL_UNPINNED
    assert report.hook_ruff == "PATH"


def test_remaining_remote_pins_are_listed(tmp_path: Path) -> None:
    """Every remote rev pin is surfaced so gitleaks/uv drift stays visible too."""
    repo = _repo(tmp_path, "pins", precommit=_remote_block("v0.8.0", gitleaks_rev="v8.24.2"), lock=_lock("0.16.4"))

    report = classify(repo)

    assert [pin.label for pin in report.remote_pins] == [
        "uv-pre-commit@0.8.15",
        "ruff-pre-commit@v0.8.0",
        "gitleaks@v8.24.2",
    ]


def test_unreadable_config_is_an_error(tmp_path: Path) -> None:
    """A malformed pre-commit config is reported rather than raising."""
    repo = _repo(tmp_path, "broken", precommit="repos: [unclosed", lock=_lock("0.16.8"))

    report = classify(repo)

    assert report.state is HookState.UNREADABLE
    assert report.severity is Severity.ERROR


def test_cli_exit_code_follows_severity(tmp_path: Path) -> None:
    """Errors fail the command; warnings only fail under --strict."""
    aligned = _repo(tmp_path, "aligned", precommit=_remote_block("v0.16.8"), lock=_lock("0.16.8"))
    drift = _repo(tmp_path, "drift", precommit=_remote_block("v0.8.0"), lock=_lock("0.16.8"))
    runner = CliRunner()

    ok = runner.invoke(hooks_command, [str(aligned)])
    strict = runner.invoke(hooks_command, ["--strict", str(aligned)])
    failing = runner.invoke(hooks_command, [str(drift)])

    assert ok.exit_code == 0, ok.output
    assert "ALIGNED" in ok.output and "Summary: ALIGNED=1" in ok.output
    assert strict.exit_code == 1, strict.output
    assert failing.exit_code == 1, failing.output
    assert "DRIFT" in failing.output


def test_cli_scans_configured_roots_with_all(tmp_path: Path) -> None:
    """--all enumerates Python projects under the configured roots, honouring skip."""
    root = tmp_path / "fleet"
    root.mkdir()
    _repo(root, "alpha", precommit=_LOCAL_RUFF_BLOCK, lock=_lock("0.16.8"))
    _repo(root, "beta", precommit=_remote_block("v0.8.0"), lock=_lock("0.16.8"))
    _repo(root, "skipped", precommit=_remote_block("v0.8.0"), lock=_lock("0.16.8"))
    (root / "not-python").mkdir()
    config = tmp_path / "roots.toml"
    config.write_text(
        f'[defaults]\nroots = ["{root.as_posix()}", "{(tmp_path / "missing").as_posix()}"]\nskip = ["skipped"]\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(hooks_command, ["--all", "--config", str(config), "--no-pins"])

    assert result.exit_code == 1, result.output
    lines = [line for line in result.output.splitlines() if not line.startswith("Summary")]
    assert [line.split()[0] for line in lines] == ["alpha", "beta"]
    assert "Summary: DRIFT=1, LOCAL=1" in result.output


def test_cli_rejects_targets_with_all(tmp_path: Path) -> None:
    """TARGETS and --all are mutually exclusive."""
    result = CliRunner().invoke(hooks_command, ["--all", str(tmp_path)])

    assert result.exit_code == 2
    assert "not both" in result.output


def test_discover_skips_dotdirs_and_non_projects(tmp_path: Path) -> None:
    """Discovery ignores hidden directories and directories without pyproject.toml."""
    (tmp_path / ".hidden").mkdir()
    (tmp_path / ".hidden" / "pyproject.toml").write_text("", encoding="utf-8")
    (tmp_path / "plain").mkdir()
    _repo(tmp_path, "real", precommit=None, lock=None)

    assert [p.name for p in discover_repositories([tmp_path], set())] == ["real"]


def test_hooks_is_registered_on_the_main_group() -> None:
    """The command is reachable as ``acidbase hooks``."""
    assert main.commands["hooks"] is hooks_command


def _hooks_by_id(config_path: Path) -> dict[str, dict]:
    """Returns ``{hook_id: hook}`` for every hook in a pre-commit config."""
    data = yaml.safe_load(config_path.read_text(encoding="utf-8-sig"))
    return {hook["id"]: hook for repo in data["repos"] for hook in repo["hooks"]}


def test_template_carries_no_remote_pins() -> None:
    """The shipped template pins no ``rev:``; every version has one owner elsewhere."""
    data = yaml.safe_load(_TEMPLATE_PRECOMMIT.read_text(encoding="utf-8-sig"))

    assert [repo["repo"] for repo in data["repos"]] == ["local"]
    assert all("rev" not in repo for repo in data["repos"])


def test_template_ruff_hooks_resolve_through_uv_lock() -> None:
    """The template's ruff hooks classify as LOCAL against a lock that pins ruff."""
    hooks = _hooks_by_id(_TEMPLATE_PRECOMMIT)

    for hook_id in ("ruff", "ruff-format"):
        assert hooks[hook_id]["language"] == "system"
        assert hooks[hook_id]["entry"].startswith("uv run --frozen python -m ruff ")
        # CI runs `ruff format --check .`, and ruff >= 0.16 formats Markdown code
        # blocks by default, so the hook must cover the same file types.
        assert hooks[hook_id]["types_or"] == ["python", "pyi", "jupyter", "markdown"]


def test_own_precommit_mirrors_template_shared_hooks() -> None:
    """acidbase's own config and the template agree on every shared hook.

    This is the assertion that was missing when the template sat on ruff v0.8.0
    while the repo locked 0.15.x: the two files claimed to mirror each other
    and nothing checked. acidbase-only hooks (uv-export) and the gitleaks
    config file name are the only permitted differences.
    """
    template = _hooks_by_id(_TEMPLATE_PRECOMMIT)
    own = _hooks_by_id(_OWN_PRECOMMIT)

    assert set(template) <= set(own)
    assert set(own) - set(template) == {"uv-export"}
    for hook_id in ("uv-lock", "ruff", "ruff-format"):
        assert own[hook_id] == template[hook_id], hook_id

    template_gitleaks = dict(template["gitleaks"])
    own_gitleaks = dict(own["gitleaks"])
    assert template_gitleaks.pop("args") != own_gitleaks.pop("args")
    assert template_gitleaks == own_gitleaks
