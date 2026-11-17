"""
Tests the GitHub guard and the layout checks of mirror-mode repositories against real git.

No test reaches the network: GitHub URLs are only rewritten, inspected or pushed to through an unreachable proxy.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from acidbase import hosting
from acidbase.hosting import MirrorSettings

_MIRROR_TABLE = '[tool.acidbase.push]\nmode = "mirror"\nprivate_remote = "origin"\npublic_remote = "deps"\n'


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """
    Runs git in ``root`` with a proxy that cannot connect, so a guard failure can never reach GitHub.
    """
    return subprocess.run(
        ["git", "-c", "http.proxy=http://127.0.0.1:9", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=check,
    )


def _repo(tmp_path: Path, *, mirror: bool = True) -> Path:
    """
    Creates a repository with one commit and, by default, a mirror-mode pyproject.toml.
    """
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    body = '[project]\nname = "project"\nversion = "0"\n'
    (root / "pyproject.toml").write_text(body + ("\n" + _MIRROR_TABLE if mirror else ""), encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


@pytest.mark.parametrize(
    ("url", "host", "github"),
    [
        ("https://github.com/owner/repo.git", "github.com", True),
        ("git@github.com:owner/repo.git", "github.com", True),
        ("ssh://git@ssh.github.com:443/owner/repo.git", "ssh.github.com", True),
        ("https://user@GitHub.com/owner/repo", "github.com", True),
        ("git-server:project.git", "git-server", False),
        ("git@gitlab.com:owner/repo.git", "gitlab.com", False),
        ("https://notgithub.com/owner/repo", "notgithub.com", False),
        (r"C:\repos\bare.git", "", False),
        ("/srv/git/repo.git", "", False),
        ("../relative:odd/repo.git", "", False),
    ],
)
def test_url_host_and_github_detection(url: str, host: str, github: bool) -> None:
    assert hosting.url_host(url) == host
    assert hosting.is_github_url(url) is github


def test_mirror_settings_reads_only_mirror_mode(tmp_path: Path) -> None:
    root = tmp_path / "p"
    root.mkdir()
    assert hosting.mirror_settings(root) is None
    (root / "pyproject.toml").write_text('[tool.acidbase.push]\nprivate_remote = "origin"\n', encoding="utf-8")
    assert hosting.mirror_settings(root) is None
    (root / "pyproject.toml").write_text('[tool.acidbase.push]\nmode = "mirror"\n', encoding="utf-8")
    assert hosting.mirror_settings(root) == MirrorSettings("origin", "deps")
    (root / "pyproject.toml").write_text(
        '[tool.acidbase.push]\nmode = "mirror"\nprivate_remote = "code"\npublic_remote = "gh"\n', encoding="utf-8"
    )
    assert hosting.mirror_settings(root) == MirrorSettings("code", "gh")
    (root / "pyproject.toml").write_text("[tool.acidbase\n", encoding="utf-8")
    assert hosting.mirror_settings(root) is None


def test_install_guard_is_idempotent_and_complete(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    assert hosting.guard_missing(root) == list(hosting.GITHUB_PUSH_PREFIXES)
    assert hosting.install_guard(root) == list(hosting.GITHUB_PUSH_PREFIXES)
    assert hosting.guard_missing(root) == []
    assert hosting.install_guard(root) == []


def test_install_guard_raises_outside_a_repository(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        hosting.install_guard(tmp_path)


def test_guard_blocks_pushes_to_github_but_not_fetch_urls(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    hosting.install_guard(root)
    _git(root, "remote", "add", "github", "https://github.com/owner/repo.git")
    _git(root, "remote", "add", "ssh", "git@github.com:owner/repo.git")
    pushed = _git(root, "push", "https://github.com/owner/repo.git", "HEAD:main", check=False)
    assert pushed.returncode != 0
    assert "acidbase-blocks-github" in pushed.stderr
    pushed_by_name = _git(root, "push", "ssh", "HEAD:main", check=False)
    assert pushed_by_name.returncode != 0
    assert "acidbase-blocks-github" in pushed_by_name.stderr
    assert hosting.remote_url(root, "github") == "https://github.com/owner/repo.git"
    assert all(url.startswith(hosting.GUARD_BASE) for url in hosting.push_urls(root, "ssh"))


def test_hosting_problems_is_empty_for_the_intended_layout(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _git(root, "remote", "add", "origin", "git-server:project.git")
    _git(root, "remote", "add", "deps", "https://github.com/owner/project.git")
    hosting.install_guard(root)
    settings = hosting.mirror_settings(root)
    assert settings is not None
    assert hosting.hosting_problems(root, settings) == []
    assert hosting.describe(root, settings) == "code on git-server, dependency mirror on GitHub"


def test_hosting_problems_names_every_way_code_could_reach_github(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _git(root, "remote", "add", "origin", "https://github.com/owner/project.git")
    _git(root, "remote", "add", "stale", "git@github.com:owner/old.git")
    _git(root, "remote", "add", "sneaky", "git-server:project.git")
    _git(root, "remote", "set-url", "--push", "sneaky", "https://github.com/owner/sneaky.git")
    problems = hosting.hosting_problems(root, MirrorSettings("origin", "deps"))
    assert "mirror remote 'deps' is missing" in problems
    assert "remote 'origin' fetches from GitHub" in problems
    assert "remote 'stale' fetches from GitHub" in problems
    assert "remote 'sneaky' pushes to GitHub" in problems
    assert any("guard incomplete" in problem for problem in problems)
    # An explicit pushurl escapes pushInsteadOf, so the guard alone cannot hide that remote
    hosting.install_guard(root)
    assert "remote 'sneaky' pushes to GitHub" in hosting.hosting_problems(root, MirrorSettings("origin", "deps"))


def test_hosting_problems_reports_a_missing_code_remote(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    _git(root, "remote", "add", "deps", "https://github.com/owner/project.git")
    hosting.install_guard(root)
    assert hosting.hosting_problems(root, MirrorSettings("origin", "deps")) == ["code remote 'origin' is missing"]
