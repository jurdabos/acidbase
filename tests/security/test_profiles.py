"""Tests for :mod:`acidbase.security.profiles` resolution semantics."""

from __future__ import annotations

from pathlib import Path

import pytest

from acidbase.security.profiles import (
    DEFAULT_PUSH_COMMAND,
    Profile,
    load_config,
    resolve_profile,
)


def _touch(p: Path) -> Path:
    """Creates ``p`` as a directory with an empty ``.git`` marker and returns it.

    The ``.git`` marker matches what :func:`acidbase.security.profiles._is_git_checkout`
    looks for, so paths returned by this helper are accepted by the resolver.
    """
    p.mkdir(parents=True, exist_ok=True)
    (p / ".git").mkdir(exist_ok=True)
    return p


def _touch_plain(p: Path) -> Path:
    """Creates ``p`` as a directory WITHOUT a ``.git`` marker (not a checkout)."""
    p.mkdir(parents=True, exist_ok=True)
    return p


def test_resolve_profile_uses_explicit_paths_first(tmp_path):
    """`paths` list wins over defaults.roots when at least one entry exists."""
    real = _touch(tmp_path / "elsewhere" / "repo")
    config = {
        "defaults": {"roots": [str(tmp_path / "default-root")]},
        "profiles": {
            "MyRepo": {
                "paths": [
                    str(tmp_path / "missing"),
                    str(real),
                ],
            }
        },
    }
    profile = resolve_profile("MyRepo", config)
    assert profile is not None
    assert profile.path == real
    assert profile.push_command == DEFAULT_PUSH_COMMAND


def test_resolve_profile_falls_back_to_roots_with_locals(tmp_path):
    """When no explicit path is set, defaults.roots + locals[] are tried in order."""
    root_a = _touch(tmp_path / "rootA")
    _touch(root_a / "repo-lower")
    config = {
        "defaults": {
            "roots": [str(tmp_path / "missing"), str(root_a)],
        },
        "profiles": {
            "RepoLower": {"locals": ["repo-upper", "repo-lower"]},
        },
    }
    profile = resolve_profile("RepoLower", config)
    assert profile is not None
    assert profile.path == root_a / "repo-lower"


def test_resolve_profile_uses_repo_name_when_no_local(tmp_path):
    """Falls back to the repo name as the local folder when no overrides exist."""
    root = _touch(tmp_path / "root")
    _touch(root / "MyRepo")
    config = {"defaults": {"roots": [str(root)]}}
    profile = resolve_profile("MyRepo", config)
    assert profile is not None
    assert profile.path == root / "MyRepo"


def test_resolve_profile_returns_none_when_nothing_exists(tmp_path):
    """No path exists for the repo on this host => None signals MISSING."""
    config = {"defaults": {"roots": [str(tmp_path / "absent")]}}
    assert resolve_profile("ghost", config) is None


def test_resolve_profile_skips_non_git_directory_in_paths(tmp_path):
    """A candidate path that exists but lacks ``.git`` must NOT be selected.

    Regression test for the misconfiguration where ``profiles.<repo>.paths``
    pointed at the parent directory of the real checkout: the parent existed
    (so old ``_first_existing`` returned it), but the repo actually lived in
    a sub-folder. The resolver should now skip the parent and pick the real
    checkout.
    """
    parent = _touch_plain(tmp_path / "parent")  # exists, no .git
    real = _touch(parent / "repo")  # exists, has .git
    config = {
        "profiles": {
            "MisplacedRepo": {
                "paths": [
                    str(parent),  # bait: exists but not a repo
                    str(real),  # the real checkout
                ],
            }
        },
    }
    profile = resolve_profile("MisplacedRepo", config)
    assert profile is not None
    assert profile.path == real


def test_resolve_profile_skips_non_git_directory_in_roots(tmp_path):
    """Stale directory under a root must NOT mask a real repo at a later root."""
    root_a = _touch_plain(tmp_path / "rootA")
    _touch_plain(root_a / "MyRepo")  # exists, no .git
    root_b = _touch_plain(tmp_path / "rootB")
    real = _touch(root_b / "MyRepo")  # the real checkout
    config = {"defaults": {"roots": [str(root_a), str(root_b)]}}
    profile = resolve_profile("MyRepo", config)
    assert profile is not None
    assert profile.path == real


def test_resolve_profile_accepts_git_file_marker(tmp_path):
    """A worktree/submodule with ``.git`` as a file (not dir) is still accepted."""
    p = tmp_path / "worktree"
    p.mkdir()
    (p / ".git").write_text("gitdir: ../main/.git/worktrees/wt1\n", encoding="utf-8")
    config = {"profiles": {"WT": {"paths": [str(p)]}}}
    profile = resolve_profile("WT", config)
    assert profile is not None
    assert profile.path == p


def test_resolve_profile_overrides_push_command(tmp_path):
    """Per-repo push_command wins over defaults.push_command."""
    root = _touch(tmp_path / "root")
    _touch(root / "evidencia")
    config = {
        "defaults": {
            "roots": [str(root)],
            "push_command": ["git", "push", "origin", "{branch}"],
        },
        "profiles": {
            "evidencia": {"push_command": ["uv", "run", "evidencia", "push"]},
        },
    }
    profile = resolve_profile("evidencia", config)
    assert profile is not None
    assert profile.push_command == ("uv", "run", "evidencia", "push")


def test_load_config_returns_empty_when_nothing_resolves(tmp_path, monkeypatch):
    """Returns an empty dict when no config path is given/found anywhere."""
    monkeypatch.delenv("ACIDBASE_SECURITY_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    assert load_config(None) == {}


def test_load_config_parses_valid_toml(tmp_path):
    """A real TOML file is parsed into the expected nested dict."""
    p = tmp_path / "config.toml"
    p.write_text(
        '[defaults]\nroots = ["/tmp"]\nskip = ["a"]\n[profiles.foo]\nlocal = "foo"\n',
        encoding="utf-8",
    )
    cfg = load_config(p)
    assert cfg["defaults"]["roots"] == ["/tmp"]
    assert cfg["profiles"]["foo"]["local"] == "foo"


def test_profile_dataclass_is_immutable():
    """Profile is frozen so consumers can rely on its values."""
    profile = Profile(repo="x", path=Path("."))
    with pytest.raises(Exception):
        profile.repo = "y"  # type: ignore[misc]


def test_resolve_profile_reads_npm_dir(tmp_path):
    """`profiles.<Repo>.npm_dir` is exposed via :attr:`Profile.npm_dir`."""
    root = _touch(tmp_path / "root")
    _touch(root / "bracket")
    config = {
        "defaults": {"roots": [str(root)]},
        "profiles": {"bracket": {"npm_dir": "frontend"}},
    }
    profile = resolve_profile("bracket", config)
    assert profile is not None
    assert profile.npm_dir == "frontend"
    # extras must not include the reserved npm_dir key, otherwise the resolver leaks it twice.
    assert "npm_dir" not in profile.extras


def test_resolve_profile_matches_profile_key_case_insensitively(tmp_path):
    """A repo requested in a different casing still resolves its profile block.

    Regression: `--repo canonfodder` (lowercase) missed the
    `[profiles.CanonFodder]` block because the lookup was case-sensitive, so the
    block's explicit `paths` were skipped and the default-roots fallback then
    failed on a case-sensitive filesystem where only `CanonFodder` exists. The
    lookup now matches the profiles-table key under casefold. `default-root`
    does not exist, so resolution can only succeed via the matched block.
    """
    real = _touch(tmp_path / "wsl-home" / "CanonFodder")
    config = {
        "defaults": {"roots": [str(tmp_path / "default-root")]},
        "profiles": {"CanonFodder": {"paths": [str(real)]}},
    }
    profile = resolve_profile("canonfodder", config)
    assert profile is not None
    assert profile.path == real


def test_resolve_profile_case_insensitive_key_applies_overrides(tmp_path):
    """A casefold-matched block contributes all its overrides, not just paths.

    The differently-cased request must still pick up the block's non-path
    overrides (here `push_command`), confirming the whole overrides dict — not
    only `paths` — flows through when the key matches under casefold.
    """
    real = _touch(tmp_path / "checkout" / "CanonFodder")
    config = {
        "profiles": {
            "CanonFodder": {
                "paths": [str(real)],
                "push_command": ["uv", "run", "canonfodder", "push"],
            }
        },
    }
    profile = resolve_profile("canonfodder", config)
    assert profile is not None
    assert profile.path == real
    assert profile.push_command == ("uv", "run", "canonfodder", "push")
