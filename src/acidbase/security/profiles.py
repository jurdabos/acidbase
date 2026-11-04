"""
Per-repository profile resolution for security patches.

A profile combines a repository's GitHub name with the local checkout path,
default branch (auto-detected if absent), and the publish command used to
ship the security commit. Profiles let the same patcher loop work across
repos that differ only in checkout location (e.g. a Windows drive vs a
Linux/WSL home directory) or push behaviour (vanilla ``git push`` vs a
project-specific wrapper such as ``uv run <repo> push``).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence

DEFAULT_PUSH_COMMAND: tuple[str, ...] = ("git", "push", "origin", "{branch}")


@dataclass(frozen=True)
class Profile:
    """Resolved per-repo settings used by the patcher and publisher."""

    repo: str
    path: Path
    branch: Optional[str] = None
    push_command: tuple[str, ...] = DEFAULT_PUSH_COMMAND
    npm_dir: Optional[str] = None
    extras: dict[str, Any] = field(default_factory=dict)


def _expand(p: str) -> Path:
    """Returns ``p`` with ``~`` and ``$VAR`` expanded; relative paths are unchanged."""
    return Path(os.path.expandvars(os.path.expanduser(p)))


def _is_git_checkout(p: Path) -> bool:
    """
    Returns True when ``p`` looks like a git working tree.

    Accepts both normal checkouts (``p/.git`` is a directory) and worktrees /
    submodules / sparse setups (``p/.git`` is a file containing a ``gitdir:``
    pointer). Requiring this prevents the resolver from silently accepting a
    *parent* directory that happens to exist but is not the repo itself.
    """
    return p.is_dir() and (p / ".git").exists()


def _first_git_checkout(candidates: Sequence[str]) -> Optional[Path]:
    """Returns the first expanded candidate that is a git checkout, or None."""
    for raw in candidates:
        p = _expand(raw)
        if _is_git_checkout(p):
            return p
    return None


def load_config(toml_path: Optional[Path] = None) -> dict[str, Any]:
    """
    Returns parsed config from ``toml_path``.

    When ``toml_path`` is None the resolution order is:
    1. ``$ACIDBASE_SECURITY_CONFIG`` env var if it points to an existing file.
    2. ``<repo-root>/config/security_patch.toml`` discovered by walking up from
       the current working directory.
    3. An empty config (caller falls back to package defaults).
    """
    if toml_path is None:
        env_value = os.environ.get("ACIDBASE_SECURITY_CONFIG")
        if env_value:
            candidate = Path(env_value).expanduser()
            if candidate.is_file():
                toml_path = candidate
    if toml_path is None:
        toml_path = _discover_repo_config()
    if toml_path is None:
        return {}
    with toml_path.open("rb") as fh:
        return tomllib.load(fh)


def _discover_repo_config() -> Optional[Path]:
    """Walks upward from the cwd to find ``config/security_patch.toml``."""
    here = Path.cwd().resolve()
    for directory in (here, *here.parents):
        candidate = directory / "config" / "security_patch.toml"
        if candidate.is_file():
            return candidate
    return None


def _match_profile_key(profiles: dict[str, Any], repo: str) -> Optional[str]:
    """
    Returns the ``profiles`` table key matching ``repo``, or None.

    Prefers an exact match; when absent, falls back to the first key equal
    under :meth:`str.casefold` so a repo requested in a different casing (e.g.
    ``--repo canonfodder``) still resolves a ``[profiles.CanonFodder]`` block.
    This matters because the scanner stamps each hit with the literal ``--repo``
    value while the checkout may live on a case-sensitive filesystem (WSL ext4),
    where the block's explicit ``paths``/``locals`` are the only way to locate
    it. Returns None when no key matches so the caller drops to defaults.
    """
    if repo in profiles:
        return repo
    target = repo.casefold()
    for key in profiles:
        if key.casefold() == target:
            return key
    return None


def resolve_profile(repo: str, config: dict[str, Any]) -> Optional[Profile]:
    """
    Returns a :class:`Profile` for ``repo`` using ``config`` defaults and overrides.

    The ``profiles`` table is matched case-insensitively (see
    :func:`_match_profile_key`) so a repo requested in a different casing than
    its ``[profiles.<Repo>]`` key — e.g. ``--repo canonfodder`` against a
    ``[profiles.CanonFodder]`` block — still picks up that block's ``paths`` /
    ``locals`` / ``push_command`` / ``npm_dir`` overrides. Returns ``None`` if no
    local checkout can be located on this machine; the caller marks such repos
    as ``MISSING`` in the run report.
    """
    defaults = config.get("defaults", {}) or {}
    profiles = config.get("profiles", {}) or {}
    matched_key = _match_profile_key(profiles, repo)
    overrides: dict[str, Any] = (profiles.get(matched_key) if matched_key else {}) or {}
    path = _resolve_path(repo, defaults, overrides)
    if path is None:
        return None
    push_command_raw = overrides.get("push_command") or defaults.get("push_command") or DEFAULT_PUSH_COMMAND
    reserved_keys = {"path", "paths", "local", "locals", "branch", "push_command", "npm_dir"}
    return Profile(
        repo=repo,
        path=path,
        branch=overrides.get("branch") or defaults.get("branch"),
        push_command=tuple(push_command_raw),
        npm_dir=overrides.get("npm_dir") or defaults.get("npm_dir"),
        extras={k: v for k, v in overrides.items() if k not in reserved_keys},
    )


def _resolve_path(repo: str, defaults: dict[str, Any], overrides: dict[str, Any]) -> Optional[Path]:
    """
    Returns the local checkout path for ``repo`` according to the resolution order.

    Order: ``paths`` list (per-repo) -> ``path`` (per-repo) ->
    ``defaults.roots`` joined with ``locals``/``local``/repo-name
    (first one that is an actual git checkout wins).

    A candidate is accepted only when :func:`_is_git_checkout` returns True, so
    a directory that exists but lacks ``.git`` is skipped rather than silently
    treated as the repo. This guards against misconfigured ``paths`` entries
    that point at the *parent* of the real checkout.
    """
    explicit_paths = overrides.get("paths")
    if explicit_paths:
        found = _first_git_checkout(explicit_paths)
        if found is not None:
            return found
    explicit_path = overrides.get("path")
    if explicit_path:
        candidate = _expand(explicit_path)
        if _is_git_checkout(candidate):
            return candidate
    roots: list[str] = list(defaults.get("roots") or [])
    locals_list: list[str] = list(overrides.get("locals") or [])
    if not locals_list:
        single_local = overrides.get("local")
        locals_list = [single_local] if single_local else [repo]
    for root in roots:
        for local_name in locals_list:
            candidate = _expand(root) / local_name
            if _is_git_checkout(candidate):
                return candidate
    return None


def list_skipped(config: dict[str, Any]) -> list[str]:
    """Returns the configured skip list (repos never touched by the scanner)."""
    return list((config.get("defaults") or {}).get("skip") or [])
