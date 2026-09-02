"""
Publish strategies for the security patch flow.

Two strategies cover the runbook variants currently in use:

* :class:`PushStrategy` runs the resolved ``push_command`` from the profile
  (defaulting to ``git push origin <branch>``). Custom wrappers like
  ``uv run evidencia push`` are first-class via the profile.
* :class:`PrStrategy` opens a feature-branch pull request via the GitHub CLI
  and best-effort enables auto-merge so the patch lands once required checks
  pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

from acidbase.security import shell
from acidbase.security.patcher import (
    PatchResult,
    PatchStatus,
    patch_repo,
)
from acidbase.security.profiles import Profile

_BRANCH_TOKEN_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _slugify_branch_segment(value: str) -> str:
    """Returns a git-branch-safe slug derived from ``value``."""
    cleaned = _BRANCH_TOKEN_RE.sub("-", value).strip("-")
    return cleaned or "patch"


def _count_unpushed(path: Path) -> int:
    """
    Returns how many commits HEAD is ahead of its upstream at ``path``.

    Uses ``git rev-list --count @{upstream}..HEAD`` — the same probe as
    ``acidbase push``'s clean-but-ahead guard. A missing upstream or any git
    failure conservatively counts as 0 so a NOOP without a known upstream
    stays a no-op instead of triggering a push at an unknown target.
    """
    res = shell.run(["git", "rev-list", "--count", "@{upstream}..HEAD"], cwd=path)
    if not res.ok:
        return 0
    try:
        return int(res.stdout.strip() or "0")
    except ValueError:
        return 0


def _run_push_command(
    profile: Profile,
    result: PatchResult,
    on_log: Optional[Callable[[str], None]] = None,
) -> bool:
    """
    Runs the profile's ``push_command`` for ``result.branch``; returns True on success.

    On failure ``result`` is mutated to :attr:`PatchStatus.PUSHFAIL` with the
    standard note, so the DONE path and the NOOP-but-ahead path report push
    failures identically.
    """

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    push_args = shell.render_template(
        profile.push_command,
        branch=result.branch or "main",
        repo=profile.repo,
    )
    _log(f"  push: {' '.join(push_args)}")
    push = shell.run(push_args, cwd=profile.path)
    result.log.append(push.stdout + push.stderr)
    if not push.ok:
        result.status = PatchStatus.PUSHFAIL
        result.note = f"push failed via {push_args[0]}"
        _log(f"  PUSHFAIL rc={push.returncode}: {push.stderr.strip()[:200]!r}")
        return False
    return True


class PublishStrategy(Protocol):
    """Protocol implemented by every publish strategy."""

    def run(
        self,
        profile: Profile,
        *,
        dep_name: str,
        new_version: str,
        cve_id: str,
        owner: str,
        dry_run: bool,
        ecosystem: str = "pip",
        sync_env: bool = False,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> PatchResult:
        """Performs the bump and ships it according to the strategy's rules."""


@dataclass(frozen=True)
class PushStrategy:
    """Commits on the default branch and runs the profile's ``push_command``."""

    def run(
        self,
        profile: Profile,
        *,
        dep_name: str,
        new_version: str,
        cve_id: str,
        owner: str,
        dry_run: bool,
        ecosystem: str = "pip",
        sync_env: bool = False,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> PatchResult:
        def _log(msg: str) -> None:
            if on_log is not None:
                on_log(msg)

        result = patch_repo(
            profile,
            dep_name=dep_name,
            new_version=new_version,
            cve_id=cve_id,
            dry_run=dry_run,
            ecosystem=ecosystem,
            sync_env=sync_env,
            on_log=on_log,
        )
        if result.status is PatchStatus.NOOP and not dry_run:
            # A NOOP tree can still hide a stranded security commit: an earlier
            # run may have committed the bump and failed to publish (evidencia:
            # Pillow 12.3.0 sat unpushed while origin stayed vulnerable), and a
            # re-run then found everything "already satisfied" and never
            # re-attempted the push. Mirroring `acidbase push`'s clean-but-ahead
            # guard: when the branch is ahead of upstream, the profile's
            # push_command runs anyway.
            ahead = _count_unpushed(profile.path)
            if ahead > 0:
                _log(f"  NOOP but {ahead} commit(s) ahead of upstream; publishing stranded work")
                if _run_push_command(profile, result, on_log=on_log):
                    result.note = f"{result.note}; pushed {ahead} stranded commit(s)"
                    _log("  push OK")
            return result
        if result.status is not PatchStatus.DONE:
            return result
        if _run_push_command(profile, result, on_log=on_log):
            _log("  push OK")
        return result


@dataclass(frozen=True)
class PrStrategy:
    """Commits on a feature branch and opens a PR via ``gh pr create``."""

    auto_merge: bool = True
    merge_method: str = "squash"  # one of "squash", "merge", "rebase"

    def run(
        self,
        profile: Profile,
        *,
        dep_name: str,
        new_version: str,
        cve_id: str,
        owner: str,
        dry_run: bool,
        ecosystem: str = "pip",
        sync_env: bool = False,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> PatchResult:
        def _log(msg: str) -> None:
            if on_log is not None:
                on_log(msg)

        feature_branch = f"security/{_slugify_branch_segment(dep_name)}-{_slugify_branch_segment(new_version)}"
        _log(f"PrStrategy: feature_branch={feature_branch}")
        result = patch_repo(
            profile,
            dep_name=dep_name,
            new_version=new_version,
            cve_id=cve_id,
            dry_run=dry_run,
            commit_branch=feature_branch,
            ecosystem=ecosystem,
            sync_env=sync_env,
            on_log=on_log,
        )
        if result.status is not PatchStatus.DONE:
            return result
        # Pushing the feature branch and opening a PR via gh.
        _log(f"  git push -u origin {feature_branch}")
        push = shell.run(
            ["git", "push", "-u", "origin", feature_branch],
            cwd=profile.path,
        )
        result.log.append(push.stdout + push.stderr)
        if not push.ok:
            result.status = PatchStatus.PUSHFAIL
            result.note = f"failed to push {feature_branch}"
            _log(f"  PUSHFAIL rc={push.returncode}: {push.stderr.strip()[:200]!r}")
            return result
        title = f"security: update {dep_name} to {new_version} to fix {cve_id}"
        body = f"Automated security bump of `{dep_name}` to `>={new_version}` addressing `{cve_id}`."
        _log(f"  gh pr create --repo {owner}/{profile.repo} --head {feature_branch}")
        pr = shell.run(
            [
                "gh",
                "pr",
                "create",
                "--repo",
                f"{owner}/{profile.repo}",
                "--head",
                feature_branch,
                "--title",
                title,
                "--body",
                body,
            ],
            cwd=profile.path,
        )
        result.log.append(pr.stdout + pr.stderr)
        if not pr.ok:
            result.status = PatchStatus.PUSHFAIL
            result.note = "gh pr create failed"
            _log(f"  gh pr create failed rc={pr.returncode}: {pr.stderr.strip()[:200]!r}")
            return result
        if self.auto_merge:
            merge_flag = {"squash": "--squash", "merge": "--merge", "rebase": "--rebase"}.get(
                self.merge_method, "--squash"
            )
            _log(f"  gh pr merge --auto {merge_flag} {feature_branch}")
            am = shell.run(
                ["gh", "pr", "merge", "--auto", merge_flag, feature_branch, "--repo", f"{owner}/{profile.repo}"],
                cwd=profile.path,
            )
            result.log.append(am.stdout + am.stderr)
            # auto-merge enablement is best-effort; don't fail the whole row.
            if not am.ok:
                result.note = (result.note + " | auto-merge not enabled").strip(" |")
                _log(f"  auto-merge not enabled rc={am.returncode}")
            else:
                _log("  auto-merge enabled")
        result.note = f"PR opened on {feature_branch}"
        return result
