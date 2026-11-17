"""
Catch-all patching of every fixable Dependabot alert in one repository.

``acidbase repopatch`` plans from a single alerts query, then reuses the
per-package bump that ``acidbase patch`` performs (:func:`patch_repo`), so each
package keeps its preflight, rebase, lock verification, and revert-on-failure
behaviour and lands as its own commit. The branch is pushed once at the end, so
CI runs once instead of once per package.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Optional

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from acidbase.security import shell
from acidbase.security.alerts import DependabotAlert
from acidbase.security.patcher import PatchResult, PatchStatus, patch_repo
from acidbase.security.profiles import Profile
from acidbase.security.publisher import _count_unpushed, _run_push_command

# Ecosystems the per-package bump can handle; anything else is reported for manual work.
SUPPORTED_ECOSYSTEMS: tuple[str, ...] = ("pip", "npm")

# Listing at most this many advisory ids in a commit message before summarizing the rest.
_ADVISORIES_IN_MESSAGE = 3

# Failures that happen after the bump started editing files; only these are safe to revert,
# because the bump's preflight verified a clean tree immediately before.
_REVERTIBLE_FAILURES = frozenset(
    {PatchStatus.UVADDFAIL, PatchStatus.NPMADDFAIL, PatchStatus.EXPORTFAIL, PatchStatus.COMMITFAIL}
)

# Failures about the repository itself; every remaining package would hit them too, so the run stops.
# DIRTY in particular means the user's own uncommitted work, which must never be reverted.
_REPO_LEVEL_FAILURES = frozenset(
    {
        PatchStatus.DIRTY,
        PatchStatus.GITERROR,
        PatchStatus.MISSING,
        PatchStatus.NOTUV,
        PatchStatus.NOTNPM,
        PatchStatus.SELFSKIP,
        PatchStatus.UNSUPPORTED_LOCKFILE,
    }
)


@dataclass
class PackagePlan:
    """One planned bump: a package, its target version, and every advisory it closes."""

    ecosystem: str
    package: str
    new_version: str
    advisories: list[str] = field(default_factory=list)
    manifest: Optional[str] = None

    @property
    def advisory_label(self) -> str:
        """Returns the advisory reference used in the commit message (first few ids plus a count)."""
        shown = self.advisories[:_ADVISORIES_IN_MESSAGE]
        rest = len(self.advisories) - len(shown)
        label = ", ".join(shown) if shown else "Dependabot alerts"
        return f"{label} and {rest} more" if rest > 0 else label


@dataclass
class ManualItem:
    """An alerted package repopatch cannot bump automatically, with the reason why."""

    ecosystem: str
    package: str
    reason: str
    advisories: list[str] = field(default_factory=list)


@dataclass
class RepoPatchOutcome:
    """Per-package results plus the outcome of the single final push."""

    results: list[tuple[PackagePlan, PatchResult]] = field(default_factory=list)
    pushed: bool = False
    push_note: str = ""


def _package_key(ecosystem: str, package: str) -> str:
    """Returns the grouping key; pip names are PEP 503-normalized, other ecosystems stay raw."""
    return canonicalize_name(package) if ecosystem == "pip" else package


def _is_secondary_requirements(manifest: Optional[str]) -> bool:
    """Returns True for a requirements file below the repo root (e.g. ``producer/requirements.txt``)."""
    return bool(manifest and "/" in manifest and manifest.endswith("requirements.txt"))


def plan_repo_patches(alerts: Iterable[DependabotAlert]) -> tuple[list[PackagePlan], list[ManualItem]]:
    """
    Returns ``(plans, manual)`` built from one repository's open alerts.

    Alerts are grouped per ``(ecosystem, package)``, folding pip spelling
    variants such as ``GitPython``/``Gitpython``. Each plan targets the highest
    patched version among its alerts and lists every advisory id once, in first
    seen order. The displayed package name is the most frequent spelling.
    Packages whose alerts carry no patched version, or whose ecosystem
    acidbase cannot bump, go to ``manual``. Plans are returned sorted by
    ecosystem, then case-insensitive package name.
    """
    buckets: dict[tuple[str, str], dict] = {}
    for alert in alerts:
        eco = (alert.ecosystem or "").casefold()
        key = (eco, _package_key(eco, alert.package))
        bucket = buckets.setdefault(key, {"spellings": Counter(), "advisories": [], "best": None, "manifest": None})
        bucket["spellings"][alert.package] += 1
        if alert.advisory_id and alert.advisory_id not in bucket["advisories"]:
            bucket["advisories"].append(alert.advisory_id)
        if _is_secondary_requirements(alert.manifest) and bucket["manifest"] is None:
            bucket["manifest"] = alert.manifest
        if not alert.patched_version:
            continue
        try:
            candidate = Version(alert.patched_version)
        except InvalidVersion:
            continue
        if bucket["best"] is None or candidate > Version(bucket["best"]):
            bucket["best"] = alert.patched_version
    plans: list[PackagePlan] = []
    manual: list[ManualItem] = []
    for (eco, _key), bucket in sorted(buckets.items(), key=lambda item: (item[0][0], item[0][1].casefold())):
        package = bucket["spellings"].most_common(1)[0][0]
        if eco not in SUPPORTED_ECOSYSTEMS:
            manual.append(
                ManualItem(eco, package, f"acidbase cannot bump the {eco or 'unknown'} ecosystem", bucket["advisories"])
            )
        elif bucket["best"] is None:
            manual.append(ManualItem(eco, package, "no patched version published", bucket["advisories"]))
        else:
            plans.append(PackagePlan(eco, package, bucket["best"], bucket["advisories"], bucket["manifest"]))
    return plans, manual


def _restore_tracked_files(profile: Profile, on_log: Optional[Callable[[str], None]]) -> bool:
    """
    Returns True after discarding tracked-file edits a failed bump left behind.

    Each bump starts from a verified-clean tree (``patch_repo`` refuses dirty
    ones), so any tracked modification present after a failure was made by
    that bump. Untracked files are left alone, matching the clean check.
    """
    status = shell.run(["git", "--no-pager", "status", "--porcelain", "--untracked-files=no"], cwd=profile.path)
    if not status.ok or not status.stdout.strip():
        return False
    if on_log is not None:
        on_log("  restoring tracked files left modified by the failed bump")
    restore = shell.run(["git", "checkout", "--", "."], cwd=profile.path)
    return restore.ok


def run_repo_patches(
    profile: Profile,
    plans: list[PackagePlan],
    *,
    dry_run: bool = False,
    on_log: Optional[Callable[[str], None]] = None,
    on_start: Optional[Callable[[PackagePlan], None]] = None,
) -> RepoPatchOutcome:
    """
    Bumps every planned package with one commit each, then pushes once.

    A package that fails after editing files (e.g. ``UVADDFAIL`` when an
    override blocks the bump) is reported and skipped; its edits are reverted so
    the next package still starts from a clean tree. A repository-level failure
    (dirty tree, git error, missing clone, wrong project type, self-patch) stops
    the run instead, because every remaining package would fail the same way;
    those packages are reported as not attempted and nothing is reverted, so
    uncommitted user work is never touched. The push runs when at least one
    commit landed or the branch was already ahead of upstream, so successful
    bumps ship even if others failed. ``dry_run`` exercises each bump's
    preflight without side effects and never pushes.
    """
    outcome = RepoPatchOutcome()
    stopped: Optional[PatchResult] = None
    for plan in plans:
        if stopped is not None:
            outcome.results.append(
                (
                    plan,
                    PatchResult(
                        repo=profile.repo,
                        path=profile.path,
                        status=stopped.status,
                        note=f"not attempted: {stopped.status.value} on an earlier package",
                    ),
                )
            )
            continue
        if on_start is not None:
            on_start(plan)
        result = patch_repo(
            profile,
            dep_name=plan.package,
            new_version=plan.new_version,
            cve_id=plan.advisory_label,
            dry_run=dry_run,
            ecosystem=plan.ecosystem,
            on_log=on_log,
        )
        if result.status in _REVERTIBLE_FAILURES and _restore_tracked_files(profile, on_log):
            result.note = f"{result.note}; reverted its edits".lstrip("; ")
        if result.status in _REPO_LEVEL_FAILURES:
            stopped = result
        outcome.results.append((plan, result))
    if dry_run:
        return outcome
    committed = any(result.status is PatchStatus.DONE for _plan, result in outcome.results)
    if not committed and _count_unpushed(profile.path) == 0:
        outcome.push_note = "nothing to push"
        return outcome
    branch = next((result.branch for _plan, result in outcome.results if result.branch), None)
    push_result = PatchResult(repo=profile.repo, path=profile.path, status=PatchStatus.DONE, branch=branch)
    outcome.pushed = _run_push_command(profile, push_result, on_log=on_log)
    outcome.push_note = "pushed once" if outcome.pushed else push_result.note
    if not outcome.pushed:
        # Marking committed rows so the summary shows their fix did not reach origin
        for _plan, result in outcome.results:
            if result.status is PatchStatus.DONE:
                result.status = PatchStatus.PUSHFAIL
                result.note = f"{result.note}; {push_result.note}"
    return outcome
