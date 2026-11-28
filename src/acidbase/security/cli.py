"""
Click subcommand for the security patch flow.

Wires :mod:`acidbase.security` into a single ``acidbase patch`` command that
discovers affected repos, applies the bump per repo via the chosen publish
strategy, and verifies that Dependabot alerts clear afterwards. All progress
and the final report are rendered through ``rich`` so the output is the same
"cinema" you get from the original PowerShell driver, regardless of platform.
"""

from __future__ import annotations

import shlex
from collections import Counter
from pathlib import Path
from typing import Optional

import click
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from acidbase.security import shell
from acidbase.security.alerts import (
    VALID_DISMISS_REASONS,
    VALID_SEVERITIES,
    VALID_STATES,
    AlertSettingResult,
    AlertUpdateResult,
    DependabotAlert,
    dismiss_alert,
    enable_automated_security_fixes,
    enable_vulnerability_alerts,
    fetch_alerts_for_owner,
    fetch_alerts_for_repo,
    reopen_alert,
)
from acidbase.security.patcher import PatchResult, PatchStatus
from acidbase.security.profiles import (
    Profile,
    list_skipped,
    load_config,
    resolve_profile,
)
from acidbase.security.publisher import PrStrategy, PublishStrategy, PushStrategy
from acidbase.security.repopatch import PackagePlan, plan_repo_patches, run_repo_patches
from acidbase.security.scanner import VulnerableHit, discover_affected_repos
from acidbase.security.verifier import (
    ALERT_FIXED,
    ALERT_OPEN,
    verify_remote_bump,
)

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}

_STATUS_STYLE = {
    PatchStatus.DONE: "green",
    PatchStatus.NOOP: "yellow",
    PatchStatus.WOULD_RUN: "cyan",
    PatchStatus.MISSING: "magenta",
    PatchStatus.DIRTY: "magenta",
    PatchStatus.NOTUV: "magenta",
    PatchStatus.NOTNPM: "magenta",
    PatchStatus.UNSUPPORTED_LOCKFILE: "magenta",
    PatchStatus.SELFSKIP: "yellow",  # not a failure: deferred-by-design on Windows
    PatchStatus.GITERROR: "red",
    PatchStatus.PULLFAIL: "red",
    PatchStatus.UVADDFAIL: "red",
    PatchStatus.NPMADDFAIL: "red",
    PatchStatus.EXPORTFAIL: "red",
    PatchStatus.COMMITFAIL: "red",
    PatchStatus.PUSHFAIL: "red",
}


_SUPPORTED_ECOSYSTEMS: tuple[str, ...] = ("pip", "npm")

_ECOSYSTEM_TOOLS: dict[str, tuple[str, ...]] = {
    "pip": ("git", "gh", "uv"),
    "npm": ("git", "gh", "npm"),
}


def _ensure_tools(console: Console, ecosystem: str = "pip") -> bool:
    """Returns True when every external tool the ``ecosystem`` backend needs is on PATH."""
    required = _ECOSYSTEM_TOOLS.get(ecosystem.casefold(), _ECOSYSTEM_TOOLS["pip"])
    missing: list[str] = []
    for tool in required:
        try:
            shell.which_or_die(tool)
        except shell.ShellError:
            missing.append(tool)
    if missing:
        console.print(
            f"[red]Missing required tools on PATH: {', '.join(missing)}.[/red] Install them and retry.",
        )
        return False
    return True


def _render_hits(console: Console, hits: list[VulnerableHit]) -> None:
    """Prints a Rich table summarizing the SBOM scan results."""
    table = Table(title="Vulnerable repositories", show_lines=False)
    table.add_column("Repo", style="bold")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Threshold")
    for hit in hits:
        table.add_row(hit.repo, hit.package, hit.version, hit.threshold)
    console.print(table)


def _alert_display(alert_value: Optional[str], status: PatchStatus) -> tuple[str, str]:
    """
    Returns ``(text, style)`` for the Summary's Alert column.

    A bare ``FIXED`` from the verifier only means "the manifest now satisfies
    ``>= new_version``" — it does not say whether *this run* changed anything.
    Qualify it with the patch status so a no-op is visually obvious:

    * ``FIXED`` + :attr:`PatchStatus.NOOP` → ``FIXED (already satisfied)`` — the
      repo was already at/above the target before the run; nothing was bumped.
    * ``FIXED`` + :attr:`PatchStatus.DONE` → ``FIXED (bumped)`` — this run
      committed the change that satisfied the threshold.
    * any other ``FIXED`` → plain ``FIXED``.
    """
    if alert_value == ALERT_FIXED:
        if status == PatchStatus.NOOP:
            return "FIXED (already satisfied)", "green"
        if status == PatchStatus.DONE:
            return "FIXED (bumped)", "green"
        return ALERT_FIXED, "green"
    if alert_value == ALERT_OPEN:
        return ALERT_OPEN, "red"
    return alert_value or "-", "white"


def _render_summary(console: Console, results: list[PatchResult]) -> None:
    """Prints the per-repo status table including the post-verification Alert column."""
    table = Table(title="Summary", show_lines=False)
    table.add_column("Repo", style="bold")
    table.add_column("Path", overflow="fold")
    table.add_column("Status")
    table.add_column("Note", overflow="fold")
    table.add_column("Alert")
    for r in sorted(results, key=lambda x: x.repo.casefold()):
        status_style = _STATUS_STYLE.get(r.status, "white")
        alert_text, alert_style = _alert_display(r.alert, r.status)
        table.add_row(
            r.repo,
            str(r.path),
            f"[{status_style}]{r.status.value}[/{status_style}]",
            r.note,
            f"[{alert_style}]{alert_text}[/{alert_style}]",
        )
    console.print(table)


def _build_strategy(name: str) -> PublishStrategy:
    """Returns the publish strategy implementation matching ``name``."""
    if name == "push":
        return PushStrategy()
    if name == "pr":
        return PrStrategy()
    raise click.BadParameter(f"unknown strategy: {name}")


@click.command(name="patch")
@click.option("--owner", required=True, help="GitHub owner whose repos should be scanned.")
@click.option(
    "--repo",
    "repos",
    multiple=True,
    help=(
        "Repository to patch (repeatable). Each named repo is still re-checked against origin "
        "before patching. Omit to scan every non-archived, non-empty repo of OWNER."
    ),
)
@click.option("--dep", "dep_name", required=True, help="Vulnerable dependency name.")
@click.option(
    "--max-vulnerable",
    default=None,
    help=(
        "Optional inclusive upper bound for the SBOM scan. If omitted, the scan "
        "matches any version strictly below --new-version (i.e. anything still "
        "unpatched). Provide this only when you need a tighter window than the "
        "patched-vs-unpatched split (e.g. backporting)."
    ),
)
@click.option("--new-version", required=True, help="Patched version to bump to (uv add >=NEW).")
@click.option(
    "--cve",
    "cve_id",
    required=True,
    help=(
        "Advisory identifier referenced in the commit message. Accepts CVE IDs "
        "(CVE-YYYY-XXXXX) or GHSA IDs (GHSA-xxxx-xxxx-xxxx); use the value shown "
        "in the Advisory column of `acidbase alerts`."
    ),
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, path_type=Path, exists=True),
    default=None,
    help="Override the default security_patch.toml location.",
)
@click.option(
    "--strategy",
    type=click.Choice(["push", "pr"], case_sensitive=False),
    default="push",
    show_default=True,
    help="Publish mode: direct push to the default branch or open a PR per repo.",
)
@click.option("--dry-run", is_flag=True, help="Plan only; never run uv/git/gh side effects.")
@click.option(
    "--skip-verify",
    is_flag=True,
    help="Do not check origin's manifest for the patched version after the bump.",
)
@click.option(
    "--sync-env",
    "sync_env",
    is_flag=True,
    help=(
        "pip only: after each successful bump, also run `uv sync --frozen` in "
        "that repo so its local .venv picks up the fix immediately. Skipped "
        "automatically when the existing venv is not native to the uv that "
        "would perform the sync (e.g. a Linux venv reached from Windows "
        "outside WSL routing) \u2014 sync those on their native side instead."
    ),
)
@click.option(
    "--ecosystem",
    type=click.Choice(_SUPPORTED_ECOSYSTEMS, case_sensitive=False),
    default="pip",
    show_default=True,
    help=(
        "Package ecosystem to patch. 'pip' is GitHub's label for the PyPI "
        "ecosystem and runs uv (not pip) under the hood. 'npm' runs npm "
        "install with a package.json overrides fallback for transitive deps."
    ),
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help=("Print per-step diagnostics for every stage (scan, patch, publish, verify)."),
)
def patch_command(
    owner: str,
    repos: tuple[str, ...],
    dep_name: str,
    max_vulnerable: Optional[str],
    new_version: str,
    cve_id: str,
    config_path: Optional[Path],
    strategy: str,
    dry_run: bool,
    skip_verify: bool,
    sync_env: bool,
    ecosystem: str,
    verbose: bool,
) -> None:
    """Find vulnerable repos owner-wide, patch each, and verify alerts clear."""
    console = Console()
    ecosystem = ecosystem.casefold()
    if not _ensure_tools(console, ecosystem=ecosystem):
        raise click.exceptions.Exit(1)
    if sync_env and ecosystem != "pip":
        console.print("[yellow]--sync-env applies to the pip ecosystem only; ignoring for npm.[/yellow]")
        sync_env = False

    config = load_config(config_path)
    skip = list_skipped(config)

    # When --max-vulnerable is omitted, default to "strictly below --new-version"
    # so anything still unpatched is matched without including the patched version itself.
    if max_vulnerable is None:
        scan_threshold = new_version
        strict_below = True
        threshold_label = f"< {new_version}"
    else:
        scan_threshold = max_vulnerable
        strict_below = False
        threshold_label = f"<= {max_vulnerable}"

    # Deduplicating repeated --repo values while keeping the order given
    targets = list(dict.fromkeys(repos))
    if not targets:
        scope_label = owner
    elif len(targets) == 1:
        scope_label = f"{owner}/{targets[0]}"
    else:
        scope_label = f"{owner}/{{{','.join(targets)}}}"
    console.print(
        Panel.fit(
            f"[bold]{ecosystem}:{dep_name}[/bold] {threshold_label} "
            f"\u2192 bump to [bold green]>={new_version}[/bold green] "
            f"(strategy={strategy}, dry_run={dry_run}, scope={scope_label})",
            title="acidbase patch",
            border_style="cyan",
        )
    )

    def _on_log(msg: str) -> None:
        console.print(f"[dim]{msg}[/dim]", highlight=False)

    log_cb = _on_log if verbose else None

    # Stale dependency-graph (SBOM) nodes are demoted during discovery; collect
    # the warnings so they surface even without -v, since they explain why a
    # freshly-patched repo is intentionally absent from the vulnerable table.
    stale_warnings: list[str] = []

    # Running the same per-repo discovery (SBOM + live-manifest check + alerts fallback)
    # for each named repo, or once owner-wide when no --repo is given.
    hits: list[VulnerableHit] = []
    scopes: list[Optional[str]] = list(targets) or [None]  # None means owner-wide
    with console.status(f"Scanning {scope_label} repositories..."):
        for target in scopes:
            hits.extend(
                discover_affected_repos(
                    owner=owner,
                    dep_name=dep_name,
                    max_vulnerable=scan_threshold,
                    skip=skip,
                    strict_below=strict_below,
                    repo=target,
                    ecosystem=ecosystem,
                    patch_target=new_version,
                    cve_id=cve_id,
                    on_log=log_cb,
                    on_stale_warning=stale_warnings.append,
                )
            )
    hits.sort(key=lambda h: h.repo.casefold())

    for warning in stale_warnings:
        console.print(f"[yellow]Skipped stale dependency-graph hit:[/yellow] [dim]{warning}[/dim]")

    if not hits:
        console.print("[green]No vulnerable repositories found.[/green]")
        return
    _render_hits(console, hits)

    publisher = _build_strategy(strategy)
    results: list[PatchResult] = []
    profiles: dict[str, Profile] = {}
    for hit in hits:
        profile = resolve_profile(hit.repo, config)
        if profile is None:
            results.append(
                PatchResult(
                    repo=hit.repo,
                    path=Path("<unknown>"),
                    status=PatchStatus.MISSING,
                    note="no local clone discoverable on this host",
                )
            )
            continue
        profiles[hit.repo] = profile
        console.rule(f"[cyan]{hit.repo}[/cyan]  ({profile.path})")
        result = publisher.run(
            profile,
            dep_name=dep_name,
            new_version=new_version,
            cve_id=cve_id,
            owner=owner,
            dry_run=dry_run,
            ecosystem=ecosystem,
            sync_env=sync_env,
            on_log=log_cb,
        )
        results.append(result)

    if not skip_verify and not dry_run:
        verifiable = {r.repo: r.branch or "main" for r in results if r.status in {PatchStatus.DONE, PatchStatus.NOOP}}
        if verifiable:
            console.print("\n[yellow]Verifying remote manifest on origin...[/yellow]")
            npm_dirs = (
                {repo: (profiles[repo].npm_dir or ".") for repo in verifiable if repo in profiles}
                if ecosystem == "npm"
                else None
            )
            # Carry each repo's alert manifest into verification so a fix in a
            # secondary requirements file (e.g. producer/requirements.txt) is
            # confirmed on that exact file, not just the root manifest.
            hit_manifests = {hit.repo: hit.manifest for hit in hits}
            manifests = {repo: m for repo in verifiable if (m := hit_manifests.get(repo))}
            verdicts = verify_remote_bump(
                verifiable,
                owner=owner,
                dep=dep_name,
                new_version=new_version,
                ecosystem=ecosystem,
                npm_dirs=npm_dirs,
                manifests=manifests or None,
                on_log=log_cb,
            )
            for r in results:
                r.alert = verdicts.get(r.repo)

    _render_summary(console, results)


def _render_plan(console: Console, plans: list[PackagePlan], *, repo: str) -> None:
    """Prints the per-package bump plan that repopatch is about to execute."""
    table = Table(title=f"repopatch plan — {repo}", show_lines=False)
    table.add_column("Package", style="bold")
    table.add_column("Ecosystem")
    table.add_column("Bump to")
    table.add_column("Advisories", justify="right")
    for plan in plans:
        table.add_row(plan.package, plan.ecosystem, f">={plan.new_version}", str(len(plan.advisories)))
    console.print(table)


@click.command(name="repopatch")
@click.option("--owner", required=True, help="GitHub owner of the repository.")
@click.option("--repo", required=True, help="Repository whose open Dependabot alerts should all be patched.")
@click.option(
    "--dep",
    "deps",
    multiple=True,
    help="Only patch these packages (repeatable, case-insensitive); default is every alerted package.",
)
@click.option(
    "--severity",
    type=click.Choice(VALID_SEVERITIES, case_sensitive=False),
    default=None,
    help="Only patch packages with an open alert of this severity.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, path_type=Path, exists=True),
    default=None,
    help="Override the default security_patch.toml location.",
)
@click.option(
    "--dry-run", is_flag=True, help="Print the plan and run each bump's preflight; no edits, commits, or push."
)
@click.option("--skip-verify", is_flag=True, help="Do not check origin's manifests after the push.")
@click.option("-v", "--verbose", is_flag=True, help="Print per-step diagnostics for every bump.")
def repopatch_command(
    owner: str,
    repo: str,
    deps: tuple[str, ...],
    severity: Optional[str],
    config_path: Optional[Path],
    dry_run: bool,
    skip_verify: bool,
    verbose: bool,
) -> None:
    """Patch every fixable open alert in one repo: one commit per package, one push."""
    console = Console()
    try:
        shell.which_or_die("gh")
    except shell.ShellError as exc:
        console.print(f"[red]{exc}[/red]")
        raise click.exceptions.Exit(1) from exc
    config = load_config(config_path)
    if repo.casefold() in {name.casefold() for name in list_skipped(config)}:
        console.print(f"[yellow]{owner}/{repo} is on the security_patch.toml skip list; nothing to do.[/yellow]")
        return

    with console.status(f"Fetching open alerts for {owner}/{repo}..."):
        alerts = fetch_alerts_for_repo(owner, repo, packages=list(deps), state="open", severity=severity)
    plans, manual = plan_repo_patches(alerts)
    if not plans:
        console.print("[green]No open alerts with a patched version to apply.[/green]")
    else:
        _render_plan(console, plans, repo=repo)
    for item in manual:
        console.print(f"[yellow]Manual:[/yellow] {item.ecosystem}:{item.package} ({item.reason})")
    if not plans:
        return
    for ecosystem in sorted({plan.ecosystem for plan in plans}):
        if not _ensure_tools(console, ecosystem=ecosystem):
            raise click.exceptions.Exit(1)
    profile = resolve_profile(repo, config)
    if profile is None:
        console.print(f"[red]No local clone of {repo} is discoverable on this host; nothing was patched.[/red]")
        raise click.exceptions.Exit(1)

    def _on_log(msg: str) -> None:
        console.print(f"[dim]{msg}[/dim]", highlight=False)

    outcome = run_repo_patches(
        profile,
        plans,
        dry_run=dry_run,
        on_log=_on_log if verbose else None,
        on_start=lambda plan: console.rule(f"[cyan]{plan.package}[/cyan] >={plan.new_version}"),
    )

    verdicts: dict[str, Optional[str]] = {}
    push_ok = outcome.pushed or outcome.push_note == "nothing to push"
    if not dry_run and not skip_verify and push_ok:
        console.print("\n[yellow]Verifying remote manifests on origin...[/yellow]")
        for plan, result in outcome.results:
            if result.status not in {PatchStatus.DONE, PatchStatus.NOOP}:
                continue
            verdict = verify_remote_bump(
                {repo: result.branch or "main"},
                owner=owner,
                dep=plan.package,
                new_version=plan.new_version,
                ecosystem=plan.ecosystem,
                npm_dirs={repo: profile.npm_dir or "."} if plan.ecosystem == "npm" else None,
                manifests={repo: plan.manifest} if plan.manifest else None,
                on_log=_on_log if verbose else None,
            )
            verdicts[plan.package] = verdict.get(repo)

    table = Table(title=f"repopatch summary — {owner}/{repo}", show_lines=False)
    table.add_column("Package", style="bold")
    table.add_column("Bump to")
    table.add_column("Advisories", justify="right")
    table.add_column("Status")
    table.add_column("Note", overflow="fold")
    table.add_column("Alert")
    for plan, result in outcome.results:
        status_style = _STATUS_STYLE.get(result.status, "white")
        alert_text, alert_style = _alert_display(verdicts.get(plan.package), result.status)
        table.add_row(
            plan.package,
            f">={plan.new_version}",
            str(len(plan.advisories)),
            f"[{status_style}]{result.status.value}[/{status_style}]",
            result.note,
            f"[{alert_style}]{alert_text}[/{alert_style}]",
        )
    console.print(table)
    if not dry_run:
        style = "green" if push_ok else "red"
        console.print(f"[{style}]Push: {outcome.push_note}[/{style}]")


def _render_alerts(console: Console, alerts: list[DependabotAlert], *, title: str) -> None:
    """Prints a Rich table grouping Dependabot alerts by repo."""
    table = Table(title=title, show_lines=False)
    table.add_column("Repo", style="bold")
    table.add_column("#", justify="right")
    table.add_column("State")
    table.add_column("Severity")
    table.add_column("Package")
    table.add_column("Vulnerable", overflow="fold")
    table.add_column("Patched")
    table.add_column("Advisory", overflow="fold")
    table.add_column("Manifest", overflow="fold")
    for alert in alerts:
        sev_style = _SEVERITY_STYLE.get(alert.severity.casefold(), "white")
        table.add_row(
            alert.repo,
            str(alert.number),
            alert.state,
            f"[{sev_style}]{alert.severity or '-'}[/{sev_style}]",
            f"{alert.ecosystem}:{alert.package}" if alert.ecosystem else alert.package,
            alert.vulnerable_range or "-",
            alert.patched_version or "-",
            alert.advisory_id or "-",
            alert.manifest or "-",
        )
    console.print(table)


def _package_key(ecosystem: str, package: str) -> str:
    """
    Returns the grouping key for ``package`` within ``ecosystem``.

    pip names are case- and separator-insensitive (PEP 503), and GitHub keeps each
    advisory's original spelling, so ``Pillow`` and ``pillow`` alerts are folded
    together via :func:`canonicalize_name`. Other ecosystems keep the raw name.
    """
    if ecosystem == "pip":
        return canonicalize_name(package)
    return package


def _suggest_patches(
    console: Console,
    alerts: list[DependabotAlert],
    *,
    owner: str,
    repo: Optional[str] = None,
    filters: Optional[str] = None,
    deps: tuple[str, ...] = (),
    severity: Optional[str] = None,
) -> None:
    """
    Prints ready-to-paste suggestions for each (ecosystem, package) pair.

    For ``pip`` and ``npm`` alerts the suggestion is a runnable
    ``uv run acidbase patch ... --ecosystem <eco>`` invocation; for any other
    ecosystem the suggestion is a manual hint that mentions the package, the
    first patched version, and the manifest that flagged the alert, since
    acidbase does not yet patch those backends.

    The alerts were already fetched for every listed repo, so each acidbase
    suggestion is targeted with one ``--repo`` per repository that showed the
    alert; ``patch`` still re-checks each of those repos against origin before
    bumping. An owner-wide sweep command is printed after the targeted ones for
    repos the alert list can miss (dismissed or not-yet-raised alerts, or rows
    hidden by ``filters``). When ``repo`` is provided, the alerts were queried
    for that repository only, so the suggestion is scoped to it and no sweep is
    offered. ``filters`` describes any ``--dep``/``--severity``/``--state``
    narrowing so the reader knows the targeted commands cover only what was shown.

    When a single-repo query yields more than one patchable package, an extra
    ``acidbase repopatch`` line is printed that bumps all of them in one go
    (one commit per package, one push), repeating any ``deps``/``severity``
    filters so it covers the same alerts.
    """
    by_key: dict[tuple[str, str], dict[str, Optional[str]]] = {}
    spellings: dict[tuple[str, str], Counter[str]] = {}
    repos_by_key: dict[tuple[str, str], set[str]] = {}
    for alert in alerts:
        if not alert.patched_version:
            continue
        eco = alert.ecosystem.casefold() or ""
        key = (eco, _package_key(eco, alert.package))
        spellings.setdefault(key, Counter())[alert.package] += 1
        repos_by_key.setdefault(key, set()).add(alert.repo)
        bucket = by_key.setdefault(key, {"patched": None, "advisory": None, "manifest": None})
        try:
            current_best = Version(bucket["patched"]) if bucket["patched"] else None
            candidate = Version(alert.patched_version)
        except InvalidVersion:
            current_best = None
            candidate = None
        if candidate is not None and (current_best is None or candidate > current_best):
            bucket["patched"] = alert.patched_version
        if not bucket["advisory"] and alert.advisory_id:
            bucket["advisory"] = alert.advisory_id
        if not bucket["manifest"] and alert.manifest:
            bucket["manifest"] = alert.manifest
    if not by_key:
        return
    acidbase_keys = [k for k in by_key if k[0] in _SUPPORTED_ECOSYSTEMS and by_key[k]["patched"] is not None]
    manual_keys = [k for k in by_key if k[0] not in _SUPPORTED_ECOSYSTEMS]

    def _command(eco: str, key_pkg: str, repo_args: str) -> str:
        """Renders one runnable patch invocation for an (ecosystem, package) bucket."""
        info = by_key[(eco, key_pkg)]
        # Showing the most frequent advisory spelling (first seen on ties) to keep familiar names
        pkg = spellings[(eco, key_pkg)].most_common(1)[0][0]
        advisory = info["advisory"] or "<advisory-id>"
        patched = info["patched"] or "<version>"
        return (
            f"  uv run acidbase patch --owner {shlex.quote(owner)}{repo_args} "
            f"--dep {shlex.quote(pkg)} "
            f"--new-version {shlex.quote(patched)} "
            f"--cve {shlex.quote(advisory)} "
            f"--ecosystem {eco}"
        )

    if acidbase_keys:
        console.print(
            "\n[yellow]Suggested patch commands, targeted at the repos listed above"
            ' (omit --max-vulnerable for "anything strictly below --new-version"):[/yellow]'
        )
        for eco, key_pkg in sorted(acidbase_keys):
            targets = [repo] if repo else sorted(repos_by_key[(eco, key_pkg)], key=str.casefold)
            repo_args = "".join(f" --repo {shlex.quote(target)}" for target in targets)
            # soft_wrap keeps each command on one physical line so it stays copy-pasteable
            console.print(_command(eco, key_pkg, repo_args), soft_wrap=True, highlight=False)
        if filters:
            console.print(
                f"[dim]Alerts were filtered ({filters}); the targeted commands cover only the repos shown.[/dim]"
            )
        if repo and len(acidbase_keys) > 1:
            narrowing = "".join(f" --dep {shlex.quote(dep)}" for dep in deps)
            if severity:
                narrowing += f" --severity {shlex.quote(severity)}"
            console.print("\n[yellow]Or patch all of them in one go (one commit per package, one push):[/yellow]")
            console.print(
                f"  uv run acidbase repopatch --owner {shlex.quote(owner)} --repo {shlex.quote(repo)}{narrowing}",
                soft_wrap=True,
                highlight=False,
            )
        if not repo:
            console.print(
                "\n[dim]Optional owner-wide sweep (re-scans every repo; also catches repos whose alert "
                "is dismissed, not yet raised, or filtered out):[/dim]"
            )
            for eco, key_pkg in sorted(acidbase_keys):
                console.print(_command(eco, key_pkg, ""), style="dim", soft_wrap=True, highlight=False)
    if manual_keys:
        console.print("\n[yellow]Other ecosystems (acidbase does not auto-patch these yet); handle manually:[/yellow]")
        for eco, key_pkg in sorted(manual_keys):
            info = by_key[(eco, key_pkg)]
            pkg = spellings[(eco, key_pkg)].most_common(1)[0][0]
            label = f"{eco}:{pkg}" if eco else pkg
            patched = info["patched"] or "<version>"
            manifest = info["manifest"] or "<manifest>"
            advisory = info["advisory"] or "<advisory-id>"
            console.print(
                f"  {label} -> bump to >={patched} ({advisory}); edit {manifest} and run the matching package manager"
            )


@click.command(name="alerts")
@click.option("--owner", required=True, help="GitHub owner whose Dependabot alerts to query.")
@click.option(
    "--repo",
    "repo",
    default=None,
    help="Single repository to query. Omit to scan every non-archived, non-empty repo of OWNER.",
)
@click.option(
    "--dep",
    "deps",
    multiple=True,
    help="Limit results to one or more package names (repeatable, case-insensitive).",
)
@click.option(
    "--state",
    type=click.Choice([*VALID_STATES, "all"], case_sensitive=False),
    default="open",
    show_default=True,
    help="Alert state filter; 'all' returns every state.",
)
@click.option(
    "--severity",
    type=click.Choice(VALID_SEVERITIES, case_sensitive=False),
    default=None,
    help="Optional severity filter applied client-side.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, path_type=Path, exists=True),
    default=None,
    help="Override the security_patch.toml config (used for the owner-wide skip list).",
)
def alerts_command(
    owner: str,
    repo: Optional[str],
    deps: tuple[str, ...],
    state: str,
    severity: Optional[str],
    config_path: Optional[Path],
) -> None:
    """List Dependabot alerts for a single repo or every repo of an owner."""
    console = Console()
    try:
        shell.which_or_die("gh")
    except shell.ShellError as exc:
        console.print(f"[red]{exc}[/red]")
        raise click.exceptions.Exit(1) from exc

    state_arg: Optional[str] = None if state.lower() == "all" else state
    pkg_filter = list(deps)

    if repo is not None:
        alerts = fetch_alerts_for_repo(
            owner,
            repo,
            packages=pkg_filter,
            state=state_arg,
            severity=severity,
        )
        title = f"Dependabot alerts — {owner}/{repo}"
    else:
        config = load_config(config_path)
        skip = list_skipped(config)
        with console.status(f"Scanning {owner} repositories..."):
            alerts = fetch_alerts_for_owner(
                owner,
                packages=pkg_filter,
                state=state_arg,
                severity=severity,
                skip=skip,
            )
        title = f"Dependabot alerts — {owner} (all repos)"

    if not alerts:
        console.print("[green]No matching alerts found.[/green]")
        return
    _render_alerts(console, alerts, title=title)
    console.print(
        f"\n[dim]{len(alerts)} alert(s)"
        f"{' for ' + ', '.join(pkg_filter) if pkg_filter else ''}"
        f" in state={state}"
        f"{', severity=' + severity if severity else ''}"
        f"[/dim]"
    )
    narrowing = [f"dep={','.join(pkg_filter)}"] if pkg_filter else []
    if severity:
        narrowing.append(f"severity={severity}")
    if state.casefold() != "open":
        narrowing.append(f"state={state}")
    _suggest_patches(
        console,
        alerts,
        owner=owner,
        repo=repo,
        filters=", ".join(narrowing) or None,
        deps=deps,
        severity=severity,
    )


def _render_setting_result(
    console: Console,
    result: AlertSettingResult,
    *,
    setting_label: str,
) -> None:
    """Prints a one-line ``rich`` summary for an enable/check toggle call."""
    target = f"{result.owner}/{result.repo}"
    if result.ok and result.already_enabled and not result.changed:
        console.print(
            f"[yellow]{setting_label} already enabled for[/yellow] [bold]{target}[/bold] "
            f"[dim]({result.status_line or 'HTTP 204'})[/dim]"
        )
        return
    if result.ok and result.changed:
        console.print(
            f"[green]Enabled {setting_label} for[/green] [bold]{target}[/bold] "
            f"[dim]({result.status_line or 'HTTP 204'})[/dim]"
        )
        return
    detail = result.stderr or result.status_line or "unknown error"
    console.print(f"[red]Failed to enable {setting_label} for[/red] [bold]{target}[/bold] [dim]({detail})[/dim]")


@click.command(name="enable-alerts")
@click.option("--owner", required=True, help="GitHub owner (user or organization).")
@click.option("--repo", required=True, help="Repository name within OWNER.")
def enable_alerts_command(owner: str, repo: str) -> None:
    """Enable Dependabot vulnerability alerts on a single repo (idempotent)."""
    console = Console()
    try:
        shell.which_or_die("gh")
    except shell.ShellError as exc:
        console.print(f"[red]{exc}[/red]")
        raise click.exceptions.Exit(1) from exc
    result = enable_vulnerability_alerts(owner, repo)
    _render_setting_result(console, result, setting_label="vulnerability alerts")
    if not result.ok:
        raise click.exceptions.Exit(1)


@click.command(name="enable-fixes")
@click.option("--owner", required=True, help="GitHub owner (user or organization).")
@click.option("--repo", required=True, help="Repository name within OWNER.")
def enable_fixes_command(owner: str, repo: str) -> None:
    """Enable Dependabot automated security fix PRs on a single repo (idempotent)."""
    console = Console()
    try:
        shell.which_or_die("gh")
    except shell.ShellError as exc:
        console.print(f"[red]{exc}[/red]")
        raise click.exceptions.Exit(1) from exc
    result = enable_automated_security_fixes(owner, repo)
    _render_setting_result(console, result, setting_label="automated security fixes")
    if not result.ok:
        raise click.exceptions.Exit(1)


def _render_update_result(console: Console, result: AlertUpdateResult) -> None:
    """Prints a one-line ``rich`` summary for a dismiss/reopen PATCH call."""
    if result.requested_state == "dismissed":
        verb_ok, verb_fail = "Dismissed", "dismiss"
    else:
        verb_ok, verb_fail = "Reopened", "reopen"
    if result.ok:
        reason = f" [dim](reason: {result.dismissed_reason})[/dim]" if result.dismissed_reason else ""
        console.print(
            f"[green]{verb_ok}[/green] [bold]{result.target}[/bold]{reason} "
            f"[dim]({result.status_line or 'HTTP 200'})[/dim]"
        )
        return
    detail = result.stderr or result.status_line or "unknown error"
    console.print(f"[red]Failed to {verb_fail}[/red] [bold]{result.target}[/bold] [dim]({detail})[/dim]")


@click.command(name="dismiss-alert")
@click.option("--owner", required=True, help="GitHub owner (user or organization).")
@click.option("--repo", required=True, help="Repository name within OWNER.")
@click.option(
    "--number",
    "numbers",
    type=int,
    multiple=True,
    required=True,
    help="Dependabot alert number to dismiss (repeatable). See the '#' column of `acidbase alerts`.",
)
@click.option(
    "--reason",
    type=click.Choice(VALID_DISMISS_REASONS, case_sensitive=False),
    required=True,
    help="Dismissal reason recorded on the alert.",
)
@click.option(
    "--comment",
    default=None,
    help="Optional free-text note stored with the dismissal (GitHub caps this at 280 characters).",
)
@click.option("--dry-run", is_flag=True, help="Print which alerts would be dismissed without calling GitHub.")
def dismiss_alert_command(
    owner: str,
    repo: str,
    numbers: tuple[int, ...],
    reason: str,
    comment: Optional[str],
    dry_run: bool,
) -> None:
    """Dismiss one or more Dependabot alerts on a repo (reversible via `reopen-alert`)."""
    console = Console()
    try:
        shell.which_or_die("gh")
    except shell.ShellError as exc:
        console.print(f"[red]{exc}[/red]")
        raise click.exceptions.Exit(1) from exc
    reason = reason.casefold()
    if dry_run:
        for number in numbers:
            console.print(
                f"[cyan]DRY-RUN[/cyan] would dismiss [bold]{owner}/{repo}#{number}[/bold] [dim](reason: {reason})[/dim]"
            )
        return
    failures = 0
    for number in numbers:
        result = dismiss_alert(owner, repo, number, reason=reason, comment=comment)
        _render_update_result(console, result)
        if not result.ok:
            failures += 1
    if failures:
        raise click.exceptions.Exit(1)


@click.command(name="reopen-alert")
@click.option("--owner", required=True, help="GitHub owner (user or organization).")
@click.option("--repo", required=True, help="Repository name within OWNER.")
@click.option(
    "--number",
    "numbers",
    type=int,
    multiple=True,
    required=True,
    help="Dependabot alert number to reopen (repeatable).",
)
@click.option("--dry-run", is_flag=True, help="Print which alerts would be reopened without calling GitHub.")
def reopen_alert_command(owner: str, repo: str, numbers: tuple[int, ...], dry_run: bool) -> None:
    """Reopen one or more previously dismissed Dependabot alerts on a repo."""
    console = Console()
    try:
        shell.which_or_die("gh")
    except shell.ShellError as exc:
        console.print(f"[red]{exc}[/red]")
        raise click.exceptions.Exit(1) from exc
    if dry_run:
        for number in numbers:
            console.print(f"[cyan]DRY-RUN[/cyan] would reopen [bold]{owner}/{repo}#{number}[/bold]")
        return
    failures = 0
    for number in numbers:
        result = reopen_alert(owner, repo, number)
        _render_update_result(console, result)
        if not result.ok:
            failures += 1
    if failures:
        raise click.exceptions.Exit(1)


if __name__ == "__main__":  # pragma: no cover - module-as-script convenience
    patch_command.main(standalone_mode=True)
