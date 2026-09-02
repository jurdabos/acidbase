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
from pathlib import Path
from typing import Optional

import click
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
    "repo",
    default=None,
    help="Single repository to patch. Omit to scan every non-archived, non-empty repo of OWNER.",
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
    repo: Optional[str],
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

    scope_label = f"{owner}/{repo}" if repo else owner
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

    with console.status(f"Scanning {scope_label} repositories..."):
        hits = discover_affected_repos(
            owner=owner,
            dep_name=dep_name,
            max_vulnerable=scan_threshold,
            skip=skip,
            strict_below=strict_below,
            repo=repo,
            ecosystem=ecosystem,
            patch_target=new_version,
            cve_id=cve_id,
            on_log=log_cb,
            on_stale_warning=stale_warnings.append,
        )

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


def _suggest_patches(
    console: Console,
    alerts: list[DependabotAlert],
    *,
    owner: str,
    repo: Optional[str] = None,
) -> None:
    """
    Prints ready-to-paste suggestions for each (ecosystem, package) pair.

    For ``pip`` and ``npm`` alerts the suggestion is a runnable
    ``uv run acidbase patch ... --ecosystem <eco>`` invocation; for any other
    ecosystem the suggestion is a manual hint that mentions the package, the
    first patched version, and the manifest that flagged the alert, since
    acidbase does not yet patch those backends. When ``repo`` is provided,
    each acidbase suggestion is scoped to that single repository via
    ``--repo``.
    """
    by_key: dict[tuple[str, str], dict[str, Optional[str]]] = {}
    for alert in alerts:
        if not alert.patched_version:
            continue
        key = (alert.ecosystem.casefold() or "", alert.package)
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
    repo_arg = f" --repo {shlex.quote(repo)}" if repo else ""
    if acidbase_keys:
        console.print(
            "\n[yellow]Suggested patch commands"
            ' (omit --max-vulnerable for "anything strictly below --new-version"):[/yellow]'
        )
        for eco, pkg in sorted(acidbase_keys):
            info = by_key[(eco, pkg)]
            advisory = info["advisory"] or "<advisory-id>"
            patched = info["patched"] or "<version>"
            cmd = (
                f"  uv run acidbase patch --owner {shlex.quote(owner)}{repo_arg} "
                f"--dep {shlex.quote(pkg)} "
                f"--new-version {shlex.quote(patched)} "
                f"--cve {shlex.quote(advisory)} "
                f"--ecosystem {eco}"
            )
            console.print(cmd)
    if manual_keys:
        console.print("\n[yellow]Other ecosystems (acidbase does not auto-patch these yet); handle manually:[/yellow]")
        for eco, pkg in sorted(manual_keys):
            info = by_key[(eco, pkg)]
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
    _suggest_patches(console, alerts, owner=owner, repo=repo)


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
