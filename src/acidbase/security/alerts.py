"""
Dependabot alert lookup and toggle helpers.

Wraps ``gh api .../dependabot/alerts`` with pagination, optional dependency
filtering, and a typed :class:`DependabotAlert` row so the CLI and any other
caller can present alerts uniformly. Works the same on Windows pwsh and
Ubuntu/WSL bash.

Also provides idempotent enablers for the two Dependabot repo settings:

* ``enable_vulnerability_alerts`` toggles the per-repo Dependabot alerts
  (``PUT /repos/{owner}/{repo}/vulnerability-alerts``). Enabling alerts also
  implicitly enables the dependency graph.
* ``enable_automated_security_fixes`` toggles Dependabot security update PRs
  (``PUT /repos/{owner}/{repo}/automated-security-fixes``). Requires that
  vulnerability alerts are already enabled on the same repo.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Optional

from acidbase.security import shell

VALID_STATES: tuple[str, ...] = ("open", "dismissed", "auto_dismissed", "fixed")
VALID_SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
# Reasons GitHub accepts when dismissing an alert via PATCH .../dependabot/alerts/{n}.
VALID_DISMISS_REASONS: tuple[str, ...] = (
    "fix_started",
    "inaccurate",
    "no_bandwidth",
    "not_used",
    "tolerable_risk",
)

# HTTP status returned by the toggle endpoints when the setting is enabled.
_ENABLED_STATUS: int = 204
# Returned by the GET when the setting is currently disabled.
_DISABLED_STATUS: int = 404
# Returned by PATCH .../dependabot/alerts/{n} on a successful state update.
_UPDATED_STATUS: int = 200


@dataclass(frozen=True)
class AlertSettingResult:
    """Outcome of an enable/check call against a repo-level Dependabot setting."""

    owner: str
    repo: str
    endpoint: str
    ok: bool
    already_enabled: bool
    status_line: str
    stderr: str

    @property
    def changed(self) -> bool:
        """Returns True when the call flipped the setting from off to on."""
        return self.ok and not self.already_enabled


@dataclass(frozen=True)
class DependabotAlert:
    """One Dependabot alert flattened into the fields we render and filter on."""

    repo: str
    number: int
    state: str
    severity: str
    package: str
    ecosystem: str
    vulnerable_range: str
    patched_version: Optional[str]
    summary: str
    manifest: Optional[str]
    html_url: Optional[str]
    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None

    @property
    def advisory_id(self) -> Optional[str]:
        """Returns the preferred advisory identifier (CVE first, then GHSA)."""
        return self.cve_id or self.ghsa_id


@dataclass(frozen=True)
class AlertUpdateResult:
    """Outcome of a PATCH against a single Dependabot alert (dismiss or reopen)."""

    owner: str
    repo: str
    number: int
    requested_state: str
    ok: bool
    status_line: str
    stderr: str
    dismissed_reason: Optional[str] = None

    @property
    def target(self) -> str:
        """Returns the ``owner/repo#number`` label used in human-facing output."""
        return f"{self.owner}/{self.repo}#{self.number}"


def _normalize_packages(packages: Iterable[str]) -> set[str]:
    """Returns a casefolded set of package names for fast membership checks."""
    return {p.casefold() for p in packages if p}


def _flatten_alert(repo: str, raw: dict) -> Optional[DependabotAlert]:
    """Returns a :class:`DependabotAlert` from the raw API payload, or None on missing fields."""
    advisory = raw.get("security_advisory") or {}
    vuln = raw.get("security_vulnerability") or {}
    pkg = vuln.get("package") or {}
    name = pkg.get("name")
    if not name:
        return None
    patched = (vuln.get("first_patched_version") or {}).get("identifier")
    dependency = raw.get("dependency") or {}
    return DependabotAlert(
        repo=repo,
        number=int(raw.get("number") or 0),
        state=str(raw.get("state") or ""),
        severity=str(advisory.get("severity") or ""),
        package=name,
        ecosystem=str(pkg.get("ecosystem") or ""),
        vulnerable_range=str(vuln.get("vulnerable_version_range") or ""),
        patched_version=patched,
        summary=str(advisory.get("summary") or ""),
        manifest=dependency.get("manifest_path"),
        html_url=raw.get("html_url"),
        cve_id=advisory.get("cve_id"),
        ghsa_id=advisory.get("ghsa_id"),
    )


def fetch_alerts_for_repo(
    owner: str,
    repo: str,
    *,
    packages: Iterable[str] = (),
    state: Optional[str] = "open",
    severity: Optional[str] = None,
) -> list[DependabotAlert]:
    """
    Returns Dependabot alerts for ``owner/repo`` after applying optional filters.

    ``state`` may be one of :data:`VALID_STATES` or ``None``/``"all"`` to skip
    state filtering server-side. ``severity`` is applied client-side to keep
    the call fully cacheable. ``packages`` is a case-insensitive allowlist;
    when empty all package names are accepted.
    """
    args = ["gh", "api", "--paginate"]
    endpoint = f"repos/{owner}/{repo}/dependabot/alerts"
    if state and state.lower() != "all":
        endpoint = f"{endpoint}?state={state}"
    args.append(endpoint)
    res = shell.run(args)
    if not res.ok or not res.stdout.strip():
        return []
    try:
        payload = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    pkg_filter = _normalize_packages(packages)
    sev_filter = severity.casefold() if severity else None
    out: list[DependabotAlert] = []
    for raw in payload:
        alert = _flatten_alert(repo, raw)
        if alert is None:
            continue
        if pkg_filter and alert.package.casefold() not in pkg_filter:
            continue
        if sev_filter and alert.severity.casefold() != sev_filter:
            continue
        out.append(alert)
    return out


def _list_owner_repos(owner: str) -> list[str]:
    """Returns non-archived, non-empty repo names for ``owner`` via ``gh repo list``."""
    res = shell.run(
        [
            "gh",
            "repo",
            "list",
            owner,
            "--limit",
            "1000",
            "--json",
            "name,isArchived,isEmpty",
            "-q",
            ".[] | select(.isArchived==false and .isEmpty==false) | .name",
        ],
    )
    if not res.ok:
        return []
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def _status_line(stdout: str) -> str:
    """Returns the first ``HTTP/...`` line found in ``stdout``, or an empty string."""
    for line in stdout.splitlines():
        if line.startswith("HTTP/"):
            return line.strip()
    return ""


def check_repo_setting(owner: str, repo: str, endpoint_suffix: str) -> AlertSettingResult:
    """
    Returns the current enable-state of a repo-level Dependabot setting.

    ``endpoint_suffix`` is appended to ``repos/{owner}/{repo}/`` and queried with
    ``gh api -i`` so the HTTP status line is included in stdout. 204 means the
    setting is currently enabled; 404 means it's disabled. Any other status is
    surfaced verbatim through :attr:`AlertSettingResult.status_line` so the
    caller can decide how to react.
    """
    endpoint = f"repos/{owner}/{repo}/{endpoint_suffix}"
    res = shell.run(["gh", "api", "-i", endpoint])
    status = _status_line(res.stdout)
    enabled = f" {_ENABLED_STATUS} " in f" {status} "
    return AlertSettingResult(
        owner=owner,
        repo=repo,
        endpoint=endpoint,
        ok=res.ok or f" {_DISABLED_STATUS} " in f" {status} ",
        already_enabled=enabled,
        status_line=status,
        stderr=res.stderr,
    )


def _enable_repo_setting(owner: str, repo: str, endpoint_suffix: str) -> AlertSettingResult:
    """
    Returns the outcome of ``PUT repos/{owner}/{repo}/{endpoint_suffix}``.

    Performs a status check first so the result can distinguish three outcomes:

    * Setting was already on — ``ok=True``, ``already_enabled=True``,
      ``changed=False`` (no PUT issued).
    * Setting was off and the PUT flipped it on — ``ok=True``,
      ``already_enabled=False``, ``changed=True``. ``status_line`` reflects the
      post-PUT re-check so callers can verify GitHub actually accepted the
      toggle (otherwise ``ok`` is downgraded to False).
    * PUT failed outright — ``ok=False``, ``already_enabled=False``, with the
      underlying stderr surfaced for diagnostics.

    ``already_enabled`` always reflects the pre-call state of the setting so
    ``AlertSettingResult.changed`` is a reliable "we flipped it" signal.
    """
    pre = check_repo_setting(owner, repo, endpoint_suffix)
    if pre.already_enabled:
        return pre
    endpoint = f"repos/{owner}/{repo}/{endpoint_suffix}"
    res = shell.run(["gh", "api", "-X", "PUT", endpoint])
    if not res.ok:
        return AlertSettingResult(
            owner=owner,
            repo=repo,
            endpoint=endpoint,
            ok=False,
            already_enabled=False,
            status_line=_status_line(res.stdout),
            stderr=res.stderr.strip(),
        )
    # The PUT succeeded; re-check so we can confirm the setting is actually on
    # and surface the post-PUT status line, but preserve the pre-call state in
    # ``already_enabled`` so ``changed`` accurately reports the flip.
    post = check_repo_setting(owner, repo, endpoint_suffix)
    return AlertSettingResult(
        owner=owner,
        repo=repo,
        endpoint=endpoint,
        ok=post.already_enabled,
        already_enabled=False,
        status_line=post.status_line,
        stderr=post.stderr,
    )


def enable_vulnerability_alerts(owner: str, repo: str) -> AlertSettingResult:
    """Returns the result of enabling Dependabot vulnerability alerts on ``owner/repo``."""
    return _enable_repo_setting(owner, repo, "vulnerability-alerts")


def enable_automated_security_fixes(owner: str, repo: str) -> AlertSettingResult:
    """
    Returns the result of enabling Dependabot automated security fix PRs on ``owner/repo``.

    GitHub requires vulnerability alerts to be enabled first; callers that
    invoke this without enabling alerts beforehand will receive a 4xx response
    captured in :attr:`AlertSettingResult.stderr`.
    """
    return _enable_repo_setting(owner, repo, "automated-security-fixes")


def update_alert(
    owner: str,
    repo: str,
    number: int,
    *,
    state: str,
    dismissed_reason: Optional[str] = None,
    dismissed_comment: Optional[str] = None,
) -> AlertUpdateResult:
    """
    Returns the outcome of ``PATCH repos/{owner}/{repo}/dependabot/alerts/{number}``.

    ``state`` must be ``"dismissed"`` or ``"open"``; the other two alert states
    (``fixed`` / ``auto_dismissed``) are assigned by GitHub and cannot be set
    here. When dismissing, ``dismissed_reason`` is required and must be one of
    :data:`VALID_DISMISS_REASONS`; ``dismissed_comment`` is optional and capped
    by GitHub at 280 characters. The call is issued with ``gh api -i`` so the
    HTTP status line is captured: a 200 means GitHub accepted the update and
    anything else is surfaced verbatim through
    :attr:`AlertUpdateResult.status_line` / :attr:`AlertUpdateResult.stderr`.
    Reopening (``state="open"``) is the inverse operation, so every dismissal
    made through this route is fully reversible.
    """
    if state not in ("dismissed", "open"):
        raise ValueError(f"state must be 'dismissed' or 'open', got {state!r}")
    if state == "dismissed" and dismissed_reason not in VALID_DISMISS_REASONS:
        raise ValueError(f"dismissed_reason must be one of {VALID_DISMISS_REASONS}, got {dismissed_reason!r}")
    endpoint = f"repos/{owner}/{repo}/dependabot/alerts/{number}"
    args = ["gh", "api", "-i", "-X", "PATCH", endpoint, "-f", f"state={state}"]
    if state == "dismissed":
        args += ["-f", f"dismissed_reason={dismissed_reason}"]
        if dismissed_comment:
            args += ["-f", f"dismissed_comment={dismissed_comment}"]
    res = shell.run(args)
    status = _status_line(res.stdout)
    ok = f" {_UPDATED_STATUS} " in f" {status} " if status else res.ok
    return AlertUpdateResult(
        owner=owner,
        repo=repo,
        number=int(number),
        requested_state=state,
        ok=ok,
        status_line=status,
        stderr=res.stderr.strip(),
        dismissed_reason=dismissed_reason if state == "dismissed" else None,
    )


def dismiss_alert(
    owner: str,
    repo: str,
    number: int,
    *,
    reason: str,
    comment: Optional[str] = None,
) -> AlertUpdateResult:
    """Returns the result of dismissing alert ``number`` with ``reason`` (see :func:`update_alert`)."""
    return update_alert(
        owner,
        repo,
        number,
        state="dismissed",
        dismissed_reason=reason,
        dismissed_comment=comment,
    )


def reopen_alert(owner: str, repo: str, number: int) -> AlertUpdateResult:
    """Returns the result of reopening a previously dismissed alert ``number``."""
    return update_alert(owner, repo, number, state="open")


def fetch_alerts_for_owner(
    owner: str,
    *,
    packages: Iterable[str] = (),
    state: Optional[str] = "open",
    severity: Optional[str] = None,
    skip: Iterable[str] = (),
) -> list[DependabotAlert]:
    """
    Returns Dependabot alerts across every non-archived, non-empty repo of ``owner``.

    Repos in ``skip`` are excluded. Per-repo failures (alerts disabled, private
    fork without permission, transient API hiccup) are logged-as-empty so a
    single bad repo never aborts the owner-wide scan.
    """
    skip_set = set(skip)
    out: list[DependabotAlert] = []
    for repo in _list_owner_repos(owner):
        if repo in skip_set:
            continue
        out.extend(
            fetch_alerts_for_repo(
                owner,
                repo,
                packages=packages,
                state=state,
                severity=severity,
            )
        )
    out.sort(key=lambda a: (a.repo.casefold(), -a.number))
    return out
