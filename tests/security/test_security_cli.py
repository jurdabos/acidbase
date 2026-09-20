"""Tests for the rendering and routing in :mod:`acidbase.security.cli`."""

from __future__ import annotations

import pytest
from click.testing import CliRunner
from rich.console import Console

from acidbase.security import cli as security_cli
from acidbase.security import shell
from acidbase.security.alerts import AlertUpdateResult, DependabotAlert
from acidbase.security.patcher import PatchResult, PatchStatus
from acidbase.security.profiles import Profile
from acidbase.security.verifier import ALERT_FIXED, ALERT_OPEN


def _make_alert(
    *,
    package: str,
    ecosystem: str = "pip",
    patched: str | None = "1.2.3",
    advisory: str | None = "CVE-2024-0001",
    manifest: str | None = "uv.lock",
) -> DependabotAlert:
    """Returns a minimal :class:`DependabotAlert` for suggestion tests."""
    return DependabotAlert(
        repo="r",
        number=1,
        state="open",
        severity="high",
        package=package,
        ecosystem=ecosystem,
        vulnerable_range="<1.2.3",
        patched_version=patched,
        summary="",
        manifest=manifest,
        html_url=None,
        cve_id=advisory if advisory and advisory.startswith("CVE") else None,
        ghsa_id=advisory if advisory and advisory.startswith("GHSA") else None,
    )


def _capture(alerts: list[DependabotAlert], *, owner: str = "o", repo: str | None = None) -> str:
    """Runs ``_suggest_patches`` against a recording Console and returns the rendered text."""
    console = Console(record=True, width=200, color_system=None, force_terminal=False)
    security_cli._suggest_patches(console, alerts, owner=owner, repo=repo)
    return console.export_text()


def test_suggest_patches_emits_pip_invocation_for_pip_alert():
    """A pip alert produces a runnable ``--ecosystem pip`` suggestion line."""
    out = _capture([_make_alert(package="Mako", ecosystem="pip", patched="1.3.12", advisory="CVE-X")])
    assert "Suggested patch commands" in out
    assert "uv run acidbase patch --owner o --dep Mako" in out
    assert "--new-version 1.3.12" in out
    assert "--ecosystem pip" in out


def test_suggest_patches_emits_npm_invocation_for_npm_alert():
    """An npm alert produces a runnable ``--ecosystem npm`` suggestion line."""
    out = _capture([_make_alert(package="yaml", ecosystem="npm", patched="2.8.3", advisory="CVE-Y")])
    assert "--dep yaml" in out
    assert "--ecosystem npm" in out
    assert "--new-version 2.8.3" in out


def test_suggest_patches_includes_repo_arg_when_scoped():
    """When ``repo`` is set, the suggestion includes ``--repo <repo>``."""
    out = _capture([_make_alert(package="yaml", ecosystem="npm", patched="2.8.3")], repo="bracket")
    assert "--repo bracket" in out


def test_suggest_patches_falls_back_to_manual_hint_for_unsupported_ecosystem():
    """An alert for an ecosystem acidbase does not yet patch emits a manual hint, not a broken command."""
    out = _capture(
        [
            _make_alert(
                package="some-jar",
                ecosystem="maven",
                patched="3.1.0",
                advisory="GHSA-abcd-efgh-ijkl",
                manifest="pom.xml",
            )
        ]
    )
    # No acidbase patch line for maven (it would silently fail).
    assert "--ecosystem maven" not in out
    # But the manual hint mentions the ecosystem, the bump floor, and the manifest.
    assert "maven:some-jar" in out
    assert ">=3.1.0" in out
    assert "pom.xml" in out


def test_suggest_patches_returns_silently_when_no_patched_version():
    """Alerts without a patched_version yield no output at all (preserves the legacy behaviour)."""
    out = _capture([_make_alert(package="ecdsa", ecosystem="pip", patched=None)])
    assert out.strip() == ""


def test_suggest_patches_buckets_by_ecosystem_and_package():
    """Multiple alerts for the same package across ecosystems produce one suggestion per (ecosystem, package)."""
    alerts = [
        _make_alert(package="yaml", ecosystem="pip", patched="6.0.2", advisory="CVE-A"),
        _make_alert(package="yaml", ecosystem="npm", patched="2.8.3", advisory="CVE-B"),
    ]
    out = _capture(alerts)
    # both ecosystems get their own line; the bare name 'yaml' alone is not enough to collide.
    assert "--ecosystem pip" in out
    assert "--ecosystem npm" in out
    # the pip line carries the pip patched floor, the npm line carries the npm one.
    assert "--new-version 6.0.2" in out
    assert "--new-version 2.8.3" in out


def test_ensure_tools_pip_requires_uv(monkeypatch):
    """pip preflight insists on git, gh, and uv \u2014 npm is NOT queried."""
    queried: list[str] = []

    def fake_which(tool: str) -> str:
        queried.append(tool)
        if tool == "npm":
            raise shell.ShellError("npm not on PATH")
        return f"/fake/{tool}"

    monkeypatch.setattr(security_cli.shell, "which_or_die", fake_which)
    console = Console(record=True, width=120)
    assert security_cli._ensure_tools(console, ecosystem="pip") is True
    assert set(queried) == {"git", "gh", "uv"}


def test_ensure_tools_npm_requires_npm(monkeypatch):
    """npm preflight insists on git, gh, and npm \u2014 uv is NOT queried."""
    queried: list[str] = []

    def fake_which(tool: str) -> str:
        queried.append(tool)
        if tool == "uv":
            raise shell.ShellError("uv not on PATH")
        return f"/fake/{tool}"

    monkeypatch.setattr(security_cli.shell, "which_or_die", fake_which)
    console = Console(record=True, width=120)
    assert security_cli._ensure_tools(console, ecosystem="npm") is True
    assert set(queried) == {"git", "gh", "npm"}


def test_ensure_tools_reports_missing(monkeypatch):
    """A missing tool yields False and prints a guidance line for the user."""
    monkeypatch.setattr(
        security_cli.shell,
        "which_or_die",
        lambda tool: (_ for _ in ()).throw(shell.ShellError(f"{tool} missing")),
    )
    console = Console(record=True, width=120, color_system=None, force_terminal=False)
    assert security_cli._ensure_tools(console, ecosystem="npm") is False
    out = console.export_text()
    assert "Missing required tools on PATH" in out


def test_alert_display_qualifies_fixed_for_noop_as_already_satisfied():
    """A verifier FIXED on a NOOP patch reads 'already satisfied' so no-ops are obvious."""
    text, style = security_cli._alert_display(ALERT_FIXED, PatchStatus.NOOP)
    assert text == "FIXED (already satisfied)"
    assert style == "green"


def test_alert_display_qualifies_fixed_for_done_as_bumped():
    """A verifier FIXED on a DONE patch reads 'bumped' so a real change is distinguishable."""
    text, style = security_cli._alert_display(ALERT_FIXED, PatchStatus.DONE)
    assert text == "FIXED (bumped)"
    assert style == "green"


def test_alert_display_plain_fixed_for_other_statuses():
    """FIXED with neither DONE nor NOOP stays unqualified."""
    text, style = security_cli._alert_display(ALERT_FIXED, PatchStatus.WOULD_RUN)
    assert text == ALERT_FIXED
    assert style == "green"


def test_alert_display_open_is_red():
    """OPEN renders red regardless of patch status."""
    text, style = security_cli._alert_display(ALERT_OPEN, PatchStatus.DONE)
    assert text == ALERT_OPEN
    assert style == "red"


def test_alert_display_none_is_dash():
    """A missing verdict (verification skipped) renders a neutral dash."""
    text, style = security_cli._alert_display(None, PatchStatus.DONE)
    assert text == "-"
    assert style == "white"


def test_patch_command_threads_cve_and_patch_target_into_discovery(monkeypatch):
    """`acidbase patch` passes --new-version as patch_target and --cve as cve_id to discovery.
    This locks in the scoping wiring: without these, the alerts fallback would
    revert to matching any open alert for the package (the cross-advisory bug).
    """
    captured: dict[str, object] = {}

    def fake_discover(**kwargs):
        captured.update(kwargs)
        return []  # empty => command prints "No vulnerable repositories found." and returns

    monkeypatch.setattr(security_cli, "_ensure_tools", lambda console, ecosystem="pip": True)
    monkeypatch.setattr(security_cli, "load_config", lambda path: {})
    monkeypatch.setattr(security_cli, "list_skipped", lambda config: [])
    monkeypatch.setattr(security_cli, "discover_affected_repos", fake_discover)

    runner = CliRunner()
    result = runner.invoke(
        security_cli.patch_command,
        [
            "--owner",
            "jurdabos",
            "--dep",
            "Pillow",
            "--new-version",
            "10.2.0",
            "--cve",
            "CVE-2023-50447",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["patch_target"] == "10.2.0"
    assert captured["cve_id"] == "CVE-2023-50447"
    # --max-vulnerable omitted => strictly-below scan at the new version.
    assert captured["max_vulnerable"] == "10.2.0"
    assert captured["strict_below"] is True


def test_patch_command_threads_sync_env_into_strategy(monkeypatch, tmp_path):
    """--sync-env reaches the publish strategy for pip; npm runs drop it with a notice."""
    from types import SimpleNamespace

    captured: list[dict] = []

    class RecordingStrategy:
        def run(self, profile, **kwargs):
            captured.append(kwargs)
            return PatchResult(repo=profile.repo, path=profile.path, status=PatchStatus.WOULD_RUN, note="")

    hit = SimpleNamespace(repo="r", package="p", version="1.0", threshold="2.0", manifest="uv.lock")
    monkeypatch.setattr(security_cli, "_ensure_tools", lambda console, ecosystem="pip": True)
    monkeypatch.setattr(security_cli, "load_config", lambda path: {})
    monkeypatch.setattr(security_cli, "list_skipped", lambda config: [])
    monkeypatch.setattr(security_cli, "discover_affected_repos", lambda **kw: [hit])
    monkeypatch.setattr(security_cli, "resolve_profile", lambda repo, config: Profile(repo=repo, path=tmp_path))
    monkeypatch.setattr(security_cli, "_build_strategy", lambda name: RecordingStrategy())
    base = ["--owner", "o", "--dep", "p", "--new-version", "2.0", "--cve", "CVE-1", "--dry-run"]

    result = CliRunner().invoke(security_cli.patch_command, [*base, "--sync-env"])
    assert result.exit_code == 0, result.output
    assert captured[-1]["sync_env"] is True

    result = CliRunner().invoke(security_cli.patch_command, [*base, "--sync-env", "--ecosystem", "npm"])
    assert result.exit_code == 0, result.output
    assert "pip ecosystem only" in result.output
    assert captured[-1]["sync_env"] is False


@pytest.fixture(autouse=True)
def _silence_rich(monkeypatch):
    """Keep tests deterministic across local terminals (no width inference, no colour)."""
    yield


def test_dismiss_alert_command_dismisses_each_number(monkeypatch):
    """`dismiss-alert` calls dismiss_alert once per --number with the chosen reason."""
    calls: list[tuple] = []

    def fake_dismiss(owner, repo, number, *, reason, comment=None):
        calls.append((owner, repo, number, reason, comment))
        return AlertUpdateResult(
            owner=owner,
            repo=repo,
            number=number,
            requested_state="dismissed",
            ok=True,
            status_line="HTTP/2.0 200 OK",
            stderr="",
            dismissed_reason=reason,
        )

    monkeypatch.setattr(security_cli.shell, "which_or_die", lambda tool: f"/fake/{tool}")
    monkeypatch.setattr(security_cli, "dismiss_alert", fake_dismiss)
    result = CliRunner().invoke(
        security_cli.dismiss_alert_command,
        ["--owner", "o", "--repo", "r", "--number", "22", "--number", "24", "--reason", "fix_started"],
    )
    assert result.exit_code == 0, result.output
    assert [c[2] for c in calls] == [22, 24]
    assert {c[3] for c in calls} == {"fix_started"}


def test_dismiss_alert_command_dry_run_makes_no_calls(monkeypatch):
    """--dry-run prints the plan and never touches GitHub."""

    def fake_dismiss(*args, **kwargs):
        raise AssertionError("dismiss_alert must not be called during --dry-run")

    monkeypatch.setattr(security_cli.shell, "which_or_die", lambda tool: f"/fake/{tool}")
    monkeypatch.setattr(security_cli, "dismiss_alert", fake_dismiss)
    result = CliRunner().invoke(
        security_cli.dismiss_alert_command,
        ["--owner", "o", "--repo", "r", "--number", "22", "--reason", "fix_started", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in result.output


def test_dismiss_alert_command_exits_nonzero_on_failure(monkeypatch):
    """A failed dismissal yields a non-zero exit code so scripts can react."""

    def fake_dismiss(owner, repo, number, *, reason, comment=None):
        return AlertUpdateResult(
            owner=owner,
            repo=repo,
            number=number,
            requested_state="dismissed",
            ok=False,
            status_line="HTTP/2.0 422",
            stderr="nope",
            dismissed_reason=reason,
        )

    monkeypatch.setattr(security_cli.shell, "which_or_die", lambda tool: f"/fake/{tool}")
    monkeypatch.setattr(security_cli, "dismiss_alert", fake_dismiss)
    result = CliRunner().invoke(
        security_cli.dismiss_alert_command,
        ["--owner", "o", "--repo", "r", "--number", "1", "--reason", "not_used"],
    )
    assert result.exit_code == 1


def test_dismiss_alert_command_rejects_invalid_reason(monkeypatch):
    """An out-of-enum --reason is rejected by Click before any dismissal."""
    monkeypatch.setattr(security_cli.shell, "which_or_die", lambda tool: f"/fake/{tool}")
    result = CliRunner().invoke(
        security_cli.dismiss_alert_command,
        ["--owner", "o", "--repo", "r", "--number", "1", "--reason", "whatever"],
    )
    assert result.exit_code != 0


def test_reopen_alert_command_reopens_each_number(monkeypatch):
    """`reopen-alert` calls reopen_alert once per --number."""
    calls: list[int] = []

    def fake_reopen(owner, repo, number):
        calls.append(number)
        return AlertUpdateResult(
            owner=owner,
            repo=repo,
            number=number,
            requested_state="open",
            ok=True,
            status_line="HTTP/2.0 200 OK",
            stderr="",
            dismissed_reason=None,
        )

    monkeypatch.setattr(security_cli.shell, "which_or_die", lambda tool: f"/fake/{tool}")
    monkeypatch.setattr(security_cli, "reopen_alert", fake_reopen)
    result = CliRunner().invoke(
        security_cli.reopen_alert_command,
        ["--owner", "o", "--repo", "r", "--number", "5"],
    )
    assert result.exit_code == 0, result.output
    assert calls == [5]
