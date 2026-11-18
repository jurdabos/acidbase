"""Tests for :mod:`acidbase.security.alerts` lookup, filtering, and toggles."""

from __future__ import annotations

import json
from typing import Any, Iterable

import pytest

from acidbase.security import alerts as alerts_module
from acidbase.security.alerts import (
    AlertSettingResult,
    AlertUpdateResult,
    DependabotAlert,
    check_repo_setting,
    dismiss_alert,
    enable_automated_security_fixes,
    enable_vulnerability_alerts,
    fetch_alerts_for_owner,
    fetch_alerts_for_repo,
    reopen_alert,
    update_alert,
)
from acidbase.security.shell import CommandResult


def _alert_payload(
    *,
    package: str,
    severity: str = "high",
    state: str = "open",
    number: int = 1,
    ecosystem: str = "pip",
    patched: str | None = "1.0.0",
    cve: str | None = "CVE-2024-0001",
    ghsa: str | None = "GHSA-xxxx-xxxx-xxxx",
) -> dict:
    """Returns a synthetic Dependabot alert payload mirroring the GitHub API shape."""
    return {
        "number": number,
        "state": state,
        "html_url": f"https://example/{package}/{number}",
        "security_advisory": {
            "severity": severity,
            "summary": f"vuln in {package}",
            "cve_id": cve,
            "ghsa_id": ghsa,
        },
        "security_vulnerability": {
            "package": {"ecosystem": ecosystem, "name": package},
            "vulnerable_version_range": "<= 1.0.0",
            "first_patched_version": {"identifier": patched} if patched else None,
        },
        "dependency": {"manifest_path": "uv.lock", "scope": "runtime"},
    }


class _StubShell:
    """Replacement for :func:`acidbase.security.shell.run` recording calls."""

    def __init__(self, responses: dict[str, CommandResult]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args: Iterable[str], **_: Any) -> CommandResult:
        argv = tuple(args)
        self.calls.append(argv)
        # The endpoint is the last positional argument for `gh api`.
        endpoint = argv[-1]
        return self.responses.get(endpoint, CommandResult(0, "[]", ""))


def test_fetch_alerts_for_repo_returns_typed_rows(monkeypatch):
    """A populated payload is unwrapped into DependabotAlert instances with advisory IDs."""
    payload = json.dumps([_alert_payload(package="GitPython")])
    fake = _StubShell({"repos/o/r/dependabot/alerts?state=open": CommandResult(0, payload, "")})
    monkeypatch.setattr(alerts_module.shell, "run", fake)
    out = fetch_alerts_for_repo("o", "r")
    assert len(out) == 1
    assert isinstance(out[0], DependabotAlert)
    assert out[0].package == "GitPython"
    assert out[0].patched_version == "1.0.0"
    assert out[0].severity == "high"
    assert out[0].cve_id == "CVE-2024-0001"
    assert out[0].ghsa_id == "GHSA-xxxx-xxxx-xxxx"
    assert out[0].advisory_id == "CVE-2024-0001"  # CVE wins over GHSA


def test_advisory_id_falls_back_to_ghsa(monkeypatch):
    """advisory_id surfaces GHSA when CVE is absent."""
    payload = json.dumps([_alert_payload(package="foo", cve=None, ghsa="GHSA-aaaa-bbbb-cccc")])
    fake = _StubShell({"repos/o/r/dependabot/alerts?state=open": CommandResult(0, payload, "")})
    monkeypatch.setattr(alerts_module.shell, "run", fake)
    out = fetch_alerts_for_repo("o", "r")
    assert out[0].advisory_id == "GHSA-aaaa-bbbb-cccc"


def test_fetch_alerts_for_repo_filters_by_package(monkeypatch):
    """Only alerts for the requested package(s) come back when --dep is set."""
    payload = json.dumps(
        [
            _alert_payload(package="GitPython", number=1),
            _alert_payload(package="requests", number=2),
            _alert_payload(package="urllib3", number=3),
        ]
    )
    fake = _StubShell({"repos/o/r/dependabot/alerts?state=open": CommandResult(0, payload, "")})
    monkeypatch.setattr(alerts_module.shell, "run", fake)
    out = fetch_alerts_for_repo("o", "r", packages=["GitPython", "urllib3"])
    assert {a.package for a in out} == {"GitPython", "urllib3"}


def test_fetch_alerts_for_repo_filters_by_severity(monkeypatch):
    """Severity filter is applied client-side and is case-insensitive."""
    payload = json.dumps(
        [
            _alert_payload(package="a", severity="low", number=1),
            _alert_payload(package="b", severity="HIGH", number=2),
            _alert_payload(package="c", severity="medium", number=3),
        ]
    )
    fake = _StubShell({"repos/o/r/dependabot/alerts?state=open": CommandResult(0, payload, "")})
    monkeypatch.setattr(alerts_module.shell, "run", fake)
    out = fetch_alerts_for_repo("o", "r", severity="high")
    assert len(out) == 1
    assert out[0].package == "b"


def test_fetch_alerts_for_repo_state_all_omits_query_string(monkeypatch):
    """state='all' or None hits the endpoint without a state= query."""
    fake = _StubShell({"repos/o/r/dependabot/alerts": CommandResult(0, "[]", "")})
    monkeypatch.setattr(alerts_module.shell, "run", fake)
    fetch_alerts_for_repo("o", "r", state="all")
    assert fake.calls[-1][-1] == "repos/o/r/dependabot/alerts"


def test_fetch_alerts_for_repo_handles_invalid_json(monkeypatch):
    """Malformed payload produces an empty list instead of raising."""
    fake = _StubShell({"repos/o/r/dependabot/alerts?state=open": CommandResult(0, "not-json", "")})
    monkeypatch.setattr(alerts_module.shell, "run", fake)
    assert fetch_alerts_for_repo("o", "r") == []


def test_fetch_alerts_for_owner_aggregates_and_skips(monkeypatch):
    """Owner-wide aggregation iterates over all repos minus the skip list."""
    repos = ["alpha", "beta", "gamma"]

    def fake_run(args, **_: Any):
        argv = tuple(args)
        # `gh repo list ...` -> newline-delimited names
        if argv[:3] == ("gh", "repo", "list"):
            return CommandResult(0, "\n".join(repos) + "\n", "")
        endpoint = argv[-1]
        # Each repo gets a different alert payload
        if endpoint.startswith("repos/o/alpha"):
            return CommandResult(0, json.dumps([_alert_payload(package="GitPython", number=10)]), "")
        if endpoint.startswith("repos/o/gamma"):
            return CommandResult(0, json.dumps([_alert_payload(package="requests", number=20)]), "")
        return CommandResult(0, "[]", "")

    monkeypatch.setattr(alerts_module.shell, "run", fake_run)
    out = fetch_alerts_for_owner("o", skip=["beta"])
    repos_seen = sorted({a.repo for a in out})
    assert repos_seen == ["alpha", "gamma"]
    assert {a.package for a in out} == {"GitPython", "requests"}


# --- toggle helper tests --------------------------------------------------


def _http_response(status: int, *, body: str = "", stderr: str = "") -> CommandResult:
    """Returns a synthetic ``gh api -i`` response with a leading HTTP/2.0 status line."""
    head = f"HTTP/2.0 {status} OK" if status < 400 else f"HTTP/2.0 {status} Not Found"
    stdout = head + "\n\n" + body
    return CommandResult(0 if status < 400 else 1, stdout, stderr)


class _Recorder:
    """Records every ``shell.run`` invocation and returns scripted responses."""

    def __init__(self, responses: list[CommandResult]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args: Iterable[str], **_: Any) -> CommandResult:
        argv = tuple(args)
        self.calls.append(argv)
        if not self.responses:
            return CommandResult(0, "", "")
        return self.responses.pop(0)


def test_check_repo_setting_reports_enabled_on_204(monkeypatch):
    """A 204 GET marks the setting as already enabled."""
    rec = _Recorder([_http_response(204)])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = check_repo_setting("o", "r", "vulnerability-alerts")
    assert isinstance(res, AlertSettingResult)
    assert res.already_enabled is True
    assert res.ok is True
    assert "204" in res.status_line
    assert rec.calls[0] == ("gh", "api", "-i", "repos/o/r/vulnerability-alerts")


def test_check_repo_setting_reports_disabled_on_404(monkeypatch):
    """A 404 GET marks the setting as currently disabled (but the call itself is OK)."""
    rec = _Recorder([_http_response(404, stderr="Vulnerability alerts are disabled.")])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = check_repo_setting("o", "r", "vulnerability-alerts")
    assert res.already_enabled is False
    assert res.ok is True  # 404 is a well-defined "disabled" signal, not a failure
    assert "404" in res.status_line


def test_enable_vulnerability_alerts_short_circuits_when_already_on(monkeypatch):
    """When the pre-check returns 204, no PUT is issued."""
    rec = _Recorder([_http_response(204)])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = enable_vulnerability_alerts("o", "r")
    assert res.ok is True
    assert res.already_enabled is True
    assert res.changed is False
    assert len(rec.calls) == 1
    assert rec.calls[0][:3] == ("gh", "api", "-i")


def test_enable_vulnerability_alerts_puts_when_disabled(monkeypatch):
    """Pre-check 404 triggers PUT, followed by a post-check 204 (reports a real flip)."""
    rec = _Recorder(
        [
            _http_response(404),  # pre-check: disabled
            CommandResult(0, "", ""),  # PUT succeeds with empty body
            _http_response(204),  # post-check: enabled
        ]
    )
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = enable_vulnerability_alerts("o", "r")
    assert res.ok is True
    assert res.already_enabled is False  # pre-call state
    assert res.changed is True  # the call flipped it on
    assert "204" in res.status_line  # post-PUT verification line
    # Verify the PUT shape and that the endpoint matches the requested suffix.
    put_call = rec.calls[1]
    assert put_call == ("gh", "api", "-X", "PUT", "repos/o/r/vulnerability-alerts")


def test_enable_vulnerability_alerts_flags_failure_when_post_check_still_404(monkeypatch):
    """If the post-PUT re-check still reports disabled, the call is treated as failed."""
    rec = _Recorder(
        [
            _http_response(404),  # pre-check: disabled
            CommandResult(0, "", ""),  # PUT returns 0 but didn't actually enable
            _http_response(404),  # post-check: still disabled
        ]
    )
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = enable_vulnerability_alerts("o", "r")
    assert res.ok is False
    assert res.changed is False


def test_enable_vulnerability_alerts_returns_failure_when_put_fails(monkeypatch):
    """A failing PUT produces ok=False with the underlying stderr surfaced."""
    rec = _Recorder(
        [
            _http_response(404),  # pre-check: disabled
            CommandResult(1, "", "HTTP 403 Forbidden: admin required"),  # PUT fails
        ]
    )
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = enable_vulnerability_alerts("o", "r")
    assert res.ok is False
    assert res.already_enabled is False
    assert "403" in res.stderr


def test_enable_automated_security_fixes_targets_correct_endpoint(monkeypatch):
    """The fixes toggle hits ``automated-security-fixes`` rather than the alerts endpoint."""
    rec = _Recorder(
        [
            _http_response(404),
            CommandResult(0, "", ""),
            _http_response(204),
        ]
    )
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = enable_automated_security_fixes("o", "r")
    assert res.ok is True
    assert rec.calls[1] == (
        "gh",
        "api",
        "-X",
        "PUT",
        "repos/o/r/automated-security-fixes",
    )


# --- dismiss / reopen route tests -----------------------------------------


def test_dismiss_alert_sends_patch_with_state_and_reason(monkeypatch):
    """Dismissing issues a PATCH carrying state=dismissed and the chosen reason."""
    rec = _Recorder([_http_response(200, body='{"state": "dismissed"}')])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = dismiss_alert("o", "r", 22, reason="fix_started")
    assert isinstance(res, AlertUpdateResult)
    assert res.ok is True
    assert res.requested_state == "dismissed"
    assert res.dismissed_reason == "fix_started"
    assert res.target == "o/r#22"
    call = rec.calls[0]
    assert call[:6] == ("gh", "api", "-i", "-X", "PATCH", "repos/o/r/dependabot/alerts/22")
    assert "state=dismissed" in call
    assert "dismissed_reason=fix_started" in call


def test_dismiss_alert_includes_comment_when_provided(monkeypatch):
    """A comment rides along as the dismissed_comment field."""
    rec = _Recorder([_http_response(200)])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    dismiss_alert("o", "r", 1, reason="tolerable_risk", comment="lockfile already pins 1.7.2")
    assert "dismissed_comment=lockfile already pins 1.7.2" in rec.calls[0]


def test_dismiss_alert_omits_comment_when_absent(monkeypatch):
    """No comment means no dismissed_comment field is sent."""
    rec = _Recorder([_http_response(200)])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    dismiss_alert("o", "r", 1, reason="not_used")
    assert not any(str(arg).startswith("dismissed_comment=") for arg in rec.calls[0])


def test_dismiss_alert_rejects_unknown_reason(monkeypatch):
    """An invalid reason raises before any gh call is made."""
    rec = _Recorder([])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    with pytest.raises(ValueError):
        dismiss_alert("o", "r", 1, reason="because-i-said-so")
    assert rec.calls == []


def test_reopen_alert_sends_state_open_without_reason(monkeypatch):
    """Reopening issues a PATCH with state=open and no dismissed_reason."""
    rec = _Recorder([_http_response(200)])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = reopen_alert("o", "r", 5)
    assert res.ok is True
    assert res.requested_state == "open"
    assert res.dismissed_reason is None
    call = rec.calls[0]
    assert "state=open" in call
    assert not any(str(arg).startswith("dismissed_reason=") for arg in call)


def test_update_alert_reports_failure_on_non_200(monkeypatch):
    """A 422 response yields ok=False with the status line preserved."""
    rec = _Recorder([_http_response(422, stderr="Validation Failed")])
    monkeypatch.setattr(alerts_module.shell, "run", rec)
    res = update_alert("o", "r", 1, state="dismissed", dismissed_reason="not_used")
    assert res.ok is False
    assert "422" in res.status_line


def test_update_alert_rejects_bad_state():
    """A state other than dismissed/open raises ValueError."""
    with pytest.raises(ValueError):
        update_alert("o", "r", 1, state="fixed")
