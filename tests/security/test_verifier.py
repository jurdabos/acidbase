"""Tests for :mod:`acidbase.security.verifier` remote-manifest checks."""

from __future__ import annotations

import json as _json

from acidbase.security import verifier
from acidbase.security.shell import CommandResult
from acidbase.security.verifier import (
    ALERT_FIXED,
    ALERT_OPEN,
    _find_in_npm_lock,
    resolve_remote_pip_version,
    verify_remote_bump,
)

_UV_LOCK_TEMPLATE = """\
version = 1
revision = 1

[[package]]
name = "acidbase"
version = "0.1.0"
source = {{ editable = "." }}

[[package]]
name = "{dep}"
version = "{version}"
source = {{ registry = "https://pypi.org/simple" }}
"""


def _ok(content: str) -> CommandResult:
    return CommandResult(0, content, "")


def _not_found() -> CommandResult:
    return CommandResult(1, "", 'gh: Not Found (HTTP 404)\n{"message":"Not Found"}')


def test_verify_remote_bump_marks_fixed_when_uv_lock_at_target(monkeypatch):
    """uv.lock on origin with dep >= new_version yields FIXED."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/uv.lock" in endpoint:
            return _ok(_UV_LOCK_TEMPLATE.format(dep="urllib3", version="2.7.0"))
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"some-repo": "main"},
        owner="o",
        dep="urllib3",
        new_version="2.7.0",
    )
    assert state == {"some-repo": ALERT_FIXED}


def test_verify_remote_bump_marks_open_when_uv_lock_below_target(monkeypatch):
    """uv.lock on origin with dep below new_version yields OPEN."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/uv.lock" in endpoint:
            return _ok(_UV_LOCK_TEMPLATE.format(dep="urllib3", version="2.5.0"))
        if "contents/requirements.txt" in endpoint:
            return _not_found()
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"some-repo": "main"},
        owner="o",
        dep="urllib3",
        new_version="2.7.0",
    )
    assert state == {"some-repo": ALERT_OPEN}


def test_verify_remote_bump_falls_back_to_requirements_txt(monkeypatch):
    """When uv.lock is absent, the verifier inspects requirements.txt."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/uv.lock" in endpoint:
            return _not_found()
        if "contents/requirements.txt" in endpoint:
            return _ok("urllib3==2.7.0\nrequests==2.32.5\n")
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"legacy": "main"},
        owner="o",
        dep="urllib3",
        new_version="2.7.0",
    )
    assert state == {"legacy": ALERT_FIXED}


def test_verify_remote_bump_uses_secondary_manifest_when_provided(monkeypatch):
    """When the alert manifest is a secondary requirements file, the verdict is taken from it.
    The root uv.lock could be patched while ``producer/requirements.txt`` is
    stale (or vice versa); the verifier must read the exact file the alert is
    about. Here the secondary file satisfies the target -> FIXED, and the root
    manifest is never consulted.
    """
    seen: list[str] = []

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        seen.append(endpoint)
        if "contents/producer/requirements.txt" in endpoint:
            return _ok("authlib==1.7.2\nrequests==2.32.5\n")
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"vlc": "main"},
        owner="o",
        dep="authlib",
        new_version="1.6.9",
        manifests={"vlc": "producer/requirements.txt"},
    )
    assert state == {"vlc": ALERT_FIXED}
    # Verdict came from the secondary file only; the root uv.lock was not read.
    assert any("contents/producer/requirements.txt" in e for e in seen)
    assert not any("contents/uv.lock" in e for e in seen)


def test_verify_remote_bump_secondary_manifest_open_when_still_stale(monkeypatch):
    """A secondary manifest that still pins the dep below the target yields OPEN."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/producer/requirements.txt" in endpoint:
            return _ok("authlib==1.6.5\n")
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"vlc": "main"},
        owner="o",
        dep="authlib",
        new_version="1.6.9",
        manifests={"vlc": "producer/requirements.txt"},
    )
    assert state == {"vlc": ALERT_OPEN}


def test_verify_remote_bump_uses_raw_accept_header_and_branch(monkeypatch):
    """The gh api call must pass the raw accept header and the right ref."""
    seen: list[list[str]] = []

    def fake_run(args, **_kw):
        seen.append(list(args))
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/uv.lock" in endpoint:
            return _ok(_UV_LOCK_TEMPLATE.format(dep="black", version="26.3.1"))
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    verify_remote_bump(
        {"some-repo": "develop"},
        owner="o",
        dep="black",
        new_version="26.3.1",
    )
    first = seen[0]
    assert "gh" in first and "api" in first
    assert "-H" in first
    assert any("Accept: application/vnd.github.raw" in a for a in first)
    assert any("?ref=develop" in a for a in first), first


def test_verify_remote_bump_open_when_dep_missing_from_both_manifests(monkeypatch):
    """A repo whose manifests don't mention the dep at all is OPEN."""

    def fake_run(args, **_kw):
        return _ok(_UV_LOCK_TEMPLATE.format(dep="requests", version="2.32.5"))

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"some-repo": "main"},
        owner="o",
        dep="urllib3",
        new_version="2.7.0",
    )
    assert state == {"some-repo": ALERT_OPEN}


def test_resolve_remote_pip_version_prefers_uv_lock(monkeypatch):
    """uv.lock wins when it pins the dep; requirements.txt is not consulted."""
    seen: list[str] = []

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        seen.append(endpoint)
        if "contents/uv.lock" in endpoint:
            return _ok(_UV_LOCK_TEMPLATE.format(dep="cryptography", version="49.0.0"))
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    assert resolve_remote_pip_version("o", "vlc", "cryptography") == "49.0.0"
    assert any("contents/uv.lock" in e for e in seen)
    assert not any("contents/requirements.txt" in e for e in seen)


def test_resolve_remote_pip_version_falls_back_to_requirements(monkeypatch):
    """When uv.lock lacks the dep, requirements.txt provides the resolved version."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/uv.lock" in endpoint:
            return _not_found()
        if "contents/requirements.txt" in endpoint:
            return _ok("cryptography==49.0.0\nrequests==2.32.5\n")
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    assert resolve_remote_pip_version("o", "vlc", "cryptography") == "49.0.0"


def test_resolve_remote_pip_version_none_when_absent_and_uses_default_branch(monkeypatch):
    """Returns None when neither root manifest pins the dep, and omits ?ref for the default branch."""
    seen: list[list[str]] = []

    def fake_run(args, **_kw):
        seen.append(list(args))
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    assert resolve_remote_pip_version("o", "vlc", "cryptography") is None
    assert seen, "expected at least one gh api call"
    # ref=None -> the Contents API call must not carry a ?ref= query.
    assert all(not any("?ref=" in token for token in call) for call in seen)


def test_verify_remote_bump_handles_invalid_toml(monkeypatch):
    """A malformed uv.lock does not raise; we fall back to requirements.txt."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/uv.lock" in endpoint:
            return _ok("this is = not = valid TOML\n[[[broken")
        if "contents/requirements.txt" in endpoint:
            return _ok("urllib3==2.7.0\n")
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"some-repo": "main"},
        owner="o",
        dep="urllib3",
        new_version="2.7.0",
    )
    assert state == {"some-repo": ALERT_FIXED}


def test_verify_remote_bump_case_insensitive_package_name(monkeypatch):
    """uv.lock matching is case-insensitive on the package name."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/uv.lock" in endpoint:
            return _ok(_UV_LOCK_TEMPLATE.format(dep="pygments", version="2.20.0"))
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"some-repo": "main"},
        owner="o",
        dep="Pygments",
        new_version="2.20.0",
    )
    assert state == {"some-repo": ALERT_FIXED}


def test_verify_remote_bump_empty_input_returns_empty(monkeypatch):
    """No repos in => no verdicts and no API calls."""
    calls = {"n": 0}

    def fake_run(args, **_kw):
        calls["n"] += 1
        return _ok("")

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump({}, owner="o", dep="urllib3", new_version="2.7.0")
    assert state == {}
    assert calls["n"] == 0


def test_verify_remote_bump_invokes_on_log_per_step(monkeypatch):
    """Verbose mode emits per-step diagnostics through ``on_log``."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/uv.lock" in endpoint:
            return _ok(_UV_LOCK_TEMPLATE.format(dep="urllib3", version="2.7.0"))
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    logs: list[str] = []
    state = verify_remote_bump(
        {"some-repo": "main"},
        owner="o",
        dep="urllib3",
        new_version="2.7.0",
        on_log=logs.append,
    )
    assert state == {"some-repo": ALERT_FIXED}
    assert any("Verifying remote manifest" in line for line in logs)
    assert any("uv.lock: urllib3==2.7.0" in line for line in logs)
    assert any("-> some-repo: FIXED" in line for line in logs)


# --- npm ecosystem ----------------------------------------------------------


def test_find_in_npm_lock_handles_v3_packages_key():
    """v2/v3 lockfile parses the bare package via the `packages` map."""
    content = _json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/yaml": {"version": "2.8.3"},
            },
        }
    )
    assert _find_in_npm_lock(content, "yaml") == "2.8.3"


def test_find_in_npm_lock_handles_v1_dependencies():
    """v1 lockfile falls through to the `dependencies` map keyed by name."""
    content = _json.dumps({"lockfileVersion": 1, "dependencies": {"yaml": {"version": "2.8.0"}}})
    assert _find_in_npm_lock(content, "yaml") == "2.8.0"


def test_find_in_npm_lock_handles_scoped_packages():
    """Scoped names resolve through `node_modules/@scope/pkg`."""
    content = _json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {"node_modules/@types/node": {"version": "22.1.0"}},
        }
    )
    assert _find_in_npm_lock(content, "@types/node") == "22.1.0"


def test_find_in_npm_lock_returns_none_when_missing():
    """Missing dep and malformed JSON both return None instead of raising."""
    assert _find_in_npm_lock("{}", "yaml") is None
    assert _find_in_npm_lock("not-json", "yaml") is None


def test_verify_remote_bump_npm_uses_npm_dir_lockfile_path(monkeypatch):
    """ecosystem=npm fetches `<npm_dir>/package-lock.json` from origin."""
    seen_paths: list[str] = []

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        seen_paths.append(endpoint)
        if "contents/frontend/package-lock.json" in endpoint:
            return _ok(
                _json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {"node_modules/yaml": {"version": "2.8.3"}},
                    }
                )
            )
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"bracket": "main"},
        owner="o",
        dep="yaml",
        new_version="2.8.3",
        ecosystem="npm",
        npm_dirs={"bracket": "frontend"},
    )
    assert state == {"bracket": ALERT_FIXED}
    # the request must target the npm_dir-prefixed lockfile, not the repo-root one
    assert any("contents/frontend/package-lock.json" in p for p in seen_paths)


def test_verify_remote_bump_npm_reports_open_when_resolved_below_target(monkeypatch):
    """npm lockfile pin still below the patched threshold yields OPEN."""

    def fake_run(args, **_kw):
        endpoint = next((a for a in args if "contents/" in a), "")
        if "contents/package-lock.json" in endpoint:
            return _ok(
                _json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {"node_modules/yaml": {"version": "2.8.1"}},
                    }
                )
            )
        return _not_found()

    monkeypatch.setattr(verifier.shell, "run", fake_run)

    state = verify_remote_bump(
        {"repo": "main"},
        owner="o",
        dep="yaml",
        new_version="2.8.3",
        ecosystem="npm",
    )
    assert state == {"repo": ALERT_OPEN}
