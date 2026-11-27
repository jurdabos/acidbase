"""Tests for :mod:`acidbase.security.repopatch` and the ``repopatch`` CLI wiring."""

from __future__ import annotations

from click.testing import CliRunner
from rich.console import Console

from acidbase.security import cli as security_cli
from acidbase.security import repopatch
from acidbase.security.alerts import DependabotAlert
from acidbase.security.patcher import PatchResult, PatchStatus
from acidbase.security.profiles import Profile
from acidbase.security.repopatch import PackagePlan, plan_repo_patches, run_repo_patches


def _alert(
    package: str,
    patched: str | None,
    advisory: str,
    *,
    ecosystem: str = "pip",
    manifest: str = "uv.lock",
    repo: str = "canonfodder",
) -> DependabotAlert:
    """Returns a minimal open alert for planning tests."""
    return DependabotAlert(
        repo=repo,
        number=1,
        state="open",
        severity="high",
        package=package,
        ecosystem=ecosystem,
        vulnerable_range="<9",
        patched_version=patched,
        summary="",
        manifest=manifest,
        html_url=None,
        cve_id=advisory if advisory.startswith("CVE") else None,
        ghsa_id=advisory if advisory.startswith("GHSA") else None,
    )


def test_plan_folds_spellings_takes_highest_patch_and_dedupes_advisories():
    """GitPython/Gitpython merge into one plan at the highest patched version, advisories listed once."""
    plans, manual = plan_repo_patches(
        [
            _alert("GitPython", "3.2.0", "GHSA-23mf-xhv8-69c2"),
            _alert("GitPython", "3.2.0", "GHSA-23mf-xhv8-69c2", manifest="requirements.txt"),
            _alert("Gitpython", "3.2.1", "CVE-2026-114145"),
            _alert("aiohttp", "3.14.4", "CVE-2026-111066"),
        ]
    )
    assert manual == []
    assert [(p.package, p.new_version) for p in plans] == [("aiohttp", "3.14.4"), ("GitPython", "3.2.1")]
    assert plans[1].advisories == ["GHSA-23mf-xhv8-69c2", "CVE-2026-114145"]


def test_plan_routes_unpatched_and_unsupported_packages_to_manual():
    """No patched version, or an ecosystem acidbase cannot bump, becomes a manual item."""
    plans, manual = plan_repo_patches(
        [
            _alert("python-jose", None, "CVE-2026-85394"),
            _alert("some-jar", "3.1.0", "GHSA-abcd-efgh-ijkl", ecosystem="maven"),
            _alert("Mako", "1.4.2", "CVE-2026-102991"),
        ]
    )
    assert [p.package for p in plans] == ["Mako"]
    assert {(m.package, m.reason) for m in manual} == {
        ("python-jose", "no patched version published"),
        ("some-jar", "acidbase cannot bump the maven ecosystem"),
    }


def test_plan_keeps_secondary_requirements_manifest_for_verification():
    """A subdirectory requirements file is carried into the plan so verification checks that exact file."""
    plans, _ = plan_repo_patches(
        [
            _alert("authlib", "1.9.0", "CVE-2026-96760"),
            _alert("authlib", "1.9.0", "CVE-2026-96760", manifest="producer/requirements.txt"),
        ]
    )
    assert plans[0].manifest == "producer/requirements.txt"


def test_advisory_label_summarizes_long_lists():
    """The commit-message label lists the first three advisories and counts the rest."""
    plan = PackagePlan("pip", "aiohttp", "3.14.4", [f"CVE-2026-{n}" for n in range(1, 11)])
    assert plan.advisory_label == "CVE-2026-1, CVE-2026-2, CVE-2026-3 and 7 more"
    assert PackagePlan("pip", "x", "1.0", ["CVE-1"]).advisory_label == "CVE-1"


def _fake_patch_repo(statuses: dict[str, PatchStatus], calls: list[dict]):
    """Returns a patch_repo stand-in that records calls and answers with the given statuses."""

    def fake(profile, **kwargs):
        calls.append(kwargs)
        status = statuses[kwargs["dep_name"]]
        return PatchResult(repo=profile.repo, path=profile.path, status=status, note=status.value, branch="main")

    return fake


def _plans(*names: str) -> list[PackagePlan]:
    """Returns pip plans for the given package names."""
    return [PackagePlan("pip", name, "9.0", ["CVE-X"]) for name in names]


def test_run_commits_each_package_and_pushes_once(monkeypatch, tmp_path):
    """Every package gets its own bump (one commit each) and the push runs exactly once."""
    calls: list[dict] = []
    pushes: list[str] = []
    monkeypatch.setattr(
        repopatch, "patch_repo", _fake_patch_repo({"a": PatchStatus.DONE, "b": PatchStatus.DONE}, calls)
    )
    monkeypatch.setattr(repopatch, "_run_push_command", lambda profile, result, on_log=None: pushes.append("x") or True)
    outcome = run_repo_patches(Profile(repo="r", path=tmp_path), _plans("a", "b"))
    assert [c["dep_name"] for c in calls] == ["a", "b"]
    assert all(c["cve_id"] == "CVE-X" for c in calls)
    assert pushes == ["x"]
    assert outcome.pushed and outcome.push_note == "pushed once"


def test_run_continues_after_a_failure_reverts_its_edits_and_still_pushes(monkeypatch, tmp_path):
    """A failing package is reverted and skipped; the remaining commits still ship."""
    restored: list[str] = []
    monkeypatch.setattr(
        repopatch, "patch_repo", _fake_patch_repo({"a": PatchStatus.EXPORTFAIL, "b": PatchStatus.DONE}, [])
    )
    monkeypatch.setattr(repopatch, "_restore_tracked_files", lambda profile, on_log: restored.append("a") or True)
    monkeypatch.setattr(repopatch, "_run_push_command", lambda profile, result, on_log=None: True)
    outcome = run_repo_patches(Profile(repo="r", path=tmp_path), _plans("a", "b"))
    statuses = [result.status for _plan, result in outcome.results]
    assert statuses == [PatchStatus.EXPORTFAIL, PatchStatus.DONE]
    assert restored == ["a"]
    assert "reverted its edits" in outcome.results[0][1].note
    assert outcome.pushed


def test_run_stops_on_dirty_tree_without_reverting_user_work(monkeypatch, tmp_path):
    """DIRTY is the user's own work: nothing is restored and the remaining packages are not attempted."""
    calls: list[dict] = []
    monkeypatch.setattr(repopatch, "patch_repo", _fake_patch_repo({"a": PatchStatus.DIRTY}, calls))
    monkeypatch.setattr(
        repopatch, "_restore_tracked_files", lambda *a: (_ for _ in ()).throw(AssertionError("must not restore"))
    )
    monkeypatch.setattr(repopatch, "_count_unpushed", lambda path: 0)
    outcome = run_repo_patches(Profile(repo="r", path=tmp_path), _plans("a", "b", "c"))
    assert [c["dep_name"] for c in calls] == ["a"]
    assert [r.status for _p, r in outcome.results] == [PatchStatus.DIRTY] * 3
    assert outcome.results[2][1].note == "not attempted: DIRTY on an earlier package"
    assert not outcome.pushed


def test_run_does_not_revert_after_pullfail(monkeypatch, tmp_path):
    """A failed rebase is left for the user to inspect rather than checked out over."""
    monkeypatch.setattr(repopatch, "patch_repo", _fake_patch_repo({"a": PatchStatus.PULLFAIL}, []))
    monkeypatch.setattr(
        repopatch, "_restore_tracked_files", lambda *a: (_ for _ in ()).throw(AssertionError("must not restore"))
    )
    monkeypatch.setattr(repopatch, "_count_unpushed", lambda path: 0)
    outcome = run_repo_patches(Profile(repo="r", path=tmp_path), _plans("a"))
    assert outcome.results[0][1].status is PatchStatus.PULLFAIL


def test_run_skips_push_when_nothing_committed_and_not_ahead(monkeypatch, tmp_path):
    """All-NOOP runs with nothing unpushed do not invoke the push command."""
    monkeypatch.setattr(repopatch, "patch_repo", _fake_patch_repo({"a": PatchStatus.NOOP}, []))
    monkeypatch.setattr(repopatch, "_count_unpushed", lambda path: 0)

    def no_push(*args, **kwargs):
        raise AssertionError("push must not run")

    monkeypatch.setattr(repopatch, "_run_push_command", no_push)
    outcome = run_repo_patches(Profile(repo="r", path=tmp_path), _plans("a"))
    assert not outcome.pushed and outcome.push_note == "nothing to push"


def test_run_marks_committed_packages_pushfail_when_the_push_fails(monkeypatch, tmp_path):
    """A failed final push turns DONE rows into PUSHFAIL so the summary does not claim the fix shipped."""
    monkeypatch.setattr(repopatch, "patch_repo", _fake_patch_repo({"a": PatchStatus.DONE, "b": PatchStatus.NOOP}, []))

    def failing_push(profile, result, on_log=None):
        result.note = "push failed via git"
        return False

    monkeypatch.setattr(repopatch, "_run_push_command", failing_push)
    outcome = run_repo_patches(Profile(repo="r", path=tmp_path), _plans("a", "b"))
    assert [r.status for _p, r in outcome.results] == [PatchStatus.PUSHFAIL, PatchStatus.NOOP]
    assert not outcome.pushed


def test_run_dry_run_never_pushes(monkeypatch, tmp_path):
    """Dry runs only exercise each bump's preflight."""
    calls: list[dict] = []
    monkeypatch.setattr(repopatch, "patch_repo", _fake_patch_repo({"a": PatchStatus.WOULD_RUN}, calls))
    monkeypatch.setattr(repopatch, "_run_push_command", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    outcome = run_repo_patches(Profile(repo="r", path=tmp_path), _plans("a"), dry_run=True)
    assert calls[0]["dry_run"] is True
    assert not outcome.pushed


def _suggest(alerts: list[DependabotAlert], **kwargs) -> str:
    """Renders alert suggestions to text."""
    console = Console(record=True, width=300, color_system=None, force_terminal=False)
    security_cli._suggest_patches(console, alerts, owner="jurdabos", **kwargs)
    return console.export_text()


def test_alerts_suggests_repopatch_for_single_repo_with_several_packages():
    """`alerts --repo X` with two or more patchable packages prints one repopatch line."""
    out = _suggest([_alert("Mako", "1.4.2", "CVE-1"), _alert("aiohttp", "3.14.4", "CVE-2")], repo="canonfodder")
    assert "uv run acidbase repopatch --owner jurdabos --repo canonfodder" in out


def test_alerts_repopatch_line_mirrors_filters():
    """The repopatch suggestion repeats --dep and --severity so it covers the same alerts."""
    out = _suggest(
        [_alert("Mako", "1.4.2", "CVE-1"), _alert("aiohttp", "3.14.4", "CVE-2")],
        repo="canonfodder",
        deps=("Mako", "aiohttp"),
        severity="high",
    )
    assert "repopatch --owner jurdabos --repo canonfodder --dep Mako --dep aiohttp --severity high" in out


def test_alerts_omits_repopatch_for_one_package_or_owner_wide_queries():
    """A single patchable package, or an owner-wide query, gets no repopatch line."""
    assert "repopatch" not in _suggest([_alert("Mako", "1.4.2", "CVE-1")], repo="canonfodder")
    assert "repopatch" not in _suggest([_alert("Mako", "1.4.2", "CVE-1"), _alert("aiohttp", "3.14.4", "CVE-2")])


def _stub_cli(monkeypatch, *, alerts, profile, skip=()):
    """Stubs network, config, and tool lookups for repopatch CLI tests."""
    monkeypatch.setattr(security_cli.shell, "which_or_die", lambda tool: f"/fake/{tool}")
    monkeypatch.setattr(security_cli, "_ensure_tools", lambda console, ecosystem="pip": True)
    monkeypatch.setattr(security_cli, "load_config", lambda path: {})
    monkeypatch.setattr(security_cli, "list_skipped", lambda config: list(skip))
    monkeypatch.setattr(security_cli, "fetch_alerts_for_repo", lambda *a, **k: alerts)
    monkeypatch.setattr(security_cli, "resolve_profile", lambda repo, config: profile)


def test_repopatch_command_dry_run_prints_plan_and_preflight(monkeypatch, tmp_path):
    """A dry run renders the plan and the per-package preflight results without pushing."""
    _stub_cli(
        monkeypatch,
        alerts=[_alert("Mako", "1.4.2", "CVE-1"), _alert("aiohttp", "3.14.4", "CVE-2")],
        profile=Profile(repo="canonfodder", path=tmp_path),
    )
    monkeypatch.setattr(
        repopatch, "patch_repo", _fake_patch_repo({"Mako": PatchStatus.WOULD_RUN, "aiohttp": PatchStatus.WOULD_RUN}, [])
    )
    result = CliRunner().invoke(
        security_cli.repopatch_command, ["--owner", "jurdabos", "--repo", "canonfodder", "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    assert "repopatch plan" in result.output
    assert "WOULD-RUN" in result.output
    assert "Push:" not in result.output


def test_repopatch_command_respects_skip_list(monkeypatch, tmp_path):
    """Repos on the security_patch.toml skip list are left untouched."""
    _stub_cli(monkeypatch, alerts=[], profile=Profile(repo="r", path=tmp_path), skip=("CanonFodder",))
    result = CliRunner().invoke(security_cli.repopatch_command, ["--owner", "o", "--repo", "canonfodder"])
    assert result.exit_code == 0
    assert "skip list" in result.output


def test_repopatch_command_fails_without_local_clone(monkeypatch):
    """No discoverable checkout is an error, and nothing is patched."""
    _stub_cli(monkeypatch, alerts=[_alert("Mako", "1.4.2", "CVE-1")], profile=None)
    result = CliRunner().invoke(security_cli.repopatch_command, ["--owner", "o", "--repo", "canonfodder"])
    assert result.exit_code == 1
    assert "No local clone" in result.output


def test_repopatch_registered_on_top_level_cli():
    """`acidbase repopatch` is reachable from the main entry point."""
    from acidbase.cli import main

    assert "repopatch" in main.commands
