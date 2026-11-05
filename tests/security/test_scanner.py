"""Tests for :mod:`acidbase.security.scanner` helpers."""

from __future__ import annotations

import pytest

from acidbase.security import scanner
from acidbase.security.alerts import DependabotAlert
from acidbase.security.scanner import (
    VulnerableHit,
    _alert_addressed_by_patch,
    _bare_name,
    _iter_ecosystem_packages,
    _iter_packages,
    _parse_purl,
    _split_sbom_name,
    _version_at_or_above,
    _version_at_or_below,
    _version_strictly_below,
    discover_affected_repos,
)
from acidbase.security.shell import CommandResult

_UV_LOCK_CRYPTO = """\
version = 1
revision = 1

[[package]]
name = "cryptography"
version = "{version}"
source = {{ registry = "https://pypi.org/simple" }}
"""


def _alert(
    *,
    package: str = "Pillow",
    ecosystem: str = "pip",
    vulnerable_range: str = "< 10.2.0",
    patched: str | None = "10.2.0",
    cve: str | None = "CVE-2023-50447",
    ghsa: str | None = None,
    repo: str = "r",
    number: int = 1,
) -> DependabotAlert:
    """Returns a minimal :class:`DependabotAlert` for scope tests."""
    return DependabotAlert(
        repo=repo,
        number=number,
        state="open",
        severity="critical",
        package=package,
        ecosystem=ecosystem,
        vulnerable_range=vulnerable_range,
        patched_version=patched,
        summary="",
        manifest="uv.lock",
        html_url=None,
        cve_id=cve,
        ghsa_id=ghsa,
    )


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("pip:GitPython", "GitPython"),
        ("actions:owner/name", "owner/name"),
        ("npm:@scope/pkg", "@scope/pkg"),
        ("plain", "plain"),
    ],
)
def test_bare_name_strips_ecosystem_prefix(raw: str, expected: str) -> None:
    """Ecosystem prefixes such as ``pip:`` are removed before name comparison."""
    assert _bare_name(raw) == expected


@pytest.mark.parametrize(
    "found,threshold,expected",
    [
        ("3.1.49", "3.1.49", True),
        ("3.1.48", "3.1.49", True),
        ("3.1.50", "3.1.49", False),
        ("3.1.49rc1", "3.1.49", True),
        ("3.1.49.post1", "3.1.49", False),
        ("not-a-version", "3.1.49", False),
    ],
)
def test_version_at_or_below_handles_pep_440(found: str, threshold: str, expected: bool) -> None:
    """PEP 440 ordering rules apply across pre/post releases and invalid strings."""
    assert _version_at_or_below(found, threshold) is expected


def test_iter_packages_yields_name_and_version_pairs() -> None:
    """SBOM dict is unwrapped to ``(name, version)`` tuples."""
    sbom = {
        "sbom": {
            "packages": [
                {"name": "pip:foo", "versionInfo": "1.2.3"},
                {"name": "pip:bar"},  # missing versionInfo => skipped
                {"name": "pip:baz", "versionInfo": "0.1"},
            ]
        }
    }
    pairs = list(_iter_packages(sbom))
    assert pairs == [("pip:foo", "1.2.3"), ("pip:baz", "0.1")]


def test_iter_packages_handles_missing_keys() -> None:
    """An SBOM payload without a packages list yields nothing instead of raising."""
    assert list(_iter_packages({})) == []
    assert list(_iter_packages({"sbom": {}})) == []
    assert list(_iter_packages({"sbom": {"packages": None}})) == []


@pytest.mark.parametrize(
    "locator,expected",
    [
        ("pkg:pypi/flask-cors@6.0.2", ("pip", "flask-cors", "6.0.2")),
        ("pkg:npm/yaml@2.8.1", ("npm", "yaml", "2.8.1")),
        ("pkg:npm/%40scope/pkg@1.2.3", ("npm", "@scope/pkg", "1.2.3")),  # percent-decoded scoped name
        ("pkg:githubactions/actions/checkout@4", ("actions", "actions/checkout", "4")),
        ("pkg:pypi/requests", ("pip", "requests", None)),  # version-less purl
        ("pkg:pypi/foo@1.0?os=windows#sub/path", ("pip", "foo", "1.0")),  # qualifiers/subpath stripped
        ("pkg:rpm/centos/openssl@1.1.1", ("rpm", "centos/openssl", "1.1.1")),  # unknown type round-trips
    ],
)
def test_parse_purl_handles_github_sbom_locators(locator: str, expected: tuple) -> None:
    """`_parse_purl` maps purl types to dependency-graph ecosystems and decodes names."""
    assert _parse_purl(locator) == expected


@pytest.mark.parametrize("locator", ["", "not-a-purl", "pkg:", "pkg:pypi", "pkg:pypi/"])
def test_parse_purl_rejects_non_purls(locator: str) -> None:
    """Strings that are not parseable package-urls yield None instead of raising."""
    assert _parse_purl(locator) is None


def test_iter_ecosystem_packages_prefers_purl_over_bare_name() -> None:
    """The modern SBOM shape (bare name + pkg:pypi purl) resolves to the pip ecosystem."""
    sbom = {
        "sbom": {
            "packages": [
                {
                    "name": "flask-cors",
                    "versionInfo": "6.0.2",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/flask-cors@6.0.2",
                        }
                    ],
                }
            ]
        }
    }
    assert list(_iter_ecosystem_packages(sbom)) == [("pip", "flask-cors", "6.0.2")]


def test_iter_ecosystem_packages_falls_back_to_legacy_prefix() -> None:
    """Old-style `pip:GitPython` names still resolve when no purl is present."""
    sbom = {"sbom": {"packages": [{"name": "pip:GitPython", "versionInfo": "3.1.40"}]}}
    assert list(_iter_ecosystem_packages(sbom)) == [("pip", "GitPython", "3.1.40")]


def test_iter_ecosystem_packages_uses_purl_version_when_versioninfo_missing() -> None:
    """The purl's @version fills in for an absent versionInfo instead of dropping the entry."""
    sbom = {
        "sbom": {
            "packages": [
                {
                    "name": "flask-cors",
                    "externalRefs": [{"referenceLocator": "pkg:pypi/flask-cors@3.0.10"}],
                }
            ]
        }
    }
    assert list(_iter_ecosystem_packages(sbom)) == [("pip", "flask-cors", "3.0.10")]


def test_iter_ecosystem_packages_yields_empty_ecosystem_without_purl_or_prefix() -> None:
    """Entries with neither purl nor prefix keep an empty ecosystem so pip filters skip them."""
    sbom = {"sbom": {"packages": [{"name": "plain", "versionInfo": "1.0"}]}}
    assert list(_iter_ecosystem_packages(sbom)) == [("", "plain", "1.0")]


def test_vulnerable_hit_is_immutable() -> None:
    """VulnerableHit is frozen so reports can be safely cached."""
    hit = VulnerableHit(repo="r", package="p", version="1", threshold="2")
    with pytest.raises(Exception):
        hit.repo = "x"  # type: ignore[misc]


@pytest.mark.parametrize(
    "found,threshold,expected",
    [
        ("3.1.49", "3.1.50", True),
        ("3.1.50", "3.1.50", False),  # equal => NOT strictly below
        ("3.1.51", "3.1.50", False),
        ("3.1.50rc1", "3.1.50", True),
        ("not-a-version", "3.1.50", False),
    ],
)
def test_version_strictly_below_handles_pep_440(found: str, threshold: str, expected: bool) -> None:
    """`_version_strictly_below` is the comparator used when --max-vulnerable is omitted."""
    assert _version_strictly_below(found, threshold) is expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("pip:GitPython", ("pip", "GitPython")),
        ("npm:yaml", ("npm", "yaml")),
        ("npm:@scope/pkg", ("npm", "@scope/pkg")),  # scoped packages keep '/'
        ("actions:owner/name", ("actions", "owner/name")),
        ("plain", ("", "plain")),  # no prefix => empty ecosystem
    ],
)
def test_split_sbom_name_parses_ecosystem_and_name(raw: str, expected: tuple[str, str]) -> None:
    """`_split_sbom_name` returns (ecosystem, package) and handles scoped npm names."""
    assert _split_sbom_name(raw) == expected


@pytest.mark.parametrize(
    "found,threshold,expected",
    [
        ("10.2.0", "10.2.0", True),
        ("10.3.0", "10.2.0", True),
        ("10.1.0", "10.2.0", False),
        ("not-a-version", "10.2.0", False),
    ],
)
def test_version_at_or_above_handles_pep_440(found: str, threshold: str, expected: bool) -> None:
    """`_version_at_or_above` is the reach comparator used to scope the alerts fallback."""
    assert _version_at_or_above(found, threshold) is expected


def test_alert_addressed_by_patch_cve_match_wins_even_if_target_lower() -> None:
    """An exact CVE match is in scope even when --new-version is below the alert's fix."""
    alert = _alert(cve="CVE-2023-50447", patched="12.2.0")
    assert (
        _alert_addressed_by_patch(alert, max_vulnerable="10.2.0", patch_target="10.2.0", cve_id="CVE-2023-50447")
        is True
    )


def test_alert_addressed_by_patch_ghsa_match_is_case_insensitive() -> None:
    """The advisory match also accepts a GHSA id and ignores case."""
    alert = _alert(cve=None, ghsa="GHSA-abcd-efgh-ijkl", patched="99.0.0")
    assert (
        _alert_addressed_by_patch(alert, max_vulnerable="1.0.0", patch_target=None, cve_id="ghsa-abcd-efgh-ijkl")
        is True
    )


def test_alert_addressed_by_patch_version_reach_includes_when_bump_reaches_fix() -> None:
    """With no CVE match, an alert is in scope when the bump target reaches its patched version."""
    alert = _alert(cve="CVE-OTHER", patched="10.2.0")
    assert (
        _alert_addressed_by_patch(alert, max_vulnerable="10.2.0", patch_target="10.2.0", cve_id="CVE-2023-50447")
        is True
    )


def test_alert_addressed_by_patch_excludes_later_cve_above_target() -> None:
    """The reported bug: a later advisory (patched 12.2.0) is out of scope for a 10.2.0 bump."""
    alert = _alert(cve="CVE-2099-9999", vulnerable_range=">= 10.3.0, < 12.2.0", patched="12.2.0")
    assert (
        _alert_addressed_by_patch(alert, max_vulnerable="10.2.0", patch_target="10.2.0", cve_id="CVE-2023-50447")
        is False
    )


def test_alert_addressed_by_patch_falls_back_to_max_vulnerable_when_no_patch_target() -> None:
    """When patch_target is None the scan threshold is used as the reach target."""
    later = _alert(cve="CVE-2099-9999", patched="12.2.0")
    assert _alert_addressed_by_patch(later, max_vulnerable="10.2.0", patch_target=None, cve_id=None) is False
    on_target = _alert(cve="CVE-2099-9999", patched="10.2.0")
    assert _alert_addressed_by_patch(on_target, max_vulnerable="10.2.0", patch_target=None, cve_id=None) is True


def test_alert_addressed_by_patch_excludes_when_no_patched_version_and_no_cve_match() -> None:
    """No parseable patched version and no advisory match => not in scope (conservative)."""
    alert = _alert(cve="CVE-OTHER", patched=None)
    assert (
        _alert_addressed_by_patch(alert, max_vulnerable="10.2.0", patch_target="10.2.0", cve_id="CVE-2023-50447")
        is False
    )


def test_discover_affected_repos_filters_by_ecosystem_pip(monkeypatch) -> None:
    """`discover_affected_repos(ecosystem="pip")` ignores npm SBOM entries with the same bare name."""
    import json

    sbom = {
        "sbom": {
            "packages": [
                {"name": "npm:yaml", "versionInfo": "2.8.1"},
                {"name": "pip:Mako", "versionInfo": "1.3.10"},
            ]
        }
    }

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and argv[-1].endswith("vulnerability-alerts"):
            return CommandResult(0, "HTTP/2.0 204 OK\n", "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            return CommandResult(0, json.dumps(sbom), "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    hits = discover_affected_repos(
        owner="o",
        dep_name="yaml",
        max_vulnerable="2.8.3",
        strict_below=True,
        repo="r",
        ecosystem="pip",
    )
    # pip:yaml does not exist in the SBOM; npm:yaml must NOT bleed into the pip scan.
    assert hits == []


def test_discover_affected_repos_pip_sbom_consolidation_falls_back_to_alerts(monkeypatch) -> None:
    """
    When GitHub's SBOM consolidates a pip package to its patched root-lockfile version,
    the scanner falls back to Dependabot alerts and still reports the repo as vulnerable.

    Real-world trigger: root ``uv.lock`` already has ``Pillow==12.2.0``, so the SBOM
    reports ``pip:Pillow 12.2.0`` (not vulnerable).  But ``server/requirements.txt``
    still pins ``Pillow==9.3.0`` and Dependabot has an open alert for it.  The
    SBOM-only path would silently skip the repo; the alerts fallback catches it.
    """
    import json

    # SBOM only reflects the root lockfile's patched version.
    sbom = {
        "sbom": {
            "packages": [
                {"name": "pip:Pillow", "versionInfo": "12.2.0"},
            ]
        }
    }

    # Dependabot still has an open alert for the subdirectory manifest.
    alert_payload = [
        {
            "number": 14,
            "state": "open",
            "html_url": "https://github.com/jurdabos/RateMyMeat/security/dependabot/14",
            "security_advisory": {
                "severity": "critical",
                "summary": "Pillow buffer overflow via crafted image",
                "cve_id": "CVE-2023-50447",
                "ghsa_id": None,
            },
            "security_vulnerability": {
                "package": {"ecosystem": "pip", "name": "Pillow"},
                "vulnerable_version_range": "< 10.2.0",
                "first_patched_version": {"identifier": "10.2.0"},
            },
            "dependency": {"manifest_path": "server/requirements.txt"},
        }
    ]

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and argv[-1].endswith("vulnerability-alerts"):
            return CommandResult(0, "HTTP/2.0 204 OK\n", "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            return CommandResult(0, json.dumps(sbom), "")
        if argv and argv[0] == "gh" and "dependabot/alerts" in argv[-1]:
            return CommandResult(0, json.dumps(alert_payload), "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    hits = discover_affected_repos(
        owner="jurdabos",
        dep_name="Pillow",
        max_vulnerable="10.2.0",
        strict_below=True,
        repo="RateMyMeat",
        ecosystem="pip",
    )
    assert len(hits) == 1
    assert hits[0].repo == "RateMyMeat"
    assert hits[0].package == "Pillow"
    assert hits[0].ecosystem == "pip"
    # Version on the hit carries the alert's vulnerable range, not the SBOM version.
    assert "10.2.0" in hits[0].version
    # The alert's manifest path rides along so the verifier can target it.
    assert hits[0].manifest == "server/requirements.txt"


def test_discover_affected_repos_pip_sbom_consolidation_no_open_alerts_yields_no_hit(monkeypatch) -> None:
    """
    When the SBOM shows the patched version AND no open Dependabot alert exists, the
    repo is correctly reported as clean (no false positive from the fallback).
    """
    import json

    sbom = {
        "sbom": {
            "packages": [
                {"name": "pip:Pillow", "versionInfo": "12.2.0"},
            ]
        }
    }

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and argv[-1].endswith("vulnerability-alerts"):
            return CommandResult(0, "HTTP/2.0 204 OK\n", "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            return CommandResult(0, json.dumps(sbom), "")
        # Alerts API returns empty list — all alerts resolved.
        if argv and argv[0] == "gh" and "dependabot/alerts" in argv[-1]:
            return CommandResult(0, "[]", "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    hits = discover_affected_repos(
        owner="jurdabos",
        dep_name="Pillow",
        max_vulnerable="10.2.0",
        strict_below=True,
        repo="RateMyMeat",
        ecosystem="pip",
    )
    assert hits == []


def test_discover_affected_repos_handles_modern_purl_sbom(monkeypatch) -> None:
    """
    Regression for the 2026 SBOM format change: GitHub now emits bare package
    names with the ecosystem only in externalRefs PURLs. The pip path used to
    require a `pip:` name prefix, skipped every entry silently, and rode the
    alerts fallback for all repos. Mirrors the real RateMyMeat payload, where
    a stale flask-cors 3.0.10 graph node coexists with the locked 6.0.2 — the
    vulnerable stale entry must be matched by the SBOM path itself.
    """
    import json

    sbom = {
        "sbom": {
            "packages": [
                {
                    "name": "flask-cors",
                    "versionInfo": "3.0.10",
                    "externalRefs": [{"referenceLocator": "pkg:pypi/flask-cors@3.0.10"}],
                },
                {
                    "name": "flask-cors",
                    "versionInfo": "6.0.2",
                    "externalRefs": [{"referenceLocator": "pkg:pypi/flask-cors@6.0.2"}],
                },
            ]
        }
    }

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and argv[-1].endswith("vulnerability-alerts"):
            return CommandResult(0, "HTTP/2.0 204 OK\n", "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            return CommandResult(0, json.dumps(sbom), "")
        if argv and argv[0] == "gh" and "dependabot/alerts" in argv[-1]:
            raise AssertionError("an SBOM hit must not fall through to the alerts endpoint")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    hits = discover_affected_repos(
        owner="jurdabos",
        dep_name="Flask-Cors",
        max_vulnerable="4.0.2",
        strict_below=True,
        repo="RateMyMeat",
        ecosystem="pip",
    )
    assert len(hits) == 1
    assert hits[0].package == "flask-cors"
    assert hits[0].version == "3.0.10"
    assert hits[0].ecosystem == "pip"


def test_discover_affected_repos_npm_uses_dependabot_alerts(monkeypatch) -> None:
    """npm discovery routes through the Dependabot alerts endpoint, not the SBOM.

    GitHub's SBOM emits bare names for npm entries (the ecosystem only appears
    in ``externalRefs[].referenceLocator`` as a PURL like ``pkg:npm/yaml@2.8.1``)
    and is empirically flaky for large npm trees. The alerts endpoint is the
    reliable source-of-truth; this test enforces that route.
    """
    import json

    alert_payload = [
        {
            "number": 5,
            "state": "open",
            "html_url": "https://example/yaml/5",
            "security_advisory": {
                "severity": "medium",
                "summary": "vuln",
                "cve_id": "CVE-2026-33532",
                "ghsa_id": None,
            },
            "security_vulnerability": {
                "package": {"ecosystem": "npm", "name": "yaml"},
                "vulnerable_version_range": ">= 2.0.0, < 2.8.3",
                "first_patched_version": {"identifier": "2.8.3"},
            },
            "dependency": {"manifest_path": "frontend/package-lock.json"},
        }
    ]

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and "dependabot/alerts" in argv[-1]:
            return CommandResult(0, json.dumps(alert_payload), "")
        # SBOM must NOT be reached for npm discovery; fail loudly if it is.
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            raise AssertionError("npm discovery must not call the SBOM endpoint")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    hits = discover_affected_repos(
        owner="o",
        dep_name="yaml",
        max_vulnerable="2.8.3",
        strict_below=True,
        repo="r",
        ecosystem="npm",
    )
    assert len(hits) == 1
    assert hits[0].repo == "r"
    assert hits[0].package == "yaml"
    assert hits[0].ecosystem == "npm"
    # version on the hit carries the alert's vulnerable range so the table is informative.
    assert "2.8.3" in hits[0].version
    # npm hits also carry the alert manifest path.
    assert hits[0].manifest == "frontend/package-lock.json"


def test_discover_pip_fallback_excludes_out_of_scope_later_cve(monkeypatch) -> None:
    """
    Regression for the cross-advisory false positive.

    The SBOM shows Pillow already at 10.3.1 (above the 10.2.0 bump target, so no
    direct SBOM hit). The repo's only open Pillow alert is a *later* advisory
    whose range is ``>= 10.3.0, < 12.2.0`` (first patched 12.2.0). Bumping to
    10.2.0 does nothing for that advisory, so the fallback must NOT flag the
    repo — otherwise the version-only verifier would mislabel it FIXED.
    """
    import json

    sbom = {"sbom": {"packages": [{"name": "pip:Pillow", "versionInfo": "10.3.1"}]}}
    later_alert = [
        {
            "number": 33,
            "state": "open",
            "html_url": "https://example/Pillow/33",
            "security_advisory": {
                "severity": "high",
                "summary": "later Pillow advisory",
                "cve_id": "CVE-2099-9999",
                "ghsa_id": None,
            },
            "security_vulnerability": {
                "package": {"ecosystem": "pip", "name": "Pillow"},
                "vulnerable_version_range": ">= 10.3.0, < 12.2.0",
                "first_patched_version": {"identifier": "12.2.0"},
            },
            "dependency": {"manifest_path": "uv.lock"},
        }
    ]

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and argv[-1].endswith("vulnerability-alerts"):
            return CommandResult(0, "HTTP/2.0 204 OK\n", "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            return CommandResult(0, json.dumps(sbom), "")
        if argv and argv[0] == "gh" and "dependabot/alerts" in argv[-1]:
            return CommandResult(0, json.dumps(later_alert), "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    hits = discover_affected_repos(
        owner="jurdabos",
        dep_name="Pillow",
        max_vulnerable="10.2.0",
        strict_below=True,
        repo="uteal",
        ecosystem="pip",
        patch_target="10.2.0",
        cve_id="CVE-2023-50447",
    )
    assert hits == []


def test_discover_npm_excludes_out_of_scope_later_cve(monkeypatch) -> None:
    """npm discovery scopes alerts too: a later-CVE-only repo is not flagged for an earlier bump."""
    import json

    alert_payload = [
        {
            "number": 7,
            "state": "open",
            "html_url": "https://example/yaml/7",
            "security_advisory": {
                "severity": "high",
                "summary": "later yaml advisory",
                "cve_id": "CVE-2099-0001",
                "ghsa_id": None,
            },
            "security_vulnerability": {
                "package": {"ecosystem": "npm", "name": "yaml"},
                "vulnerable_version_range": ">= 2.9.0, < 3.0.0",
                "first_patched_version": {"identifier": "3.0.0"},
            },
            "dependency": {"manifest_path": "package-lock.json"},
        }
    ]

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and "dependabot/alerts" in argv[-1]:
            return CommandResult(0, json.dumps(alert_payload), "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            raise AssertionError("npm discovery must not call the SBOM endpoint")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    hits = discover_affected_repos(
        owner="o",
        dep_name="yaml",
        max_vulnerable="2.8.3",
        strict_below=True,
        repo="r",
        ecosystem="npm",
        patch_target="2.8.3",
        cve_id="CVE-2026-33532",
    )
    # The only open alert needs 3.0.0; bumping to 2.8.3 does not address it.
    assert hits == []


def _crypto_sbom(*versions: str) -> dict:
    """Returns a modern-shape SBOM listing one cryptography node per version in ``versions``."""
    return {
        "sbom": {
            "packages": [
                {
                    "name": "cryptography",
                    "versionInfo": v,
                    "externalRefs": [{"referenceLocator": f"pkg:pypi/cryptography@{v}"}],
                }
                for v in versions
            ]
        }
    }


def test_discover_pip_demotes_stale_sbom_hit_when_origin_manifest_fixed(monkeypatch) -> None:
    """A phantom SBOM node is demoted when origin's uv.lock already resolves the dep above the threshold.

    Mirrors the jurdabos/vlc case: the dependency-graph SBOM still lists both
    cryptography 49.0.0 and a stale 48.0.0 node, but origin's uv.lock is already
    on 49.0.0. The ``< 48.0.1`` SBOM hit must be demoted to a warning rather than
    surfaced as a vulnerability, and the alerts fallback must find nothing.
    """
    import json

    sbom = _crypto_sbom("49.0.0", "48.0.0")

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and argv[-1].endswith("vulnerability-alerts"):
            return CommandResult(0, "HTTP/2.0 204 OK\n", "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            return CommandResult(0, json.dumps(sbom), "")
        if argv and argv[0] == "gh" and "contents/uv.lock" in argv[-1]:
            return CommandResult(0, _UV_LOCK_CRYPTO.format(version="49.0.0"), "")
        if argv and argv[0] == "gh" and "dependabot/alerts" in argv[-1]:
            return CommandResult(0, "[]", "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    warnings: list[str] = []
    hits = discover_affected_repos(
        owner="jurdabos",
        dep_name="cryptography",
        max_vulnerable="48.0.1",
        strict_below=True,
        repo="vlc",
        ecosystem="pip",
        patch_target="48.0.1",
        cve_id="GHSA-537c-gmf6-5ccf",
        on_stale_warning=warnings.append,
    )
    assert hits == []
    assert len(warnings) == 1
    assert "vlc" in warnings[0]
    assert "48.0.0" in warnings[0]
    assert "49.0.0" in warnings[0]


def test_discover_pip_keeps_hit_when_origin_manifest_still_vulnerable(monkeypatch) -> None:
    """When origin's manifest still pins a vulnerable version, the SBOM hit stands (no demotion)."""
    import json

    sbom = _crypto_sbom("48.0.0")

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and argv[-1].endswith("vulnerability-alerts"):
            return CommandResult(0, "HTTP/2.0 204 OK\n", "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            return CommandResult(0, json.dumps(sbom), "")
        if argv and argv[0] == "gh" and "contents/uv.lock" in argv[-1]:
            return CommandResult(0, _UV_LOCK_CRYPTO.format(version="48.0.0"), "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    warnings: list[str] = []
    hits = discover_affected_repos(
        owner="jurdabos",
        dep_name="cryptography",
        max_vulnerable="48.0.1",
        strict_below=True,
        repo="vlc",
        ecosystem="pip",
        on_stale_warning=warnings.append,
    )
    assert len(hits) == 1
    assert hits[0].version == "48.0.0"
    assert warnings == []


def test_discover_pip_stale_demotion_still_flags_real_subdir_alert(monkeypatch) -> None:
    """After demoting a stale root-level SBOM node, a genuine subdirectory alert still flags the repo.

    The root uv.lock is patched (so the SBOM's ``< 48.0.1`` node is stale for the
    root), but ``producer/requirements.txt`` still pins an old version and
    Dependabot has an open, in-scope alert for it. The alerts fallback must still
    surface the repo with that manifest so the guard never hides a real pin.
    """
    import json

    sbom = _crypto_sbom("48.0.0")
    alert_payload = [
        {
            "number": 9,
            "state": "open",
            "html_url": "https://example/cryptography/9",
            "security_advisory": {
                "severity": "high",
                "summary": "cryptography vuln",
                "cve_id": None,
                "ghsa_id": "GHSA-537c-gmf6-5ccf",
            },
            "security_vulnerability": {
                "package": {"ecosystem": "pip", "name": "cryptography"},
                "vulnerable_version_range": "< 48.0.1",
                "first_patched_version": {"identifier": "48.0.1"},
            },
            "dependency": {"manifest_path": "producer/requirements.txt"},
        }
    ]

    def fake_run(args, **_kw):
        argv = tuple(args)
        if argv and argv[0] == "gh" and argv[-1].endswith("vulnerability-alerts"):
            return CommandResult(0, "HTTP/2.0 204 OK\n", "")
        if argv and argv[0] == "gh" and argv[-1].endswith("/dependency-graph/sbom"):
            return CommandResult(0, json.dumps(sbom), "")
        if argv and argv[0] == "gh" and "contents/uv.lock" in argv[-1]:
            return CommandResult(0, _UV_LOCK_CRYPTO.format(version="49.0.0"), "")
        if argv and argv[0] == "gh" and "dependabot/alerts" in argv[-1]:
            return CommandResult(0, json.dumps(alert_payload), "")
        return CommandResult(0, "", "")

    monkeypatch.setattr(scanner.shell, "run", fake_run)

    warnings: list[str] = []
    hits = discover_affected_repos(
        owner="jurdabos",
        dep_name="cryptography",
        max_vulnerable="48.0.1",
        strict_below=True,
        repo="vlc",
        ecosystem="pip",
        patch_target="48.0.1",
        cve_id="GHSA-537c-gmf6-5ccf",
        on_stale_warning=warnings.append,
    )
    assert len(warnings) == 1  # the root-level SBOM node was demoted
    assert len(hits) == 1  # but the subdirectory alert still flags the repo
    assert hits[0].manifest == "producer/requirements.txt"
