"""Tests for :mod:`acidbase.push` (sanitize-on-publish dual-publish flow).

Coverage:
- Basic workflow helpers (``get_project_root``, ``_has_changes``,
  ``_hooks_modified_files``, ``_auto_commit_message``) — unit tests
  adopted from ratemyhuman's consumer suite.
- ``PushConfig`` loading from ``pyproject.toml`` (single, dual, defaults,
  ``public_substitutions``).
- Substitution parsing / application.
- ``_detect_topology`` classification.
- ``_compile_allowlist`` / ``_check_public_allowlist`` regex semantics.
- ``_build_public_projection`` (UTF-8 + binary + allowlist filter).
- ``_projection_context`` (discard vs keep modes).
- ``_run_local_gitleaks`` with ``--no-git --source <scan_root>``.
- ``_run_public_preflight`` end-to-end against a projection.
- ``_resolve_destination`` precedence between ``--to`` / ``--yes`` /
  ``--no-prompt``.
- ``_resolve_public_message`` (override / inherit / fallback).
- ``_publish_projection`` git command sequence.
- ``_perform_pushes`` ordering, partial-failure exit codes, single-mode
  fallback, and integration with the projection.
- ``push_command`` CLI flag validation via ``click.testing``.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from acidbase import push as push_mod
from acidbase.push import (
    PROJECTION_KEEP_SUBDIR,
    PUBLIC_AUTHOR_EMAIL,
    PUBLIC_AUTHOR_NAME,
    PUBLIC_BRANCH,
    SUBSTITUTION_EXEMPT_PATHS,
    PublicPreflight,
    PushConfig,
    _apply_substitutions,
    _auto_commit_message,
    _build_public_projection,
    _check_projection_imports,
    _check_public_allowlist,
    _compile_allowlist,
    _detect_topology,
    _has_changes,
    _hooks_modified_files,
    _list_remotes,
    _list_tracked_files,
    _load_push_config,
    _parse_substitutions,
    _perform_pushes,
    _projection_context,
    _projection_module_index,
    _publish_projection,
    _render_preflight,
    _resolve_destination,
    _resolve_public_message,
    _run_local_gitleaks,
    _run_public_preflight,
    get_project_root,
    push_command,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pyproject(tmp_path: Path, body: str) -> None:
    """Writes a ``pyproject.toml`` into *tmp_path* with the given body."""
    (tmp_path / "pyproject.toml").write_text(body, encoding="utf-8")


def _make_completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    """Constructs a ``subprocess.CompletedProcess`` for stubbing ``_run`` results."""
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# _load_push_config
# ---------------------------------------------------------------------------


def test_load_push_config_returns_default_when_pyproject_missing(tmp_path: Path):
    """Absent pyproject.toml means single-mode (today's behaviour)."""
    cfg = _load_push_config(tmp_path)
    assert cfg == PushConfig()
    assert cfg.public_remote is None
    assert cfg.public_substitutions == ()


def test_load_push_config_returns_default_when_section_absent(tmp_path: Path):
    """A pyproject.toml without [tool.acidbase.push] still means single-mode."""
    _write_pyproject(tmp_path, '[project]\nname = "x"\nversion = "0"\n')
    cfg = _load_push_config(tmp_path)
    assert cfg.public_remote is None
    assert cfg.private_remote == "origin"
    assert cfg.public_substitutions == ()


def test_load_push_config_empty_section_opts_in_to_dual_mode(tmp_path: Path):
    """Even an empty [tool.acidbase.push] table fills in defaults."""
    _write_pyproject(
        tmp_path,
        '[project]\nname = "x"\nversion = "0"\n\n[tool.acidbase.push]\n',
    )
    cfg = _load_push_config(tmp_path)
    assert cfg.private_remote == "origin"
    assert cfg.public_remote == "public"
    assert cfg.allowlist_file is None
    assert cfg.gitleaks_config is None
    assert cfg.public_substitutions == ()


def test_load_push_config_picks_up_default_safety_inputs_when_present(tmp_path: Path):
    """PUBLIC_ALLOWLIST.txt and .gitleaks.toml become defaults when on disk."""
    _write_pyproject(
        tmp_path,
        '[project]\nname = "x"\nversion = "0"\n\n[tool.acidbase.push]\n',
    )
    (tmp_path / "PUBLIC_ALLOWLIST.txt").write_text("README.md\n", encoding="utf-8")
    (tmp_path / ".gitleaks.toml").write_text("# config\n", encoding="utf-8")
    cfg = _load_push_config(tmp_path)
    assert cfg.allowlist_file == Path("PUBLIC_ALLOWLIST.txt")
    assert cfg.gitleaks_config == Path(".gitleaks.toml")


def test_load_push_config_honours_explicit_overrides(tmp_path: Path):
    """Explicit keys in the [tool.acidbase.push] table win over defaults."""
    _write_pyproject(
        tmp_path,
        "\n".join(
            [
                "[project]",
                'name = "x"',
                'version = "0"',
                "",
                "[tool.acidbase.push]",
                'private_remote = "primary"',
                'public_remote = "mirror"',
                'allowlist_file = "ALLOW.txt"',
                'gitleaks_config = "scan.toml"',
                "",
            ]
        ),
    )
    cfg = _load_push_config(tmp_path)
    assert cfg.private_remote == "primary"
    assert cfg.public_remote == "mirror"
    assert cfg.allowlist_file == Path("ALLOW.txt")
    assert cfg.gitleaks_config == Path("scan.toml")


def test_load_push_config_parses_public_substitutions(tmp_path: Path):
    """[[tool.acidbase.push.public_substitutions]] entries are compiled into rules."""
    _write_pyproject(
        tmp_path,
        "\n".join(
            [
                "[project]",
                'name = "x"',
                'version = "0"',
                "",
                "[tool.acidbase.push]",
                "",
                "[[tool.acidbase.push.public_substitutions]]",
                "pattern = 'C:[\\\\\\\\/]+acidvuca'",
                'replacement = "<acidbase>"',
                "",
                "[[tool.acidbase.push.public_substitutions]]",
                "pattern = '<REAL_WSL_HOME>'",
                'replacement = "<home>"',
            ]
        ),
    )
    cfg = _load_push_config(tmp_path)
    assert len(cfg.public_substitutions) == 2
    pat0, repl0 = cfg.public_substitutions[0]
    assert pat0.search("<REAL_A6E_FOLDER>") is not None
    assert repl0 == "<acidbase>"
    pat1, repl1 = cfg.public_substitutions[1]
    assert pat1.search("<REAL_WSL_HOME>/url-rag") is not None
    assert repl1 == "<home>"


# ---------------------------------------------------------------------------
# Substitution helpers
# ---------------------------------------------------------------------------


def test_parse_substitutions_drops_malformed_entries():
    """Wrong types, missing keys, and bad regex are silently skipped."""
    raw = [
        {"pattern": "foo", "replacement": "FOO"},
        {"pattern": "no replacement field"},  # missing replacement -> ""
        {"pattern": 12, "replacement": "bad type"},  # not a string -> dropped
        {"replacement": "orphan replacement"},  # no pattern -> dropped
        {"pattern": "(", "replacement": "broken regex"},  # invalid regex -> dropped
        "not even a table",  # not a dict -> dropped
    ]
    result = _parse_substitutions(raw)
    # The first two are kept; everything else is dropped.
    assert len(result) == 2
    assert result[0][0].pattern == "foo"
    assert result[0][1] == "FOO"
    assert result[1][0].pattern == "no replacement field"
    assert result[1][1] == ""


def test_parse_substitutions_returns_empty_for_non_list():
    """Anything that isn't a list yields an empty tuple."""
    assert _parse_substitutions(None) == ()
    assert _parse_substitutions({"pattern": "x", "replacement": "y"}) == ()
    assert _parse_substitutions("foo") == ()


def test_apply_substitutions_runs_rules_in_order():
    """Substitutions are applied sequentially so later rules can match the output of earlier ones."""
    subs = (
        (re.compile(r"<REAL_A6E_FOLDER>"), "<acidbase>"),
        (re.compile(r"<REAL_WSL_HOME>"), "<home>"),
    )
    text = "Visit <REAL_A6E_FOLDER> and <REAL_WSL_HOME>/notes."
    assert _apply_substitutions(text, subs) == "Visit <acidbase> and <home>/notes."


def test_apply_substitutions_with_empty_rules_returns_input_unchanged():
    """An empty rule set is a no-op."""
    assert _apply_substitutions("hello", ()) == "hello"


# ---------------------------------------------------------------------------
# _detect_topology / _list_remotes
# ---------------------------------------------------------------------------


def test_detect_topology_returns_single_when_no_public_remote_configured(tmp_path: Path):
    """A PushConfig without public_remote always classifies as single."""
    cfg = PushConfig()
    assert _detect_topology(tmp_path, cfg) == "single"


def test_detect_topology_returns_dual_when_both_remotes_exist(tmp_path: Path):
    """Both configured remote names being present in `git remote` => dual."""
    cfg = PushConfig(private_remote="origin", public_remote="public")
    with patch.object(push_mod, "_list_remotes", return_value={"origin", "public"}):
        assert _detect_topology(tmp_path, cfg) == "dual"


def test_detect_topology_returns_dual_misconfigured_when_remote_missing(tmp_path: Path):
    """If either remote is not configured locally, topology is dual_misconfigured."""
    cfg = PushConfig(private_remote="origin", public_remote="public")
    with patch.object(push_mod, "_list_remotes", return_value={"origin"}):
        assert _detect_topology(tmp_path, cfg) == "dual_misconfigured"
    with patch.object(push_mod, "_list_remotes", return_value={"public"}):
        assert _detect_topology(tmp_path, cfg) == "dual_misconfigured"


def test_list_remotes_parses_one_per_line(tmp_path: Path):
    """`git remote` stdout is split on newlines and stripped."""
    with patch.object(push_mod, "_run", return_value=_make_completed(stdout="origin\npublic\nupstream\n")):
        assert _list_remotes(tmp_path) == {"origin", "public", "upstream"}


# ---------------------------------------------------------------------------
# Allowlist compilation and matching
# ---------------------------------------------------------------------------


@pytest.fixture()
def allowlist_file(tmp_path: Path) -> Path:
    """Writes a representative allowlist mirroring the real PUBLIC_ALLOWLIST.txt."""
    body = """
# PUBLIC_ALLOWLIST
# Comments and blank lines are ignored.

README.md
.gitleaks.toml
src/acidbase/push.py
.github/workflows/lint.yml
docs/guidelines/security_patching.md
tests/test_placeholder.py
"""
    p = tmp_path / "PUBLIC_ALLOWLIST.txt"
    p.write_text(body, encoding="utf-8")
    return p


def test_compile_allowlist_skips_comments_and_blank_lines(allowlist_file: Path):
    """Comment and blank lines do not produce regex patterns."""
    patterns = _compile_allowlist(allowlist_file)
    assert len(patterns) == 6


def test_compile_allowlist_escapes_dot_only(allowlist_file: Path):
    """Dots must be escaped so '.gitleaks.toml' matches literally, not 'Xgitleaks_toml'."""
    patterns = _compile_allowlist(allowlist_file)
    assert any(pat.match(".gitleaks.toml") for pat in patterns)
    assert not any(pat.match("Xgitleaks-toml") for pat in patterns)


def test_check_public_allowlist_directory_match(allowlist_file: Path):
    """A directory entry matches itself and anything underneath it."""
    ok, violations = _check_public_allowlist(
        [
            "src/acidbase/push.py",
            ".github/workflows/lint.yml",
            "docs/guidelines/security_patching.md",
        ],
        allowlist_file,
    )
    assert ok is True
    assert violations == []


def test_check_public_allowlist_rejects_unlisted_paths(allowlist_file: Path):
    """Paths outside the allowlist are returned as violations.
    Neutral placeholder paths are used so the test stays green even
    under the strict public-mirror `.gitleaks.toml` ruleset.
    """
    ok, violations = _check_public_allowlist(
        [
            "README.md",
            "src/extra/module.py",
            "notes/draft.md",
        ],
        allowlist_file,
    )
    assert ok is False
    assert violations == ["src/extra/module.py", "notes/draft.md"]


def test_check_public_allowlist_handles_empty_input(allowlist_file: Path):
    """No changed paths => trivially ok."""
    ok, violations = _check_public_allowlist([], allowlist_file)
    assert ok is True
    assert violations == []


# ---------------------------------------------------------------------------
# _list_tracked_files
# ---------------------------------------------------------------------------


def test_list_tracked_files_returns_sorted_unique(tmp_path: Path):
    """The helper sorts and deduplicates the `git ls-files` output."""
    stdout = "b.py\na.py\nb.py\nsrc/x.py\n"
    with patch.object(push_mod, "_run", return_value=_make_completed(stdout=stdout)):
        assert _list_tracked_files(tmp_path) == ["a.py", "b.py", "src/x.py"]


# ---------------------------------------------------------------------------
# _build_public_projection
# ---------------------------------------------------------------------------


def test_build_public_projection_copies_allowlisted_text_with_substitutions(tmp_path: Path, allowlist_file: Path):
    """UTF-8 files are decoded, run through substitutions, and re-written."""
    # Create one allowlisted text file with an internal marker.
    src = tmp_path / "README.md"
    src.write_text("Hello from <REAL_A6E_FOLDER>!\n", encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
        public_substitutions=((re.compile(r"<REAL_A6E_FOLDER>"), "<acidbase>"),),
    )
    with patch.object(push_mod, "_list_tracked_files", return_value=["README.md"]):
        included, excluded, err = _build_public_projection(tmp_path, projection, cfg)
    assert err is None
    assert included == ["README.md"]
    assert excluded == []
    assert (projection / "README.md").read_text(encoding="utf-8") == "Hello from <acidbase>!\n"


def test_build_public_projection_passes_binary_files_through(tmp_path: Path, allowlist_file: Path):
    """Files that can't be decoded as UTF-8 are copied byte-for-byte."""
    src = tmp_path / "README.md"
    payload = b"\x89PNG\r\n\x1a\n\x00\x00rest"
    src.write_bytes(payload)
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
        # A substitution that WOULD match the bytes if they were decoded; binary
        # files must skip the substitution step.
        public_substitutions=((re.compile(r"PNG"), "JPG"),),
    )
    with patch.object(push_mod, "_list_tracked_files", return_value=["README.md"]):
        included, excluded, err = _build_public_projection(tmp_path, projection, cfg)
    assert err is None
    assert included == ["README.md"]
    assert (projection / "README.md").read_bytes() == payload


def test_build_public_projection_filters_out_non_allowlisted_paths(tmp_path: Path, allowlist_file: Path):
    """Tracked paths that don't match any allowlist pattern stay private-only."""
    # README.md is allowlisted; SECRETS.txt is not.
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    (tmp_path / "SECRETS.txt").write_text("nope\n", encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
    )
    with patch.object(push_mod, "_list_tracked_files", return_value=["README.md", "SECRETS.txt"]):
        included, excluded, err = _build_public_projection(tmp_path, projection, cfg)
    assert err is None
    assert included == ["README.md"]
    assert excluded == ["SECRETS.txt"]
    assert (projection / "README.md").exists()
    assert not (projection / "SECRETS.txt").exists()


def test_build_public_projection_returns_error_when_no_allowlist_configured(tmp_path: Path):
    """Without an allowlist file, the build short-circuits with an error message."""
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(public_remote="public", allowlist_file=None)
    included, excluded, err = _build_public_projection(tmp_path, projection, cfg)
    assert err == "no allowlist_file configured"
    assert included == [] and excluded == []


def test_build_public_projection_returns_error_when_allowlist_missing(tmp_path: Path):
    """A configured-but-missing allowlist file produces a clear build error."""
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(public_remote="public", allowlist_file=Path("MISSING.txt"))
    included, excluded, err = _build_public_projection(tmp_path, projection, cfg)
    assert err is not None
    assert "MISSING.txt" in err
    assert included == [] and excluded == []


def test_substitution_exempt_paths_contains_gitleaks_configs():
    """The hardcoded exempt set covers BOTH gitleaks config filenames."""
    assert ".gitleaks.toml" in SUBSTITUTION_EXEMPT_PATHS
    assert ".gitleaks-private.toml" in SUBSTITUTION_EXEMPT_PATHS


def test_build_public_projection_copies_gitleaks_config_verbatim(tmp_path: Path):
    """`.gitleaks.toml` is exempted from substitutions so its regex patterns survive.
    Regression: an earlier projection build ran the `<REAL_WSL_HOME>` substitution
    against the projected `.gitleaks.toml`, which rewrote the rule's own
    `<REAL_WSL_HOME>` alternation into the placeholder `<REAL_WSL_HOME>`. The
    public CI then matched that placeholder everywhere in the projection,
    creating a self-match cascade. This test pins the verbatim behaviour
    for both gitleaks config filenames.
    """
    # Allowlist that includes the gitleaks configs and a regular file.
    allowlist = tmp_path / "PUBLIC_ALLOWLIST.txt"
    allowlist.write_text(
        ".gitleaks.toml\n.gitleaks-private.toml\nREADME.md\n",
        encoding="utf-8",
    )
    # Source files that contain the trigger substring.
    gitleaks_body = "regex = '(.*?<REAL_WSL_HOME>)'\n"
    private_body = "# explains why <REAL_WSL_HOME> must stay in the rule\n"
    readme_body = "Visit <REAL_WSL_HOME> for the notes.\n"
    (tmp_path / ".gitleaks.toml").write_text(gitleaks_body, encoding="utf-8")
    (tmp_path / ".gitleaks-private.toml").write_text(private_body, encoding="utf-8")
    (tmp_path / "README.md").write_text(readme_body, encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=Path("PUBLIC_ALLOWLIST.txt"),
        public_substitutions=((re.compile(r"<REAL_WSL_HOME>"), "<REAL_WSL_HOME>"),),
    )
    with patch.object(
        push_mod,
        "_list_tracked_files",
        return_value=[".gitleaks.toml", ".gitleaks-private.toml", "README.md"],
    ):
        included, excluded, err = _build_public_projection(tmp_path, projection, cfg)
    assert err is None
    assert set(included) == {".gitleaks.toml", ".gitleaks-private.toml", "README.md"}
    assert excluded == []
    # The two gitleaks configs are copied byte-for-byte: the trigger
    # substring survives.
    assert (projection / ".gitleaks.toml").read_text(encoding="utf-8") == gitleaks_body
    assert (projection / ".gitleaks-private.toml").read_text(encoding="utf-8") == private_body
    # README.md is NOT exempt; the substitution applies as usual.
    assert (projection / "README.md").read_text(encoding="utf-8") == "Visit <REAL_WSL_HOME> for the notes.\n"


def test_run_public_preflight_prefers_projected_gitleaks_config(tmp_path: Path, allowlist_file: Path):
    """Preflight scans with the projection's `.gitleaks.toml` when present.
    This is the second half of the projection-corruption regression fix: even
    with `SUBSTITUTION_EXEMPT_PATHS` keeping `.gitleaks.toml` verbatim today,
    the preflight should still scan the projected config so any future
    deviation from source is caught locally before pushing.
    """
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    (tmp_path / ".gitleaks.toml").write_text("# source\n", encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    # Pretend the projection contains its own `.gitleaks.toml` (which it
    # would, since `.gitleaks.toml` is normally on the allowlist).
    (projection / ".gitleaks.toml").write_text("# projected\n", encoding="utf-8")
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
        gitleaks_config=Path(".gitleaks.toml"),
    )
    captured: dict[str, Any] = {}

    def fake_gitleaks(scan_root, config_path):
        captured["scan_root"] = scan_root
        captured["config_path"] = config_path
        return True, "no leaks detected"

    with (
        patch.object(push_mod, "_list_tracked_files", return_value=["README.md"]),
        patch.object(push_mod, "_run_local_gitleaks", side_effect=fake_gitleaks),
    ):
        preflight = _run_public_preflight(tmp_path, projection, cfg)
    assert preflight.public_safe is True
    # The preflight used the PROJECTED gitleaks config, not the source.
    assert captured["config_path"] == (projection / ".gitleaks.toml").resolve()


def test_run_public_preflight_falls_back_to_source_gitleaks_config(tmp_path: Path, allowlist_file: Path):
    """When the projection doesn't ship a gitleaks config, the source one is used."""
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    (tmp_path / ".gitleaks.toml").write_text("# source\n", encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    # Deliberately do NOT write `.gitleaks.toml` into the projection.
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
        gitleaks_config=Path(".gitleaks.toml"),
    )
    captured: dict[str, Any] = {}

    def fake_gitleaks(scan_root, config_path):
        captured["config_path"] = config_path
        return True, "no leaks detected"

    with (
        patch.object(push_mod, "_list_tracked_files", return_value=["README.md"]),
        patch.object(push_mod, "_run_local_gitleaks", side_effect=fake_gitleaks),
    ):
        _run_public_preflight(tmp_path, projection, cfg)
    assert captured["config_path"] == (tmp_path / ".gitleaks.toml").resolve()


# ---------------------------------------------------------------------------
# _check_projection_imports (projection self-containment gate)
# ---------------------------------------------------------------------------


def _make_src_package(root: Path, modules: dict[str, str]) -> None:
    """Writes a ``src/<pkg>/`` layout from a ``{dotted_name: source}`` mapping."""
    for dotted, source in modules.items():
        rel = Path(*dotted.split("."))
        path = root / "src" / rel.with_suffix(".py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def test_projection_module_index_finds_src_layout_packages(tmp_path: Path):
    """The index recognises a src/<pkg>/ layout and enumerates its modules."""
    _make_src_package(
        tmp_path,
        {
            "pkg.__init__": "",
            "pkg.alpha": "x = 1\n",
            "pkg.sub.__init__": "",
            "pkg.sub.beta": "y = 2\n",
        },
    )
    modules, roots = _projection_module_index(tmp_path)
    assert roots == {"pkg"}
    assert {"pkg", "pkg.alpha", "pkg.sub", "pkg.sub.beta"} <= modules


def test_projection_module_index_finds_flat_layout_packages(tmp_path: Path):
    """A flat <pkg>/ layout at the projection root is recognised too."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "alpha.py").write_text("x = 1\n", encoding="utf-8")
    modules, roots = _projection_module_index(tmp_path)
    assert roots == {"pkg"}
    assert {"pkg", "pkg.alpha"} <= modules


def test_check_projection_imports_flags_unpublished_sibling(tmp_path: Path):
    """The cli_utils regression: a published module importing an unpublished one fails.

    This is exactly the shape that shipped a broken public package — the
    allowlist admitted `acidbase/cli.py` (which does
    `from acidbase.cli_utils import RichGroup`) while omitting
    `acidbase/cli_utils.py`, so `import acidbase.cli` raised
    ModuleNotFoundError for anyone installing from the mirror. Note a
    byte-compile pass would NOT catch this: cli.py compiles fine.
    """
    _make_src_package(
        tmp_path,
        {
            "pkg.__init__": "",
            "pkg.cli": "from pkg.cli_utils import RichGroup\n",
        },
    )
    ok, message = _check_projection_imports(tmp_path)
    assert ok is False
    assert "pkg.cli_utils" in message
    assert "does not publish" in message


def test_check_projection_imports_passes_when_sibling_present(tmp_path: Path):
    """Publishing the imported module alongside it satisfies the gate."""
    _make_src_package(
        tmp_path,
        {
            "pkg.__init__": "",
            "pkg.cli": "from pkg.cli_utils import RichGroup\n",
            "pkg.cli_utils": "class RichGroup: ...\n",
        },
    )
    ok, message = _check_projection_imports(tmp_path)
    assert ok is True
    assert "resolve" in message


def test_check_projection_imports_ignores_third_party_and_stdlib(tmp_path: Path):
    """Only imports rooted in a published package are the projection's concern."""
    _make_src_package(
        tmp_path,
        {
            "pkg.__init__": "",
            "pkg.mod": "from __future__ import annotations\nimport click\nfrom rich.table import Table\nimport os.path\n",
        },
    )
    ok, _ = _check_projection_imports(tmp_path)
    assert ok is True


def test_check_projection_imports_resolves_relative_imports(tmp_path: Path):
    """A relative import of a missing sibling is caught; a present one passes."""
    _make_src_package(
        tmp_path,
        {
            "pkg.__init__": "",
            "pkg.mod": "from . import helper\n",
        },
    )
    ok, message = _check_projection_imports(tmp_path)
    assert ok is False
    assert "pkg" in message
    # Publishing the sibling clears it.
    _make_src_package(tmp_path, {"pkg.helper": "value = 1\n"})
    ok_after, _ = _check_projection_imports(tmp_path)
    assert ok_after is True


def test_check_projection_imports_reports_syntax_errors(tmp_path: Path):
    """An unparseable published file is surfaced rather than silently skipped."""
    _make_src_package(tmp_path, {"pkg.__init__": "", "pkg.broken": "def oops(:\n"})
    ok, message = _check_projection_imports(tmp_path)
    assert ok is False
    assert "syntax error" in message


def test_check_projection_imports_noop_without_packages(tmp_path: Path):
    """A docs-only projection has nothing to verify and passes trivially."""
    (tmp_path / "README.md").write_text("hi\n", encoding="utf-8")
    ok, message = _check_projection_imports(tmp_path)
    assert ok is True
    assert "no published packages" in message


def test_public_safe_is_false_when_imports_dangle():
    """A dangling import blocks the public destination even with gitleaks green."""
    unsafe = PublicPreflight(
        included_paths=["src/pkg/cli.py"],
        gitleaks_ok=True,
        gitleaks_skipped=False,
        imports_ok=False,
        imports_checked=True,
    )
    assert unsafe.public_safe is False


def test_public_safe_unaffected_when_import_check_waived():
    """--skip-projection-check leaves the verdict to the other gates."""
    waived = PublicPreflight(
        included_paths=["src/pkg/cli.py"],
        gitleaks_ok=True,
        gitleaks_skipped=False,
        imports_ok=True,
        imports_checked=False,
    )
    assert waived.public_safe is True


def test_run_public_preflight_can_waive_the_import_check(tmp_path: Path, allowlist_file: Path):
    """``check_imports=False`` records the waiver instead of running the gate."""
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    (tmp_path / ".gitleaks.toml").write_text("# stub\n", encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
        gitleaks_config=Path(".gitleaks.toml"),
    )
    with (
        patch.object(push_mod, "_list_tracked_files", return_value=["README.md"]),
        patch.object(push_mod, "_run_local_gitleaks", return_value=(True, "no leaks detected")),
        patch.object(push_mod, "_check_projection_imports") as checker,
    ):
        preflight = _run_public_preflight(tmp_path, projection, cfg, check_imports=False)
    checker.assert_not_called()
    assert preflight.imports_checked is False
    assert preflight.imports_ok is True
    assert preflight.public_safe is True


# ---------------------------------------------------------------------------
# _projection_context
# ---------------------------------------------------------------------------


def test_projection_context_discard_mode_cleans_up_tempdir(tmp_path: Path):
    """``keep=False`` yields a tempdir that disappears after the with-block."""
    with _projection_context(tmp_path, keep=False) as proj:
        assert proj.exists()
        seen = proj
    assert not seen.exists()


def test_projection_context_keep_mode_materializes_under_build(tmp_path: Path):
    """``keep=True`` materializes the projection at <root>/build/public-projection/ and leaves it."""
    target = tmp_path / PROJECTION_KEEP_SUBDIR
    with _projection_context(tmp_path, keep=True) as proj:
        assert proj == target.resolve()
        assert proj.exists()
        (proj / "sample.txt").write_text("hi", encoding="utf-8")
    # Directory and contents persist past the context exit.
    assert target.exists()
    assert (target / "sample.txt").read_text(encoding="utf-8") == "hi"


def test_projection_context_keep_mode_wipes_existing_contents(tmp_path: Path):
    """A pre-existing keep-target is wiped at entry so stale files don't leak."""
    target = tmp_path / PROJECTION_KEEP_SUBDIR
    target.mkdir(parents=True)
    (target / "stale.txt").write_text("stale", encoding="utf-8")
    with _projection_context(tmp_path, keep=True) as proj:
        assert not (proj / "stale.txt").exists()


# ---------------------------------------------------------------------------
# _run_local_gitleaks
# ---------------------------------------------------------------------------


def test_run_local_gitleaks_skips_when_executable_missing(tmp_path: Path):
    """Without gitleaks on PATH, the gate is reported as failed (not raised)."""
    with patch("shutil.which", return_value=None):
        ok, msg = _run_local_gitleaks(tmp_path, tmp_path / ".gitleaks.toml")
    assert ok is False
    assert "not on PATH" in msg


def test_run_local_gitleaks_invocation_uses_no_git_and_explicit_source(tmp_path: Path):
    """The command shape is `gitleaks detect --no-git --source <scan_root> --config <cfg> --redact --no-banner`."""
    captured: dict[str, Any] = {}

    def fake_run(cmd, cwd, check=True):
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        return _make_completed(returncode=0, stdout="")

    scan_root = tmp_path / "projection"
    scan_root.mkdir()
    config_path = tmp_path / ".gitleaks.toml"
    with patch("shutil.which", return_value="/usr/bin/gitleaks"), patch.object(push_mod, "_run", side_effect=fake_run):
        ok, msg = _run_local_gitleaks(scan_root, config_path)
    assert ok is True
    assert msg == "no leaks detected"
    cmd = captured["cmd"]
    assert cmd[0] == "gitleaks"
    assert cmd[1] == "detect"
    assert "--no-git" in cmd
    # The --source argument is the absolute scan_root, never bare ".".
    src_idx = cmd.index("--source")
    assert cmd[src_idx + 1] == str(scan_root)
    cfg_idx = cmd.index("--config")
    assert cmd[cfg_idx + 1] == str(config_path)
    assert "--redact" in cmd
    assert "--no-banner" in cmd
    # cwd matches scan_root so the relative `.` interpretation doesn't matter.
    assert captured["cwd"] == scan_root


def test_run_local_gitleaks_reports_failure_message(tmp_path: Path):
    """Non-zero exit produces a failed verdict with the combined output."""
    with (
        patch("shutil.which", return_value="/usr/bin/gitleaks"),
        patch.object(
            push_mod,
            "_run",
            return_value=_make_completed(returncode=1, stdout="leak found", stderr=""),
        ),
    ):
        ok, msg = _run_local_gitleaks(tmp_path, tmp_path / ".gitleaks.toml")
    assert ok is False
    assert "leak found" in msg


# ---------------------------------------------------------------------------
# _run_public_preflight
# ---------------------------------------------------------------------------


def test_public_preflight_skips_when_build_fails(tmp_path: Path):
    """A build error short-circuits the preflight; gitleaks is reported as skipped."""
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(public_remote="public", allowlist_file=None)
    preflight = _run_public_preflight(tmp_path, projection, cfg)
    assert preflight.build_error is not None
    assert preflight.gitleaks_skipped is True
    assert preflight.public_safe is False


def test_public_preflight_public_safe_when_projection_clean(tmp_path: Path, allowlist_file: Path):
    """A non-empty projection that gitleaks accepts flips public_safe to True."""
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    (tmp_path / ".gitleaks.toml").write_text("# stub\n", encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
        gitleaks_config=Path(".gitleaks.toml"),
    )
    with (
        patch.object(push_mod, "_list_tracked_files", return_value=["README.md"]),
        patch.object(push_mod, "_run_local_gitleaks", return_value=(True, "no leaks detected")),
    ):
        preflight = _run_public_preflight(tmp_path, projection, cfg)
    assert preflight.build_error is None
    assert preflight.included_paths == ["README.md"]
    assert preflight.gitleaks_ok is True
    assert preflight.gitleaks_skipped is False
    assert preflight.public_safe is True


def test_public_preflight_marks_not_safe_when_gitleaks_finds_leaks(tmp_path: Path, allowlist_file: Path):
    """A gitleaks failure flips public_safe to False even with a clean projection."""
    (tmp_path / "README.md").write_text("internal: oops\n", encoding="utf-8")
    (tmp_path / ".gitleaks.toml").write_text("# stub\n", encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
        gitleaks_config=Path(".gitleaks.toml"),
    )
    with (
        patch.object(push_mod, "_list_tracked_files", return_value=["README.md"]),
        patch.object(push_mod, "_run_local_gitleaks", return_value=(False, "1 leak found")),
    ):
        preflight = _run_public_preflight(tmp_path, projection, cfg)
    assert preflight.gitleaks_ok is False
    assert preflight.gitleaks_skipped is False
    assert preflight.public_safe is False


def test_public_preflight_skips_gitleaks_when_config_missing(tmp_path: Path, allowlist_file: Path):
    """A missing gitleaks_config marks the gate as skipped (and not safe)."""
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    projection = tmp_path / "_projection"
    projection.mkdir()
    cfg = PushConfig(
        public_remote="public",
        allowlist_file=allowlist_file.relative_to(tmp_path),
        gitleaks_config=Path("nope.toml"),
    )
    with patch.object(push_mod, "_list_tracked_files", return_value=["README.md"]):
        preflight = _run_public_preflight(tmp_path, projection, cfg)
    assert preflight.gitleaks_skipped is True
    assert preflight.public_safe is False


# ---------------------------------------------------------------------------
# _resolve_destination
# ---------------------------------------------------------------------------


def _preflight(public_safe: bool) -> PublicPreflight:
    """Builds a minimal PublicPreflight whose ``public_safe`` matches *public_safe*."""
    if public_safe:
        return PublicPreflight(
            included_paths=["README.md"],
            gitleaks_ok=True,
            gitleaks_skipped=False,
            build_error=None,
        )
    return PublicPreflight(
        included_paths=[],
        gitleaks_ok=False,
        gitleaks_skipped=True,
        build_error=None,
    )


def test_resolve_destination_explicit_to_wins():
    """``--to`` always wins regardless of preflight verdict."""
    assert (
        _resolve_destination(to="public", no_prompt=False, yes=False, interactive=True, preflight=_preflight(False))
        == "public"
    )
    assert (
        _resolve_destination(to="none", no_prompt=False, yes=False, interactive=True, preflight=_preflight(True))
        == "none"
    )


def test_resolve_destination_no_prompt_defaults_to_private():
    """``--no-prompt`` without ``--to`` falls back to private only."""
    assert (
        _resolve_destination(to=None, no_prompt=True, yes=False, interactive=False, preflight=_preflight(True))
        == "private"
    )


def test_resolve_destination_yes_accepts_default():
    """``--yes`` accepts the preflight-derived default ('both' when public_safe)."""
    assert (
        _resolve_destination(to=None, no_prompt=False, yes=True, interactive=False, preflight=_preflight(True))
        == "both"
    )
    assert (
        _resolve_destination(to=None, no_prompt=False, yes=True, interactive=False, preflight=_preflight(False))
        == "private"
    )


def test_resolve_destination_non_interactive_uses_default():
    """No TTY and no flags => the preflight-derived default."""
    assert (
        _resolve_destination(to=None, no_prompt=False, yes=False, interactive=False, preflight=_preflight(True))
        == "both"
    )
    assert (
        _resolve_destination(to=None, no_prompt=False, yes=False, interactive=False, preflight=_preflight(False))
        == "private"
    )


def test_resolve_destination_prompts_when_interactive():
    """When interactive, _resolve_destination delegates to _prompt_destination."""
    with patch.object(push_mod, "_prompt_destination", return_value="both") as mock_prompt:
        result = _resolve_destination(to=None, no_prompt=False, yes=False, interactive=True, preflight=_preflight(True))
    assert result == "both"
    mock_prompt.assert_called_once()


# ---------------------------------------------------------------------------
# _resolve_public_message
# ---------------------------------------------------------------------------


def test_resolve_public_message_override_is_sanitized(tmp_path: Path):
    """An explicit override still passes through the substitution pipeline."""
    subs = ((re.compile(r"<REAL_A6A_FOLDER>"), "<acidbase>"),)
    msg = _resolve_public_message(tmp_path, "fix: tidy <REAL_A6A_FOLDER>", subs)
    assert msg == "fix: tidy <acidbase>"


def test_resolve_public_message_inherits_from_git_log(tmp_path: Path):
    """When no override is supplied, the most recent private commit message is inherited."""
    subs = ()
    with patch.object(push_mod, "_run", return_value=_make_completed(stdout="feat: ship something\n")):
        assert _resolve_public_message(tmp_path, None, subs) == "feat: ship something"


def test_resolve_public_message_falls_back_when_git_log_empty(tmp_path: Path):
    """If `git log` yields no output, the generic fallback message is used."""
    subs = ()
    with patch.object(push_mod, "_run", return_value=_make_completed(stdout="")):
        msg = _resolve_public_message(tmp_path, None, subs)
    assert "publish sanitized snapshot" in msg


# ---------------------------------------------------------------------------
# _publish_projection
# ---------------------------------------------------------------------------


def test_publish_projection_issues_the_documented_command_sequence(tmp_path: Path):
    """The orphan force-push performs init + config + add + commit + remote add + push, in order."""
    calls: list[list[str]] = []

    def fake_run(cmd, cwd, check=True):
        calls.append(list(cmd))
        return _make_completed()

    with patch.object(push_mod, "_run", side_effect=fake_run):
        ok, _msg = _publish_projection(
            tmp_path,
            "https://example.invalid/owner/repo.git",
            "main",
            "chore: publish",
        )
    assert ok is True
    assert calls[0] == ["git", "init", "-q", "-b", "main"]
    assert calls[1] == ["git", "config", "user.name", PUBLIC_AUTHOR_NAME]
    assert calls[2] == ["git", "config", "user.email", PUBLIC_AUTHOR_EMAIL]
    assert calls[3] == ["git", "add", "-A"]
    assert calls[4] == ["git", "commit", "-q", "--no-verify", "-m", "chore: publish"]
    assert calls[5] == ["git", "remote", "add", "public", "https://example.invalid/owner/repo.git"]
    assert calls[6] == ["git", "push", "--force", "public", "HEAD:main"]


def test_publish_projection_returns_failure_with_step_label(tmp_path: Path):
    """When any step fails, the returned message names the failing step."""

    def fake_run(cmd, cwd, check=True):
        if cmd[:2] == ["git", "push"]:
            raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="", stderr="rejected by remote")
        return _make_completed()

    with patch.object(push_mod, "_run", side_effect=fake_run):
        ok, msg = _publish_projection(tmp_path, "https://x.invalid/r.git", PUBLIC_BRANCH, "m")
    assert ok is False
    assert "push" in msg.lower()
    assert "rejected" in msg.lower()


# ---------------------------------------------------------------------------
# _perform_pushes
# ---------------------------------------------------------------------------


def test_perform_pushes_none_returns_zero_without_running_git(tmp_path: Path):
    """target='none' never invokes git push."""
    with patch.object(push_mod, "_run", side_effect=AssertionError("should not be called")):
        rc = _perform_pushes("none", tmp_path, PushConfig(public_remote="public"), topology="dual")
    assert rc == 0


def test_perform_pushes_single_mode_uses_bare_git_push(tmp_path: Path):
    """Single mode keeps today's bare `git push` regardless of target value."""
    calls: list[list[str]] = []

    def fake_run(cmd, cwd, check=True):
        calls.append(list(cmd))
        return _make_completed()

    with patch.object(push_mod, "_run", side_effect=fake_run):
        rc = _perform_pushes("private", tmp_path, PushConfig(), topology="single")
    assert rc == 0
    assert calls == [["git", "push"]]


def test_perform_pushes_dual_misconfigured_falls_back_to_single(tmp_path: Path):
    """dual_misconfigured topology uses bare `git push`, ignoring remote names."""
    calls: list[list[str]] = []

    def fake_run(cmd, cwd, check=True):
        calls.append(list(cmd))
        return _make_completed()

    with patch.object(push_mod, "_run", side_effect=fake_run):
        rc = _perform_pushes(
            "private",
            tmp_path,
            PushConfig(private_remote="origin", public_remote="public"),
            topology="dual_misconfigured",
        )
    assert rc == 0
    assert calls == [["git", "push"]]


def test_perform_pushes_private_only_invokes_git_push_origin(tmp_path: Path):
    """target='private' pushes only to the configured private remote."""
    calls: list[list[str]] = []

    def fake_run(cmd, cwd, check=True):
        calls.append(list(cmd))
        return _make_completed()

    cfg = PushConfig(private_remote="origin", public_remote="public")
    with patch.object(push_mod, "_run", side_effect=fake_run):
        rc = _perform_pushes("private", tmp_path, cfg, topology="dual")
    assert rc == 0
    assert calls == [["git", "push", "origin"]]


def test_perform_pushes_public_routes_through_publish_projection(tmp_path: Path):
    """target='public' delegates to _publish_projection with the sanitized projection."""
    projection = tmp_path / "_proj"
    projection.mkdir()
    cfg = PushConfig(private_remote="origin", public_remote="public")
    with (
        patch.object(push_mod, "_get_remote_url", return_value="https://x.invalid/r.git"),
        patch.object(
            push_mod,
            "_resolve_public_message",
            return_value="feat: sanitized",
        ),
        patch.object(push_mod, "_publish_projection", return_value=(True, "pushed")) as mock_pub,
        patch.object(push_mod, "_run", side_effect=AssertionError("should not be called")),
    ):
        rc = _perform_pushes(
            "public",
            tmp_path,
            cfg,
            topology="dual",
            projection_dir=projection,
        )
    assert rc == 0
    mock_pub.assert_called_once_with(projection, "https://x.invalid/r.git", PUBLIC_BRANCH, "feat: sanitized")


def test_perform_pushes_both_pushes_private_then_publishes_projection(tmp_path: Path):
    """target='both' pushes to the private remote, then publishes the projection."""
    projection = tmp_path / "_proj"
    projection.mkdir()
    cfg = PushConfig(private_remote="origin", public_remote="public")
    run_calls: list[list[str]] = []

    def fake_run(cmd, cwd, check=True):
        run_calls.append(list(cmd))
        return _make_completed()

    with (
        patch.object(push_mod, "_run", side_effect=fake_run),
        patch.object(push_mod, "_get_remote_url", return_value="https://x.invalid/r.git"),
        patch.object(push_mod, "_resolve_public_message", return_value="msg"),
        patch.object(push_mod, "_publish_projection", return_value=(True, "pushed")) as mock_pub,
    ):
        rc = _perform_pushes("both", tmp_path, cfg, topology="dual", projection_dir=projection)
    assert rc == 0
    # The private push lands first (only one _run call expected: the bare push).
    assert run_calls == [["git", "push", "origin"]]
    mock_pub.assert_called_once()


def test_perform_pushes_both_partial_failure_returns_two(tmp_path: Path):
    """target='both' with public publish failing returns 2 (private already landed)."""
    projection = tmp_path / "_proj"
    projection.mkdir()
    cfg = PushConfig(private_remote="origin", public_remote="public")

    def fake_run(cmd, cwd, check=True):
        return _make_completed()

    with (
        patch.object(push_mod, "_run", side_effect=fake_run),
        patch.object(push_mod, "_get_remote_url", return_value="https://x.invalid/r.git"),
        patch.object(push_mod, "_resolve_public_message", return_value="msg"),
        patch.object(push_mod, "_publish_projection", return_value=(False, "remote rejected")),
    ):
        rc = _perform_pushes("both", tmp_path, cfg, topology="dual", projection_dir=projection)
    assert rc == 2


def test_perform_pushes_private_failure_skips_public_and_returns_one(tmp_path: Path):
    """target='both' with private failing returns 1 and never attempts public publish."""
    projection = tmp_path / "_proj"
    projection.mkdir()
    cfg = PushConfig(private_remote="origin", public_remote="public")
    publish_calls: list[Any] = []

    def fake_run(cmd, cwd, check=True):
        if cmd[-1] == "origin":
            raise subprocess.CalledProcessError(returncode=1, cmd=cmd, output="", stderr="auth failed")
        return _make_completed()

    def fake_publish(*args, **kwargs):
        publish_calls.append((args, kwargs))
        return True, "pushed"

    with (
        patch.object(push_mod, "_run", side_effect=fake_run),
        patch.object(push_mod, "_publish_projection", side_effect=fake_publish),
    ):
        rc = _perform_pushes("both", tmp_path, cfg, topology="dual", projection_dir=projection)
    assert rc == 1
    assert publish_calls == []


def test_perform_pushes_public_only_failure_returns_one(tmp_path: Path):
    """target='public' with the publish failing returns 1."""
    projection = tmp_path / "_proj"
    projection.mkdir()
    cfg = PushConfig(private_remote="origin", public_remote="public")
    with (
        patch.object(push_mod, "_get_remote_url", return_value="https://x.invalid/r.git"),
        patch.object(push_mod, "_resolve_public_message", return_value="msg"),
        patch.object(push_mod, "_publish_projection", return_value=(False, "rejected")),
    ):
        rc = _perform_pushes("public", tmp_path, cfg, topology="dual", projection_dir=projection)
    assert rc == 1


def test_perform_pushes_public_without_projection_is_internal_error(tmp_path: Path):
    """target='public' without a projection_dir is an internal error (returns 1)."""
    cfg = PushConfig(private_remote="origin", public_remote="public")
    rc = _perform_pushes("public", tmp_path, cfg, topology="dual", projection_dir=None)
    assert rc == 1


# ---------------------------------------------------------------------------
# run_push: clean tree with committed-but-unpushed work (evidencia regression)
# ---------------------------------------------------------------------------


def _fake_run_for_clean_tree(ahead: str):
    """Returns (calls, fake _run) simulating a clean tree that is ``ahead`` commits ahead."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        if cmd[:3] == ["git", "status", "--porcelain"]:
            return _make_completed(0, "")
        if cmd[:3] == ["git", "rev-list", "--count"]:
            return _make_completed(0, ahead + "\n")
        return _make_completed(0, "")

    return calls, fake_run


def _single_mode_root(tmp_path: Path) -> Path:
    """Creates a minimal single-mode project root (no [tool.acidbase.push])."""
    _write_pyproject(tmp_path, '[project]\nname = "x"\nversion = "0"\n')
    return tmp_path


def test_run_push_pushes_committed_work_when_tree_clean_but_ahead(tmp_path: Path, capsys):
    """The evidencia regression: acidbase patch commits, then calls the wrapper.
    The wrapper used to see a clean tree, print 'Nothing to push', and exit 0
    without pushing — stranding security commits while the patch run logged
    'push OK'. A clean tree that is ahead of upstream must still push.
    """
    root = _single_mode_root(tmp_path)
    calls, fake_run = _fake_run_for_clean_tree(ahead="2")
    with patch.object(push_mod, "_run", side_effect=fake_run):
        push_mod.run_push(root=root)
    out = capsys.readouterr().out
    assert "2 commit(s) ahead of upstream" in out
    assert ["git", "push"] in calls
    assert "changes committed & pushed" in out


def test_run_push_skips_push_when_clean_and_synced(tmp_path: Path, capsys):
    """Clean tree AND in sync with upstream still short-circuits without pushing."""
    root = _single_mode_root(tmp_path)
    calls, fake_run = _fake_run_for_clean_tree(ahead="0")
    with patch.object(push_mod, "_run", side_effect=fake_run):
        push_mod.run_push(root=root)
    out = capsys.readouterr().out
    assert "Nothing to push" in out
    assert ["git", "push"] not in calls


def test_run_push_clean_but_ahead_respects_dry_run(tmp_path: Path, capsys):
    """--dry-run on the clean-but-ahead path reports the plan and pushes nothing."""
    root = _single_mode_root(tmp_path)
    calls, fake_run = _fake_run_for_clean_tree(ahead="1")
    with patch.object(push_mod, "_run", side_effect=fake_run):
        push_mod.run_push(root=root, dry_run=True)
    out = capsys.readouterr().out
    assert "1 commit(s) ahead of upstream" in out
    assert "dry run" in out
    assert ["git", "push"] not in calls


def test_count_unpushed_parses_ahead_count_and_tolerates_no_upstream(tmp_path: Path):
    """_count_unpushed returns the parsed count; missing upstream/garbage yield 0."""
    with patch.object(push_mod, "_run", return_value=_make_completed(0, "3\n")):
        assert push_mod._count_unpushed(tmp_path) == 3
    with patch.object(push_mod, "_run", return_value=_make_completed(128, "", "fatal: no upstream")):
        assert push_mod._count_unpushed(tmp_path) == 0
    with patch.object(push_mod, "_run", return_value=_make_completed(0, "not-a-number")):
        assert push_mod._count_unpushed(tmp_path) == 0


# ---------------------------------------------------------------------------
# Basic workflow helpers (adopted from ratemyhuman's consumer suite)
# ---------------------------------------------------------------------------


def test_hooks_modified_files_detects_hook_message():
    """Detects the pre-commit 'files were modified' marker."""
    assert _hooks_modified_files("Files were modified by this hook") is True


def test_hooks_modified_files_ignores_unrelated_output():
    """Leaves unrelated command output unflagged."""
    assert _hooks_modified_files("Committed successfully") is False


def test_hooks_modified_files_matches_case_insensitively():
    """Matches the marker regardless of casing."""
    assert _hooks_modified_files("FILES WERE MODIFIED BY THIS HOOK") is True


def test_auto_commit_message_is_storage_neutral():
    """Returns the generic fallback without inferring a storage policy."""
    assert _auto_commit_message() == "chore: update tracked files"


def test_get_project_root_walks_up_from_subdir(tmp_path: Path):
    """Locates the root holding pyproject.toml from a nested start directory."""
    (tmp_path / "pyproject.toml").touch()
    sub = tmp_path / "src"
    sub.mkdir()
    assert get_project_root(start=sub) == tmp_path


def test_get_project_root_defaults_to_cwd(tmp_path: Path, monkeypatch):
    """Starts the walk from the current working directory when start is omitted."""
    (tmp_path / "pyproject.toml").touch()
    monkeypatch.chdir(tmp_path)
    assert get_project_root() == tmp_path


def test_get_project_root_falls_back_without_pyproject(tmp_path: Path):
    """Falls back to the start directory when no pyproject.toml exists on the walk."""
    assert get_project_root(start=tmp_path) == tmp_path


def test_has_changes_false_on_clean_tree(tmp_path: Path):
    """Reports False when git status --porcelain prints nothing."""
    with patch.object(push_mod, "_run", return_value=_make_completed(0, "")):
        assert _has_changes(tmp_path) is False


def test_has_changes_true_on_dirty_tree(tmp_path: Path):
    """Reports True when git status --porcelain lists a change."""
    with patch.object(push_mod, "_run", return_value=_make_completed(0, " M file.py\n")):
        assert _has_changes(tmp_path) is True


# ---------------------------------------------------------------------------
# push_command flag validation (Click integration)
# ---------------------------------------------------------------------------


def test_render_preflight_lists_every_included_and_excluded_path(capsys):
    """The preflight prints all Included/Excluded paths — never a '+N more' fold.
    Operators must be able to audit the complete public/private split before
    choosing a destination, so neither list is truncated regardless of length.
    """
    included = [f"src/pkg/module_{i:02d}.py" for i in range(25)]
    excluded = [f"private/secret_{i:02d}.md" for i in range(15)]
    preflight = PublicPreflight(
        included_paths=included,
        excluded_paths=excluded,
        projection_dir=Path("/tmp/projection"),
        build_error=None,
        gitleaks_ok=True,
        gitleaks_message="no leaks detected",
        gitleaks_skipped=False,
    )
    _render_preflight(preflight, PushConfig(public_remote="public"))
    out = capsys.readouterr().out
    # Every single path is present verbatim ...
    for path in included:
        assert f"+ {path}" in out
    for path in excluded:
        assert f"- {path}" in out
    # ... and nothing was folded away.
    assert "more)" not in out
    # The counts still head each list.
    assert "Included:       25 file(s)" in out
    assert "Excluded:       15 file(s) (private-only)" in out


def test_push_command_rejects_to_with_yes():
    """`--to public --yes` exits non-zero with a clear error."""
    runner = CliRunner()
    result = runner.invoke(push_command, ["--to", "public", "--yes"])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output.lower()


def test_push_command_rejects_yes_with_no_prompt():
    """`--yes --no-prompt` exits non-zero with a clear error."""
    runner = CliRunner()
    result = runner.invoke(push_command, ["--yes", "--no-prompt"])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output.lower()


def test_push_command_to_with_no_prompt_warns_but_continues():
    """`--to public --no-prompt` is redundant but not fatal; emits a warning."""
    runner = CliRunner()
    with patch.object(push_mod, "run_push") as mock_run:
        result = runner.invoke(push_command, ["--to", "public", "--no-prompt", "--dry-run"])
    assert result.exit_code == 0
    assert "redundant" in result.output.lower()
    mock_run.assert_called_once()


def test_push_command_rejects_invalid_to_value():
    """`--to` is constrained to the documented values."""
    runner = CliRunner()
    result = runner.invoke(push_command, ["--to", "everywhere"])
    assert result.exit_code != 0
    assert "invalid value" in result.output.lower() or "not one of" in result.output.lower()


def test_push_command_threads_public_message_and_keep_projection_through():
    """The new flags reach run_push as keyword arguments."""
    runner = CliRunner()
    with patch.object(push_mod, "run_push") as mock_run:
        result = runner.invoke(
            push_command,
            ["--to", "public", "--public-message", "feat: sanitized", "--keep-projection"],
        )
    assert result.exit_code == 0
    mock_run.assert_called_once()
    kwargs = mock_run.call_args.kwargs
    assert kwargs["public_message"] == "feat: sanitized"
    assert kwargs["keep_projection"] is True
    assert kwargs["to"] == "public"
