"""
Canonical ``push`` workflow shared across the a6a ecosystem.
Exposes a reusable Click command (:data:`push_command`) that consumer repos
attach to their own CLI group via ``cli.add_command(push_command)``. The
command automates the git commit-and-push workflow with pre-commit hook
retry logic. The commit message is whatever
the caller passes (or an auto-generated fallback) — **no co-author line
is ever appended**; git's local user identity is the sole authorship
signal.
Typical use in a consumer repo::
    from acidbase.push import push_command
    @click.group()
    def cli() -> None: ...
    cli.add_command(push_command)
"""

from __future__ import annotations

import ast
import contextlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import click

# Markers the pre-commit framework emits when a hook modifies files.
_HOOK_MODIFIED_MARKERS: tuple[str, ...] = ("files were modified by this hook",)


def ensure_unicode_safe_streams() -> None:
    """Reconfigures stdout/stderr so the workflow's Unicode glyphs survive.
    Windows consoles and pipes default to legacy code pages (e.g. cp1250),
    which cannot encode the circled-digit/check-mark glyphs this module
    prints; reconfiguring to UTF-8 (with ``errors="replace"`` as a final
    guard) prevents ``UnicodeEncodeError`` crashes on redirected output.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        encoding = (getattr(stream, "encoding", "") or "").lower()
        if "utf" in encoding:
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


def get_project_root(start: Path | None = None) -> Path:
    """Locates the project root by walking up to find pyproject.toml.
    Falls back to *start* (or the current working directory) when no
    pyproject.toml is found.
    """
    current = (start or Path.cwd()).resolve()
    for parent in [current, *current.parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    return current


def get_project_name(root: Path | None = None) -> str:
    """Reads ``[project].name`` from pyproject.toml, falling back to directory name."""
    root = root or get_project_root()
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        name = data.get("project", {}).get("name")
        if isinstance(name, str) and name:
            return name
    return root.name


def _run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Runs a subprocess command, returning ``CompletedProcess``."""
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=check,
    )


def _has_changes(root: Path) -> bool:
    """Checks whether the working tree has any staged or unstaged changes."""
    result = _run(["git", "status", "--porcelain"], cwd=root, check=False)
    return bool(result.stdout.strip())


def _count_unpushed(root: Path) -> int:
    """Returns how many commits HEAD is ahead of its upstream (0 when none/unknown).
    A missing upstream (fresh branch, detached HEAD) yields 0 so callers fall
    back to the existing "nothing to push" behaviour rather than guessing a
    push target.
    """
    result = _run(["git", "rev-list", "--count", "@{upstream}..HEAD"], cwd=root, check=False)
    if result.returncode != 0:
        return 0
    try:
        return int(result.stdout.strip() or "0")
    except ValueError:
        return 0


def _hooks_modified_files(output: str) -> bool:
    """Checks whether pre-commit hooks modified files (retryable failure)."""
    lower = output.lower()
    return any(m in lower for m in _HOOK_MODIFIED_MARKERS)


def _auto_commit_message() -> str:
    """Returns the storage-neutral fallback commit message."""

    return "chore: update tracked files"


# ---------------------------------------------------------------------------
# Dual-publish (private + public mirror) helpers
# ---------------------------------------------------------------------------
# Valid values for the destination of a push.
VALID_DESTINATIONS: tuple[str, ...] = ("private", "public", "both", "none")
# Max number of *gitleaks output* lines shown inline when the scan fails.
# The Included/Excluded file lists are deliberately NOT capped — the operator
# must be able to audit every path that would land on the public mirror (and
# every path held back as private) before choosing a destination. Only raw
# gitleaks machine output, which can be arbitrarily long, is truncated.
_PREFLIGHT_GITLEAKS_PREVIEW = 10
# Identity used to author the public mirror's projection commit. Fixed per
# the signing rule ("Blai <balazs.torda@iu-study.org>"); the public mirror
# is a distinct legal/release artefact and must always carry the maintainer
# identity, regardless of whatever `git config user.*` says locally.
PUBLIC_AUTHOR_NAME = "Blai"
PUBLIC_AUTHOR_EMAIL = "balazs.torda@iu-study.org"
# Branch the public projection is force-pushed to.
PUBLIC_BRANCH = "main"
# Path under the project root where ``--keep-projection`` materializes the
# sanitized projection so the user can inspect it.
PROJECTION_KEEP_SUBDIR = Path("build") / "public-projection"
# Repo-relative paths copied into the public projection VERBATIM — i.e. no
# ``public_substitutions`` are applied to their content. These files
# encode the leak-detection grammar that the public CI runs; substituting
# inside them rewrites the rules' own regex alternations into the
# placeholder strings (e.g. ``<REAL_WSL_HOME>`` in a rule becomes
# ``<REAL_WSL_HOME>``), turning the rule into a self-match against the
# placeholder. Keep these files byte-identical to the source so the
# public-side gitleaks scan uses the intended rules.
SUBSTITUTION_EXEMPT_PATHS: frozenset[str] = frozenset(
    {
        ".gitleaks.toml",
        ".gitleaks-private.toml",
    }
)
# Fallback commit message when neither --public-message nor the inherited
# private commit message yields anything usable.
_PUBLIC_COMMIT_FALLBACK = "chore: publish sanitized snapshot"


@dataclass(frozen=True)
class PushConfig:
    """Configuration for dual-publish behaviour.
    Defaults preserve today's single-remote behaviour when no
    ``[tool.acidbase.push]`` section is present in ``pyproject.toml``.
    ``public_substitutions`` is an ordered tuple of (compiled-regex,
    replacement) pairs applied to every UTF-8 file copied into the public
    projection. Patterns are repo-tunable via the
    ``[[tool.acidbase.push.public_substitutions]]`` array of inline
    tables.
    """

    private_remote: str = "origin"
    public_remote: str | None = None
    allowlist_file: Path | None = None
    gitleaks_config: Path | None = None
    public_substitutions: tuple[tuple[re.Pattern[str], str], ...] = ()


@dataclass(frozen=True)
class PublicPreflight:
    """Result of running the public-side pre-flight on the sanitized projection.
    ``public_safe`` is the consolidated verdict the destination resolver
    consults when picking a default. It is True only when the projection
    built cleanly, contained at least one file, and the gitleaks scan
    over the sanitized output found no leaks.
    """

    included_paths: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    projection_dir: Path | None = None
    build_error: str | None = None
    gitleaks_ok: bool = False
    gitleaks_message: str = ""
    gitleaks_skipped: bool = False
    imports_ok: bool = True
    imports_message: str = "not checked"
    imports_checked: bool = False

    @property
    def public_safe(self) -> bool:
        """Returns True when the projection is valid, self-contained, AND gitleaks passed.

        ``imports_ok`` defaults to True so an unchecked projection (or one
        explicitly waived with ``--skip-projection-check``) does not block;
        only a check that actually ran and found a dangling import flips it.
        """
        return (
            self.build_error is None
            and len(self.included_paths) > 0
            and self.gitleaks_ok
            and not self.gitleaks_skipped
            and self.imports_ok
        )


def _load_push_config(root: Path) -> PushConfig:
    """Loads ``[tool.acidbase.push]`` from ``pyproject.toml``.
    Returns a default :class:`PushConfig` (single-mode) when:
      * ``pyproject.toml`` does not exist, or
      * the file has no ``[tool.acidbase.push]`` table.
    When the table *is* present the loader fills in opinionated defaults:
      * ``public_remote`` defaults to ``"public"``.
      * ``allowlist_file`` defaults to ``PUBLIC_ALLOWLIST.txt`` when that
        file exists at the project root.
      * ``gitleaks_config`` defaults to ``.gitleaks.toml`` when that file
        exists at the project root.
    """
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return PushConfig()
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)
    section = data.get("tool", {}).get("acidbase", {}).get("push")
    if section is None:
        return PushConfig()
    if not isinstance(section, dict):
        return PushConfig()
    private_remote = str(section.get("private_remote", "origin"))
    public_remote = section.get("public_remote", "public")
    if public_remote is not None:
        public_remote = str(public_remote)
    allowlist_raw = section.get("allowlist_file")
    if allowlist_raw is None and (root / "PUBLIC_ALLOWLIST.txt").exists():
        allowlist_raw = "PUBLIC_ALLOWLIST.txt"
    gitleaks_raw = section.get("gitleaks_config")
    if gitleaks_raw is None and (root / ".gitleaks.toml").exists():
        gitleaks_raw = ".gitleaks.toml"
    substitutions = _parse_substitutions(section.get("public_substitutions", []))
    return PushConfig(
        private_remote=private_remote,
        public_remote=public_remote,
        allowlist_file=Path(allowlist_raw) if allowlist_raw else None,
        gitleaks_config=Path(gitleaks_raw) if gitleaks_raw else None,
        public_substitutions=substitutions,
    )


def _parse_substitutions(raw: object) -> tuple[tuple[re.Pattern[str], str], ...]:
    """Parses the TOML ``public_substitutions`` array into compiled rules.
    Each entry is expected to be an inline table with ``pattern`` and
    ``replacement`` keys. Malformed entries (wrong type, missing keys,
    invalid regex) are silently dropped so a single bad rule cannot
    block the whole push pipeline; the projection then just keeps the
    original text for the affected pattern.
    """
    if not isinstance(raw, list):
        return ()
    compiled: list[tuple[re.Pattern[str], str]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        pattern_raw = entry.get("pattern")
        replacement = entry.get("replacement", "")
        if not isinstance(pattern_raw, str) or not isinstance(replacement, str):
            continue
        try:
            compiled.append((re.compile(pattern_raw), replacement))
        except re.error:
            continue
    return tuple(compiled)


def _apply_substitutions(text: str, substitutions: tuple[tuple[re.Pattern[str], str], ...]) -> str:
    """Applies every (pattern, replacement) rule to *text* in order."""
    out = text
    for pat, repl in substitutions:
        out = pat.sub(repl, out)
    return out


def _list_remotes(root: Path) -> set[str]:
    """Returns the set of git remote names configured in *root*."""
    result = _run(["git", "remote"], cwd=root, check=False)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _detect_topology(root: Path, config: PushConfig) -> str:
    """Classifies the repository as ``"single"``, ``"dual"``, or ``"dual_misconfigured"``.
    * ``single`` — no public remote was configured; today's bare
      ``git push`` behaviour applies.
    * ``dual`` — both private and public remotes are configured *and*
      exist on the local repository.
    * ``dual_misconfigured`` — dual mode was requested but at least one
      configured remote is missing locally. Callers warn and fall back
      to single-mode pushing rather than blocking the user.
    """
    if config.public_remote is None:
        return "single"
    remotes = _list_remotes(root)
    if config.private_remote in remotes and config.public_remote in remotes:
        return "dual"
    return "dual_misconfigured"


def _list_tracked_files(root: Path) -> list[str]:
    """Returns the set of tracked file paths via ``git ls-files``.
    Output is sorted and deduplicated. Untracked files and ignored
    files are excluded by design — only what's actually in the index
    is eligible for the public projection.
    """
    result = _run(["git", "ls-files"], cwd=root, check=False)
    return sorted({ln.strip() for ln in result.stdout.splitlines() if ln.strip()})


def _compile_allowlist(allowlist_path: Path) -> list[re.Pattern[str]]:
    """Compiles ``PUBLIC_ALLOWLIST.txt`` into anchored regexes.
    Mirrors the awk pipeline in ``.github/workflows/public-allowlist.yml``:
    only ``.`` is escaped (everything else in the allowlist today is a
    literal POSIX path segment), and each pattern is anchored with
    ``^entry(/|$)`` so the entry matches its exact path or anything
    underneath it (directory-style match).
    """
    patterns: list[re.Pattern[str]] = []
    for raw_line in allowlist_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        escaped = line.replace(".", "\\.")
        patterns.append(re.compile(f"^{escaped}(/|$)"))
    return patterns


def _path_is_allowlisted(path: str, patterns: list[re.Pattern[str]]) -> bool:
    """Returns True when *path* matches any compiled allowlist pattern."""
    return any(pat.match(path) for pat in patterns)


def _check_public_allowlist(paths: list[str], allowlist_path: Path) -> tuple[bool, list[str]]:
    """Returns ``(ok, violations)`` for *paths* against *allowlist_path*.
    Retained for callers that want the plain allowlist verdict (e.g. the
    legacy CI-equivalent gate). The dual-publish preflight no longer
    uses this directly because non-allowlisted paths get silently
    excluded from the sanitized projection instead.
    """
    patterns = _compile_allowlist(allowlist_path)
    violations = [p for p in paths if not _path_is_allowlisted(p, patterns)]
    return (not violations, violations)


def _build_public_projection(
    source_root: Path,
    projection_dir: Path,
    config: PushConfig,
) -> tuple[list[str], list[str], str | None]:
    """Materializes a sanitized copy of the allowlisted working tree.
    Returns ``(included_paths, excluded_paths, build_error)``:
    * ``included_paths`` — paths copied into the projection (and, for
      text files, run through ``config.public_substitutions``).
    * ``excluded_paths`` — tracked paths intentionally NOT in the
      public allowlist; these stay private-only.
    * ``build_error`` — ``None`` on success; a human-readable message
      when the projection could not be built (e.g. no allowlist).
    The projection is a flat filesystem tree, NOT a git repo. The
    caller adds a fresh ``.git/`` later in :func:`_publish_projection`.
    """
    if config.allowlist_file is None:
        return [], [], "no allowlist_file configured"
    allowlist_path = (source_root / config.allowlist_file).resolve()
    if not allowlist_path.exists():
        return [], [], f"allowlist file {config.allowlist_file} not found"
    patterns = _compile_allowlist(allowlist_path)
    if not patterns:
        return [], [], f"allowlist {config.allowlist_file} is empty"
    tracked = _list_tracked_files(source_root)
    included: list[str] = []
    excluded: list[str] = []
    for rel_path in tracked:
        if not _path_is_allowlisted(rel_path, patterns):
            excluded.append(rel_path)
            continue
        src = source_root / rel_path
        if not src.is_file():
            # Tracked but missing on disk (e.g. submodule, symlink to nowhere).
            continue
        dst = projection_dir / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        if rel_path in SUBSTITUTION_EXEMPT_PATHS:
            # Verbatim copy: do NOT run substitutions against files whose
            # content IS the leak-detection / leak-config grammar (see
            # the SUBSTITUTION_EXEMPT_PATHS docstring above).
            dst.write_bytes(src.read_bytes())
        else:
            try:
                text = src.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                # Binary file — copy bytes through unchanged.
                dst.write_bytes(src.read_bytes())
            else:
                sanitized = _apply_substitutions(text, config.public_substitutions)
                dst.write_text(sanitized, encoding="utf-8")
        included.append(rel_path)
    return included, excluded, None


@contextlib.contextmanager
def _projection_context(root: Path, *, keep: bool) -> Iterator[Path]:
    """Yields a directory the projection can be built into.
    * ``keep=False`` — a fresh ``tempfile.TemporaryDirectory`` cleaned up
      on exit (default).
    * ``keep=True`` — ``<root>/build/public-projection/`` wiped at entry
      and left in place at exit so the user can inspect the result.
    """
    if keep:
        target = (root / PROJECTION_KEEP_SUBDIR).resolve()
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
        yield target
        return
    with tempfile.TemporaryDirectory(prefix="acidbase-public-projection-") as tmp:
        yield Path(tmp)


def _run_local_gitleaks(scan_root: Path, config: Path) -> tuple[bool, str]:
    """Runs ``gitleaks detect --no-git --source <scan_root>``.
    ``--no-git`` is gitleaks' documented flag for “scan files as a flat
    directory, ignore git history.” Combined with an explicit
    ``--source <scan_root>`` it lets callers point the scan at either
    the live working tree (single mode) or the sanitized projection
    (dual mode) without ever walking the surrounding ``.git/`` of the
    source repo. Returns ``(ok, message)``. When the ``gitleaks``
    executable is not on ``PATH``, returns ``(False, ...)`` so callers
    treat the gate as failed rather than silently skipped.
    """
    if shutil.which("gitleaks") is None:
        return False, "gitleaks executable not on PATH"
    result = _run(
        [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            str(scan_root),
            "--config",
            str(config),
            "--redact",
            "--no-banner",
        ],
        cwd=scan_root,
        check=False,
    )
    if result.returncode == 0:
        return True, "no leaks detected"
    combined = (result.stdout or "") + (result.stderr or "")
    return False, combined.strip() or f"gitleaks exited with status {result.returncode}"


def _projection_module_index(projection_dir: Path) -> tuple[set[str], set[str]]:
    """Returns ``(module_names, package_roots)`` importable from the projection.

    Recognises both the ``src/<pkg>/`` and the flat ``<pkg>/`` layout: any
    directory holding an ``__init__.py`` directly under the projection root or
    under ``src/`` counts as a package root. ``module_names`` holds the dotted
    name of every published module and subpackage, e.g. ``acidbase.cli_utils``.
    """
    roots: set[str] = set()
    modules: set[str] = set()
    for base in (projection_dir, projection_dir / "src"):
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            if not entry.is_dir() or not (entry / "__init__.py").is_file():
                continue
            roots.add(entry.name)
            for path in entry.rglob("*.py"):
                rel = path.relative_to(base).with_suffix("")
                parts = list(rel.parts)
                if parts[-1] == "__init__":
                    parts.pop()
                if parts:
                    modules.add(".".join(parts))
    return modules, roots


def _iter_internal_imports(tree: ast.AST, module_dotted: str | None, roots: set[str]) -> Iterator[str]:
    """Yields dotted module names imported from a published package root.

    Only imports whose top-level name is one of *roots* are considered, so
    third-party and stdlib imports are ignored (they are not the projection's
    responsibility). Relative imports are resolved against *module_dotted*
    when the importing file itself lives inside a package.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in roots:
                    yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module and node.module.split(".")[0] in roots:
                    yield node.module
                continue
            if module_dotted is None:
                continue
            # Relative import: drop `level - 1` trailing components of the
            # importing module's own package, then append the target.
            package_parts = module_dotted.split(".")[:-1]
            if node.level > 1:
                package_parts = package_parts[: -(node.level - 1)] if node.level - 1 <= len(package_parts) else []
            if not package_parts:
                continue
            if node.module:
                target = ".".join([*package_parts, node.module])
                if target.split(".")[0] in roots:
                    yield target
                continue
            # ``from . import name`` — with no module part, each name must
            # itself be a submodule, so it is checkable (unlike
            # ``from .mod import name``, where the name may be an attribute).
            for alias in node.names:
                target = ".".join([*package_parts, alias.name])
                if target.split(".")[0] in roots:
                    yield target


def _check_projection_imports(projection_dir: Path) -> tuple[bool, str]:
    """Verifies every intra-package import in the projection resolves within it.

    This is the gate that a byte-compile pass cannot provide: compiling
    ``cli.py`` succeeds even when the module it imports was never published,
    because the failure only surfaces at import time. Resolving the imports
    statically catches exactly the case where the allowlist admits a module
    but omits one it depends on — which shipped a broken public package once
    already (``acidbase.cli`` importing an unpublished ``acidbase.cli_utils``).

    Static resolution is deliberate: it needs no virtualenv, installs nothing,
    and runs no published code. Returns ``(ok, message)``.
    """
    modules, roots = _projection_module_index(projection_dir)
    if not roots:
        return True, "no published packages to check"
    problems: list[str] = []
    for path in sorted(projection_dir.rglob("*.py")):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            problems.append(f"{path.relative_to(projection_dir).as_posix()}: syntax error ({exc.msg})")
            continue
        # Dotted name of this file, when it lives inside a published package.
        module_dotted: str | None = None
        for base in (projection_dir, projection_dir / "src"):
            try:
                rel = path.relative_to(base).with_suffix("")
            except ValueError:
                continue
            parts = list(rel.parts)
            if parts and parts[0] in roots:
                if parts[-1] == "__init__":
                    parts.pop()
                module_dotted = ".".join(parts)
                break
        for target in _iter_internal_imports(tree, module_dotted, roots):
            # ``from pkg.mod import name`` is satisfied by ``pkg.mod`` alone;
            # the imported name may be an attribute rather than a submodule,
            # which cannot be resolved statically and is not this gate's
            # concern. Note there is deliberately NO "parent package exists"
            # fallback: `pkg` being published says nothing about whether
            # `pkg.cli_utils` is, and accepting the prefix would silently
            # neuter the whole check.
            if target in modules:
                continue
            rel_name = path.relative_to(projection_dir).as_posix()
            problems.append(f"{rel_name}: imports {target}, which the projection does not publish")
    if problems:
        return False, "\n".join(sorted(set(problems)))
    return True, f"all intra-package imports resolve ({len(modules)} module(s))"


def _run_public_preflight(
    source_root: Path,
    projection_dir: Path,
    config: PushConfig,
    *,
    check_imports: bool = True,
) -> PublicPreflight:
    """Builds the sanitized projection and runs gitleaks against it.
    The projection is materialized into *projection_dir* (the caller
    owns its lifecycle via :func:`_projection_context`). The strict
    ``config.gitleaks_config`` ruleset then runs over the sanitized
    output via :func:`_run_local_gitleaks` with ``--no-git``, so the
    scan reflects exactly what would land on the public mirror.
    Returns a :class:`PublicPreflight` carrying:
      * included/excluded path lists from the projection build,
      * the projection directory (for the user to inspect),
      * a ``build_error`` when the projection could not be built,
      * the gitleaks verdict on the sanitized projection.
    """
    included, excluded, build_error = _build_public_projection(source_root, projection_dir, config)
    if build_error is not None:
        return PublicPreflight(
            included_paths=included,
            excluded_paths=excluded,
            projection_dir=projection_dir,
            build_error=build_error,
            gitleaks_ok=False,
            gitleaks_message="(skipped because projection could not be built)",
            gitleaks_skipped=True,
        )
    if config.gitleaks_config is None:
        return PublicPreflight(
            included_paths=included,
            excluded_paths=excluded,
            projection_dir=projection_dir,
            build_error=None,
            gitleaks_ok=False,
            gitleaks_message="no gitleaks_config configured",
            gitleaks_skipped=True,
        )
    # Prefer the projected gitleaks config when it landed in the
    # projection, so the local scan exercises exactly the same ruleset
    # the public CI will. Fall back to the source config when the
    # projection skipped the file (e.g. not on the allowlist).
    projection_gitleaks_path = (projection_dir / config.gitleaks_config).resolve()
    if projection_gitleaks_path.is_file():
        gitleaks_path = projection_gitleaks_path
    else:
        gitleaks_path = (source_root / config.gitleaks_config).resolve()
    if not gitleaks_path.exists():
        return PublicPreflight(
            included_paths=included,
            excluded_paths=excluded,
            projection_dir=projection_dir,
            build_error=None,
            gitleaks_ok=False,
            gitleaks_message=f"gitleaks config {config.gitleaks_config} not found",
            gitleaks_skipped=True,
        )
    ok, msg = _run_local_gitleaks(projection_dir, gitleaks_path)
    if check_imports:
        imports_ok, imports_message = _check_projection_imports(projection_dir)
    else:
        imports_ok, imports_message = True, "skipped by --skip-projection-check"
    return PublicPreflight(
        included_paths=included,
        excluded_paths=excluded,
        projection_dir=projection_dir,
        build_error=None,
        gitleaks_ok=ok,
        gitleaks_message=msg,
        gitleaks_skipped=False,
        imports_ok=imports_ok,
        imports_message=imports_message,
        imports_checked=check_imports,
    )


def _render_preflight(preflight: PublicPreflight, config: PushConfig) -> None:
    """Pretty-prints the preflight summary used in the destination Q&A.
    The Included and Excluded file lists are printed in full — never folded
    into a ``+N more`` summary. The whole purpose of the preflight is to let
    the operator audit exactly which paths would land on the public mirror and
    which stay private before picking a destination, so truncating either list
    would defeat the review. Only raw gitleaks failure output (potentially
    very long machine output) is capped, at :data:`_PREFLIGHT_GITLEAKS_PREVIEW`.
    """
    click.echo(f"   Public remote:  {config.public_remote}")
    if preflight.projection_dir is not None:
        click.echo(f"   Projection:     {preflight.projection_dir}")
    if preflight.build_error is not None:
        click.echo(click.style(f"   Build:          \u2717 {preflight.build_error}", fg="red"))
    n_inc = len(preflight.included_paths)
    n_exc = len(preflight.excluded_paths)
    click.echo(f"   Included:       {n_inc} file(s)")
    for p in preflight.included_paths:
        click.echo(f"     + {p}")
    click.echo(f"   Excluded:       {n_exc} file(s) (private-only)")
    for p in preflight.excluded_paths:
        click.echo(f"     - {p}")
    # Gitleaks line
    if preflight.gitleaks_skipped:
        click.echo(click.style(f"   Gitleaks:       \u26a0 {preflight.gitleaks_message}", fg="yellow"))
    elif preflight.gitleaks_ok:
        click.echo(click.style(f"   Gitleaks:       \u2713 {preflight.gitleaks_message}", fg="green"))
    else:
        click.echo(click.style("   Gitleaks:       \u2717 leaks or errors detected:", fg="red"))
        lines = preflight.gitleaks_message.splitlines()
        for line in lines[:_PREFLIGHT_GITLEAKS_PREVIEW]:
            click.echo(click.style(f"     {line}", fg="red"))
        extra = len(lines) - _PREFLIGHT_GITLEAKS_PREVIEW
        if extra > 0:
            click.echo(click.style(f"     ... (+{extra} more line(s); see the projection dir above)", fg="red"))
    # Import-resolution line: every dangling import is printed in full, since
    # each one names a file the allowlist should probably admit.
    if not preflight.imports_checked:
        click.echo(click.style(f"   Imports:        \u26a0 {preflight.imports_message}", fg="yellow"))
    elif preflight.imports_ok:
        click.echo(click.style(f"   Imports:        \u2713 {preflight.imports_message}", fg="green"))
    else:
        click.echo(click.style("   Imports:        \u2717 projection references unpublished modules:", fg="red"))
        for line in preflight.imports_message.splitlines():
            click.echo(click.style(f"     {line}", fg="red"))
        click.echo(
            click.style(
                "     \u2192 add the missing path(s) to the allowlist, or re-run with "
                "--skip-projection-check to override.",
                fg="yellow",
            )
        )


def _is_interactive() -> bool:
    """Returns True when stdin AND stdout are TTYs (user can answer prompts)."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _prompt_destination(*, default: str, preflight: PublicPreflight) -> str:
    """Asks the user which destination to push to, returning the chosen value.
    When the public side is not safe (allowlist or gitleaks gate failed
    or was skipped), the prompt only exposes ``private`` and ``none``;
    selecting a public destination requires re-running with ``--to``.
    """
    if preflight.public_safe:
        options: list[tuple[str, str]] = [
            ("1", "private"),
            ("2", "both"),
            ("3", "public"),
            ("4", "none"),
        ]
    else:
        options = [("1", "private"), ("2", "none")]
    options_str = " / ".join(f"{k}={v}" for k, v in options)
    default_key = next((k for k, v in options if v == default), options[0][0])
    while True:
        choice = click.prompt(
            f"Push destination [{options_str}]",
            default=default_key,
            show_default=True,
        )
        for k, v in options:
            if choice in (k, v):
                return v
        click.echo(click.style("   Invalid choice. Try again.", fg="yellow"))


def _resolve_destination(
    *,
    to: str | None,
    no_prompt: bool,
    yes: bool,
    interactive: bool,
    preflight: PublicPreflight,
) -> str:
    """Resolves the push destination from flags + preflight + interactivity.
    Precedence:
      1. ``--to`` always wins (validated by Click).
      2. ``--no-prompt`` falls back to ``private`` unless ``--yes`` was
         passed, in which case the preflight-derived default is used.
      3. ``--yes`` accepts the preflight-derived default without
         prompting.
      4. Otherwise, when interactive, the user is prompted; when
         non-interactive (no TTY), the default is used.
    The preflight default is ``both`` when the public side is safe,
    ``private`` otherwise.
    """
    if to is not None:
        return to
    default = "both" if preflight.public_safe else "private"
    if no_prompt and not yes:
        return "private"
    if yes or not interactive:
        return default
    return _prompt_destination(default=default, preflight=preflight)


def _resolve_public_message(
    source_root: Path,
    override: str | None,
    substitutions: tuple[tuple[re.Pattern[str], str], ...],
) -> str:
    """Resolves the commit message used on the public projection.
    Precedence:
      1. ``--public-message`` override (sanitized just like file content).
      2. The most recent private commit message at ``HEAD``, sanitized
         through ``substitutions``.
      3. A generic fallback.
    The substitutions filter the inherited message defensively so any
    internal markers a private commit message happened to carry never
    surface on the public side.
    """
    if override is not None:
        return _apply_substitutions(override, substitutions)
    result = _run(["git", "log", "-1", "--format=%B"], cwd=source_root, check=False)
    raw = (result.stdout or "").strip()
    if not raw:
        return _PUBLIC_COMMIT_FALLBACK
    return _apply_substitutions(raw, substitutions)


def _get_remote_url(source_root: Path, remote: str) -> str | None:
    """Returns the URL of *remote* in the source repo, or ``None``."""
    result = _run(["git", "remote", "get-url", remote], cwd=source_root, check=False)
    if result.returncode != 0:
        return None
    url = (result.stdout or "").strip()
    return url or None


def _publish_projection(
    projection_dir: Path,
    public_url: str,
    branch: str,
    message: str,
    *,
    author_name: str = PUBLIC_AUTHOR_NAME,
    author_email: str = PUBLIC_AUTHOR_EMAIL,
) -> tuple[bool, str]:
    """Materializes the projection as a single-commit orphan and force-pushes.
    Initializes a fresh ``.git/`` inside *projection_dir*, configures the
    fixed public author identity, stages everything, makes one commit
    with *message*, adds the public remote, and force-pushes to
    ``HEAD:<branch>``. Returns ``(ok, message)``; on failure *message*
    contains the failing command's stderr so the caller can surface it.
    The projection's directory layout (single root commit, single
    branch, no remotes prior to this point) means the force-push lands
    exactly the sanitized snapshot — no private history can leak.
    """
    steps: list[tuple[str, list[str]]] = [
        ("init", ["git", "init", "-q", "-b", branch]),
        ("config user.name", ["git", "config", "user.name", author_name]),
        ("config user.email", ["git", "config", "user.email", author_email]),
        ("add", ["git", "add", "-A"]),
        ("commit", ["git", "commit", "-q", "--no-verify", "-m", message]),
        ("remote add", ["git", "remote", "add", "public", public_url]),
        ("push", ["git", "push", "--force", "public", f"HEAD:{branch}"]),
    ]
    for label, cmd in steps:
        try:
            _run(cmd, cwd=projection_dir)
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or exc.stdout or "").strip()
            return False, f"git {label} failed: {err}" if err else f"git {label} failed"
    return True, "pushed"


def _perform_pushes(
    target: str,
    root: Path,
    config: PushConfig,
    topology: str,
    projection_dir: Path | None = None,
    public_message: str | None = None,
) -> int:
    """Executes the git pushes for the given destination.
    Return code semantics (mapped to ``SystemExit`` by the caller):
      * ``0`` — full success (or ``target == 'none'``).
      * ``1`` — push failed and there is no successful sibling push.
      * ``2`` — partial success: ``both`` was requested, private landed
        but public failed. The caller reports a backfill hint and keeps
        the overall process status zero so automation does not retry the
        already-landed private push.
    The public push runs the sanitized projection at *projection_dir*
    (see :func:`_build_public_projection`) through
    :func:`_publish_projection` rather than a raw ``git push <remote>``.
    """
    if target == "none":
        click.echo(click.style("\n\u2463 No push requested \u2014 commit retained locally.", fg="yellow"))
        return 0
    if topology != "dual":
        # Single-mode or dual_misconfigured: preserve today's bare `git push`.
        click.echo(click.style("\n\u2463 Pushing to GitHub ...", bold=True))
        try:
            _run(["git", "push"], cwd=root)
            click.echo("   \u2713 Pushed to GitHub")
            return 0
        except subprocess.CalledProcessError as exc:
            click.echo(click.style(f"   \u2717 git push failed: {exc.stderr.strip()}", fg="red"), err=True)
            return 1
    private_ok = True
    if target in ("private", "both"):
        click.echo(click.style(f"\n\u2463 Pushing to private remote ({config.private_remote}) ...", bold=True))
        try:
            _run(["git", "push", config.private_remote], cwd=root)
            click.echo(f"   \u2713 Pushed to {config.private_remote}")
        except subprocess.CalledProcessError as exc:
            click.echo(
                click.style(
                    f"   \u2717 git push {config.private_remote} failed: {exc.stderr.strip()}",
                    fg="red",
                ),
                err=True,
            )
            private_ok = False
            if target == "private":
                return 1
    if target in ("public", "both"):
        if target == "both" and not private_ok:
            click.echo(
                click.style(
                    "\n\u26a0 Skipping public push because the private push failed.",
                    fg="yellow",
                )
            )
            return 1
        public_remote = config.public_remote or "public"
        click.echo(click.style(f"\n\u2464 Publishing sanitized projection to {public_remote} ...", bold=True))
        if projection_dir is None:
            click.echo(
                click.style(
                    "   \u2717 internal error: no projection directory was provided.",
                    fg="red",
                ),
                err=True,
            )
            return 1 if target == "public" else 2
        public_url = _get_remote_url(root, public_remote)
        if public_url is None:
            click.echo(
                click.style(
                    f"   \u2717 could not resolve URL of remote {public_remote}.",
                    fg="red",
                ),
                err=True,
            )
            return 1 if target == "public" else 2
        commit_msg = _resolve_public_message(root, public_message, config.public_substitutions)
        ok, msg = _publish_projection(projection_dir, public_url, PUBLIC_BRANCH, commit_msg)
        if ok:
            click.echo(f"   \u2713 Pushed sanitized projection to {public_remote}")
        else:
            click.echo(click.style(f"   \u2717 {msg}", fg="red"), err=True)
            if target == "public":
                return 1
            click.echo(
                click.style(
                    "\n\u26a0 Private push succeeded but public push failed. To backfill, run:\n"
                    "    uv run acidbase push --to public --no-prompt\n"
                    "  once the issue is resolved.",
                    fg="yellow",
                )
            )
            return 2
    return 0


def run_push(
    message: str | None = None,
    dry_run: bool = False,
    root: Path | None = None,
    *,
    to: str | None = None,
    no_prompt: bool = False,
    yes: bool = False,
    public_message: str | None = None,
    keep_projection: bool = False,
    skip_projection_check: bool = False,
) -> None:
    """Stages, commits, and pushes everything for the current project.
    The workflow:
    1. Stage everything with ``git add .``.
    2. Commit using *message* (or an auto-generated fallback) with up to
       three retries when pre-commit hooks modify files.
    3. Amend if a post-commit hook leaves the tree dirty.
    4. In dual mode, build the sanitized public projection, run the
       gitleaks pre-flight gate against it, and ask for the
       destination(s).
    5. Push to the chosen destination(s); the public destination always
       lands as a single-commit orphan force-pushed from the projection.
    The private commit message is whatever *message* says (or the
    auto-generated fallback). The public commit message defaults to the
    sanitized inherited private message; *public_message* overrides it.
    """
    ensure_unicode_safe_streams()
    root = (root or get_project_root()).resolve()
    name = get_project_name(root)
    push_config = _load_push_config(root)
    topology = _detect_topology(root, push_config)
    click.echo(click.style(f"\n=== {name} push ===", fg="cyan", bold=True))
    click.echo(f"Root:     {root}")
    if topology == "dual":
        click.echo(f"Remotes:  private={push_config.private_remote}, public={push_config.public_remote} (dual mode)")
    elif topology == "dual_misconfigured":
        click.echo(
            click.style(
                f"Remotes:  dual mode requested (private={push_config.private_remote}, "
                f"public={push_config.public_remote}) but at least one remote is missing locally "
                "\u2014 falling back to single-mode push.",
                fg="yellow",
            )
        )
    else:
        click.echo("Remotes:  single-mode (no [tool.acidbase.push] section)")
    click.echo("")
    # Summarising all git changes
    status_result = _run(["git", "status", "--porcelain"], cwd=root, check=False)
    status_lines = [ln for ln in status_result.stdout.strip().splitlines() if ln.strip()]
    unpushed = _count_unpushed(root)
    if not status_lines and not unpushed:
        click.echo(click.style("\n\u2713 Nothing to push \u2014 working tree clean, upstream up to date.", fg="green"))
        return
    if not status_lines:
        # Working tree clean but commits never left the machine. The
        # `acidbase patch` flow commits BEFORE invoking this command as the
        # profile's push_command, so "clean tree" must not short-circuit the
        # push of already-committed work — that stranded security commits on
        # repos whose wrapper reported "Nothing to push" with rc=0 while the
        # patch run logged "push OK".
        click.echo(
            click.style(
                f"\n\u2460 Working tree clean, but {unpushed} commit(s) ahead of upstream "
                "\u2014 pushing committed work.",
                bold=True,
            )
        )
        if dry_run:
            click.echo(click.style("\n\u2500\u2500 dry run \u2500\u2500 no changes made", fg="yellow"))
            return
    else:
        click.echo(click.style(f"\n\u2460 {len(status_lines)} git change(s) detected:", bold=True))
        for ln in status_lines:
            click.echo(f"   {ln}")
        if dry_run:
            click.echo(click.style("\n\u2500\u2500 dry run \u2500\u2500 no changes made", fg="yellow"))
            return
        # Staging all changes
        click.echo(click.style("\n\u2461 Staging all changes ...", bold=True))
        _run(["git", "add", "."], cwd=root)
        staged = _run(["git", "diff", "--cached", "--name-only"], cwd=root, check=False)
        committed = False
        if not staged.stdout.strip():
            click.echo(click.style("   \u26a0 Nothing staged after git add \u2014 skipping commit.", fg="yellow"))
        else:
            staged_count = len(staged.stdout.strip().splitlines())
            click.echo(f"   {staged_count} file(s) staged")
            commit_msg = message or _auto_commit_message()
            click.echo(click.style("\n\u2462 Committing ...", bold=True))
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                try:
                    _run(["git", "commit", "-m", commit_msg], cwd=root)
                    label = f" (attempt {attempt})" if attempt > 1 else ""
                    click.echo(f"   \u2713 Committed{label}")
                    committed = True
                    break
                except subprocess.CalledProcessError as exc:
                    combined = exc.stdout + exc.stderr
                    if _hooks_modified_files(combined) and attempt < max_attempts:
                        click.echo(
                            f"   \u27f3 Pre-commit hooks modified files (attempt {attempt}) \u2014 re-staging ..."
                        )
                        _run(["git", "add", "."], cwd=root)
                        continue
                    click.echo(
                        click.style(f"   \u2717 Commit failed (attempt {attempt}): {exc.stderr.strip()}", fg="red"),
                        err=True,
                    )
                    raise SystemExit(1) from exc
            if committed and _has_changes(root):
                click.echo("   \u27f3 Post-commit hook left changes \u2014 amending ...")
                _run(["git", "add", "."], cwd=root)
                _run(["git", "commit", "--amend", "--no-edit", "--no-verify"], cwd=root, check=False)
                click.echo("   \u2713 Amended")
    # Destination resolution + pushes
    if topology == "dual":
        # Build the sanitized public projection ONCE, run the preflight
        # against it, and re-use the same projection for the public push
        # so the snapshot the user inspected is exactly what lands on the
        # mirror. The context manager owns the directory's lifecycle:
        # ``--keep-projection`` materializes it under build/, otherwise
        # it's a self-cleaning tempdir.
        with _projection_context(root, keep=keep_projection) as projection_dir:
            click.echo(click.style("\n\u2463 Public preflight (dual mode):", bold=True))
            preflight = _run_public_preflight(
                root,
                projection_dir,
                push_config,
                check_imports=not skip_projection_check,
            )
            _render_preflight(preflight, push_config)
            destination = _resolve_destination(
                to=to,
                no_prompt=no_prompt,
                yes=yes,
                interactive=_is_interactive(),
                preflight=preflight,
            )
            click.echo(click.style(f"   \u2192 Destination: {destination}", bold=True))
            push_status = _perform_pushes(
                destination,
                root,
                push_config,
                topology,
                projection_dir=projection_dir,
                public_message=public_message,
            )
    else:
        # Single mode (or dual_misconfigured fallback): honour --to when it
        # is explicitly 'none', otherwise fall through to the bare git push.
        destination = to if to is not None else "private"
        push_status = _perform_pushes(destination, root, push_config, topology)
    if push_status == 1:
        raise SystemExit(1)
    if push_status == 2:
        # Partial success: private landed, public failed. Exit 0 so
        # automation does not retry the already-landed private push.
        click.echo(
            click.style(
                "\n\u2713 Private commit pushed; public push pending (see hint above).",
                fg="yellow",
                bold=True,
            )
        )
        return
    click.echo(click.style("\n\u2713 All done \u2014 changes committed & pushed.", fg="green", bold=True))


@click.command("push")
@click.option("--message", "-m", default=None, help="Custom commit message")
@click.option("--dry-run", is_flag=True, help="Preview without making changes")
@click.option(
    "--to",
    "to",
    type=click.Choice(list(VALID_DESTINATIONS), case_sensitive=False),
    default=None,
    help="Push destination in dual mode. Skips the interactive prompt.",
)
@click.option(
    "--yes",
    "-y",
    "yes_",
    is_flag=True,
    help="Accept the preflight-derived default destination without prompting.",
)
@click.option(
    "--no-prompt",
    is_flag=True,
    help="Never prompt; defaults to --to private unless --to or --yes is supplied.",
)
@click.option(
    "--public-message",
    default=None,
    help=("Commit message for the public projection. Defaults to the inherited (sanitized) private commit message."),
)
@click.option(
    "--keep-projection",
    is_flag=True,
    help="Materialize the public projection at build/public-projection/ for inspection.",
)
@click.option(
    "--skip-projection-check",
    is_flag=True,
    help=(
        "Skip verifying that every intra-package import in the public projection "
        "resolves within it. The check exists because the allowlist can admit a "
        "module while omitting one it imports, publishing a package that fails at "
        "import; only override when you know the dangling import is intentional."
    ),
)
@click.pass_context
def push_command(
    ctx: click.Context,
    message: str | None,
    dry_run: bool,
    to: str | None,
    yes_: bool,
    no_prompt: bool,
    public_message: str | None,
    keep_projection: bool,
    skip_projection_check: bool,
) -> None:
    """Stages, commits, and pushes everything (hook-aware and dual-publish-aware)."""
    if to is not None and yes_:
        ctx.fail("--to and --yes are mutually exclusive (--to already selects the destination).")
    if to is not None and no_prompt:
        # Allowed: --to alone already skips the prompt. Treat this combo as
        # a no-op since --to wins, but emit a hint so the user knows.
        click.echo(
            click.style("   \u26a0 --no-prompt is redundant with --to; ignoring.", fg="yellow"),
            err=True,
        )
    if yes_ and no_prompt:
        ctx.fail("--yes and --no-prompt are mutually exclusive.")
    run_push(
        message=message,
        dry_run=dry_run,
        to=to,
        no_prompt=no_prompt,
        yes=yes_,
        public_message=public_message,
        keep_projection=keep_projection,
        skip_projection_check=skip_projection_check,
    )
