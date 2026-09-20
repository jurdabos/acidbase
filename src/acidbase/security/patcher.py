"""
Per-repository security patch operations.

Implements the cross-platform patch workflow in pure Python and dispatches by
package ecosystem. The string ``"pip"`` here is GitHub's SBOM / Dependabot
label for the PyPI ecosystem; the implementation actually drives ``uv``,
which is the only Python package manager acidbase supports. The internal
helpers are therefore named after the tools they invoke (``_apply_uv_bump``,
``_preflight_uv``) while the public ``ecosystem`` parameter keeps GitHub's
vocabulary so it lines up 1:1 with SBOM rows and ``DependabotAlert.ecosystem``.

Supported flows:

* ``ecosystem="pip"`` (default): clean working tree check, default-branch
  detection, ``git pull --rebase``, ``uv add --no-sync <dep>>=<new>``,
  header-guarded regeneration of tracked ``requirements*.txt`` uv-export
  artifacts (root file included; curated files are reported, never
  overwritten), NOOP detection, and a single security-themed commit with one
  hook-aware retry. The target repo's virtual environment is never synced,
  created, or replaced — only ``pyproject.toml`` / ``uv.lock`` / exports move.
* ``ecosystem="npm"``: same git scaffold, then ``npm install <dep>@^<new>``
  with an automatic fallback to a ``package.json`` ``overrides`` entry so
  transitive pins actually move. NOOP detection reads ``package-lock.json``
  directly.

The publish step is intentionally **not** performed here; the caller's
:class:`acidbase.security.publisher.PublishStrategy` runs after the commit.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from packaging.version import InvalidVersion, Version

from acidbase.security import shell
from acidbase.security.profiles import Profile

# Lockfiles for npm-adjacent package managers we do NOT yet patch automatically.
# Each entry maps the lockfile filename to the manager name shown in messages.
_UNSUPPORTED_NPM_LOCKFILES: tuple[tuple[str, str], ...] = (
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("bun.lockb", "bun"),
)


class PatchStatus(str, Enum):
    """Final status of a single repository's patch attempt."""

    DONE = "DONE"
    NOOP = "NOOP"
    DIRTY = "DIRTY"
    GITERROR = "GITERROR"  # git itself refused/failed (e.g. dubious ownership)
    NOTUV = "NOTUV"
    NOTNPM = "NOTNPM"
    UNSUPPORTED_LOCKFILE = "UNSUPPORTED_LOCKFILE"
    MISSING = "MISSING"
    SELFSKIP = "SELFSKIP"  # acidbase cannot mutate its own venv on Windows mid-run
    PULLFAIL = "PULLFAIL"
    UVADDFAIL = "UVADDFAIL"
    NPMADDFAIL = "NPMADDFAIL"
    EXPORTFAIL = "EXPORTFAIL"
    COMMITFAIL = "COMMITFAIL"
    PUSHFAIL = "PUSHFAIL"
    WOULD_RUN = "WOULD-RUN"


@dataclass
class PatchResult:
    """Outcome of one repository's patch attempt; renderable in the run report."""

    repo: str
    path: Path
    status: PatchStatus
    note: str = ""
    branch: Optional[str] = None
    alert: Optional[str] = None
    log: list[str] = field(default_factory=list)


def detect_default_branch(cwd: Path) -> str:
    """
    Returns the default branch name for the repo at ``cwd``.

    Reads ``origin/HEAD`` first; falls back to ``main`` so freshly-cloned repos
    without a tracked HEAD still produce a sensible push target.
    """
    res = shell.run(
        ["git", "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
        cwd=cwd,
    )
    if res.ok and res.stdout.strip():
        return res.stdout.strip().removeprefix("origin/")
    return "main"


def _check_clean(cwd: Path) -> tuple[bool, Optional[str]]:
    """
    Returns ``(is_clean, error_message)`` describing the working-tree state at ``cwd``.

    Three distinguishable outcomes:

    * ``(True, None)``  - git ran successfully and reports no modifications.
    * ``(False, None)`` - git ran successfully and reports modifications.
    * ``(False, msg)``  - git failed to run (non-zero exit). ``msg`` is the
      truncated stderr so the caller can surface the real failure cause
      (e.g. ``fatal: detected dubious ownership in repository at '...'``)
      instead of misreporting it as ``DIRTY``.

    Untracked files are intentionally ignored (``--untracked-files=no``). They
    do not interfere with ``git pull --rebase`` / ``uv add`` / the explicit
    ``git add pyproject.toml uv.lock requirements.txt`` step, and treating
    them as "dirty" would force the user to stash unrelated WIP notes,
    scratch files, etc. just to apply a security bump.
    """
    res = shell.run(
        ["git", "--no-pager", "status", "--porcelain", "--untracked-files=no"],
        cwd=cwd,
    )
    if not res.ok:
        err = res.stderr.strip() or f"git status exited with rc={res.returncode}"
        return False, err[:200]
    return (not res.stdout.strip()), None


def _is_clean(cwd: Path) -> bool:
    """
    Returns True only when git ran AND found no modifications to tracked files.

    Backwards-compat wrapper around :func:`_check_clean`. Callers that need to
    distinguish ``git refused/errored`` from ``tracked files modified`` should
    use :func:`_check_clean` directly.
    """
    clean, _err = _check_clean(cwd)
    return clean


def _own_project_root() -> Optional[Path]:
    """
    Returns the path to acidbase's own project root, or None if undetectable.

    Walks up from this file looking for the first ancestor that contains both
    ``pyproject.toml`` AND ``src/acidbase`` — the unambiguous signature of the
    project root that owns the running interpreter (typical in an editable
    install used during development). Returns None when acidbase is installed
    as a regular wheel or when the layout is otherwise unrecognisable; callers
    treat that as "not a self-patch".
    """
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        if (ancestor / "pyproject.toml").is_file() and (ancestor / "src" / "acidbase").is_dir():
            return ancestor
    return None


def _is_self_patching(target_path: Path) -> bool:
    """
    Returns True when ``target_path`` is the very project source acidbase is running from.

    Comparing resolved paths so symlinks and case differences (Windows) do not
    mask a match. False when acidbase is installed as a regular package (no
    own project root discoverable) — in that case self-patching is impossible
    by construction because the user is not inside the acidbase source tree.
    """
    own = _own_project_root()
    if own is None:
        return False
    try:
        return own.resolve() == target_path.resolve()
    except OSError:
        return False


def _self_skip_command(path: Path, dep_name: str, new_version: str, cve_id: str) -> str:
    """Returns the copy-pasteable command sequence the user should run manually."""
    spec = f"{dep_name}>={new_version}"
    commit_msg = f"security: update {dep_name} to {new_version} to fix {cve_id}"
    # Suggesting the export only for verifiable uv-export artifacts so the
    # manual command never tells the user to clobber a curated requirements file.
    export_root = _parse_uv_export_header(path / "requirements.txt", "requirements.txt") is not None
    parts: list[str] = [
        f"cd {path}",
        f'uv add "{spec}"',
    ]
    if export_root:
        parts.append("uv export --frozen --output-file=requirements.txt")
        parts.append("git add pyproject.toml uv.lock requirements.txt")
    else:
        parts.append("git add pyproject.toml uv.lock")
    parts.append(f'git commit -m "{commit_msg}"')
    parts.append("git push")
    return " && ".join(parts)


def _discover_npm_dir(repo_path: Path) -> Optional[str]:
    """
    Returns the relative path (POSIX-style) to the unique npm project directory, or None.

    Scans the repo for ``package-lock.json`` files, skipping ``node_modules``
    and any dot-directory. Returns the relative directory only when exactly
    one location is found; multiple matches or none yield ``None`` so the
    caller can demand an explicit ``npm_dir`` override in the profile.
    """
    if (repo_path / "package-lock.json").is_file():
        return "."
    candidates: list[Path] = []
    try:
        for lock in repo_path.rglob("package-lock.json"):
            parts = lock.relative_to(repo_path).parts
            if any(part == "node_modules" or part.startswith(".") for part in parts):
                continue
            candidates.append(lock.parent)
    except OSError:
        return None
    if len(candidates) != 1:
        return None
    rel = candidates[0].relative_to(repo_path)
    return rel.as_posix() or "."


def _detect_unsupported_lockfile(npm_dir: Path) -> Optional[str]:
    """Returns a human-readable note when an unsupported package manager is in use, else None."""
    for filename, manager in _UNSUPPORTED_NPM_LOCKFILES:
        if (npm_dir / filename).is_file():
            return f"found {manager} lockfile ({filename}); only npm (package-lock.json) is supported"
    return None


def _read_npm_lock_version(lockfile: Path, dep_name: str) -> Optional[str]:
    """
    Returns the resolved version of ``dep_name`` from ``package-lock.json``, or None.

    Handles npm lockfile v1 (top-level ``dependencies``), v2, and v3
    (top-level ``packages`` map keyed by ``node_modules/<pkg>`` paths,
    including scoped names like ``node_modules/@scope/pkg``). The first
    matching entry wins; for transitive duplicates this is the top-level
    resolved version, which is exactly what we compare against the patched
    threshold.
    """
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    target = dep_name.casefold()
    # v2 / v3 packages map: keys are POSIX paths like "node_modules/yaml".
    packages = data.get("packages") or {}
    for key, value in packages.items():
        if not isinstance(value, dict) or not key:
            continue
        name_part = key.rsplit("node_modules/", 1)[-1]
        if name_part.casefold() == target:
            version = value.get("version")
            if version:
                return str(version)
    # v1 dependencies map: keys are package names directly.
    dependencies = data.get("dependencies") or {}
    for key, value in dependencies.items():
        if key.casefold() != target:
            continue
        if isinstance(value, dict):
            version = value.get("version")
            if version:
                return str(version)
    return None


def _version_meets(found: str, required: str) -> bool:
    """Returns True when ``found`` parses as a version and is >= ``required``."""
    try:
        return Version(found) >= Version(required)
    except InvalidVersion:
        return False


def _ensure_npm_override(package_json: Path, dep_name: str, new_version: str) -> bool:
    """
    Adds or updates ``overrides[dep_name] = "^<new_version>"`` in ``package.json``.

    Returns True when the file was written, False when the file already pinned
    the dep to ``new_version`` or higher (idempotent) or when the existing
    ``overrides`` shape is non-standard. The function preserves a trailing
    newline if the source had one so diffs stay minimal.
    """
    try:
        raw = package_json.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    overrides = data.setdefault("overrides", {})
    if not isinstance(overrides, dict):
        return False
    spec = f"^{new_version}"
    existing = overrides.get(dep_name)
    if isinstance(existing, str) and existing.lstrip("^~>=< ") == new_version:
        return False
    overrides[dep_name] = spec
    trailing_newline = "\n" if raw.endswith("\n") else ""
    package_json.write_text(json.dumps(data, indent=2) + trailing_newline, encoding="utf-8")
    return True


def patch_repo(
    profile: Profile,
    *,
    dep_name: str,
    new_version: str,
    cve_id: str,
    dry_run: bool = False,
    commit_branch: Optional[str] = None,
    ecosystem: str = "pip",
    sync_env: bool = False,
    on_log: Optional[Callable[[str], None]] = None,
) -> PatchResult:
    """
    Applies the dependency bump to a single repository and returns a :class:`PatchResult`.

    The function never raises on per-repo failures; it captures every fault as a
    status code so the surrounding loop can continue across the rest of the
    affected repos. The publish step is intentionally **not** performed here;
    the caller's :class:`PublishStrategy` runs after the commit.

    When ``commit_branch`` is provided, a fresh branch with that name is created
    from the up-to-date default branch and the bump is committed there (used by
    the PR strategy). When omitted, the commit lands on the default branch (used
    by the push strategy). When ``on_log`` is provided, each subprocess step is
    reported through the callback so the CLI can render a verbose trace.

    ``ecosystem`` selects the per-package-manager backend:

    * ``"pip"`` (default) — GitHub's label for the PyPI ecosystem. The
      implementation runs ``uv add`` / ``uv export``; acidbase does not call
      ``pip`` directly.
    * ``"npm"`` runs ``npm install`` and falls back to a ``package.json``
      ``overrides`` entry when the lockfile does not move on the first
      attempt (typical for transitive npm dependencies).

    ``sync_env`` (pip only) opts into a guarded ``uv sync --frozen`` after a
    ``DONE`` bump so the repo's local environment picks up the fix
    immediately; see :func:`_sync_environment` for the platform safety
    matrix. npm repos ignore the flag (``npm install`` already updates
    ``node_modules``).
    """

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    repo = profile.repo
    path = profile.path
    result = PatchResult(repo=repo, path=path, status=PatchStatus.WOULD_RUN)

    _log(f"patch_repo: repo={repo} path={path} dep={dep_name} new={new_version} ecosystem={ecosystem}")

    if not path.exists():
        result.status = PatchStatus.MISSING
        result.note = "no local clone"
        _log("  MISSING: path does not exist")
        return result

    clean, git_error = _check_clean(path)
    if git_error is not None:
        result.status = PatchStatus.GITERROR
        result.note = f"git status failed: {git_error}"
        _log(f"  GITERROR: {git_error}")
        return result
    if not clean:
        result.status = PatchStatus.DIRTY
        result.note = "uncommitted changes"
        _log("  DIRTY: tracked files have uncommitted changes")
        return result

    eco = ecosystem.casefold()
    if eco == "pip":
        guard = _preflight_uv(path, dep_name=dep_name, new_version=new_version, cve_id=cve_id, on_log=on_log)
    elif eco == "npm":
        guard = _preflight_npm(profile, on_log=on_log)
    else:
        result.status = PatchStatus.NOTUV
        result.note = f"unsupported ecosystem: {ecosystem}"
        _log(f"  unsupported ecosystem {ecosystem!r}")
        return result
    if guard is not None:
        guard.repo = repo
        guard.path = path
        return guard

    base_branch = profile.branch or detect_default_branch(path)
    target_branch = commit_branch or base_branch
    result.branch = target_branch
    _log(f"  base_branch={base_branch} target_branch={target_branch}")

    if dry_run:
        result.status = PatchStatus.WOULD_RUN
        result.note = f"branch={target_branch}"
        _log("  dry_run: stopping before any side effects")
        return result

    # to align with origin and absorb any Dependabot autobump that already merged
    _log(f"  git switch {base_branch}")
    switch = shell.run(["git", "switch", base_branch], cwd=path)
    result.log.append(switch.stdout + switch.stderr)
    _log(f"  git pull --rebase origin {base_branch}")
    pull = shell.run(["git", "pull", "--rebase", "origin", base_branch], cwd=path)
    result.log.append(pull.stdout + pull.stderr)
    if not pull.ok:
        result.status = PatchStatus.PULLFAIL
        _log(f"  PULLFAIL rc={pull.returncode}: {pull.stderr.strip()[:200]!r}")
        return result

    if commit_branch and commit_branch != base_branch:
        # to start the security commit on a clean feature branch off the just-pulled base
        _log(f"  git switch -C {commit_branch}")
        new_branch = shell.run(["git", "switch", "-C", commit_branch], cwd=path)
        result.log.append(new_branch.stdout + new_branch.stderr)
        if not new_branch.ok:
            result.status = PatchStatus.PULLFAIL
            result.note = f"could not create branch {commit_branch}"
            _log(f"  could not create branch {commit_branch}")
            return result

    if eco == "pip":
        return _apply_uv_bump(
            result,
            path=path,
            dep_name=dep_name,
            new_version=new_version,
            cve_id=cve_id,
            sync_env=sync_env,
            on_log=on_log,
        )
    return _apply_npm_bump(
        result,
        profile=profile,
        dep_name=dep_name,
        new_version=new_version,
        cve_id=cve_id,
        on_log=on_log,
    )


def _preflight_uv(
    path: Path,
    *,
    dep_name: str,
    new_version: str,
    cve_id: str,
    on_log: Optional[Callable[[str], None]] = None,
) -> Optional[PatchResult]:
    """Returns an early-exit :class:`PatchResult` for uv-specific guards, or None."""

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    if not (path / "uv.lock").is_file():
        result = PatchResult(repo="", path=path, status=PatchStatus.NOTUV, note="no uv.lock")
        _log("  NOTUV: no uv.lock present")
        return result
    # On Windows, acidbase cannot safely replace its own currently-loaded
    # site-packages files (rich → pygments, python-dotenv, click, ...) while
    # the python.exe running this very patcher holds open handles on them.
    # A syncing `uv add` would fail with `error: failed to remove file '...'`
    # (rc=2). The bump itself now runs `uv add --no-sync` (never touching any
    # venv), but the self-patch stays deferred: the suggested manual command
    # gives acidbase's own environment a real add + sync right after exit, so
    # the tool never keeps running against a lock its env no longer matches.
    # On POSIX, the unlink-while-open semantics make this safe, so we let the
    # normal flow proceed. See CHANGELOG "Self-patch deadlock on Windows".
    if sys.platform == "win32" and _is_self_patching(path):
        cmd = _self_skip_command(path, dep_name, new_version, cve_id)
        result = PatchResult(
            repo="",
            path=path,
            status=PatchStatus.SELFSKIP,
            note=f"acidbase cannot patch its own loaded deps on Windows; run after exit: {cmd}",
        )
        _log(f"  SELFSKIP: deferred self-patch on Windows; suggested: {cmd}")
        return result
    return None


def _preflight_npm(
    profile: Profile,
    *,
    on_log: Optional[Callable[[str], None]] = None,
) -> Optional[PatchResult]:
    """Returns an early-exit :class:`PatchResult` for npm-specific guards, or None."""

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    npm_dir_rel = profile.npm_dir or _discover_npm_dir(profile.path)
    if npm_dir_rel is None:
        result = PatchResult(
            repo="",
            path=profile.path,
            status=PatchStatus.NOTNPM,
            note=(
                "no unique package-lock.json found; set profiles.<Repo>.npm_dir to the relative directory containing it"
            ),
        )
        _log("  NOTNPM: could not auto-discover npm_dir")
        return result
    npm_dir = profile.path if npm_dir_rel == "." else profile.path / npm_dir_rel
    unsupported = _detect_unsupported_lockfile(npm_dir)
    if unsupported is not None:
        result = PatchResult(
            repo="",
            path=profile.path,
            status=PatchStatus.UNSUPPORTED_LOCKFILE,
            note=unsupported,
        )
        _log(f"  UNSUPPORTED_LOCKFILE: {unsupported}")
        return result
    if not (npm_dir / "package-lock.json").is_file():
        result = PatchResult(
            repo="",
            path=profile.path,
            status=PatchStatus.NOTNPM,
            note=f"no package-lock.json at {npm_dir_rel}",
        )
        _log(f"  NOTNPM: no package-lock.json under {npm_dir_rel}")
        return result
    return None


# Pinned-requirement line, e.g. ``authlib==1.6.5`` (env markers / hashes ignored).
_REQ_PIN_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s;#\\]+)", re.MULTILINE)
# Header stamped by ``uv export`` at the top of a generated requirements file.
_UV_AUTOGEN_RE = re.compile(r"autogenerated by uv", re.IGNORECASE)


def _read_uv_lock_dep_version(lock_path: Path, dep_name: str) -> Optional[str]:
    """Returns the resolved version of ``dep_name`` in a ``uv.lock``, or None."""
    try:
        data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    target = dep_name.casefold()
    for pkg in data.get("package") or []:
        if str(pkg.get("name") or "").casefold() == target:
            version = pkg.get("version")
            return str(version) if version else None
    return None


def _git_tracked_files(path: Path) -> list[str]:
    """Returns the repo-relative paths git tracks under ``path`` (empty on failure)."""
    res = shell.run(["git", "ls-files"], cwd=path)
    if not res.ok:
        return []
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def _looks_like_requirements(name: str) -> bool:
    """Returns True for ``requirements*.txt`` basenames (requirements.txt, requirements-dev.txt, ...)."""
    return name.startswith("requirements") and name.endswith(".txt")


def _find_requirement_pin(text: str, dep_name: str) -> Optional[str]:
    """Returns the ``==`` pinned version of ``dep_name`` in a requirements body, or None."""
    target = dep_name.casefold()
    for match in _REQ_PIN_RE.finditer(text):
        if match.group(1).casefold() == target:
            return match.group(2).strip()
    return None


def _uv_export_output_target(argv: list[str]) -> Optional[str]:
    """Returns the ``-o`` / ``--output-file`` target from a uv-export argv, or None."""
    for i, tok in enumerate(argv):
        if tok in ("-o", "--output-file"):
            if i + 1 < len(argv):
                return argv[i + 1]
        elif tok.startswith("--output-file="):
            return tok.split("=", 1)[1]
        elif tok.startswith("-o="):
            return tok.split("=", 1)[1]
    return None


def _parse_uv_export_header(file_path: Path, rel_path: str) -> Optional[list[str]]:
    """
    Returns the regenerate argv for ``file_path`` iff it is a uv-export artifact.

    A uv-exported requirements file stamps the exact command that produced it,
    e.g.::

        # This file was autogenerated by uv via the following command:
        #    uv export --no-hashes --no-dev -o producer/requirements.txt

    This returns that command split into argv, but only when it is verifiably
    ``uv export ...`` whose output target equals ``rel_path`` — a safety guard
    so we never execute an arbitrary command embedded in a file. Returns None
    for hand-maintained files (no header) or any command that fails the guard.
    """
    try:
        with file_path.open("r", encoding="utf-8") as fh:
            head = [fh.readline() for _ in range(5)]
    except (OSError, UnicodeDecodeError):
        return None
    if not any(_UV_AUTOGEN_RE.search(line) for line in head):
        return None
    command_line = None
    for line in head:
        stripped = line.lstrip("#").strip()
        if stripped.startswith("uv export"):
            command_line = stripped
            break
    if command_line is None:
        return None
    try:
        argv = shlex.split(command_line)
    except ValueError:
        return None
    if len(argv) < 2 or argv[0] != "uv" or argv[1] != "export":
        return None
    target = _uv_export_output_target(argv)
    if target is None or Path(target).as_posix() != Path(rel_path).as_posix():
        return None
    return argv


def _venv_flavor(venv_dir: Path) -> str:
    """
    Returns the platform flavor of the venv at ``venv_dir``.

    One of ``"absent"`` (no directory), ``"windows"`` (``Scripts/`` layout),
    ``"posix"`` (``bin/`` layout), or ``"unknown"`` (neither or both markers,
    e.g. a half-deleted venv). Directory markers are used instead of
    interpreter files on purpose: a Linux venv's ``bin/python`` is a symlink
    that may not resolve when inspected from Windows across the 9P share,
    while the ``bin`` directory itself always lists.
    """
    try:
        if not venv_dir.is_dir():
            return "absent"
        has_scripts = (venv_dir / "Scripts").is_dir()
        has_bin = (venv_dir / "bin").is_dir()
    except OSError:
        return "unknown"
    if has_scripts and not has_bin:
        return "windows"
    if has_bin and not has_scripts:
        return "posix"
    return "unknown"


def _sync_executor_flavor(path: Path) -> str:
    """
    Returns the venv flavor (``"windows"``/``"posix"``) a sync at ``path`` would build.

    ``shell.run`` transparently reroutes WSL UNC paths through the distro
    (see :func:`acidbase.security.shell.wsl_routing`), so a sync there is
    performed by the distro-native POSIX uv regardless of the host platform.
    Everywhere else the host platform's uv runs.
    """
    if shell.wsl_routing(path) is not None:
        return "posix"
    return "windows" if sys.platform == "win32" else "posix"


def _sync_environment(
    result: PatchResult,
    *,
    path: Path,
    on_log: Optional[Callable[[str], None]] = None,
) -> PatchResult:
    """
    Best-effort ``uv sync --frozen`` after a DONE bump; mutates and returns ``result``.

    Never changes ``result.status``: the security commit has already landed,
    so an environment problem is a workstation concern, not a patch failure.
    Outcomes are appended to the note (``synced env`` / ``env sync
    skipped: ...`` / ``env sync failed: ...``). Guards:

    * ``--frozen`` installs exactly the just-committed lock and never
      rewrites it, so the tree stays clean after the security commit.
    * The sync runs only when the existing ``.venv`` is native to the uv
      that would perform it (or absent, in which case a fresh native env is
      created). A foreign-platform or unrecognisable venv — a Linux ``.venv``
      reached from Windows without WSL routing, a Windows ``.venv`` under
      ``/mnt/c`` reached from WSL, or a half-deleted remnant — is left
      untouched and reported for a native-side ``uv sync``, preserving the
      never-rebuild-a-foreign-venv guarantee of the ``--no-sync`` bump.
    """

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    executor = _sync_executor_flavor(path)
    flavor = _venv_flavor(path / ".venv")
    if flavor == "unknown":
        result.note = f"{result.note}; env sync skipped: unrecognisable .venv layout (run `uv sync` natively)"
        _log("  env sync skipped: unrecognisable .venv layout")
        return result
    if flavor not in ("absent", executor):
        result.note = f"{result.note}; env sync skipped: {flavor} venv vs {executor} uv (run `uv sync` natively)"
        _log(f"  env sync skipped: {flavor} venv would be rebuilt by {executor} uv")
        return result
    _log("  uv sync --frozen")
    sync = shell.run(["uv", "sync", "--frozen"], cwd=path)
    result.log.append(sync.stdout + sync.stderr)
    if sync.ok:
        result.note = f"{result.note}; synced env"
        _log("  synced env")
    else:
        result.note = f"{result.note}; env sync failed: {_output_tail(sync.stdout, sync.stderr, limit=150)}"
        _log(f"  env sync failed rc={sync.returncode}")
    return result


def _apply_uv_bump(
    result: PatchResult,
    *,
    path: Path,
    dep_name: str,
    new_version: str,
    cve_id: str,
    sync_env: bool = False,
    on_log: Optional[Callable[[str], None]] = None,
) -> PatchResult:
    """
    Bumps the root uv project (when needed), regenerates every tracked
    ``uv export`` requirements artifact that still pins the dep too low
    (root file included), then commits; mutates and returns ``result``.

    The bump runs ``uv add --no-sync`` so the target repo's virtual
    environment is never synced, created, or replaced: the flow only needs
    ``pyproject.toml`` and ``uv.lock`` to move, and a cross-platform uv
    (Windows uv reaching a WSL checkout whose UNC spelling escapes
    ``shell.wsl_routing``, or WSL-side acidbase against an ``/mnt/c`` repo)
    would otherwise treat the foreign-platform ``.venv`` as invalid and
    rebuild it — observed gutting CanonFodder's Linux venv over the
    ``//wsl.localhost/`` share (``lib/`` deleted, then a fatal error on the
    dangling ``lib64`` symlink). Developers resync with ``uv sync`` when
    they next work in the repo — or opt into an eager, platform-guarded
    sync per run via ``sync_env`` (see :func:`_sync_environment`).

    After a successful ``uv add`` the lock is re-read to confirm the resolved
    version actually reached the target: ``[tool.uv]`` override/constraint
    entries replace the project's own requirement during resolution, so the
    command can exit 0 while the locked version stays below the target. Such
    a neutralised bump is reported as ``UVADDFAIL`` (with the uv add edits
    reverted) instead of being committed as a specifier-only change.
    """

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    # 1) Bump the root project — unless its lock already satisfies the target.
    #    Repos whose root is already patched but whose *secondary* exported
    #    requirements file is stale (e.g. producer/requirements.txt) would
    #    otherwise trip a spurious `uv add` failure; skipping keeps them moving
    #    so the secondary export below can still be refreshed.
    lock_version = _read_uv_lock_dep_version(path / "uv.lock", dep_name)
    root_satisfied = lock_version is not None and _version_meets(lock_version, new_version)
    if root_satisfied:
        _log(f"  root uv.lock already pins {dep_name}=={lock_version} (>= {new_version}); skipping uv add")
    else:
        spec = f"{dep_name}>={new_version}"
        # --no-sync: only pyproject.toml + uv.lock need to move; syncing the
        # target repo's venv is pure risk (a cross-platform uv rebuilds a
        # foreign-platform .venv — the CanonFodder gutting) and pure waste
        # (multi-GB GPU wheel sets reinstalled for a one-line bump).
        _log(f"  uv add --no-sync {spec}")
        add = shell.run(["uv", "add", "--no-sync", spec], cwd=path)
        result.log.append(add.stdout + add.stderr)
        if not add.ok:
            result.status = PatchStatus.UVADDFAIL
            # Tail, not head: uv prints warnings first and the resolver's
            # `No solution found ... Because ...` chain last.
            result.note = f"uv add failed: {_output_tail(add.stdout, add.stderr)}"
            _log(f"  UVADDFAIL rc={add.returncode}: {result.note!r}")
            return result
        # [tool.uv] override-dependencies / constraint-dependencies REPLACE the
        # project's own requirement during resolution, so `uv add "<dep>>=<new>"`
        # can exit 0 having only rewritten the declared specifier while the
        # locked version stays below the target (ratemyhuman: an override
        # "pillow>=12.2.0" held the lock at 12.2.0 through a >=12.3.0 bump).
        # Committing that specifier-only change would ship a security commit
        # that fixes nothing and make clean re-runs report a false NOOP.
        post_lock = _read_uv_lock_dep_version(path / "uv.lock", dep_name)
        if post_lock is not None and not _version_meets(post_lock, new_version):
            # to leave the repo clean and re-runnable after the config is fixed
            revert = shell.run(["git", "checkout", "--", "pyproject.toml", "uv.lock"], cwd=path)
            result.log.append(revert.stdout + revert.stderr)
            result.status = PatchStatus.UVADDFAIL
            result.note = (
                f"uv add ran but uv.lock still pins {dep_name}=={post_lock} (< {new_version}); "
                "check [tool.uv] override-dependencies / constraint-dependencies; reverted uv add edits"
            )
            _log(f"  UVADDFAIL: {result.note}")
            return result

    # 2) Refresh every tracked ``requirements*.txt`` that still carries a
    #    too-low pin of the target dep — the ROOT file included. uv-export
    #    artifacts (identified by their autogenerated header) are regenerated
    #    by re-running their own recorded command; anything else (hand-written
    #    or owned by repo-local tooling, e.g. a sync-requirements pre-commit
    #    hook) is reported, never overwritten. The root file used to get an
    #    unconditional ``uv export``, which clobbered curated files that merely
    #    share the conventional name (url-rag's Astro-filtered requirements.txt).
    regenerated: list[str] = []
    manual: list[str] = []
    for rel in _git_tracked_files(path):
        if not _looks_like_requirements(Path(rel).name):
            continue
        full = path / rel
        if not full.is_file():
            continue
        try:
            text = full.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        pinned = _find_requirement_pin(text, dep_name)
        if pinned is None or _version_meets(pinned, new_version):
            continue  # dep absent or already satisfied in this file -> nothing to do
        argv = _parse_uv_export_header(full, rel)
        if argv is None:
            manual.append(rel)
            _log(f"  {rel}: pins {dep_name}=={pinned} but is not a uv-export file; needs manual edit")
            continue
        _log(f"  regenerating {rel}: {' '.join(argv)}")
        ex = shell.run(argv, cwd=path)
        result.log.append(ex.stdout + ex.stderr)
        if not ex.ok:
            result.status = PatchStatus.EXPORTFAIL
            result.note = f"uv export ({rel}) failed: {_output_tail(ex.stdout, ex.stderr)}"
            _log(f"  EXPORTFAIL rc={ex.returncode}: {result.note!r}")
            return result
        regenerated.append(rel)

    # 4) NOOP when nothing changed on disk.
    if _is_clean(path):
        result.status = PatchStatus.NOOP
        if manual:
            result.note = f"root already >= {new_version}; manual attention: {', '.join(manual)}"
        else:
            result.note = f"already >= {new_version}"
        _log(f"  NOOP: {result.note}")
        return result

    # 5) Commit everything that changed: the uv project files plus whichever
    #    requirements exports were actually regenerated (root included only
    #    when it was rewritten; curated files stay out of the commit).
    files = ["pyproject.toml", "uv.lock", *regenerated]
    result = _commit_files(
        result,
        path=path,
        files=files,
        dep_name=dep_name,
        new_version=new_version,
        cve_id=cve_id,
        on_log=on_log,
    )
    # Make the note reflect what actually happened (bump vs. secondary-only refresh).
    if result.status is PatchStatus.DONE:
        hook_retry = _HOOK_RETRY_NOTE in result.note
        head = f"bumped to >={new_version}" if not root_satisfied else f"root already >= {new_version}"
        extra = []
        if regenerated:
            extra.append(f"regenerated {', '.join(regenerated)}")
        if manual:
            extra.append(f"manual: {', '.join(manual)}")
        if hook_retry:
            extra.append(_HOOK_RETRY_NOTE)
        result.note = "; ".join([head, *extra]) if extra else head
        if sync_env:
            # to install the fix locally right away without ever rebuilding
            # a foreign-platform venv (see _sync_environment's guards)
            result = _sync_environment(result, path=path, on_log=on_log)
    return result


def _apply_npm_bump(
    result: PatchResult,
    *,
    profile: Profile,
    dep_name: str,
    new_version: str,
    cve_id: str,
    on_log: Optional[Callable[[str], None]] = None,
) -> PatchResult:
    """Runs ``npm install`` (with overrides fallback) and commits; mutates and returns ``result``."""

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    path = profile.path
    npm_dir_rel = profile.npm_dir or _discover_npm_dir(path) or "."
    npm_dir = path if npm_dir_rel == "." else path / npm_dir_rel
    package_json = npm_dir / "package.json"
    lockfile = npm_dir / "package-lock.json"

    current = _read_npm_lock_version(lockfile, dep_name)
    if current and _version_meets(current, new_version):
        result.status = PatchStatus.NOOP
        result.note = f"already >= {new_version} ({dep_name}=={current})"
        _log(f"  NOOP: lockfile already pins {dep_name}=={current}")
        return result

    spec = f"{dep_name}@^{new_version}"
    _log(f"  npm install {spec} (in {npm_dir_rel})")
    install = shell.run(["npm", "install", spec], cwd=npm_dir)
    result.log.append(install.stdout + install.stderr)
    install_ok = install.ok

    resolved = _read_npm_lock_version(lockfile, dep_name) if install_ok else None
    needs_override = (not install_ok) or (resolved is None) or not _version_meets(resolved, new_version)
    if needs_override:
        if not package_json.is_file():
            result.status = PatchStatus.NPMADDFAIL
            result.note = "package.json missing; cannot insert overrides"
            _log("  NPMADDFAIL: package.json missing")
            return result
        wrote = _ensure_npm_override(package_json, dep_name, new_version)
        _log(f"  overrides {'updated' if wrote else 'unchanged'}; re-running npm install")
        reinstall = shell.run(["npm", "install"], cwd=npm_dir)
        result.log.append(reinstall.stdout + reinstall.stderr)
        if not reinstall.ok:
            result.status = PatchStatus.NPMADDFAIL
            _log(f"  NPMADDFAIL rc={reinstall.returncode}: {reinstall.stderr.strip()[:200]!r}")
            return result
        resolved = _read_npm_lock_version(lockfile, dep_name)

    if resolved is None or not _version_meets(resolved, new_version):
        result.status = PatchStatus.NPMADDFAIL
        result.note = f"npm install + overrides did not move {dep_name} to >= {new_version}" + (
            f"; resolved={resolved}" if resolved else ""
        )
        _log(f"  NPMADDFAIL: lockfile shows {dep_name}=={resolved!r}")
        return result

    if _is_clean(path):
        result.status = PatchStatus.NOOP
        result.note = f"already >= {new_version} ({dep_name}=={resolved})"
        _log(f"  NOOP: tree clean after install; {dep_name}=={resolved}")
        return result

    rel_pkg = package_json.relative_to(path).as_posix() if package_json.exists() else None
    rel_lock = lockfile.relative_to(path).as_posix()
    files = [f for f in (rel_pkg, rel_lock) if f]
    return _commit_files(
        result,
        path=path,
        files=files,
        dep_name=dep_name,
        new_version=new_version,
        cve_id=cve_id,
        on_log=on_log,
    )


# Appended to DONE notes when the security commit only landed after absorbing
# pre-commit hook rewrites; also matched by ``_apply_uv_bump``'s note reshaping.
_HOOK_RETRY_NOTE = "re-staged pre-commit hook edits"


def _output_tail(*chunks: str, limit: int = 300) -> str:
    """
    Returns the trailing ``limit`` characters of the stripped, joined ``chunks``.

    Chatty subprocess chains (pre-commit, npm) print their verdict at the END
    of their output, so failure notes keep the tail rather than the head.
    """
    text = "\n".join(part for part in (chunk.strip() for chunk in chunks if chunk) if part)
    if len(text) <= limit:
        return text
    return "…" + text[-limit:]


def _commit_files(
    result: PatchResult,
    *,
    path: Path,
    files: list[str],
    dep_name: str,
    new_version: str,
    cve_id: str,
    on_log: Optional[Callable[[str], None]] = None,
) -> PatchResult:
    """
    Stages ``files`` and creates the security commit; mutates and returns ``result``.

    Pre-commit hooks that rewrite files (``ruff --fix``, ``uv-lock``,
    repo-local sync hooks) abort the first commit by design: the fix is
    already on disk and the documented contract is "re-stage and retry".
    When the first commit fails AND the worktree differs from the index
    (``git diff --quiet`` exits 1 — meaning files changed *after* staging),
    the hook edits are absorbed with ``git add -u`` and the commit is retried
    exactly once. The preflight required a clean tree, so any such edit is
    hook-made and safe to take. Failures without hook edits (e.g. gitleaks
    findings) go straight to COMMITFAIL, with the output *tail* in the note
    because pre-commit prints its per-hook verdicts at the end.
    """

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    _log(f"  git add {' '.join(files)}")
    add_files = shell.run(["git", "add", *files], cwd=path)
    result.log.append(add_files.stdout + add_files.stderr)

    commit_msg = f"security: update {dep_name} to {new_version} to fix {cve_id}"
    _log(f"  git commit -m {commit_msg!r}")
    commit = shell.run(["git", "commit", "-m", commit_msg], cwd=path)
    result.log.append(commit.stdout + commit.stderr)
    retried = False
    if not commit.ok:
        diff = shell.run(["git", "diff", "--quiet"], cwd=path)
        if diff.returncode == 1:
            _log("  commit blocked by hook-modified files; running git add -u and retrying once")
            restage = shell.run(["git", "add", "-u"], cwd=path)
            result.log.append(restage.stdout + restage.stderr)
            commit = shell.run(["git", "commit", "-m", commit_msg], cwd=path)
            result.log.append(commit.stdout + commit.stderr)
            retried = True
    if not commit.ok:
        result.status = PatchStatus.COMMITFAIL
        result.note = f"git commit failed: {_output_tail(commit.stdout, commit.stderr)}"
        _log(f"  COMMITFAIL rc={commit.returncode}: {result.note!r}")
        return result

    result.status = PatchStatus.DONE
    result.note = f"bumped to >={new_version}"
    if retried:
        result.note = f"{result.note}; {_HOOK_RETRY_NOTE}"
    _log(f"  DONE: {result.note}")
    return result
