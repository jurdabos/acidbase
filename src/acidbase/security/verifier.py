"""
Post-patch verification by inspecting the patched manifest on the default branch.

After commits are pushed, we want a fast verdict on whether the new version is
visible on GitHub. This module reads the relevant manifest from
``origin/<branch>`` via the GitHub Contents API in raw mode and confirms that
the target package now resolves to a version at or above the patched threshold.

Verification dispatches by ecosystem:

* ``"pip"`` (default) — GitHub's label for the PyPI ecosystem. Reads
  ``uv.lock`` first and falls back to ``requirements.txt`` so legacy
  manifests still resolve. Mirrors what ``uv`` itself locks at runtime.
* ``"npm"`` — reads ``package-lock.json`` at the npm directory configured
  for each repo (defaults to the repo root). Parses v1, v2, and v3 lockfile
  shapes, including scoped package paths.

Dependabot's own alert re-evaluation can take several minutes and is
intentionally not waited on; the manifest content on the default branch is the
ground truth for "is the fix on GitHub?". Dependabot will catch up
asynchronously, and the user can reconcile any remaining open alerts with
``acidbase alerts`` afterwards.
"""

from __future__ import annotations

import json
import re
import tomllib
from typing import Callable, Mapping, Optional

from packaging.version import InvalidVersion, Version

from acidbase.security import shell

ALERT_FIXED = "FIXED"
ALERT_OPEN = "OPEN"


def _gh_get_raw_contents(
    owner: str,
    repo: str,
    path: str,
    *,
    ref: Optional[str] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """
    Returns the raw UTF-8 content of ``path`` for ``owner/repo``.

    Reads ``ref`` when given; when ``ref`` is None the Contents API resolves the
    repository's default branch (which is also the ref GitHub builds the
    dependency-graph SBOM from). Uses the ``application/vnd.github.raw`` accept
    header so files above the 1 MB Contents API base64 cutoff are still returned
    in one shot. ``None`` is returned on any failure (HTTP error, file missing,
    transport hiccup) so callers can fall back to another manifest without
    raising.
    """

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    endpoint = f"repos/{owner}/{repo}/contents/{path}"
    if ref:
        endpoint += f"?ref={ref}"
    _log(f"GET {endpoint} (raw)")
    res = shell.run(
        [
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github.raw",
            endpoint,
        ],
    )
    if not res.ok:
        _log(f"  gh api failed: rc={res.returncode}, stderr={res.stderr.strip()[:200]!r}")
        return None
    if not res.stdout:
        _log("  empty response body")
        return None
    return res.stdout


def _find_in_uv_lock(content: str, dep_name: str) -> Optional[str]:
    """Returns the version of ``dep_name`` found in ``uv.lock`` TOML content, or None."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return None
    target = dep_name.casefold()
    for pkg in data.get("package") or []:
        name = str(pkg.get("name") or "").casefold()
        if name == target:
            version = pkg.get("version")
            return str(version) if version else None
    return None


_REQS_PIN = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s;#\\]+)",
    re.MULTILINE,
)


def _find_in_requirements(content: str, dep_name: str) -> Optional[str]:
    """Returns the pinned version of ``dep_name`` in a ``requirements.txt`` body, or None."""
    target = dep_name.casefold()
    for match in _REQS_PIN.finditer(content):
        if match.group(1).casefold() == target:
            return match.group(2).strip()
    return None


def _version_meets(found: str, required: str) -> bool:
    """Returns True when ``found`` parses as PEP 440 and is >= ``required``."""
    try:
        return Version(found) >= Version(required)
    except InvalidVersion:
        return False


def _find_in_npm_lock(content: str, dep_name: str) -> Optional[str]:
    """
    Returns the resolved version of ``dep_name`` in a ``package-lock.json`` body, or None.

    Handles npm lockfile v1 (top-level ``dependencies``), v2, and v3
    (top-level ``packages`` map keyed by ``node_modules/<pkg>`` paths,
    including scoped names like ``node_modules/@scope/pkg``). The first
    matching entry wins.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None
    target = dep_name.casefold()
    packages = data.get("packages") or {}
    for key, value in packages.items():
        if not isinstance(value, dict) or not key:
            continue
        name_part = key.rsplit("node_modules/", 1)[-1]
        if name_part.casefold() == target:
            version = value.get("version")
            if version:
                return str(version)
    dependencies = data.get("dependencies") or {}
    for key, value in dependencies.items():
        if key.casefold() != target:
            continue
        if isinstance(value, dict):
            version = value.get("version")
            if version:
                return str(version)
    return None


def resolve_remote_pip_version(
    owner: str,
    repo: str,
    dep: str,
    *,
    ref: Optional[str] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """
    Returns ``dep``'s resolved version on origin (``uv.lock`` first, then ``requirements.txt``), or None.

    Reads the repository's default branch when ``ref`` is None — the Contents
    API resolves it automatically, and that is the same ref GitHub builds the
    dependency-graph SBOM from, so this is the right ground truth for
    cross-checking an SBOM row. ``uv.lock`` wins when it pins the dep (its
    fully-resolved transitive versions); ``requirements.txt`` is the fallback for
    legacy or exported manifests. ``None`` means the dep is absent from both root
    manifests, so callers must not read it as "fixed".
    """
    uv_content = _gh_get_raw_contents(owner, repo, "uv.lock", ref=ref, on_log=on_log)
    if uv_content is not None:
        version = _find_in_uv_lock(uv_content, dep)
        if version:
            return version
    req_content = _gh_get_raw_contents(owner, repo, "requirements.txt", ref=ref, on_log=on_log)
    if req_content is not None:
        version = _find_in_requirements(req_content, dep)
        if version:
            return version
    return None


def verify_remote_bump(
    repos_with_branch: dict[str, str],
    *,
    owner: str,
    dep: str,
    new_version: str,
    ecosystem: str = "pip",
    npm_dirs: Optional[Mapping[str, str]] = None,
    manifests: Optional[Mapping[str, str]] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> dict[str, str]:
    """
    Returns a dict mapping ``repo -> "FIXED" | "OPEN"`` for each entry in ``repos_with_branch``.

    ``ecosystem`` selects which manifest the verifier reads from
    ``origin/<branch>``:

    * ``"pip"`` (default) — GitHub's label for the PyPI ecosystem. Reads
      ``uv.lock`` first, then ``requirements.txt`` as fallback.
    * ``"npm"`` — reads ``<npm_dir>/package-lock.json``. ``npm_dirs`` maps
      ``repo`` to the relative directory holding that lockfile; missing
      entries default to the repo root.

    ``manifests`` maps ``repo`` to the path the Dependabot alert was filed
    against. For pip, when that path is a *secondary* requirements file (e.g.
    ``producer/requirements.txt`` — i.e. it has a directory component and ends
    in ``requirements.txt``), the verdict is taken from *that* file rather than
    the root manifest, so a stale subdirectory export is not masked by an
    already-patched root. Missing entries fall back to the root-manifest logic.

    A repo is ``FIXED`` when the resolved manifest reports a version that
    parses as PEP 440 (the ordering also matches SemVer for typical npm
    versions) and is >= ``new_version``. Otherwise the repo is ``OPEN``
    (manifest still has an older version, or the dep is not present).

    No polling, no Dependabot wait: the call returns as soon as the API
    round-trips complete. Dependabot will catch up on its own schedule, and
    ``acidbase alerts`` can be used afterwards to confirm advisory closure.
    """

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    state: dict[str, str] = {}
    if not repos_with_branch:
        return state
    eco = ecosystem.casefold()
    _log(f"Verifying remote manifest for dep={dep} (ecosystem={ecosystem}, target >= {new_version})")
    for repo in sorted(repos_with_branch):
        branch = repos_with_branch[repo]
        _log(f"Inspecting {owner}/{repo}@{branch}")
        if eco == "npm":
            verdict = _verify_npm(
                owner=owner,
                repo=repo,
                branch=branch,
                dep=dep,
                new_version=new_version,
                npm_dir=(npm_dirs or {}).get(repo) or ".",
                on_log=on_log,
            )
        else:
            verdict = _verify_pip(
                owner=owner,
                repo=repo,
                branch=branch,
                dep=dep,
                new_version=new_version,
                manifest=(manifests or {}).get(repo),
                on_log=on_log,
            )
        state[repo] = verdict
    return state


def _verify_pip(
    *,
    owner: str,
    repo: str,
    branch: str,
    dep: str,
    new_version: str,
    manifest: Optional[str] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> str:
    """Returns ``FIXED``/``OPEN`` by inspecting the alert's manifest, or ``uv.lock`` then ``requirements.txt``."""

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    # When the alert is about a secondary requirements file (a path with a
    # directory component, e.g. ``producer/requirements.txt``), the root
    # uv.lock/requirements.txt do not reflect it — verify that exact file.
    if manifest and "/" in manifest and manifest.endswith("requirements.txt"):
        content = _gh_get_raw_contents(owner, repo, manifest, ref=branch, on_log=on_log)
        if content is None:
            _log(f"  -> {repo}: OPEN ({manifest} not fetchable)")
            return ALERT_OPEN
        version = _find_in_requirements(content, dep)
        if version and _version_meets(version, new_version):
            _log(f"  {manifest}: {dep}=={version} -> FIXED")
            return ALERT_FIXED
        _log(f"  -> {repo}: OPEN ({manifest}: {dep}=={version or 'absent'} < {new_version})")
        return ALERT_OPEN

    verdict = ALERT_OPEN
    found_version: Optional[str] = None
    # uv.lock is authoritative when present (resolved transitive versions).
    uv_content = _gh_get_raw_contents(owner, repo, "uv.lock", ref=branch, on_log=on_log)
    if uv_content is not None:
        version = _find_in_uv_lock(uv_content, dep)
        if version:
            _log(f"  uv.lock: {dep}=={version}")
            found_version = version
            if _version_meets(version, new_version):
                verdict = ALERT_FIXED
        else:
            _log(f"  uv.lock: {dep} not present")
    if verdict != ALERT_FIXED:
        req_content = _gh_get_raw_contents(owner, repo, "requirements.txt", ref=branch, on_log=on_log)
        if req_content is not None:
            version = _find_in_requirements(req_content, dep)
            if version:
                _log(f"  requirements.txt: {dep}=={version}")
                found_version = found_version or version
                if _version_meets(version, new_version):
                    verdict = ALERT_FIXED
            else:
                _log(f"  requirements.txt: {dep} not present")
    if verdict == ALERT_OPEN and found_version:
        _log(f"  -> {repo}: OPEN ({dep}=={found_version} < {new_version})")
    elif verdict == ALERT_OPEN:
        _log(f"  -> {repo}: OPEN ({dep} not found in any tracked manifest)")
    else:
        _log(f"  -> {repo}: FIXED")
    return verdict


def _verify_npm(
    *,
    owner: str,
    repo: str,
    branch: str,
    dep: str,
    new_version: str,
    npm_dir: str,
    on_log: Optional[Callable[[str], None]] = None,
) -> str:
    """Returns ``FIXED``/``OPEN`` by inspecting ``<npm_dir>/package-lock.json``."""

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    lock_path = "package-lock.json" if npm_dir in (".", "") else f"{npm_dir.rstrip('/')}/package-lock.json"
    content = _gh_get_raw_contents(owner, repo, lock_path, ref=branch, on_log=on_log)
    if content is None:
        _log(f"  -> {repo}: OPEN ({lock_path} not fetchable)")
        return ALERT_OPEN
    version = _find_in_npm_lock(content, dep)
    if version is None:
        _log(f"  -> {repo}: OPEN ({dep} not found in {lock_path})")
        return ALERT_OPEN
    _log(f"  {lock_path}: {dep}=={version}")
    if _version_meets(version, new_version):
        _log(f"  -> {repo}: FIXED")
        return ALERT_FIXED
    _log(f"  -> {repo}: OPEN ({dep}=={version} < {new_version})")
    return ALERT_OPEN
