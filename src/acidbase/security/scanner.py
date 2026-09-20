"""
Discovery of repositories using a vulnerable dependency.

Wraps the GitHub CLI to enumerate non-archived, non-empty repos for an owner,
filter to those with Dependabot alerts enabled, and inspect each repo's
GitHub-generated SBOM to find versions of the target package at-or-below a
threshold. Version comparison uses :class:`packaging.version.Version` so PEP
440 pre-release / post-release ordering is honoured correctly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterable, Iterator, Optional
from urllib.parse import unquote

from packaging.version import InvalidVersion, Version

from acidbase.security import shell

if TYPE_CHECKING:
    # Imported only for type hints; the runtime import stays lazy inside the
    # discovery helpers to avoid a scanner <-> alerts circular import.
    from acidbase.security.alerts import DependabotAlert


@dataclass(frozen=True)
class VulnerableHit:
    """A single repo + dependency hit returned by :func:`discover_affected_repos`.
    ``manifest`` is the path of the manifest the Dependabot alert was filed
    against (e.g. ``producer/requirements.txt``), when the hit came from an
    alert. It is ``None`` for SBOM-direct hits, which carry no per-manifest
    information. Verification uses it to confirm the fix on the exact file the
    alert is about rather than only the root manifest.
    """

    repo: str
    package: str
    version: str
    threshold: str
    ecosystem: str = "pip"
    manifest: Optional[str] = None


def _split_sbom_name(pkg_name: str) -> tuple[str, str]:
    """
    Returns ``(ecosystem, package)`` parsed from a *legacy* SBOM SPDX package name.

    Older GitHub SBOMs labelled entries with the package manager, e.g.
    ``pip:GitPython``, ``actions:owner/repo``, ``npm:yaml``, ``npm:@scope/pkg``,
    ``cargo:foo``. Current SBOM payloads emit bare names and carry the
    ecosystem only in ``externalRefs`` PURLs (see :func:`_parse_purl`); this
    splitter remains as the fallback for older payloads. Names without a
    prefix are treated as ``("", name)`` so callers can decide whether to skip
    them or accept them. Splitting on the *first* ``:`` is deliberate so npm
    scoped packages (``npm:@scope/pkg``) keep their full name intact.
    """
    head, sep, rest = pkg_name.partition(":")
    if not sep:
        return "", pkg_name
    return head, rest


# Mapping from package-url types to the ecosystem vocabulary the scanner and
# Dependabot dispatch on. PURLs say "pypi" where GitHub's dependency graph
# says "pip"; the remaining entries keep other ecosystems on their familiar
# labels and unknown types fall through unchanged in :func:`_parse_purl`.
_PURL_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "pypi": "pip",
    "npm": "npm",
    "cargo": "cargo",
    "composer": "composer",
    "gem": "rubygems",
    "githubactions": "actions",
    "golang": "go",
    "maven": "maven",
    "nuget": "nuget",
}


def _parse_purl(locator: str) -> Optional[tuple[str, str, Optional[str]]]:
    """
    Returns ``(ecosystem, package, version)`` parsed from a package-url string.

    Handles the PURL subset GitHub SBOMs emit in
    ``externalRefs[].referenceLocator``:
    ``pkg:<type>/<namespace?>/<name>@<version>`` with percent-encoded segments
    (npm scoped packages arrive as ``pkg:npm/%40scope/name@1.2.3``). Qualifiers
    and subpaths (``?...`` / ``#...``) are stripped per the PURL grammar. The
    PURL type is translated through :data:`_PURL_TYPE_TO_ECOSYSTEM`
    (``pypi`` -> ``pip``), defaulting to the raw type so unknown ecosystems
    still round-trip. Returns None when ``locator`` is not a parseable
    package-url.
    """
    if not locator.startswith("pkg:"):
        return None
    body = locator[4:].lstrip("/")
    # Dropping qualifiers and subpath before splitting off name and version
    body = body.split("?", 1)[0].split("#", 1)[0]
    ptype, sep, rest = body.partition("/")
    if not sep or not rest:
        return None
    name_part, at, version_part = rest.rpartition("@")
    if at:
        raw_name, version = name_part, unquote(version_part) or None
    else:
        raw_name, version = rest, None
    name = unquote(raw_name)
    if not name:
        return None
    ecosystem = _PURL_TYPE_TO_ECOSYSTEM.get(ptype.casefold(), ptype.casefold())
    return ecosystem, name, version


def _bare_name(pkg_name: str) -> str:
    """
    Returns the package name with its ecosystem prefix stripped.

    Kept for backwards compatibility with existing tests; new call sites
    should prefer :func:`_split_sbom_name` so the ecosystem can be
    preserved for downstream dispatch.
    """
    return _split_sbom_name(pkg_name)[1]


def _version_at_or_below(found: str, threshold: str) -> bool:
    """Returns True when ``found`` is a parseable PEP 440 version <= ``threshold``."""
    try:
        return Version(found) <= Version(threshold)
    except InvalidVersion:
        return False


def _version_strictly_below(found: str, threshold: str) -> bool:
    """Returns True when ``found`` is a parseable PEP 440 version < ``threshold``."""
    try:
        return Version(found) < Version(threshold)
    except InvalidVersion:
        return False


def _version_at_or_above(found: str, threshold: str) -> bool:
    """Returns True when ``found`` is a parseable PEP 440 version >= ``threshold``."""
    try:
        return Version(found) >= Version(threshold)
    except InvalidVersion:
        return False


def _alert_addressed_by_patch(
    alert: "DependabotAlert",
    *,
    max_vulnerable: str,
    patch_target: Optional[str],
    cve_id: Optional[str],
) -> bool:
    """
    Returns True when the planned patch actually addresses ``alert``.

    The SBOM alerts-fallback (and the npm alerts path) used to accept *any*
    open alert for the target package, which produced cross-advisory false
    positives: a repo whose only open Pillow alert is a *later* CVE (first
    patched in 12.2.0) was reported as vulnerable to a run bumping Pillow to
    10.2.0, even though that bump does nothing for the later advisory — and
    then the verifier mislabelled it ``FIXED`` because the manifest already
    satisfied ``>= 10.2.0``. This scopes the match:

    * If ``cve_id`` is supplied and equals the alert's CVE or GHSA id, the
      alert is in scope — explicit operator intent wins even if the chosen
      ``--new-version`` turns out too low (the verifier will then surface
      ``OPEN`` rather than the discovery silently hiding the repo).
    * Otherwise the alert is in scope only when the version we are bumping to
      *reaches* the alert's first patched version. The reach target is
      ``patch_target`` when known (the real ``--new-version``), else the scan
      threshold ``max_vulnerable``. Bumping below the fix does not address the
      alert, so it is excluded.
    * An alert with no parseable patched version and no advisory match is left
      out: there is no signal that this bump would fix it.
    """
    if cve_id:
        known_ids = {i.casefold() for i in (alert.cve_id, alert.ghsa_id) if i}
        if cve_id.casefold() in known_ids:
            return True
    reach = patch_target or max_vulnerable
    if alert.patched_version and reach:
        return _version_at_or_above(reach, alert.patched_version)
    return False


def _list_repos(owner: str, *, on_log: Optional[Callable[[str], None]] = None) -> list[str]:
    """Returns all non-archived, non-empty repo names for ``owner`` via ``gh repo list``."""

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    _log(f"gh repo list {owner} (limit=1000)")
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
        _log(f"  gh repo list failed: rc={res.returncode}, stderr={res.stderr.strip()[:200]!r}")
        return []
    repos = [line.strip() for line in res.stdout.splitlines() if line.strip()]
    _log(f"  found {len(repos)} non-archived, non-empty repo(s)")
    return repos


def _alerts_enabled(owner: str, repo: str, *, on_log: Optional[Callable[[str], None]] = None) -> bool:
    """Returns True when Dependabot vulnerability alerts are enabled (HTTP 204)."""

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    res = shell.run(
        ["gh", "api", "-i", f"repos/{owner}/{repo}/vulnerability-alerts"],
    )
    # gh api returns headers + body on stdout; status line is the first line.
    first = res.stdout.splitlines()[0] if res.stdout else ""
    enabled = "204" in first
    _log(f"  alerts enabled? {enabled} (status line: {first.strip()!r})")
    return enabled


def _fetch_sbom(owner: str, repo: str, *, on_log: Optional[Callable[[str], None]] = None) -> Optional[dict]:
    """Returns the parsed SBOM JSON for the repo, or None on any failure."""

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    res = shell.run(
        ["gh", "api", f"repos/{owner}/{repo}/dependency-graph/sbom"],
    )
    if not res.ok or not res.stdout.strip():
        _log(f"  SBOM fetch failed or empty: rc={res.returncode}")
        return None
    try:
        parsed = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        _log(f"  SBOM JSON parse error: {exc}")
        return None
    if not isinstance(parsed, dict):
        _log(f"  SBOM JSON is not an object: {type(parsed).__name__}")
        return None
    return parsed


def _iter_packages(sbom: dict) -> Iterator[tuple[str, str]]:
    """Yields ``(name, version)`` tuples from a SPDX-style SBOM dict."""
    packages = (sbom.get("sbom") or {}).get("packages") or []
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("versionInfo")
        if name and version:
            yield name, version


def _iter_ecosystem_packages(sbom: dict) -> Iterator[tuple[str, str, str]]:
    """
    Yields ``(ecosystem, package, version)`` triples from a SPDX-style SBOM dict.

    Current GitHub SBOMs emit bare package names (``flask-cors``) and carry
    the ecosystem only in a ``pkg:pypi/...`` PURL under ``externalRefs``;
    older payloads encoded it as a name prefix (``pip:GitPython``). The PURL
    wins when present, the legacy prefix is the fallback, and entries with
    neither yield an empty ecosystem so caller-side filters skip them.
    ``versionInfo`` is preferred for the version; the PURL's ``@version``
    fills in when it is missing. Entries with no resolvable version are
    skipped.
    """
    packages = (sbom.get("sbom") or {}).get("packages") or []
    for pkg in packages:
        name = pkg.get("name")
        if not name:
            continue
        purl = None
        for ref in pkg.get("externalRefs") or ():
            purl = _parse_purl((ref or {}).get("referenceLocator") or "")
            if purl is not None:
                break
        if purl is not None:
            ecosystem, bare, purl_version = purl
            version = pkg.get("versionInfo") or purl_version
        else:
            ecosystem, bare = _split_sbom_name(name)
            version = pkg.get("versionInfo")
        if not version:
            continue
        yield ecosystem, bare, version


def discover_affected_repos(
    owner: str,
    dep_name: str,
    max_vulnerable: str,
    skip: Iterable[str] = (),
    *,
    strict_below: bool = False,
    repo: Optional[str] = None,
    ecosystem: str = "pip",
    patch_target: Optional[str] = None,
    cve_id: Optional[str] = None,
    on_log: Optional[Callable[[str], None]] = None,
    on_stale_warning: Optional[Callable[[str], None]] = None,
) -> list[VulnerableHit]:
    """
    Returns all repositories owned by ``owner`` that have ``dep_name`` vulnerable to a patch.

    Discovery dispatches by ecosystem because GitHub's two relevant endpoints
    do not agree on naming:

    * ``ecosystem="pip"`` uses the SBOM endpoint (SPDX). Python packages are
      identified via their ``pkg:pypi/...`` PURL in ``externalRefs`` (current
      payloads emit bare names) with the legacy ``pip:<name>`` prefix as
      fallback. The found version is compared to ``max_vulnerable`` (``<=`` or
      ``<`` depending on ``strict_below``) so a tighter window can be
      requested via ``--max-vulnerable``.
    * ``ecosystem="npm"`` (and every other non-pip ecosystem) uses the
      Dependabot alerts endpoint. GitHub's SBOM emits bare names for npm
      (the ecosystem only appears in ``externalRefs[].referenceLocator`` as a
      PURL) and is also empirically flaky for repos with large npm trees, so
      the alerts endpoint is the more reliable source-of-truth. An open
      alert *is* the vulnerability signal; ``max_vulnerable`` /
      ``strict_below`` are not applied because the alert already encodes the
      vulnerable range.

    ``patch_target`` is the actual ``--new-version`` the caller intends to bump
    to; ``cve_id`` is the advisory being patched. Both are used to scope the
    Dependabot-alert matching (SBOM fallback for pip, primary path for npm) to
    alerts the planned bump would genuinely address — see
    :func:`_alert_addressed_by_patch`. They are optional so existing callers
    keep working; when ``patch_target`` is omitted the scan threshold
    ``max_vulnerable`` is used as the reach target instead.

    Repositories listed in ``skip`` are ignored entirely. Repositories without
    Dependabot alerts enabled are silently skipped (pip path) to avoid noisy
    false negatives from private mirrors or study-only forks. When ``repo`` is
    provided, only that repository is inspected. When ``on_log`` is provided,
    each discovery step is reported through the callback; pip stale-graph
    demotions are additionally reported through ``on_stale_warning`` (see
    :func:`_discover_via_sbom`).
    """
    target_ecosystem = ecosystem.casefold()
    if target_ecosystem == "pip":
        return _discover_via_sbom(
            owner,
            dep_name,
            max_vulnerable,
            skip,
            strict_below=strict_below,
            repo=repo,
            ecosystem=ecosystem,
            patch_target=patch_target,
            cve_id=cve_id,
            on_log=on_log,
            on_stale_warning=on_stale_warning,
        )
    return _discover_via_alerts(
        owner,
        dep_name,
        max_vulnerable,
        skip,
        repo=repo,
        ecosystem=ecosystem,
        patch_target=patch_target,
        cve_id=cve_id,
        on_log=on_log,
    )


def _live_pip_version_if_fixed(
    owner: str,
    repo: str,
    dep_name: str,
    *,
    max_vulnerable: str,
    matches: Callable[[str, str], bool],
    on_log: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """
    Returns origin's resolved version of ``dep_name`` when it contradicts an SBOM hit, else None.

    GitHub's dependency-graph SBOM is rebuilt asynchronously and keeps a
    pre-bump version node around for a while after a fix is pushed, so a
    freshly-patched repo can still surface a phantom "vulnerable" row. This
    cross-checks the authoritative manifest on the default branch (``uv.lock``
    then ``requirements.txt``) via the Contents API the verifier already uses.
    When that live version parses and is NOT inside the vulnerable window
    (``matches`` is the same ``<``/``<=`` predicate discovery applied to the
    SBOM row), the hit is a stale-graph artefact and the resolved version is
    returned so the caller can demote it. ``None`` means "do not demote": either
    the manifest agrees the dep is still vulnerable (a true positive) or the dep
    is absent from both root manifests (e.g. a subdirectory-only pin the SBOM
    consolidated), and the Dependabot-alerts fallback stays responsible for it.
    """
    from acidbase.security.verifier import resolve_remote_pip_version  # noqa: PLC0415

    live = resolve_remote_pip_version(owner, repo, dep_name, on_log=on_log)
    if live is None:
        return None
    if matches(live, max_vulnerable):
        return None
    return live


def _discover_via_sbom(
    owner: str,
    dep_name: str,
    max_vulnerable: str,
    skip: Iterable[str],
    *,
    strict_below: bool,
    repo: Optional[str],
    ecosystem: str,
    patch_target: Optional[str] = None,
    cve_id: Optional[str] = None,
    on_log: Optional[Callable[[str], None]],
    on_stale_warning: Optional[Callable[[str], None]] = None,
) -> list[VulnerableHit]:
    """
    Performs SBOM-based discovery for the ``pip`` ecosystem; see :func:`discover_affected_repos`.

    Each SBOM version node inside the vulnerable window is cross-checked against
    origin's live manifest before it counts as a hit: the dependency-graph SBOM
    is rebuilt asynchronously and can keep a pre-bump version node around after a
    fix is pushed, so a node contradicted by the default-branch
    ``uv.lock``/``requirements.txt`` is demoted to a stale-graph warning
    (reported via ``on_stale_warning``) instead of a vulnerability. A demotion
    still falls through to the Dependabot-alerts fallback so a genuine
    subdirectory pin the consolidated SBOM hid is preserved.
    """

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    skip_set = {s for s in skip}
    target = dep_name.casefold()
    target_ecosystem = ecosystem.casefold()
    matches = _version_strictly_below if strict_below else _version_at_or_below
    hits: list[VulnerableHit] = []
    cmp_label = "<" if strict_below else "<="
    _log(
        f"Discovering repos vulnerable to {ecosystem}:{dep_name} {cmp_label} {max_vulnerable}"
        f" via SBOM (owner={owner}, repo={repo or '*'}, skip={sorted(skip_set) or '[]'})"
    )
    repos = [repo] if repo else _list_repos(owner, on_log=on_log)
    for repo in repos:
        _log(f"Inspecting {owner}/{repo}")
        if repo in skip_set:
            _log("  skipped via config")
            continue
        if not _alerts_enabled(owner, repo, on_log=on_log):
            _log("  Dependabot alerts disabled, skipping")
            continue
        sbom = _fetch_sbom(owner, repo, on_log=on_log)
        if sbom is None:
            _log("  no SBOM available, skipping")
            continue
        matched = False
        for eco, bare, version in _iter_ecosystem_packages(sbom):
            if eco.casefold() != target_ecosystem:
                continue
            if bare.casefold() != target:
                continue
            if matches(version, max_vulnerable):
                # Guard against stale dependency-graph nodes: the SBOM is rebuilt
                # asynchronously and can still list a pre-bump version after the
                # fix is pushed. When origin's live manifest already resolves the
                # dep above the vulnerable window, demote this phantom to a
                # warning and leave matched=False so the alerts fallback (the
                # per-manifest source of truth) can still catch a genuine
                # subdirectory pin the consolidated SBOM hid.
                live = (
                    _live_pip_version_if_fixed(
                        owner,
                        repo,
                        dep_name,
                        max_vulnerable=max_vulnerable,
                        matches=matches,
                        on_log=on_log,
                    )
                    if target_ecosystem == "pip"
                    else None
                )
                if live is not None:
                    warning = (
                        f"{repo}: dependency-graph reports {eco or target_ecosystem}:{bare}=={version} "
                        f"({cmp_label} {max_vulnerable}) but origin manifest resolves {bare}=={live}; "
                        f"treating as stale graph, not a vulnerability"
                    )
                    _log(f"  STALE-GRAPH: {warning}")
                    if on_stale_warning is not None:
                        on_stale_warning(warning)
                    break
                _log(f"  HIT: {eco}:{bare}=={version} matches {cmp_label} {max_vulnerable}")
                hits.append(
                    VulnerableHit(
                        repo=repo,
                        package=bare,
                        version=version,
                        threshold=max_vulnerable,
                        ecosystem=eco or target_ecosystem,
                        manifest=None,
                    )
                )
                matched = True
                break
            _log(f"  found {eco}:{bare}=={version} but not {cmp_label} {max_vulnerable}")
        if not matched:
            _log("  no matching version for target dep in SBOM; trying alerts fallback")
            # GitHub's SBOM endpoint consolidates each package to a single version —
            # typically the one resolved in the root lockfile.  When a subdirectory
            # manifest (e.g. server/requirements.txt) still pins an older, vulnerable
            # release, that older version never appears in the SBOM and the loop above
            # exits with matched=False even though Dependabot has an open alert for it.
            # Falling back to the alerts API catches exactly this class of miss: an open
            # alert IS the per-manifest vulnerability signal that the SBOM hid.
            # Imported lazily to avoid a scanner <-> alerts circular import at module load.
            from acidbase.security.alerts import fetch_alerts_for_repo  # noqa: PLC0415

            fallback = fetch_alerts_for_repo(owner, repo, packages=[dep_name], state="open")
            for alert in fallback:
                if alert.ecosystem.casefold() != target_ecosystem or alert.package.casefold() != target:
                    continue
                # Scope the fallback to alerts the planned bump actually fixes;
                # otherwise a repo whose only open alert is a *different, later*
                # advisory (already above the bump target) is falsely flagged
                # and then mislabelled FIXED by the version-only verifier.
                if not _alert_addressed_by_patch(
                    alert,
                    max_vulnerable=max_vulnerable,
                    patch_target=patch_target,
                    cve_id=cve_id,
                ):
                    _log(
                        f"  alerts fallback: alert #{alert.number} out of scope "
                        f"(patched={alert.patched_version}, advisory={alert.advisory_id}); skipping"
                    )
                    continue
                _log(f"  ALERTS FALLBACK HIT: alert #{alert.number} (manifest: {alert.manifest})")
                hits.append(
                    VulnerableHit(
                        repo=repo,
                        package=alert.package,
                        version=alert.vulnerable_range or "open",
                        threshold=max_vulnerable,
                        ecosystem=alert.ecosystem or target_ecosystem,
                        manifest=alert.manifest,
                    )
                )
                break
    hits.sort(key=lambda h: h.repo.casefold())
    _log(f"Discovery complete: {len(hits)} hit(s)")
    return hits


def _discover_via_alerts(
    owner: str,
    dep_name: str,
    max_vulnerable: str,
    skip: Iterable[str],
    *,
    repo: Optional[str],
    ecosystem: str,
    patch_target: Optional[str] = None,
    cve_id: Optional[str] = None,
    on_log: Optional[Callable[[str], None]],
) -> list[VulnerableHit]:
    """
    Dependabot-alert-based discovery used for ``npm`` and other non-pip ecosystems.

    An open alert for the ``(ecosystem, package)`` pair is the "vulnerable"
    signal; the per-repo SBOM lookup is intentionally skipped because (a)
    GitHub's SBOM does not prefix npm entries with ``npm:`` (the ecosystem
    lives in ``externalRefs`` PURLs), and (b) the SBOM endpoint is empirically
    flaky for repos with large npm trees. Alerts are still scoped to the
    planned patch via :func:`_alert_addressed_by_patch` so an open alert for a
    *different, later* advisory than the one being patched does not produce a
    cross-advisory false positive. The returned hit's ``version`` field carries
    the alert's vulnerable range for context.
    """
    # Imported lazily to avoid a scanner <-> alerts module circular import at module load.
    from acidbase.security.alerts import fetch_alerts_for_owner, fetch_alerts_for_repo

    def _log(msg: str) -> None:
        if on_log is not None:
            on_log(msg)

    skip_set = {s for s in skip}
    target_ecosystem = ecosystem.casefold()
    target_pkg = dep_name.casefold()
    _log(
        f"Discovering repos vulnerable to {ecosystem}:{dep_name} via Dependabot alerts "
        f"(owner={owner}, repo={repo or '*'}, skip={sorted(skip_set) or '[]'})"
    )
    if repo is not None:
        if repo in skip_set:
            _log("  skipped via config")
            return []
        alerts = fetch_alerts_for_repo(owner, repo, packages=[dep_name], state="open")
    else:
        alerts = fetch_alerts_for_owner(
            owner,
            packages=[dep_name],
            state="open",
            skip=skip_set,
        )
    seen_repos: set[str] = set()
    hits: list[VulnerableHit] = []
    for alert in alerts:
        if alert.ecosystem.casefold() != target_ecosystem:
            continue
        if alert.package.casefold() != target_pkg:
            continue
        # Scope BEFORE the per-repo dedup so an out-of-scope advisory does not
        # consume the repo's single slot and mask an in-scope alert behind it.
        if not _alert_addressed_by_patch(
            alert,
            max_vulnerable=max_vulnerable,
            patch_target=patch_target,
            cve_id=cve_id,
        ):
            _log(
                f"  out of scope: {alert.repo} alert #{alert.number} "
                f"(patched={alert.patched_version}, advisory={alert.advisory_id}); skipping"
            )
            continue
        if alert.repo in seen_repos:
            # one hit per repo even when multiple advisories overlap on the same dep
            continue
        seen_repos.add(alert.repo)
        _log(f"  HIT: {alert.repo} alert #{alert.number} ({alert.ecosystem}:{alert.package})")
        hits.append(
            VulnerableHit(
                repo=alert.repo,
                package=alert.package,
                version=alert.vulnerable_range or "open",
                threshold=max_vulnerable,
                ecosystem=alert.ecosystem or target_ecosystem,
                manifest=alert.manifest,
            )
        )
    hits.sort(key=lambda h: h.repo.casefold())
    _log(f"Discovery complete: {len(hits)} hit(s)")
    return hits
