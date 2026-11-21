"""
Keeps the code of self-hosted repositories off GitHub.

A repository in mirror mode (``mode = "mirror"`` in ``[tool.acidbase.push]``) keeps its code on a remote of its own,
such as a bare repository on a private server, and sends GitHub only its dependency manifests, so Dependabot and the
dependency-graph SBOM keep covering it. The guard is plain git configuration: ``url.<base>.pushInsteadOf`` rewrites
every push to a GitHub URL into a scheme no git helper handles, so the push stops before anything leaves the machine,
whichever tool starts it, ``gh repo create --push`` included. Fetching is unaffected, and so is the mirror publish,
which pushes from a temporary repository that does not carry this configuration.
"""

from __future__ import annotations

import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

MIRROR_MODE = "mirror"
DEFAULT_CODE_REMOTE = "origin"
DEFAULT_MIRROR_REMOTE = "deps"
GUARD_BASE = "acidbase-blocks-github://"
GUARD_KEY = f"url.{GUARD_BASE}.pushInsteadOf"
# URL prefixes git can push to GitHub through; an SSH alias such as `Host gh` is invisible to git and stays unguarded
GITHUB_PUSH_PREFIXES: tuple[str, ...] = (
    "git@github.com:",
    "http://github.com/",
    "https://github.com/",
    "ssh://git@github.com/",
    "ssh://git@ssh.github.com:443/",
)


@dataclass(frozen=True)
class MirrorSettings:
    """
    Holds the two remotes of a mirror-mode repository: the code remote and the GitHub dependency mirror.
    """

    code_remote: str
    mirror_remote: str


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """
    Runs one git command in ``root`` and returns the completed process without raising.
    """
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
    )


def url_host(url: str) -> str:
    """
    Returns the lower-case host of a git URL, for both URL syntax and the scp-like ``user@host:path`` form.
    Returns an empty string for local paths, Windows drive paths included.
    """
    text = url.strip()
    if "://" in text:
        return (urlsplit(text).hostname or "").lower()
    head, separator, _rest = text.partition(":")
    if not separator or "/" in head or "\\" in head or len(head) == 1:
        return ""
    return head.rsplit("@", 1)[-1].lower()


def is_github_url(url: str) -> bool:
    """
    Returns whether ``url`` points to GitHub.
    """
    host = url_host(url)
    return host == "github.com" or host.endswith(".github.com")


def mirror_settings(root: Path) -> MirrorSettings | None:
    """
    Returns the mirror-mode remotes declared in ``root``'s ``pyproject.toml``, or None outside mirror mode.
    """
    try:
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    tool = data.get("tool")
    acidbase = tool.get("acidbase") if isinstance(tool, dict) else None
    section = acidbase.get("push") if isinstance(acidbase, dict) else None
    if not isinstance(section, dict) or section.get("mode") != MIRROR_MODE:
        return None
    return MirrorSettings(
        code_remote=str(section.get("private_remote", DEFAULT_CODE_REMOTE)),
        mirror_remote=str(section.get("public_remote", DEFAULT_MIRROR_REMOTE)),
    )


def remote_names(root: Path) -> list[str]:
    """
    Returns the names of the remotes configured in ``root``.
    """
    result = _git(root, "remote")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()] if result.returncode == 0 else []


def remote_url(root: Path, name: str) -> str | None:
    """
    Returns the fetch URL of remote ``name`` in ``root``, or None when the remote does not exist.
    """
    result = _git(root, "remote", "get-url", name)
    url = result.stdout.strip()
    return url if result.returncode == 0 and url else None


def push_urls(root: Path, name: str) -> list[str]:
    """
    Returns the URLs a push to remote ``name`` would use, after git applies ``pushInsteadOf``.
    """
    result = _git(root, "remote", "get-url", "--push", "--all", name)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()] if result.returncode == 0 else []


def guard_missing(root: Path) -> list[str]:
    """
    Returns the GitHub URL prefixes that ``root``'s git configuration does not yet block for pushes.
    """
    result = _git(root, "config", "--get-all", GUARD_KEY)
    installed = {line.strip() for line in result.stdout.splitlines()}
    return [prefix for prefix in GITHUB_PUSH_PREFIXES if prefix not in installed]


def install_guard(root: Path) -> list[str]:
    """
    Blocks pushes from ``root`` to GitHub and returns the URL prefixes it added; an installed guard is left alone.
    Raises:
        RuntimeError: If git cannot write the repository's configuration
    """
    added: list[str] = []
    for prefix in guard_missing(root):
        result = _git(root, "config", "--add", GUARD_KEY, prefix)
        if result.returncode != 0:
            raise RuntimeError(f"git config failed in {root}: {result.stderr.strip()}")
        added.append(prefix)
    return added


def hosting_problems(root: Path, settings: MirrorSettings) -> list[str]:
    """
    Returns what keeps a mirror-mode repository from its intended layout; an empty list means none.
    The code remote must exist and stay off GitHub, the mirror remote must exist, no other remote may fetch from or
    push to GitHub, and the push guard must be complete.
    """
    problems: list[str] = []
    names = remote_names(root)
    code_url = remote_url(root, settings.code_remote) if settings.code_remote in names else None
    if code_url is None:
        problems.append(f"code remote '{settings.code_remote}' is missing")
    if settings.mirror_remote not in names:
        problems.append(f"mirror remote '{settings.mirror_remote}' is missing")
    for name in names:
        if name == settings.mirror_remote:
            continue
        url = remote_url(root, name) or ""
        if is_github_url(url):
            problems.append(f"remote '{name}' fetches from GitHub")
        elif any(is_github_url(push_url) for push_url in push_urls(root, name)):
            problems.append(f"remote '{name}' pushes to GitHub")
    if guard_missing(root):
        problems.append(
            "GitHub push guard incomplete (`acidbase push` or `acidbase scaffold --hosting mirror` adds it)"
        )
    return problems


def describe(root: Path, settings: MirrorSettings) -> str:
    """
    Returns a short label of where a mirror-mode repository keeps its code, for census output.
    """
    code_url = remote_url(root, settings.code_remote) or ""
    host = url_host(code_url) or code_url or "?"
    return f"code on {host}, dependency mirror on GitHub"
