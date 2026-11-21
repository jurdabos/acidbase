"""
Cross-platform subprocess helpers.

Wraps :mod:`subprocess` with a small surface so the rest of the package can run
``git``, ``gh``, and ``uv`` identically on Windows pwsh and Linux bash. All
internal calls pass argv lists with ``shell=False``; templated user-supplied
push commands are parsed via :func:`shlex.split` if they arrive as strings.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

_IS_WINDOWS = sys.platform == "win32"

# Recognises both forms of WSL UNC mount roots reachable from Windows:
#   - \\wsl.localhost\<distro>\...   (modern, Windows 11)
#   - \\wsl$\<distro>\...            (legacy, still works on Windows 10)
# Capture group 1 is the distro name, capture group 2 is the remaining
# (possibly empty) path. Path separators are accepted in either direction
# so the same regex matches both ``pathlib.WindowsPath.__str__`` output
# (``\\wsl.localhost\Ubuntu\...``) and POSIX-style strings users put into
# TOML config (``//wsl.localhost/Ubuntu/...``).
_WSL_UNC_PATTERN = re.compile(
    r"^[\\/]{2}(?:wsl\.localhost|wsl\$)[\\/]([^\\/]+)(?:[\\/](.*))?$",
    re.IGNORECASE,
)


class ShellError(RuntimeError):
    """Raised when a required external tool is missing or a command fails fatally."""


@dataclass(frozen=True)
class CommandResult:
    """Captured outcome of a subprocess invocation."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        """Returns True when the command exited with status 0."""
        return self.returncode == 0


def which_or_die(tool: str) -> str:
    """
    Returns the absolute path to ``tool`` or raises :class:`ShellError`.

    Used at CLI entry to fail loudly when ``git``, ``gh``, or ``uv`` is missing
    rather than producing confusing per-repo failures later.
    """
    found = shutil.which(tool)
    if not found:
        raise ShellError(
            f"Required tool '{tool}' not found on PATH. Install it before running acidbase security commands."
        )
    return found


def wsl_routing(cwd: Optional[Path]) -> Optional[tuple[str, str]]:
    """
    Returns ``(distro, linux_path)`` if ``cwd`` is a WSL UNC mount, else None.

    Recognises both the modern ``\\\\wsl.localhost\\<distro>\\...`` and the
    legacy ``\\\\wsl$\\<distro>\\...`` UNC roots. ``cwd`` may use forward or
    backward slashes. The returned ``linux_path`` is always a POSIX absolute
    path suitable for ``wsl.exe --cd``.

    Rationale: running Windows-native ``git.exe`` against a path under
    ``\\\\wsl.localhost\\<distro>\\`` fails with ``fatal: detected dubious
    ownership in repository at '...'`` because the files belong to the Linux
    uid inside the distro. By rewriting calls to run through ``wsl.exe`` with
    a Linux ``--cd``, the distro-native ``git`` / ``uv`` / ``gh`` operate on
    a normal Linux filesystem path and the ownership check is satisfied.
    """
    if cwd is None:
        return None
    raw = str(cwd)
    match = _WSL_UNC_PATTERN.match(raw)
    if not match:
        return None
    distro = match.group(1)
    rest = match.group(2) or ""
    # Normalise separators and ensure a leading slash for ``wsl --cd``
    linux_path = "/" + rest.replace("\\", "/")
    while "//" in linux_path:
        linux_path = linux_path.replace("//", "/")
    return distro, linux_path


def run(
    args: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    capture: bool = True,
    check: bool = False,
    env: Optional[dict] = None,
) -> CommandResult:
    """
    Runs ``args`` as a child process and returns a :class:`CommandResult`.

    When ``capture`` is True (default) stdout and stderr are collected as text.
    When ``capture`` is False they stream to the parent terminal so the caller
    can show live progress (used for long-running git/uv invocations).

    Output is always decoded as UTF-8 with ``errors="replace"`` so non-ASCII
    bytes from ``gh`` (advisory summaries, emoji in commit titles, etc.) never
    crash the subprocess reader threads on Windows hosts whose default code
    page is something other than UTF-8 (e.g. cp1250).

    When ``cwd`` is a WSL UNC mount (see :func:`wsl_routing`) the call is
    transparently rewritten to ``wsl.exe -d <distro> --cd <linux_path> -- <argv>``
    so the distro-native tooling runs against a normal Linux filesystem path
    instead of the UNC share. This avoids the ``dubious ownership`` git fatal,
    skips CRLF translation, and uses the WSL-side ``git``/``uv``/``gh`` so
    binary tools and credentials match the way the user normally works in WSL.
    """
    child_env = dict(env) if env is not None else None
    if child_env is None:
        child_env = os.environ.copy()
    # to nudge children that respect this var into producing UTF-8 themselves
    child_env.setdefault("PYTHONIOENCODING", "utf-8")
    # Dropping the inherited VIRTUAL_ENV: it points at the venv *running
    # acidbase* (typically acidbase/.venv via `uv run`), never at the target
    # repo's environment. uv correctly ignores the mismatch, but prepends a
    # `warning: VIRTUAL_ENV=... does not match the project environment` line
    # to stderr on every call, polluting failure notes and burying the real
    # error. Each target repo's own .venv is discovered by uv from its cwd.
    child_env.pop("VIRTUAL_ENV", None)

    wsl = wsl_routing(cwd)
    if wsl is not None:
        distro, linux_cwd = wsl
        # Build: wsl.exe -d <distro> --cd <linux_cwd> --exec /bin/bash -lc <quoted-argv>
        #
        # Why this exact shape:
        #
        # 1. Plain ``wsl.exe -- <argv>`` routes the args through the
        #    distro's default Linux shell, which interprets ``>``, ``|``,
        #    ``;``, etc. ``uv add python-dotenv>=1.2.2`` then re-parses as
        #    ``uv add python-dotenv > =1.2.2`` — the version pin gets
        #    dropped, a junk file named ``=1.2.2`` is created, and the
        #    bump silently no-ops. Empirically reproduced with
        #    ``wsl.exe -d Ubuntu --cd /tmp -- echo 'hello>world'`` —
        #    leaves ``/tmp/world`` behind.
        #
        # 2. Plain ``wsl.exe --exec <argv>`` bypasses the shell (direct
        #    ``execve``), which fixes (1) but also drops the user's WSL
        #    login PATH. ``uv`` (typically installed at
        #    ``~/.local/bin/uv`` via the official installer) then fails
        #    with ``execvpe(uv) failed: No such file or directory`` — the
        #    binary genuinely is not on the minimal exec PATH.
        #
        # 3. Combining both: ``--exec /bin/bash -lc <pre-quoted-cmd>``.
        #    ``--exec`` makes wsl ``execve`` bash directly with no
        #    implicit shell layer. ``-l`` makes bash a login shell that
        #    sources ``.bash_profile`` / ``.bashrc`` and populates PATH
        #    with ``~/.local/bin``. ``-c <cmd>`` runs the pre-quoted
        #    command. ``shlex.join`` POSIX-quotes every argv element so
        #    metacharacters inside individual args (``>``, ``|``, spaces,
        #    quotes, dollars) are preserved verbatim through bash's
        #    tokenisation. Net effect: same argv reaches ``uv``/``git`` as
        #    the user would get running them in their own WSL terminal.
        joined = shlex.join(args)
        effective_args: list[str] = [
            "wsl.exe",
            "-d",
            distro,
            "--cd",
            linux_cwd,
            "--exec",
            "/bin/bash",
            "-lc",
            joined,
        ]
        # wsl.exe handles the working directory itself via --cd; passing the
        # UNC path as the host-side cwd would re-introduce the ownership issue.
        effective_cwd: Optional[str] = None
    else:
        effective_args = list(args)
        effective_cwd = str(cwd) if cwd else None
        # On Windows, ``subprocess.run`` with ``shell=False`` calls
        # ``CreateProcess`` directly, which only resolves ``.exe`` files on
        # PATH. Tooling distributed as ``.cmd``/``.bat`` shims (notably
        # ``npm.cmd``, ``yarn.cmd``, ``pnpm.cmd``, plus a handful of node-
        # installed CLIs) is therefore invisible: passing bare ``"npm"``
        # yields ``FileNotFoundError: [WinError 2]``. ``shutil.which``
        # consults ``PATHEXT`` and returns the full ``...\npm.cmd`` path,
        # which ``CreateProcess`` happily launches via the shell extension
        # handler. Skipping when ``argv[0]`` already contains a path
        # separator avoids a redundant lookup for callers that have already
        # absolutised the path themselves (e.g. ``which_or_die``).
        if _IS_WINDOWS and effective_args:
            head = effective_args[0]
            if head and not ("\\" in head or "/" in head):
                resolved = shutil.which(head)
                if resolved is not None:
                    effective_args[0] = resolved

    completed = subprocess.run(  # noqa: S603 - argv list, shell=False
        effective_args,
        cwd=effective_cwd,
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
        env=child_env,
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def render_template(template: Iterable[str], **values: str) -> list[str]:
    """
    Returns a new argv list with ``{placeholder}`` tokens expanded.

    Each element of ``template`` is treated as a ``str.format`` template, so
    ``["git", "push", "origin", "{branch}"]`` with ``branch="main"`` becomes
    ``["git", "push", "origin", "main"]``. Missing placeholders raise KeyError
    so a typo in a profile fails loudly instead of silently shipping ``{branch}``.
    """
    return [str(token).format(**values) for token in template]


def parse_command(value: str | Sequence[str]) -> list[str]:
    """
    Returns an argv list parsed from either a string or an existing sequence.

    A string value is split with :func:`shlex.split` using POSIX rules on Linux
    and Windows-friendly rules on Windows so things like
    ``'uv run "my repo" push'`` parse predictably on both platforms.
    """
    if isinstance(value, str):
        # POSIX rules on Linux/macOS; Windows-friendly rules (preserve backslashes) on Windows.
        return shlex.split(value, posix=not _IS_WINDOWS)
    return list(value)
