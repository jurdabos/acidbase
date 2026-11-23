"""Tests for :mod:`acidbase.security.shell` (subprocess wrapper + WSL routing)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from acidbase.security import shell

# ---------------------------------------------------------------------------
# wsl_routing — pure path-detection logic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        # Modern (Windows 11) UNC root, backslashes
        (r"\\wsl.localhost\Ubuntu\home\user\some-repo", ("Ubuntu", "/home/user/some-repo")),
        # Modern, forward slashes (as written in TOML config)
        ("//wsl.localhost/Ubuntu/home/user/some-repo", ("Ubuntu", "/home/user/some-repo")),
        # Legacy (Windows 10) UNC root
        (r"\\wsl$\Debian\home\someone\project", ("Debian", "/home/someone/project")),
        # Distro root only — Linux path collapses to "/"
        (r"\\wsl.localhost\Ubuntu", ("Ubuntu", "/")),
        # Case-insensitive on the UNC host portion (Windows is case-insensitive)
        (r"\\WSL.LOCALHOST\Ubuntu\home", ("Ubuntu", "/home")),
        # Distro name with mixed case is preserved (WSL distros ARE case-sensitive)
        (r"\\wsl.localhost\Ubuntu-24.04\home", ("Ubuntu-24.04", "/home")),
    ],
)
def test_wsl_routing_recognises_wsl_unc_paths(raw, expected):
    """wsl_routing returns (distro, linux_path) for every supported WSL UNC shape."""
    assert shell.wsl_routing(Path(raw)) == expected
    # Also accept raw strings via Path(...) wrapping
    assert shell.wsl_routing(Path(str(Path(raw)))) == expected


@pytest.mark.parametrize(
    "raw",
    [
        # Plain Windows drive paths
        r"C:\projects\some-repo",
        r"D:\projects\some-repo",
        # POSIX path that happens to have // — only WSL UNC variants count
        "/home/user/some-repo",
        # UNC pointing at a non-WSL host
        r"\\some-server\share\path",
        # Empty
        ".",
    ],
)
def test_wsl_routing_returns_none_for_non_wsl_paths(raw):
    """Non-WSL paths always yield None."""
    assert shell.wsl_routing(Path(raw)) is None


def test_wsl_routing_returns_none_for_none_input():
    """Explicit None passthrough so run() can call this unconditionally."""
    assert shell.wsl_routing(None) is None


# ---------------------------------------------------------------------------
# run() — verifies the subprocess.run call is rewritten when cwd is WSL UNC
# ---------------------------------------------------------------------------


def _capture_run_call():
    """Returns a (patcher, calls) tuple that records subprocess.run invocations."""
    calls: list[dict] = []

    def fake_run(args, **kwargs):
        calls.append({"args": list(args), **kwargs})

        # Mimic subprocess.CompletedProcess just enough for shell.run to consume
        class _Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Done()

    return calls, patch("subprocess.run", side_effect=fake_run)


def test_run_with_local_cwd_does_not_route_through_wsl():
    """A normal Windows or POSIX cwd is passed straight to subprocess.run."""
    calls, ctx = _capture_run_call()
    with ctx:
        shell.run(["git", "status"], cwd=Path(r"C:\\projects\\some-repo"))
    assert len(calls) == 1
    # argv[0] may have been resolved to an absolute path on Windows (e.g.
    # 'C:\\Program Files\\Git\\cmd\\git.EXE'); behaviour we care about is
    # that the *trailing* args are untouched and the call did not route
    # through wsl.exe.
    forwarded = calls[0]["args"]
    assert Path(forwarded[0]).name.casefold().startswith("git")
    assert forwarded[1:] == ["status"]
    # cwd is forwarded as a string, not None
    assert calls[0]["cwd"] is not None
    assert forwarded[0].casefold() != "wsl.exe"
    assert "wsl.exe" not in forwarded


def test_run_with_wsl_unc_cwd_routes_through_wsl_exe():
    """A WSL UNC cwd is rewritten to `wsl.exe -d <distro> --cd <linux> --exec /bin/bash -lc <quoted>`.

    The routing combines three things:
      - ``--exec`` so wsl.exe ``execve``s bash directly (no implicit shell layer).
      - ``/bin/bash -lc`` so the inner shell is a *login* shell, sourcing the
        user's ``.bashrc`` / ``.profile`` and therefore picking up
        ``~/.local/bin`` (where ``uv`` typically lives in WSL).
      - ``shlex.join`` pre-quotes the argv so ``>`` in specs like
        ``python-dotenv>=1.2.2`` is preserved as a literal character
        instead of being parsed as a redirect by the inner bash.
    """
    calls, ctx = _capture_run_call()
    with ctx:
        shell.run(
            ["git", "--no-pager", "status", "--porcelain"],
            cwd=Path(r"\\wsl.localhost\Ubuntu\home\user\some-repo"),
        )
    assert len(calls) == 1
    new_args = calls[0]["args"]
    assert new_args[:8] == [
        "wsl.exe",
        "-d",
        "Ubuntu",
        "--cd",
        "/home/user/some-repo",
        "--exec",
        "/bin/bash",
        "-lc",
    ]
    # The 9th element is the shlex-quoted command string.
    assert new_args[8] == "git --no-pager status --porcelain"
    # Host-side cwd is cleared so wsl.exe manages its own working directory.
    assert calls[0]["cwd"] is None


def test_run_with_legacy_wsl_dollar_unc_also_routes():
    """`\\\\wsl$\\<distro>\\...` (Windows 10 form) is also routed through wsl.exe."""
    calls, ctx = _capture_run_call()
    with ctx:
        shell.run(["uv", "add", "pytest>=9.0.3"], cwd=Path(r"\\wsl$\Debian\home\someone\proj"))
    args = calls[0]["args"]
    assert args[:8] == [
        "wsl.exe",
        "-d",
        "Debian",
        "--cd",
        "/home/someone/proj",
        "--exec",
        "/bin/bash",
        "-lc",
    ]
    # The redirect-looking spec is shlex-quoted so bash treats it as one word.
    assert args[8] == "uv add 'pytest>=9.0.3'"


def test_run_quotes_redirect_metachar_so_pin_is_preserved():
    """Regression: ``shlex.join`` quotes ``>`` so the bumped version pin survives bash.

    The pre-``--exec`` routing used ``--``, which let the Linux default shell
    tokenise the args; the pre-``shlex.join`` routing used ``--exec`` alone,
    which then could not find ``uv`` on the minimal exec PATH. The current
    shape (`--exec /bin/bash -lc <quoted>`) gets both right: bash is a
    login shell (PATH includes ``~/.local/bin``) AND the args are pre-
    quoted so ``>`` is preserved as part of the version specifier instead
    of being parsed as a redirect.
    """
    calls, ctx = _capture_run_call()
    with ctx:
        shell.run(
            ["uv", "add", "python-dotenv>=1.2.2"],
            cwd=Path(r"\\wsl.localhost\Ubuntu\home\user\some-repo"),
        )
    args = calls[0]["args"]
    # The 9th element is the joined command string; the redirect metachar
    # is wrapped in single quotes so the inner bash treats the whole spec
    # as a single word.
    assert args[8] == "uv add 'python-dotenv>=1.2.2'"
    assert "'python-dotenv>=1.2.2'" in args[8]
    # The host argv never embeds the spec without quoting.
    assert "python-dotenv>=1.2.2" not in args[:8]


def test_run_with_no_cwd_does_not_route():
    """Calls without cwd never route through wsl.exe."""
    calls, ctx = _capture_run_call()
    with ctx:
        shell.run(["echo", "hi"])
    forwarded = calls[0]["args"]
    # argv[0] may resolve to an absolute path on Windows; what matters is that
    # the trailing args survive verbatim and no WSL routing was applied.
    assert Path(forwarded[0]).name.casefold().startswith("echo")
    assert forwarded[1:] == ["hi"]
    assert calls[0]["cwd"] is None
    assert "wsl.exe" not in forwarded


def test_run_strips_virtual_env_from_child_environment(monkeypatch):
    """VIRTUAL_ENV never reaches children: it names acidbase's own venv, not the target repo's.

    Regression for the transcriber UVADDFAIL note: every `uv` call inside a
    target repo carried `VIRTUAL_ENV=...acidbase\\.venv`, so uv prepended a
    mismatch warning to stderr that buried the actual resolver error in the
    truncated Summary note.
    """
    monkeypatch.setenv("VIRTUAL_ENV", r"<REAL_A6E_FOLDER>\\.venv")
    calls, ctx = _capture_run_call()
    with ctx:
        shell.run(["uv", "add", "black>=26.3.1"], cwd=Path(r"C:\\projects\\some-repo"))
    child_env = calls[0]["env"]
    assert "VIRTUAL_ENV" not in child_env
    # The rest of the environment still flows through.
    assert "PYTHONIOENCODING" in child_env


def test_run_strips_virtual_env_from_explicit_env_too():
    """An explicitly passed env dict gets the same VIRTUAL_ENV scrub."""
    calls, ctx = _capture_run_call()
    with ctx:
        shell.run(["uv", "lock"], env={"VIRTUAL_ENV": "/wrong/venv", "PATH": "/usr/bin"})
    child_env = calls[0]["env"]
    assert "VIRTUAL_ENV" not in child_env
    assert child_env["PATH"] == "/usr/bin"


def test_run_returns_command_result_with_returncode_and_streams():
    """The wrapper still returns a CommandResult based on subprocess output."""

    def fake_run(args, **kwargs):
        class _Done:
            returncode = 42
            stdout = "out"
            stderr = "err"

        return _Done()

    with patch("subprocess.run", side_effect=fake_run):
        res = shell.run(["true"])
    assert res.returncode == 42
    assert res.stdout == "out"
    assert res.stderr == "err"
    assert res.ok is False


# ---------------------------------------------------------------------------
# Windows shim resolution (npm.cmd, yarn.cmd, ...)
# ---------------------------------------------------------------------------


def test_run_resolves_windows_shim_via_shutil_which():
    """On Windows, bare argv[0] is resolved via shutil.which so .cmd/.bat shims launch.

    Regression test for ``FileNotFoundError: [WinError 2]`` when calling
    ``npm`` (which ships as ``npm.cmd`` on Windows): ``CreateProcess`` only
    searches for ``.exe`` files on PATH, so passing bare ``"npm"`` fails
    even though the user can run it interactively. The wrapper now
    consults ``shutil.which`` first so ``npm`` becomes ``...\\npm.cmd``,
    which ``CreateProcess`` does know how to launch.
    """
    calls, ctx = _capture_run_call()
    with (
        patch.object(shell, "_IS_WINDOWS", True),
        patch("shutil.which", return_value=r"C:\\Program Files\\nodejs\\npm.cmd"),
        ctx,
    ):
        shell.run(["npm", "install", "yaml@^2.8.3"])
    assert len(calls) == 1
    new_args = calls[0]["args"]
    # argv[0] is replaced with the resolved .cmd path; the rest is untouched.
    assert new_args[0].endswith("npm.cmd")
    assert new_args[1:] == ["install", "yaml@^2.8.3"]


def test_run_does_not_replace_argv_when_argv_already_absolute():
    """Callers that pre-resolved the path (e.g. via which_or_die) are NOT re-looked-up."""
    calls, ctx = _capture_run_call()
    with (
        patch.object(shell, "_IS_WINDOWS", True),
        patch("shutil.which", side_effect=AssertionError("shutil.which must not be called for absolute paths")),
        ctx,
    ):
        shell.run([r"C:\\tools\\custom.exe", "--flag"])
    assert calls[0]["args"] == [r"C:\\tools\\custom.exe", "--flag"]


def test_run_does_not_invoke_shutil_which_on_non_windows():
    """POSIX hosts don't need shim resolution; shutil.which must not be consulted."""
    calls, ctx = _capture_run_call()
    with (
        patch.object(shell, "_IS_WINDOWS", False),
        patch("shutil.which", side_effect=AssertionError("shutil.which must not be called on POSIX")),
        ctx,
    ):
        shell.run(["npm", "install"])
    assert calls[0]["args"] == ["npm", "install"]
