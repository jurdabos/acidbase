"""
Tests the startup hook in acidbase_boot.py. Every secret in here is a canary.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import acidbase_boot

CANARY = "canary-value-do-not-print"
NAMES = ("BOOT_TEST_ONE", "BOOT_TEST_TWO")


@pytest.fixture
def project(tmp_path, monkeypatch):
    """
    Makes a folder look like the active venv's project, and has os.environ restored afterwards.
    """
    folder = tmp_path / "DemoRepo"
    folder.mkdir()
    monkeypatch.setattr(sys, "prefix", str(folder / ".venv"))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "python"))
    for name in (*NAMES, acidbase_boot.TRIED):
        # Setting first, because monkeypatch only restores what it saw present
        monkeypatch.setenv(name, "placeholder")
        monkeypatch.delenv(name)
    return folder


@pytest.fixture
def fetch(monkeypatch):
    fake = MagicMock(return_value={})
    monkeypatch.setattr(acidbase_boot, "fetch", fake)
    return fake


def test_the_pth_line_calls_load():
    pth = Path(__file__).resolve().parents[1] / "src" / "acidbase_keyring.pth"
    assert pth.read_text(encoding="utf-8").strip() == "import acidbase_boot; acidbase_boot.load()"


def test_does_nothing_outside_a_venv(project, fetch, monkeypatch):
    monkeypatch.setattr(sys, "prefix", sys.base_prefix)
    acidbase_boot.load()
    fetch.assert_not_called()


def test_does_nothing_without_an_env_file(project, fetch):
    acidbase_boot.load()
    fetch.assert_not_called()


def test_does_nothing_without_markers(project, fetch):
    (project / ".env").write_text("DEBUG=true\n# An ordinary comment\n", encoding="utf-8")
    acidbase_boot.load()
    fetch.assert_not_called()


def test_a_marker_must_be_a_whole_line(project, fetch):
    (project / ".env").write_text(f"X=1 # keyring: {NAMES[0]}\n#keyring: {NAMES[1]}\n", encoding="utf-8")
    acidbase_boot.load()
    fetch.assert_not_called()


def test_fills_the_environment_from_the_folder_of_the_venv(project, fetch, tmp_path, monkeypatch):
    (project / ".env").write_text(f"# keyring: {NAMES[0]}\nDEBUG=true\n", encoding="utf-8")
    fetch.return_value = {NAMES[0]: CANARY}
    monkeypatch.chdir(tmp_path)
    acidbase_boot.load()
    fetch.assert_called_once_with("demorepo", [NAMES[0]])
    assert os.environ[NAMES[0]] == CANARY


def test_reads_a_marker_after_a_bom_with_crlf_endings(project, fetch):
    (project / ".env").write_bytes(f"﻿# keyring: {NAMES[0]}\r\n# keyring: {NAMES[1]}\r\n".encode())
    acidbase_boot.load()
    assert fetch.call_args.args[1] == list(NAMES)


def test_a_value_in_the_environment_wins(project, fetch, monkeypatch):
    (project / ".env").write_text(f"# keyring: {NAMES[0]}\n# keyring: {NAMES[1]}\n", encoding="utf-8")
    monkeypatch.setenv(NAMES[0], "from the shell")
    acidbase_boot.load()
    assert fetch.call_args.args[1] == [NAMES[1]]
    assert os.environ[NAMES[0]] == "from the shell"


def test_skips_the_keyring_when_the_environment_has_everything(project, fetch, monkeypatch):
    (project / ".env").write_text(f"# keyring: {NAMES[0]}\n", encoding="utf-8")
    monkeypatch.setenv(NAMES[0], "inherited from a parent process")
    acidbase_boot.load()
    fetch.assert_not_called()


def test_a_missing_secret_costs_one_line_naming_it(project, fetch, capsys):
    (project / ".env").write_text(f"# keyring: {NAMES[0]}\n", encoding="utf-8")
    acidbase_boot.load()
    err = capsys.readouterr().err
    assert NAMES[0] in err
    assert err.count("\n") == 1


def test_a_failure_never_raises_and_never_quotes_its_message(project, fetch, capsys):
    (project / ".env").write_text(f"# keyring: {NAMES[0]}\n", encoding="utf-8")
    fetch.side_effect = OSError(CANARY)
    acidbase_boot.load()
    err = capsys.readouterr().err
    assert "OSError" in err
    assert NAMES[0] in err
    assert CANARY not in err


def test_child_processes_do_not_repeat_a_failed_lookup(project, fetch, capsys):
    (project / ".env").write_text(f"# keyring: {NAMES[0]}\n", encoding="utf-8")
    acidbase_boot.load()
    capsys.readouterr()
    acidbase_boot.load()
    assert fetch.call_count == 1
    assert capsys.readouterr().err == ""


def test_another_project_still_gets_its_lookup(project, fetch, tmp_path, monkeypatch):
    (project / ".env").write_text(f"# keyring: {NAMES[0]}\n", encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    (other / ".env").write_text(f"# keyring: {NAMES[0]}\n", encoding="utf-8")
    acidbase_boot.load()
    monkeypatch.setattr(sys, "prefix", str(other / ".venv"))
    acidbase_boot.load()
    assert fetch.call_count == 2


@pytest.mark.parametrize(
    "release,expected",
    [("5.15.167.4-microsoft-standard-WSL2", True), ("6.8.0-45-generic", False)],
)
def test_recognises_wsl_by_the_kernel(release, expected, monkeypatch):
    monkeypatch.setattr(os, "uname", lambda: SimpleNamespace(release=release), raising=False)
    assert acidbase_boot.on_wsl() is expected


def test_fetch_goes_through_windows_on_wsl(monkeypatch):
    bridge = MagicMock(return_value={"NAME": CANARY})
    monkeypatch.setattr(acidbase_boot, "on_wsl", lambda: True)
    monkeypatch.setattr(acidbase_boot, "windows_keyring", bridge)
    assert acidbase_boot.fetch("demo", ["NAME"]) == {"NAME": CANARY}
    assert bridge.call_args.args[0] == {"op": "get", "service": "demo", "items": {"NAME": ""}}


def test_fetch_leaves_out_what_the_keyring_does_not_hold(monkeypatch):
    fake = SimpleNamespace(get_password=lambda service, name: CANARY if name == "HELD" else None)
    monkeypatch.setattr(acidbase_boot, "on_wsl", lambda: False)
    monkeypatch.setitem(sys.modules, "keyring", fake)
    assert acidbase_boot.fetch("demo", ["HELD", "GONE"]) == {"HELD": CANARY}


def test_the_bridge_sends_secrets_on_stdin_and_not_in_the_arguments(monkeypatch):
    done = SimpleNamespace(stdout="{}")
    run = MagicMock(return_value=done)
    monkeypatch.setattr("shutil.which", lambda name: "/mnt/c/python.exe")
    monkeypatch.setattr(subprocess, "run", run)
    acidbase_boot.windows_keyring({"op": "set", "service": "demo", "items": {"NAME": CANARY}})
    assert not any(CANARY in part for part in run.call_args.args[0])
    assert run.call_args.args[0][:2] == ["/mnt/c/python.exe", "-P"]
    assert CANARY in run.call_args.kwargs["input"]


def test_the_bridge_needs_windows_python(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(FileNotFoundError):
        acidbase_boot.windows_keyring({"op": "get", "service": "demo", "items": {}})


def test_the_bridge_code_runs_against_a_stand_in_keyring(tmp_path):
    (tmp_path / "keyring.py").write_text(
        "import os\n"
        "def get_password(service, name):\n"
        "    return 'held-' + service if name == 'HELD' else None\n"
        "def set_password(service, name, value):\n"
        "    open(os.environ['STAND_IN_FILE'], 'w').write(service + '|' + name + '|' + value)\n",
        encoding="utf-8",
    )
    written = tmp_path / "written.txt"
    env = {**os.environ, "PYTHONPATH": str(tmp_path), "STAND_IN_FILE": str(written)}

    def run(job):
        done = subprocess.run(
            [sys.executable, "-c", acidbase_boot.BRIDGE],
            input=json.dumps(job),
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        return json.loads(done.stdout)

    assert run({"op": "get", "service": "demo", "items": {"HELD": "", "GONE": ""}}) == {"HELD": "held-demo"}
    assert run({"op": "set", "service": "demo", "items": {"NAME": "é value"}}) == {}
    assert written.read_text(encoding=None) == "demo|NAME|é value"
