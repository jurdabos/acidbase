"""
Tests the WSL keyring backend in acidbase_wsl_keyring.py and the wsl-setup step that installs it. Every secret in here is
a canary.
"""

import configparser
import inspect
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import keyring.core
import keyring.util.platform_
import pytest
from click.testing import CliRunner
from keyring.errors import KeyringError, PasswordDeleteError

import acidbase_boot
import acidbase_wsl_keyring
from acidbase import keyring_cli
from acidbase.keyring_cli import keyring_command
from acidbase_wsl_keyring import WindowsBridgeKeyring

CANARY = "canary-value-do-not-print"
OLD_BACKEND = "keyrings.alt.file.EncryptedKeyring"


@pytest.fixture
def bridge(monkeypatch):
    """
    Stands in for Windows' Python with a dictionary, and records each job.
    """
    held: dict[tuple[str, str], str] = {}
    jobs: list[dict] = []

    def run(job):
        jobs.append(job)
        found = {}
        for name, value in job["items"].items():
            key = (job["service"], name)
            if job["op"] == "get" and key in held:
                found[name] = held[key]
            elif job["op"] == "set":
                held[key] = value
            elif job["op"] == "delete" and key in held:
                del held[key]
                found[name] = ""
        return found

    monkeypatch.setattr(acidbase_boot, "windows_keyring", run)
    monkeypatch.setattr(acidbase_boot, "on_wsl", lambda: True)
    return SimpleNamespace(held=held, jobs=jobs)


def test_the_backend_is_unusable_outside_wsl(monkeypatch):
    monkeypatch.setattr(acidbase_boot, "on_wsl", lambda: False)
    assert not WindowsBridgeKeyring.viable
    with pytest.raises(RuntimeError):
        WindowsBridgeKeyring.priority


def test_the_backend_ranks_high_on_wsl(monkeypatch):
    monkeypatch.setattr(acidbase_boot, "on_wsl", lambda: True)
    assert WindowsBridgeKeyring.viable
    assert WindowsBridgeKeyring.priority >= 1


def test_sets_gets_and_deletes_through_the_bridge(bridge):
    ring = WindowsBridgeKeyring()
    ring.set_password("demo", "NAME", CANARY)
    assert ring.get_password("demo", "NAME") == CANARY
    ring.delete_password("demo", "NAME")
    assert ring.get_password("demo", "NAME") is None
    assert [job["op"] for job in bridge.jobs] == ["set", "get", "delete", "get"]


def test_deleting_what_is_not_there_raises_as_keyring_expects(bridge):
    with pytest.raises(PasswordDeleteError):
        WindowsBridgeKeyring().delete_password("demo", "GONE")


def test_a_failing_bridge_names_its_kind_and_never_quotes_it(monkeypatch):
    def fail(job):
        raise subprocess.CalledProcessError(1, ["python.exe"], output="", stderr=f"Traceback\nValueError: {CANARY}\n")

    monkeypatch.setattr(acidbase_boot, "windows_keyring", fail)
    with pytest.raises(KeyringError) as caught:
        WindowsBridgeKeyring().get_password("demo", "NAME")
    assert "ValueError" in str(caught.value)
    assert CANARY not in str(caught.value)
    assert caught.value.__cause__ is None


def test_no_windows_python_says_what_to_install(monkeypatch):
    def missing(job):
        raise FileNotFoundError("python.exe")

    monkeypatch.setattr(acidbase_boot, "windows_keyring", missing)
    with pytest.raises(KeyringError, match="uv tool install keyring"):
        WindowsBridgeKeyring().set_password("demo", "NAME", CANARY)


def test_keyring_loads_the_copied_backend_from_its_config(tmp_path, monkeypatch):
    folder = tmp_path / "modules"
    keyring_cli.install_modules(folder)
    keyring_cli.write_config(tmp_path / "config" / "keyringrc.cfg", folder)
    monkeypatch.setattr(keyring.util.platform_, "config_root", lambda: tmp_path / "config")
    monkeypatch.setattr(acidbase_boot, "on_wsl", lambda: True)
    # Restoring what keyring changes, as it puts keyring-path on sys.path and imports the copy
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.delitem(sys.modules, "acidbase_wsl_keyring")
    ring = keyring.core.load_config()
    assert type(ring).__name__ == "WindowsBridgeKeyring"
    assert inspect.getfile(type(ring)).startswith(str(folder))


def test_install_copies_both_modules_and_reports_only_changes(tmp_path):
    folder = tmp_path / "modules"
    assert keyring_cli.install_modules(folder) == ["acidbase_boot.py", "acidbase_wsl_keyring.py"]
    assert keyring_cli.install_modules(folder) == []
    (folder / "acidbase_boot.py").write_text("# stale\n", encoding="utf-8")
    assert keyring_cli.install_modules(folder) == ["acidbase_boot.py"]
    assert (folder / "acidbase_wsl_keyring.py").read_bytes() == Path(acidbase_wsl_keyring.__file__).read_bytes()


def test_config_keeps_other_settings_and_reports_the_old_backend(tmp_path):
    path = tmp_path / "keyringrc.cfg"
    path.write_text(f"[backend]\ndefault-keyring={OLD_BACKEND}\n\n[other]\nkept=yes\n", encoding="utf-8")
    assert keyring_cli.write_config(path, tmp_path / "modules") == OLD_BACKEND
    config = configparser.RawConfigParser()
    config.read(path, encoding="utf-8")
    assert config.get("backend", "default-keyring") == keyring_cli.WSL_BACKEND
    assert config.get("backend", "keyring-path") == str(tmp_path / "modules")
    assert config.get("other", "kept") == "yes"


def test_the_probe_reports_without_a_value(tmp_path, monkeypatch):
    (tmp_path / "keyring.py").write_text(
        "import json, os\n"
        "STORE = os.environ['STAND_IN_FILE']\n"
        "class Ring: pass\n"
        "def get_keyring(): return Ring()\n"
        "def load(): return json.load(open(STORE)) if os.path.exists(STORE) else {}\n"
        "def save(held): json.dump(held, open(STORE, 'w'))\n"
        "def get_password(service, name): return load().get(service + '|' + name)\n"
        "def set_password(service, name, value): held = load(); held[service + '|' + name] = value; save(held)\n"
        "def delete_password(service, name): held = load(); del held[service + '|' + name]; save(held)\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("STAND_IN_FILE", str(tmp_path / "held.json"))
    canary = {"service": "demo", "name": "NAME", "value": CANARY}
    reports = [keyring_cli.probe(sys.executable, {**canary, "op": op}) for op in ("set", "get", "delete")]
    assert reports[0] == {"backend": "keyring.Ring"}
    assert reports[1]["same"] is True
    assert reports[2]["gone"] is True
    assert CANARY not in json.dumps(reports)


@pytest.fixture
def setup_env(tmp_path, monkeypatch):
    """
    Points wsl-setup at a temporary home, and stands in for the Pythons it probes with one shared dictionary.
    """
    system_python = tmp_path / "python3"
    system_python.touch()
    monkeypatch.setattr(keyring_cli, "on_wsl", lambda: True)
    monkeypatch.setattr(keyring_cli, "data_home", lambda: tmp_path / "share")
    monkeypatch.setattr(keyring_cli, "keyring_config_path", lambda: tmp_path / "config" / "keyringrc.cfg")
    monkeypatch.setattr(keyring_cli, "SYSTEM_PYTHON", str(system_python))
    state = SimpleNamespace(held={}, values=[], backend={}, missing=set())

    def probe(python, job):
        if python in state.missing:
            raise subprocess.CalledProcessError(
                1, [python], output="", stderr="ModuleNotFoundError: No module named 'keyring'"
            )
        key = (job["service"], job["name"])
        done = {"backend": state.backend.get(python, keyring_cli.WSL_BACKEND)}
        if job["op"] == "set":
            state.held[key] = job["value"]
            state.values.append(job["value"])
        elif job["op"] == "get":
            done["same"] = state.held.get(key) == job["value"]
        elif job["op"] == "delete":
            del state.held[key]
            done["gone"] = key not in state.held
        return done

    monkeypatch.setattr(keyring_cli, "probe", probe)
    state.system_python = str(system_python)
    state.root = tmp_path
    return state


def run_setup():
    return CliRunner().invoke(keyring_command, ["wsl-setup"])


def test_wsl_setup_refuses_outside_wsl(monkeypatch):
    monkeypatch.setattr(keyring_cli, "on_wsl", lambda: False)
    result = run_setup()
    assert result.exit_code == 1
    assert "only runs in WSL" in result.output


def test_wsl_setup_proves_itself_with_a_canary_it_removes(setup_env):
    result = run_setup()
    assert result.exit_code == 0, result.output
    assert result.output.count("checked ") == 2
    assert "removed " in result.output
    assert setup_env.held == {}
    assert setup_env.values and all(value not in result.output for value in setup_env.values)
    assert (setup_env.root / "share" / "acidbase" / "keyring" / "acidbase_wsl_keyring.py").is_file()


def test_wsl_setup_fails_when_a_python_falls_back_on_another_backend(setup_env):
    setup_env.backend[setup_env.system_python] = OLD_BACKEND
    result = run_setup()
    assert result.exit_code == 1
    assert f"failed   {setup_env.system_python} reads the canary through {OLD_BACKEND}" in result.output
    assert setup_env.held == {}


def test_wsl_setup_skips_a_python_without_keyring(setup_env):
    setup_env.missing.add(setup_env.system_python)
    result = run_setup()
    assert result.exit_code == 0, result.output
    assert f"skipped  {setup_env.system_python} (no keyring library)" in result.output


def test_wsl_setup_points_at_the_old_store(setup_env):
    old_store = setup_env.root / "share" / "python_keyring" / "crypted_pass.cfg"
    old_store.parent.mkdir(parents=True)
    old_store.touch()
    assert "is the old WSL store" in run_setup().output


def test_wsl_setup_hangs_off_the_keyring_command():
    assert "wsl-setup" in keyring_command.commands
