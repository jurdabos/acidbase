"""
Tests the .env to keyring move in acidbase.keyring_cli against a fake keyring. Every secret in here is a canary.
"""

import pytest
from click.testing import CliRunner

from acidbase import keyring_cli
from acidbase.cli import main as acidbase_main
from acidbase.keyring_cli import keyring_command

CANARY = "canary-value-do-not-print"
ENV_TEXT = f"""# A comment stays
API_TOKEN={CANARY}
DEBUG=true
DB_URL=mysql://user:{CANARY}@host/db
EMPTY_PASSWORD=
"""


class FakeStore:
    """
    Holds passwords in a dictionary, and can be told to fail or to lose what it stores.
    """

    def __init__(self):
        self.items: dict[tuple[str, str], str] = {}
        self.fail_on: str | None = None
        self.lossy = False

    def get_password(self, service, name):
        return self.items.get((service, name))

    def set_password(self, service, name, value):
        if name == self.fail_on:
            raise OSError(f"could not store {value}")
        if not self.lossy:
            self.items[(service, name)] = value


@pytest.fixture
def store(monkeypatch):
    fake = FakeStore()
    monkeypatch.setattr(keyring_cli, "load_store", lambda: fake)
    return fake


@pytest.fixture
def repo(tmp_path):
    folder = tmp_path / "demo"
    hook = folder / ".venv" / "Lib" / "site-packages" / keyring_cli.HOOK_FILE
    hook.parent.mkdir(parents=True)
    hook.touch()
    (folder / ".env").write_bytes(ENV_TEXT.encode())
    return folder


def step(repo, name, *extra):
    return CliRunner().invoke(keyring_command, [name, str(repo), *extra])


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("plain", "plain"),
        ("  spaced  ", "spaced"),
        ("value # comment", "value"),
        ("val#ue", "val#ue"),
        ("'single quoted'", "single quoted"),
        ('"double quoted"', "double quoted"),
        ("'kept # hash'  # comment", "kept # hash"),
        ("", ""),
        ("'unclosed", None),
        ('"has $VAR"', None),
        ('"has \\n escape"', None),
        ("unquoted$dollar", None),
        ("back`tick", None),
        ("'closed' then text", None),
    ],
)
def test_parses_values_or_refuses_to_guess(raw, expected):
    assert keyring_cli.parse_value(raw) == expected


def test_finds_secrets_by_name_and_by_password_in_a_url():
    entries = keyring_cli.parse_env(ENV_TEXT.splitlines(keepends=True))
    assert [e.name for e in keyring_cli.chosen(entries, set(), set())] == ["API_TOKEN", "DB_URL", "EMPTY_PASSWORD"]


@pytest.mark.parametrize("name", ["AES_ENCRYPTION_KEY", "AES_ENCRYPTION_SALT", "KAGGLE_KEY", "my_api_key"])
def test_counts_keys_and_salts_as_secrets(name):
    assert keyring_cli.is_secret(keyring_cli.Entry(0, name, "value"))


@pytest.mark.parametrize("name", ["DEBUG", "MONKEY", "KEYBOARD", "SALTY_SNACK", "LOG_LEVEL"])
def test_leaves_ordinary_names_alone(name):
    assert not keyring_cli.is_secret(keyring_cli.Entry(0, name, "value"))


def test_only_and_skip_override_the_guess():
    entries = keyring_cli.parse_env(ENV_TEXT.splitlines(keepends=True))
    assert [e.name for e in keyring_cli.chosen(entries, {"DEBUG"}, set())] == ["DEBUG"]
    picked = keyring_cli.chosen(entries, set(), {"DB_URL", "EMPTY_PASSWORD"})
    assert [e.name for e in picked] == ["API_TOKEN"]


def test_the_command_hangs_off_the_acidbase_cli():
    result = CliRunner().invoke(acidbase_main, ["keyring", "--help"])
    assert result.exit_code == 0
    for name in ("plan", "copy", "strip", "restore"):
        assert name in result.output


def test_plan_changes_nothing(repo, store):
    assert step(repo, "plan").exit_code == 0
    assert not store.items
    assert (repo / ".env").read_bytes() == ENV_TEXT.encode()


@pytest.mark.parametrize(
    "path,content",
    [
        ("compose/docker-compose.yml", "services:\n  a:\n    env_file: ../.env\n"),
        ("docker-compose.local.yml", "services:\n  a:\n    environment:\n      X: ${API_TOKEN:?set it}\n"),
        ("tool/start.ps1", "Get-Content .env | ForEach-Object { $_ }\n"),
        ("tool/start.sh", 'curl -H "$API_TOKEN" localhost\n'),
    ],
)
def test_plan_warns_about_readers_the_hook_cannot_reach(repo, store, path, content):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    assert f"{path} reads .env directly" in step(repo, "plan").output


def test_plan_warns_about_an_astro_project(repo, store):
    (repo / ".astro").mkdir()
    assert ".astro reads .env directly" in step(repo, "plan").output


@pytest.mark.parametrize(
    "path,content",
    [
        ("tool/copy.sh", "cp .env.example backup.txt\n"),
        (".venv/Scripts/Activate.ps1", "Get-Content .env\n"),
        ("src/app.py", "load_dotenv('.env')\n"),
    ],
)
def test_plan_ignores_what_only_looks_like_a_reader(repo, store, path, content):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    assert "reads .env directly" not in step(repo, "plan").output


def test_plan_warns_when_the_venv_has_no_hook(tmp_path, store):
    (tmp_path / ".env").write_text(f"API_TOKEN={CANARY}\n", encoding="utf-8")
    assert "no startup hook" in step(tmp_path, "plan").output


def test_finds_the_hook_in_a_posix_venv(tmp_path):
    hook = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages" / keyring_cli.HOOK_FILE
    hook.parent.mkdir(parents=True)
    hook.touch()
    assert keyring_cli.hook_installed(tmp_path)


def test_copy_stores_verifies_and_leaves_env_alone(repo, store):
    assert step(repo, "copy").exit_code == 0
    assert store.items[("demo", "API_TOKEN")] == CANARY
    assert ("demo", "EMPTY_PASSWORD") not in store.items
    assert (repo / ".env").read_bytes() == ENV_TEXT.encode()


def test_copy_keeps_a_different_keyring_value_unless_told(repo, store):
    store.items[("demo", "API_TOKEN")] = "something else"
    result = step(repo, "copy")
    assert result.exit_code == 0
    assert store.items[("demo", "API_TOKEN")] == "something else"
    assert "keyring differs" in result.output
    assert step(repo, "copy", "--overwrite").exit_code == 0
    assert store.items[("demo", "API_TOKEN")] == CANARY


def test_copy_reports_one_failure_and_finishes_the_rest(repo, store):
    store.fail_on = "API_TOKEN"
    result = step(repo, "copy")
    assert result.exit_code == 1
    assert "failed   API_TOKEN (OSError)" in result.output
    assert ("demo", "DB_URL") in store.items
    assert CANARY not in result.output


def test_copy_fails_when_the_read_back_differs(repo, store):
    store.lossy = True
    assert step(repo, "copy").exit_code == 1


def test_strip_refuses_a_value_the_keyring_does_not_hold(repo, store):
    result = step(repo, "strip")
    assert result.exit_code == 1
    assert "refused  API_TOKEN" in result.output
    assert (repo / ".env").read_bytes() == ENV_TEXT.encode()


def test_strip_refuses_without_the_hook(repo, store):
    step(repo, "copy")
    (repo / ".venv" / "Lib" / "site-packages" / keyring_cli.HOOK_FILE).unlink()
    assert step(repo, "strip").exit_code == 2
    assert (repo / ".env").read_bytes() == ENV_TEXT.encode()


def test_strip_replaces_only_verified_secrets_and_keeps_the_rest(repo, store):
    step(repo, "copy")
    assert step(repo, "strip").exit_code == 0
    text = (repo / ".env").read_text(encoding="utf-8")
    assert CANARY not in text
    assert "# keyring: API_TOKEN" in text
    assert "# keyring: DB_URL" in text
    assert "DEBUG=true" in text
    assert "# A comment stays" in text
    assert "EMPTY_PASSWORD=" in text


def test_strip_keeps_crlf_line_endings(repo, store):
    (repo / ".env").write_bytes(ENV_TEXT.replace("\n", "\r\n").encode())
    step(repo, "copy")
    step(repo, "strip")
    raw = (repo / ".env").read_bytes()
    assert b"# keyring: API_TOKEN\r\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_strip_can_run_twice(repo, store):
    step(repo, "copy")
    step(repo, "strip")
    assert step(repo, "strip").exit_code == 0


def test_restore_undoes_strip_exactly(repo, store):
    step(repo, "copy")
    step(repo, "strip")
    assert step(repo, "restore").exit_code == 0
    assert (repo / ".env").read_bytes() == ENV_TEXT.encode()


@pytest.mark.parametrize("value", ["plain", "with space", "has#hash", 'has"quote', "it's"])
def test_quoted_values_parse_back_unchanged(value):
    assert keyring_cli.parse_value(keyring_cli.quote(value)) == value


def test_restore_reports_a_missing_secret(repo, store):
    step(repo, "copy")
    step(repo, "strip")
    store.items.clear()
    result = step(repo, "restore")
    assert result.exit_code == 1
    assert "missing  API_TOKEN" in result.output
    assert "# keyring: API_TOKEN" in (repo / ".env").read_text(encoding="utf-8")


def test_service_defaults_to_the_folder_name_in_lower_case(tmp_path, store):
    folder = tmp_path / "MyRepo"
    folder.mkdir()
    (folder / ".env").write_text(f"API_TOKEN={CANARY}\n", encoding="utf-8")
    step(folder, "copy")
    assert ("myrepo", "API_TOKEN") in store.items


def test_repo_defaults_to_the_current_folder(repo, store, monkeypatch):
    monkeypatch.chdir(repo)
    assert CliRunner().invoke(keyring_command, ["copy"]).exit_code == 0
    assert ("demo", "API_TOKEN") in store.items


def test_a_missing_env_file_is_reported(tmp_path, store):
    result = step(tmp_path, "plan")
    assert result.exit_code == 1
    assert "No .env" in result.output


def test_wsl_goes_through_the_windows_store(monkeypatch):
    calls = []

    def bridge(job):
        calls.append(job)
        return {"NAME": CANARY} if job["op"] == "get" else {}

    monkeypatch.setattr(keyring_cli, "on_wsl", lambda: True)
    monkeypatch.setattr(keyring_cli, "windows_keyring", bridge)
    store = keyring_cli.load_store()
    assert store.get_password("demo", "NAME") == CANARY
    assert store.get_password("demo", "NAME") is not None
    store.set_password("demo", "NAME", "new")
    assert calls[-1] == {"op": "set", "service": "demo", "items": {"NAME": "new"}}


@pytest.mark.parametrize("name", ["plan", "copy", "strip", "restore"])
def test_no_step_ever_prints_a_value(repo, store, name):
    step(repo, "copy")
    assert CANARY not in step(repo, name).output
