"""Tests for the fleet manifest: registration, census, rendering, and path translation."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path, PurePosixPath, PureWindowsPath

import click
import pytest
from click.testing import CliRunner

from acidbase import fleet as fleet_module
from acidbase.cli import main
from acidbase.collation import abc_key
from acidbase.fleet import (
    WINDOWS,
    WSL,
    CensusState,
    FleetEntry,
    add_entry,
    consumes_acidbase,
    infer_cli,
    load_fleet,
    localize,
    native_location,
    remove_entry,
    render_entries,
    resolve_fleet_file,
    run_census,
    save_fleet,
    stored_path,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ACIDBASE_DEP = '"acidbase @ git+https://github.com/jurdabos/acidbase.git"'


def _project(
    root: Path,
    name: str,
    *,
    dependency: bool = True,
    scripts: dict[str, str] | None = None,
    extra: str = "",
) -> Path:
    """Creates a minimal project directory and returns it."""
    project = root / name
    project.mkdir(parents=True)
    deps = f"[{_ACIDBASE_DEP}]" if dependency else '["click>=8"]'
    lines = [f'[project]\nname = "{name.lower()}"\nversion = "0.1.0"\ndependencies = {deps}\n']
    if scripts is None:
        scripts = {name.lower(): f"{name.lower().replace('-', '_')}.cli:main"}
    if scripts:
        lines.append("[project.scripts]\n" + "".join(f'{key} = "{value}"\n' for key, value in scripts.items()))
    (project / "pyproject.toml").write_text("\n".join(lines) + extra, encoding="utf-8")
    return project


def _manifest(path: Path, entries: list[FleetEntry], *, roots: str = "", ignore: str = "[]") -> Path:
    """Writes a manifest with a header comment, census settings, and the given entries."""
    blocks = ["# Fleet manifest under test.\n", f"[census]\nignore = {ignore}\n"]
    if roots:
        blocks.append(f"[census.roots]\n{roots}\n")
    for entry in entries:
        text = f'[[repo]]\nname = "{entry.name}"\nhost = "{entry.host}"\npath = \'{entry.path}\'\ncli = "{entry.cli}"\n'
        if entry.mypy:
            text += f'mypy = "{entry.mypy}"\n'
        blocks.append(text)
    path.write_text("\n".join(blocks), encoding="utf-8")
    return path


def _here() -> str:
    """Returns the host label the tests run on."""
    return fleet_module.current_host()


def test_consumer_detection_ignores_comments_and_the_metarepo(tmp_path: Path) -> None:
    commented = '[project]\nname = "x"\n# acidbase is mentioned here only\ndependencies = ["click"]\n'
    assert consumes_acidbase(tomllib.loads(commented)) is False
    grouped = '[project]\nname = "x"\n[dependency-groups]\ndev = ["acidbase>=0.1"]\n'
    assert consumes_acidbase(tomllib.loads(grouped)) is True
    extra = '[project]\nname = "x"\n[project.optional-dependencies]\ntools = ["acidbase"]\n'
    assert consumes_acidbase(tomllib.loads(extra)) is True
    metarepo = '[project]\nname = "acidbase"\ndependencies = ["acidbase"]\n'
    assert consumes_acidbase(tomllib.loads(metarepo)) is False


@pytest.mark.parametrize(
    ("scripts", "expected"),
    [
        ({"tool": "tool.cli:main"}, "tool"),
        ({"tool": "tool.cli:main", "push": "tool.cli:push_main"}, "tool"),
        ({"a": "a.cli:main", "b": "b.other:run"}, "a"),
        ({"a": "a.cli:main", "b": "b.cli:main"}, None),
        ({}, None),
    ],
)
def test_infer_cli(scripts: dict[str, str], expected: str | None) -> None:
    assert infer_cli(scripts) == expected


def test_stored_path_spellings() -> None:
    assert stored_path(PureWindowsPath(r"C:\repos\tool"), WINDOWS) == r"C:\repos\tool"
    home = PurePosixPath("/home/user")
    assert stored_path(PurePosixPath("/home/user/tool"), WSL, home) == "~/tool"
    assert stored_path(PurePosixPath("/home/user"), WSL, home) == "~"
    assert stored_path(PurePosixPath("/srv/tool"), WSL, home) == "/srv/tool"


def test_native_location_assigns_drive_and_home_paths_to_their_owner() -> None:
    hosts = {WINDOWS: {"wsl_home": r"\\wsl.localhost\Ubuntu\home\user"}, WSL: {"windows_mount": "/mnt"}}
    home = PurePosixPath("/home/user")
    assert native_location(PurePosixPath("/mnt/c/repos/tool"), WSL, hosts, home) == (WINDOWS, r"C:\repos\tool")
    assert native_location(PurePosixPath("/home/user/tool"), WSL, hosts, home) == (WSL, "~/tool")
    unc = PureWindowsPath(r"\\wsl.localhost\Ubuntu\home\user\tool")
    assert native_location(unc, WINDOWS, hosts) == (WSL, "~/tool")
    assert native_location(PureWindowsPath(r"D:\study\tool"), WINDOWS, hosts) == (WINDOWS, r"D:\study\tool")


def test_localize_translates_between_hosts() -> None:
    hosts = {WINDOWS: {"wsl_home": r"\\wsl.localhost\Ubuntu\home\user"}}
    assert localize("~/tool", WSL, WINDOWS, hosts) == r"\\wsl.localhost\Ubuntu\home\user\tool"
    assert localize("/srv/tool", WSL, WINDOWS, hosts) is None
    assert localize("~/tool", WSL, WINDOWS, {}) is None
    assert localize(r"C:\repos\tool", WINDOWS, WSL, {}) == "/mnt/c/repos/tool"
    assert localize(r"C:\repos\tool", WINDOWS, WSL, {WSL: {"windows_mount": "/media"}}) == "/media/c/repos/tool"
    assert localize(r"C:\repos\tool", WINDOWS, WINDOWS, {}) == r"C:\repos\tool"
    assert localize("~/tool", WSL, "darwin", hosts) is None


def test_add_entry_keeps_abecedarian_order_and_comments(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path / "fleet.toml",
        [FleetEntry("alpha", WINDOWS, r"C:\r\alpha", "alpha"), FleetEntry("Zulu", WINDOWS, r"C:\r\Zulu", "zulu")],
    )
    fleet = load_fleet(manifest)
    assert add_entry(fleet, FleetEntry("Mike", WINDOWS, r"C:\r\Mike", "mike", note="no ruff")) is True
    save_fleet(fleet)
    text = manifest.read_text(encoding="utf-8")
    assert text.startswith("# Fleet manifest under test.")
    assert "path = 'C:\\r\\Mike'" in text  # to keep paths readable as literal strings
    reloaded = load_fleet(manifest)
    names = [entry.name for entry in reloaded.entries]
    # Case-interleaved order, which plain codepoint sorting (capitals first) would get wrong.
    assert names == ["alpha", "Mike", "Zulu"] == sorted(names, key=abc_key) != sorted(names)
    assert reloaded.entries[1].note == "no ruff"
    assert "\r\n" not in manifest.read_bytes().decode("utf-8")


def test_add_entry_is_idempotent_and_refuses_conflicts(tmp_path: Path) -> None:
    fleet = load_fleet(_manifest(tmp_path / "fleet.toml", [FleetEntry("tool", WINDOWS, r"C:\r\Tool", "tool")]))
    assert add_entry(fleet, FleetEntry("Tool", WINDOWS, r"c:\R\tool", "tool")) is False
    with pytest.raises(click.ClickException, match="fleet remove tool"):
        add_entry(fleet, FleetEntry("tool", WINDOWS, r"D:\elsewhere\tool", "tool"))
    with pytest.raises(click.ClickException, match="CLI 'tool'"):
        add_entry(fleet, FleetEntry("tool", WINDOWS, r"C:\r\Tool", "other"))
    assert add_entry(fleet, FleetEntry("tool", WSL, "~/tool", "tool")) is True


def test_add_entry_creates_the_array_in_an_empty_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "fleet.toml"
    manifest.write_text("# empty\n", encoding="utf-8")
    fleet = load_fleet(manifest)
    add_entry(fleet, FleetEntry("tool", WSL, "~/tool", "tool"))
    save_fleet(fleet)
    assert [entry.name for entry in load_fleet(manifest).entries] == ["tool"]


def test_remove_entry_requires_a_host_when_ambiguous(tmp_path: Path) -> None:
    entries = [FleetEntry("tool", WINDOWS, r"C:\r\tool", "tool"), FleetEntry("tool", WSL, "~/tool", "tool")]
    fleet = load_fleet(_manifest(tmp_path / "fleet.toml", entries))
    with pytest.raises(click.ClickException, match="several hosts"):
        remove_entry(fleet, "tool")
    with pytest.raises(click.ClickException, match="not registered"):
        remove_entry(fleet, "nope")
    assert remove_entry(fleet, "tool", WSL).host == WSL
    save_fleet(fleet)
    assert [(e.name, e.host) for e in load_fleet(fleet.path).entries] == [("tool", WINDOWS)]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('[[repo]]\nname = "x"\nhost = "windows"\npath = "p"\n', "'cli' must be a non-empty string"),
        ('[[repo]]\nname = "x"\nhost = "windows"\npath = "p"\ncli = "bad name"\n', "invalid CLI name"),
        (
            '[[repo]]\nname = "x"\nhost = "wsl"\npath = "a"\ncli = "x"\n\n[[repo]]\nname = "X"\nhost = "wsl"\n'
            'path = "b"\ncli = "x"\n',
            "registered twice",
        ),
        ('[census]\nignore = "x"\n', "census.ignore"),
        ('[census.roots]\nwindows = "C:/x"\n', "census.roots.windows"),
        ("repo = [", "Cannot read fleet manifest"),
    ],
)
def test_load_fleet_rejects_malformed_manifests(tmp_path: Path, body: str, message: str) -> None:
    manifest = tmp_path / "fleet.toml"
    manifest.write_text(body, encoding="utf-8")
    with pytest.raises(click.ClickException, match=message):
        load_fleet(manifest)


def test_resolve_fleet_file_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    discovered = tmp_path / "meta" / "config" / "fleet.toml"
    discovered.parent.mkdir(parents=True)
    discovered.write_text("", encoding="utf-8")
    nested = tmp_path / "meta" / "src" / "deep"
    nested.mkdir(parents=True)
    explicit = tmp_path / "explicit.toml"
    explicit.write_text("", encoding="utf-8")
    from_env = tmp_path / "env.toml"
    from_env.write_text("", encoding="utf-8")
    monkeypatch.delenv(fleet_module.FLEET_FILE_ENV, raising=False)
    assert resolve_fleet_file(start=nested) == discovered
    monkeypatch.setenv(fleet_module.FLEET_FILE_ENV, str(from_env))
    assert resolve_fleet_file(start=nested) == from_env
    assert resolve_fleet_file(explicit, start=nested) == explicit
    monkeypatch.setenv(fleet_module.FLEET_FILE_ENV, str(tmp_path / "missing.toml"))
    with pytest.raises(click.ClickException, match="missing file"):
        resolve_fleet_file(start=nested)
    monkeypatch.delenv(fleet_module.FLEET_FILE_ENV)
    with pytest.raises(click.ClickException, match="No fleet manifest found"):
        resolve_fleet_file(start=tmp_path)
    with pytest.raises(click.ClickException, match="not found"):
        resolve_fleet_file(tmp_path / "nope.toml")


def test_census_reports_every_state(tmp_path: Path) -> None:
    here = _here()
    root = tmp_path / "repos"
    ok = _project(root, "ok-tool")
    renamed = _project(root, "renamed", scripts={"newname": "renamed.cli:main"})
    lapsed = _project(root, "lapsed", dependency=False)
    _project(root, "stray")
    _project(root, "ignored-tool")
    _project(root, "plain", dependency=False)
    (root / "broken").mkdir()
    (root / "broken" / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    entries = [
        FleetEntry("gone", here, str(root / "gone"), "gone"),
        FleetEntry("lapsed", here, str(lapsed), "lapsed"),
        FleetEntry("ok-tool", here, str(ok), "ok-tool"),
        FleetEntry("renamed", here, str(renamed), "renamed"),
        FleetEntry("elsewhere", "plan9", "/n/elsewhere", "elsewhere"),
    ]
    manifest = _manifest(
        tmp_path / "fleet.toml",
        entries,
        roots=f"{here} = ['{root}']\nplan9 = ['/n']",
        ignore='["Ignored-Tool"]',
    )
    rows = {row.name: row for row in run_census(load_fleet(manifest), here)}
    assert rows["ok-tool"].state is CensusState.OK
    assert rows["gone"].state is CensusState.MISSING
    assert rows["lapsed"].state is CensusState.NOT_A_CONSUMER
    assert rows["renamed"].state is CensusState.CLI_MISMATCH and "newname" in rows["renamed"].detail
    assert rows["elsewhere"].state is CensusState.UNREACHABLE
    assert rows["stray"].state is CensusState.UNREGISTERED and "cli=stray" in rows["stray"].detail
    assert rows["broken"].state is CensusState.UNREADABLE
    assert rows["[root] /n"].state is CensusState.UNREACHABLE
    assert "ignored-tool" not in rows and "plain" not in rows
    assert not CensusState.UNREACHABLE.failing and CensusState.UNREGISTERED.failing
    local_rows = run_census(load_fleet(manifest), here, local_only=True)
    assert all(row.host == here for row in local_rows)


def test_render_entries_formats() -> None:
    rows = [
        (FleetEntry("Alpha", WINDOWS, r"C:\r\Alpha", "alpha", mypy="src", note="a | b"), r"C:\r\Alpha"),
        (FleetEntry("delta", WSL, "~/delta", "delta"), None),
    ]
    records = json.loads(render_entries(rows, "json"))
    assert records[1] == {
        "name": "delta",
        "host": "wsl",
        "path": "~/delta",
        "local_path": None,
        "cli": "delta",
        "mypy": None,
        "note": None,
    }
    tsv = render_entries(rows, "tsv").splitlines()
    assert tsv[1].split("\t") == ["delta", "wsl", "~/delta", "-", "delta", "-"]
    markdown = render_entries(rows, "markdown").splitlines()
    assert markdown[0] == "| Repo | Host/path | CLI name | mypy | Note |"
    assert markdown[2] == r"| Alpha | `C:\r\Alpha` | `alpha` | `src` | a \| b |"
    assert markdown[3] == "| delta | WSL `~/delta` | `delta` | — | |"
    assert render_entries(rows, "table").splitlines()[1].startswith("delta ")


def test_cli_add_list_census_remove_round_trip(tmp_path: Path) -> None:
    here = _here()
    root = tmp_path / "repos"
    tool = _project(root, "SomeTool", scripts={"sometool": "sometool.cli:main", "push": "sometool.cli:push_main"})
    manifest = _manifest(tmp_path / "fleet.toml", [], roots=f"{here} = ['{root}']")
    runner = CliRunner()
    args = ["--fleet-file", str(manifest)]

    census = runner.invoke(main, ["fleet", "census", *args])
    assert census.exit_code == 1 and "UNREGISTERED" in census.output

    dry = runner.invoke(main, ["fleet", "add", str(tool), "--dry-run", *args])
    assert dry.exit_code == 0 and "Would register" in dry.output
    assert load_fleet(manifest).entries == ()

    added = runner.invoke(main, ["fleet", "add", str(tool), "--mypy", "src", *args])
    assert added.exit_code == 0, added.output
    again = runner.invoke(main, ["fleet", "add", str(tool), *args])
    assert again.exit_code == 0 and "Already registered" in again.output
    entry = load_fleet(manifest).entries[0]
    assert (entry.name, entry.cli, entry.mypy) == ("SomeTool", "sometool", "src")

    assert runner.invoke(main, ["fleet", "census", *args]).exit_code == 0
    listed = json.loads(runner.invoke(main, ["fleet", "list", "--format", "json", *args]).output)
    assert listed[0]["local_path"] is not None and Path(listed[0]["local_path"]) == tool.resolve()

    removed = runner.invoke(main, ["fleet", "remove", "sometool", *args])
    assert removed.exit_code == 0 and load_fleet(manifest).entries == ()


@pytest.mark.parametrize(
    ("dependency", "scripts", "name", "message"),
    [
        (False, None, "plain", "does not declare acidbase"),
        (True, {"a": "a.cli:main", "b": "b.cli:main"}, "two", "pass --cli"),
        (True, {}, "none", "scripts: none"),
    ],
)
def test_cli_add_refuses_unsuitable_repositories(
    tmp_path: Path, dependency: bool, scripts: dict[str, str] | None, name: str, message: str
) -> None:
    project = _project(tmp_path, name, dependency=dependency, scripts=scripts)
    manifest = _manifest(tmp_path / "fleet.toml", [])
    result = CliRunner().invoke(main, ["fleet", "add", str(project), "--fleet-file", str(manifest)])
    assert result.exit_code != 0 and message in result.output


def test_cli_add_refuses_the_metarepo_and_unknown_cli(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path / "fleet.toml", [])
    meta = tmp_path / "meta"
    meta.mkdir()
    (meta / "pyproject.toml").write_text('[project]\nname = "acidbase"\n', encoding="utf-8")
    result = CliRunner().invoke(main, ["fleet", "add", str(meta), "--fleet-file", str(manifest)])
    assert result.exit_code != 0 and "metarepo" in result.output
    tool = _project(tmp_path, "tool")
    result = CliRunner().invoke(main, ["fleet", "add", str(tool), "--cli", "typo", "--fleet-file", str(manifest)])
    assert result.exit_code != 0 and "'typo' is not in [project.scripts]" in result.output


def test_fleet_group_is_registered() -> None:
    result = CliRunner().invoke(main, ["fleet", "--help"])
    assert result.exit_code == 0
    for command in ("add", "census", "list", "remove"):
        assert command in result.output


def test_checkout_manifest_is_valid_and_sorted() -> None:
    """The private checkout's manifest must parse and stay abecedarian; the public mirror has none."""
    manifest = _REPO_ROOT / "config" / "fleet.toml"
    if not manifest.is_file():
        pytest.skip("no fleet manifest in this checkout")
    names = [entry.name for entry in load_fleet(manifest).entries]
    assert names == sorted(names, key=abc_key)
