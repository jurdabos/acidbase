"""
Moves a repo's .env secrets into the keyring, where the startup hook in acidbase_boot.py finds them.

Every step prints variable names and never values, and can be repeated. In order:

    plan     lists what would move, and changes nothing
    copy     stores the secrets in the keyring and verifies each one, leaving .env alone
    strip    replaces each verified secret in .env with a "# keyring: NAME" marker
    restore  writes marked secrets back into .env, which undoes strip

Later on, set stores a new value for one secret, which is how a moved secret gets rotated. Each entry sits under the
repo's folder name in lower case, so the same variable in two repos makes two entries.

Windows uses Credential Manager. WSL uses the same store through Windows' Python, so one secret lives in one place and
nothing asks for a password. Elsewhere it is whatever the keyring library finds, such as the Secret Service.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

from acidbase.cli_utils import group
from acidbase_boot import on_wsl, windows_keyring

SECRET_NAME = re.compile(r"(?i)pass|secret|token|api_?key|private|credential|_key$|_salt$")
URL_PASSWORD = re.compile(r"://[^/\s:@]+:[^/\s@]+@")
ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=(.*)$")
MARKER = re.compile(r"^# keyring: ([A-Za-z_]\w*)\s*$")
VARIABLE = re.compile(r"[A-Za-z_]\w*")
# Matching the sample values the fleet's .gitleaks.toml allows, plus the house REAL prefix
PLACEHOLDER = re.compile(
    r"(?i)\{\{.*\}\}|<.*>|(?-i:REAL[A-Z0-9_]*)|your[_-].*|.*_here|change[_-]?me|x{3,}"
    r"|placeholder|example[_-]?token|db_user|db_password"
)
PLAIN_VALUE = re.compile(r"[\w./:@%+=,-]*")
COMPOSE_FILE = re.compile(r"compose[^/\\]*\.ya?ml$")
ENV_FILE_MENTION = re.compile(r"(?<![\w.-])\.env(?![\w.-])")
# Matching .env itself, under any folder, and not siblings such as .env.production
ENV_PATH = r"""["']?(?:[^\s"'=]*[/\\])?\.env(?![\w.-])"""
SYSTEMD_ENV_FILE = re.compile(rf"(?m)^\s*EnvironmentFile\s*=\s*-?{ENV_PATH}")
ENV_FILE_FLAG = re.compile(rf"--env-file[=\s]+{ENV_PATH}")
DOTENV_VALUES = re.compile(r"\bdotenv_values\(")
SHELL_SUFFIXES = {".ps1", ".psm1", ".sh", ".bash", ".bat", ".cmd"}
PYTHON_SUFFIXES = {".ipynb", ".py"}
TEXT_SUFFIXES = {".conf", ".md", ".mk", ".rst", ".service", ".toml", ".txt", ".yaml", ".yml"}
BUILD_NAMES = {"dockerfile", "justfile", "makefile", "procfile"}
MAX_SCANNED_BYTES = 2_000_000
SKIPPED_FOLDERS = {".git", ".venv", "node_modules", "__pycache__"}
HOOK_FILE = "acidbase_keyring.pth"


@dataclass(frozen=True)
class Entry:
    """
    Holds one assignment in a .env file. A value of None means its form is too unusual to trust.
    """

    index: int
    name: str
    value: str | None


class WindowsStore:
    """
    Reaches the Windows keyring from WSL with the interface of the keyring module.
    """

    def get_password(self, service: str, name: str) -> str | None:
        """
        Returns the stored value, or None.
        """
        return windows_keyring({"op": "get", "service": service, "items": {name: ""}}).get(name)

    def set_password(self, service: str, name: str, value: str) -> None:
        """
        Stores a value.
        """
        windows_keyring({"op": "set", "service": service, "items": {name: value}})


def load_store() -> Any:
    """
    Returns what reads and writes the keyring on this machine.
    """
    if on_wsl():
        return WindowsStore()
    import keyring

    return keyring


def parse_value(raw: str) -> str | None:
    """
    Returns the value of a .env assignment, or None when its form is too unusual to trust.
    Interpolation, escapes and multi-line values read differently across tools, so guessing could store a wrong secret.
    """
    text = raw.strip()
    quote_mark = text[:1]
    if quote_mark in {"'", '"'}:
        end = text.find(quote_mark, 1)
        if end == -1 or text[end + 1 :].strip()[:1] not in {"", "#"}:
            return None
        value = text[1:end]
        return None if quote_mark == '"' and ("\\" in value or "$" in value) else value
    value = re.split(r"\s#", text, maxsplit=1)[0].strip()
    return None if "$" in value or "`" in value else value


def read_lines(path: Path) -> list[str]:
    """
    Returns the lines of a file with their endings, so a rewrite changes only what it means to.
    """
    return path.read_bytes().decode("utf-8-sig").splitlines(keepends=True)


def parse_env(lines: list[str]) -> list[Entry]:
    """
    Returns every assignment in the lines of a .env file.
    """
    entries = []
    for index, line in enumerate(lines):
        match = ASSIGNMENT.match(line.rstrip("\r\n"))
        if match:
            entries.append(Entry(index, match[1], parse_value(match[2])))
    return entries


def markers(lines: list[str]) -> dict[str, int]:
    """
    Returns the secrets already moved out of a .env file, by name, with their line index.
    """
    found = (MARKER.match(line.rstrip("\r\n")) for line in lines)
    return {match[1]: index for index, match in enumerate(found) if match}


def is_secret(entry: Entry) -> bool:
    """
    Tells whether an entry looks secret, by its name or by a password inside a URL value.
    """
    return bool(SECRET_NAME.search(entry.name) or URL_PASSWORD.search(entry.value or ""))


def is_placeholder(value: str) -> bool:
    """
    Tells whether a value is a sample left unfilled, such as {{lastfm_api_key}}, which is no secret to store.
    """
    return bool(PLACEHOLDER.fullmatch(value))


def is_movable(entry: Entry) -> bool:
    """
    Tells whether an entry holds a real value, as opposed to nothing, an unusual form or a placeholder.
    """
    return bool(entry.value) and not is_placeholder(entry.value)


def chosen(entries: list[Entry], only: set[str], skip: set[str]) -> list[Entry]:
    """
    Applies --only and --skip to the entries, keeping the likely secrets by default.
    """
    picked = [entry for entry in entries if (entry.name in only if only else is_secret(entry))]
    return [entry for entry in picked if entry.name not in skip]


def read_text(path: Path) -> str:
    """
    Returns a file's text, or nothing when it cannot be read or is too large to be a script or a page of documentation,
    since a scan should not stop on one odd file.
    """
    try:
        if path.stat().st_size > MAX_SCANNED_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def how_it_bypasses_the_hook(path: Path, names: list[str]) -> str:
    """
    Says how a file takes values from .env without the process environment, or nothing when it does not.
    Documentation counts, because a command it describes stops working all the same.
    """
    suffix = path.suffix.lower()
    is_compose = bool(COMPOSE_FILE.search(path.name))
    is_shell = suffix in SHELL_SUFFIXES
    is_python = suffix in PYTHON_SUFFIXES
    if not (is_compose or is_shell or is_python or suffix in TEXT_SUFFIXES or path.name.lower() in BUILD_NAMES):
        return ""
    text = read_text(path)
    if SYSTEMD_ENV_FILE.search(text):
        return "systemd EnvironmentFile"
    if ENV_FILE_FLAG.search(text):
        return "--env-file"
    if is_python and DOTENV_VALUES.search(text):
        return "dotenv_values, which ignores the environment"
    if is_compose and "env_file" in text:
        return "Compose env_file"
    if is_compose and any(f"${{{name}" in text for name in names):
        return "Compose interpolation"
    if is_shell and (ENV_FILE_MENTION.search(text) or any(name in text for name in names)):
        return "a script"
    return ""


def systemd_folders() -> list[Path]:
    """
    Returns where installed systemd units live, which do not exist on Windows.
    """
    return [Path("/etc/systemd/system"), Path.home() / ".config" / "systemd" / "user"]


def installed_unit_readers(repo: Path) -> list[tuple[str, str]]:
    """
    Lists installed systemd units that depend on the repo, which may have no tracked copy to find in it.
    A service with no EnvironmentFile counts too, because whatever it loads from .env, the hook cannot reach the
    keyring from a service: its PATH lacks python.exe in WSL, and elsewhere it has no login session.
    """
    repo_path = re.compile(rf"{re.escape(repo.as_posix())}(?![\w.-])")
    units = [
        unit
        for folder in systemd_folders()
        for pattern in ("*.service", "*.service.d/*.conf")
        for unit in sorted(folder.glob(pattern))
    ]
    found = []
    for unit in units:
        text = read_text(unit).replace("%h", Path.home().as_posix())
        if repo_path.search(text):
            how = "systemd EnvironmentFile" if SYSTEMD_ENV_FILE.search(text) else "it runs as a service"
            found.append((unit.as_posix(), f"installed, {how}"))
    return found


def direct_readers(repo: Path, names: list[str]) -> list[tuple[str, str]]:
    """
    Lists what the startup hook cannot serve, because it fills the environment of Python processes it can start in.
    Args:
        repo: The repo to scan
        names: The variables about to move
    Returns:
        Each file, repo-relative unless installed elsewhere, with how it bypasses the hook
    """
    found = [(".astro", "Astro")] if (repo / ".astro").is_dir() else []
    for folder, subfolders, files in os.walk(repo):
        subfolders[:] = [name for name in subfolders if name not in SKIPPED_FOLDERS]
        for name in files:
            path = Path(folder) / name
            how = how_it_bypasses_the_hook(path, names)
            if how:
                found.append((path.relative_to(repo).as_posix(), how))
    return found + installed_unit_readers(repo)


def hook_installed(repo: Path) -> bool:
    """
    Tells whether the repo's venv holds the startup hook, without which a stripped secret would just be gone.
    """
    venv = repo / ".venv"
    return (venv / "Lib" / "site-packages" / HOOK_FILE).is_file() or any(
        venv.glob(f"lib/python*/site-packages/{HOOK_FILE}")
    )


def plan(repo: Path, service: str, picks: list[Entry], lines: list[str]) -> int:
    """
    Prints what would move, and changes nothing.
    """
    click.echo(f"Service {service}: {len(picks)} to consider, {len(markers(lines))} already moved.")
    store = load_store()
    for entry in picks:
        if entry.value is None:
            click.echo(f"  by hand  {entry.name} (unusual format)")
        elif not entry.value:
            click.echo(f"  empty    {entry.name}")
        elif is_placeholder(entry.value):
            click.echo(f"  sample   {entry.name} (a placeholder, so it stays)")
        else:
            try:
                held = store.get_password(service, entry.name)
            except Exception as error:  # to name the failure without its message, which could quote the value
                click.echo(f"  unknown  {entry.name} ({type(error).__name__})")
                continue
            state = "stored  " if held == entry.value else "differs " if held else "move    "
            hint = " (password in a URL)" if not SECRET_NAME.search(entry.name) else ""
            click.echo(f"  {state} {entry.name}{hint}")
    for reader, how in direct_readers(repo, [entry.name for entry in picks]):
        click.echo(f"  warning  {reader} bypasses the startup hook ({how}), so strip would break it. Use copy only.")
    if not hook_installed(repo):
        click.echo("  warning  .venv has no startup hook yet. Run uv lock --upgrade-package acidbase, then uv sync.")
    return 0


def copy(service: str, picks: list[Entry], overwrite: bool) -> int:
    """
    Stores each secret and reads it back. One failure does not stop the rest, and it fails the run at the end.
    """
    store = load_store()
    counts = {"stored": 0, "kept": 0, "failed": 0}
    for entry in picks:
        if not is_movable(entry):
            click.echo(f"  skipped  {entry.name} (empty, unusual or a placeholder)")
            continue
        try:
            held = store.get_password(service, entry.name)
            if held and held != entry.value and not overwrite:
                click.echo(f"  kept     {entry.name} (keyring differs, pass --overwrite to replace)")
                counts["kept"] += 1
                continue
            store.set_password(service, entry.name, entry.value)
            verified = store.get_password(service, entry.name) == entry.value
        except Exception as error:  # to name the failure without its message, which could quote the value
            click.echo(f"  failed   {entry.name} ({type(error).__name__})")
            counts["failed"] += 1
            continue
        click.echo(f"  {'stored  ' if verified else 'failed  '} {entry.name}")
        counts["stored" if verified else "failed"] += 1
    click.echo(", ".join(f"{count} {label}" for label, count in counts.items()))
    return 1 if counts["failed"] else 0


def strip(repo: Path, service: str, picks: list[Entry], lines: list[str]) -> int:
    """
    Replaces each secret in .env with a marker, only where the keyring holds the identical value and the hook exists.
    """
    if not hook_installed(repo):
        click.echo("Refused: .venv has no startup hook, so nothing would read the keyring.", err=True)
        click.echo("Run uv lock --upgrade-package acidbase, then uv sync.", err=True)
        return 2
    store = load_store()
    removed = refused = 0
    for entry in picks:
        if not is_movable(entry):
            continue
        if store.get_password(service, entry.name) != entry.value:
            click.echo(f"  refused  {entry.name} (keyring does not hold this value, run copy first)")
            refused += 1
            continue
        ending = lines[entry.index][len(lines[entry.index].rstrip("\r\n")) :]
        lines[entry.index] = f"# keyring: {entry.name}{ending}"
        click.echo(f"  stripped {entry.name}")
        removed += 1
    if removed:
        # Writing in place, because replacing the file would lose its mode and ACL
        (repo / ".env").write_bytes("".join(lines).encode("utf-8"))
    click.echo(f"{removed} stripped, {refused} refused.")
    return 1 if refused else 0


def quote(value: str) -> str:
    """
    Returns a value in a form .env parsers read back unchanged.
    """
    if PLAIN_VALUE.fullmatch(value):
        return value
    if "'" not in value:
        return f"'{value}'"
    return f'"{value}"'


def restore(repo: Path, service: str, lines: list[str]) -> int:
    """
    Writes marked secrets back into .env, which undoes strip.
    """
    store = load_store()
    restored = missing = 0
    for name, index in markers(lines).items():
        value = store.get_password(service, name)
        if value is None:
            click.echo(f"  missing  {name} (not in the keyring)")
            missing += 1
            continue
        ending = lines[index][len(lines[index].rstrip("\r\n")) :]
        lines[index] = f"{name}={quote(value)}{ending}"
        click.echo(f"  restored {name}")
        restored += 1
    if restored:
        (repo / ".env").write_bytes("".join(lines).encode("utf-8"))
    click.echo(f"{restored} restored, {missing} missing.")
    return 1 if missing else 0


def add_marker(repo: Path, name: str, lines: list[str]) -> None:
    """
    Appends a marker to .env in the file's own line ending, so the hook starts reading a brand-new secret.
    """
    ending = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += ending
    lines.append(f"# keyring: {name}{ending}")
    (repo / ".env").write_bytes("".join(lines).encode("utf-8"))


def set_secret(repo: Path, service: str, name: str, value: str, lines: list[str]) -> int:
    """
    Stores one value and reads it back, and marks the name in .env only once the store holds it.
    """
    store = load_store()
    try:
        store.set_password(service, name, value)
        verified = store.get_password(service, name) == value
    except Exception as error:  # to name the failure without its message, which could quote the value
        click.echo(f"  failed   {name} ({type(error).__name__})")
        return 1
    if not verified:
        click.echo(f"  failed   {name} (the keyring did not return this value)")
        return 1
    if name not in markers(lines):
        add_marker(repo, name, lines)
    click.echo(f"  stored   {name}")
    return 0


def split_names(text: str) -> set[str]:
    """
    Returns the names in a comma-separated option.
    """
    return {name.strip() for name in text.split(",") if name.strip()}


def open_repo(repo: Path) -> tuple[Path, list[str]]:
    """
    Resolves a repo argument into its folder and the lines of its .env.
    """
    root = repo.resolve()
    path = root / ".env"
    if not path.is_file():
        raise click.ClickException(f"No .env in {root}")
    return root, read_lines(path)


def service_of(root: Path) -> str:
    """
    Returns the keyring service of a repo, which must match what the startup hook looks up.
    """
    return root.name.lower()


def picks_from(lines: list[str], only: str, skip: str) -> list[Entry]:
    """
    Returns the entries a step acts on.
    """
    return chosen(parse_env(lines), split_names(only), split_names(skip))


REPO_ARGUMENT = click.argument("repo", type=click.Path(path_type=Path, file_okay=False, exists=True), default=".")
ONLY_OPTION = click.option("--only", default="", help="Comma-separated names, instead of the likely secrets.")
SKIP_OPTION = click.option("--skip", default="", help="Comma-separated names to leave alone.")


@group("keyring", help="Moves .env secrets into the keyring. Prints names, never values.")
def keyring_command() -> None:
    """
    Groups the steps of the move.
    """


@keyring_command.command("plan")
@REPO_ARGUMENT
@ONLY_OPTION
@SKIP_OPTION
@click.pass_context
def plan_command(ctx: click.Context, repo: Path, only: str, skip: str) -> None:
    """
    Lists what would move, and changes nothing.
    """
    root, lines = open_repo(repo)
    ctx.exit(plan(root, service_of(root), picks_from(lines, only, skip), lines))


@keyring_command.command("copy")
@REPO_ARGUMENT
@ONLY_OPTION
@SKIP_OPTION
@click.option("--overwrite", is_flag=True, help="Replaces a different value in the keyring.")
@click.pass_context
def copy_command(ctx: click.Context, repo: Path, only: str, skip: str, overwrite: bool) -> None:
    """
    Stores the secrets in the keyring and verifies each one, leaving .env alone.
    """
    root, lines = open_repo(repo)
    ctx.exit(copy(service_of(root), picks_from(lines, only, skip), overwrite))


@keyring_command.command("strip")
@REPO_ARGUMENT
@ONLY_OPTION
@SKIP_OPTION
@click.pass_context
def strip_command(ctx: click.Context, repo: Path, only: str, skip: str) -> None:
    """
    Replaces each verified secret in .env with a marker.
    """
    root, lines = open_repo(repo)
    ctx.exit(strip(root, service_of(root), picks_from(lines, only, skip), lines))


@keyring_command.command("restore")
@REPO_ARGUMENT
@click.option("--service", help="The old folder name after a rename, since entries stay under the name they got.")
@click.pass_context
def restore_command(ctx: click.Context, repo: Path, service: str | None) -> None:
    """
    Writes marked secrets back into .env, which undoes strip.
    """
    root, lines = open_repo(repo)
    ctx.exit(restore(root, service or service_of(root), lines))


@keyring_command.command("set")
@click.argument("name")
@REPO_ARGUMENT
@click.pass_context
def set_command(ctx: click.Context, name: str, repo: Path) -> None:
    """
    Stores a new value for one secret, asking for it without echo. This also adds a secret .env never held.
    """
    if not VARIABLE.fullmatch(name):
        raise click.BadParameter(f"{name} is not a variable name.", param_hint="NAME")
    root, lines = open_repo(repo)
    if not hook_installed(root):
        click.echo("Refused: .venv has no startup hook, so nothing would read the keyring.", err=True)
        click.echo("Run uv lock --upgrade-package acidbase, then uv sync.", err=True)
        ctx.exit(2)
    if any(entry.name == name for entry in parse_env(lines)):
        click.echo(f"Refused: {name} is a plain line in .env, which would hide the keyring value.", err=True)
        click.echo("Edit it there, or run copy and strip first.", err=True)
        ctx.exit(2)
    value = click.prompt(f"Value for {name}", hide_input=True, confirmation_prompt=True)
    ctx.exit(set_secret(root, service_of(root), name, value, lines))
