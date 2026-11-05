"""
Moves a repo's .env secrets into the keyring, where the startup hook in acidbase_boot.py finds them.

Every step prints variable names and never values, and can be repeated. In order:

    plan     lists what would move, and changes nothing
    copy     stores the secrets in the keyring and verifies each one, leaving .env alone
    strip    replaces each verified secret in .env with a "# keyring: NAME" marker
    restore  writes marked secrets back into .env, which undoes strip

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
PLAIN_VALUE = re.compile(r"[\w./:@%+=,-]*")
COMPOSE_FILE = re.compile(r"compose[^/\\]*\.ya?ml$")
ENV_FILE_MENTION = re.compile(r"(?<![\w.-])\.env(?![\w.-])")
SHELL_SUFFIXES = {".ps1", ".psm1", ".sh", ".bash", ".bat", ".cmd"}
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


def chosen(entries: list[Entry], only: set[str], skip: set[str]) -> list[Entry]:
    """
    Applies --only and --skip to the entries, keeping the likely secrets by default.
    """
    picked = [entry for entry in entries if (entry.name in only if only else is_secret(entry))]
    return [entry for entry in picked if entry.name not in skip]


def read_text(path: Path) -> str:
    """
    Returns a file's text, or nothing when it cannot be read, since a scan should not stop on one odd file.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def reads_env_directly(path: Path, names: list[str]) -> bool:
    """
    Tells whether a file takes its values from .env without going through a Python process.
    """
    if COMPOSE_FILE.search(path.name):
        text = read_text(path)
        return "env_file" in text or any(f"${{{name}" in text for name in names)
    if path.suffix.lower() in SHELL_SUFFIXES:
        text = read_text(path)
        return bool(ENV_FILE_MENTION.search(text)) or any(name in text for name in names)
    return False


def direct_readers(repo: Path, names: list[str]) -> list[str]:
    """
    Lists what the startup hook cannot reach, because it fills the environment of Python processes only.
    Args:
        repo: The repo to scan
        names: The variables about to move
    Returns:
        Repo-relative paths, in the order found
    """
    found = [".astro"] if (repo / ".astro").is_dir() else []
    for folder, subfolders, files in os.walk(repo):
        subfolders[:] = [name for name in subfolders if name not in SKIPPED_FOLDERS]
        for name in files:
            path = Path(folder) / name
            if reads_env_directly(path, names):
                found.append(path.relative_to(repo).as_posix())
    return found


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
        else:
            try:
                held = store.get_password(service, entry.name)
            except Exception as error:  # to name the failure without its message, which could quote the value
                click.echo(f"  unknown  {entry.name} ({type(error).__name__})")
                continue
            state = "stored  " if held == entry.value else "differs " if held else "move    "
            hint = " (password in a URL)" if not SECRET_NAME.search(entry.name) else ""
            click.echo(f"  {state} {entry.name}{hint}")
    for reader in direct_readers(repo, [entry.name for entry in picks]):
        click.echo(f"  warning  {reader} reads .env directly, so strip would break it. Use copy only.")
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
        if not entry.value:
            click.echo(f"  skipped  {entry.name} (empty or unusual)")
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
        if not entry.value:
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


def split_names(text: str) -> set[str]:
    """
    Returns the names in a comma-separated option.
    """
    return {name.strip() for name in text.split(",") if name.strip()}


def open_repo(repo: Path, service: str | None, only: str, skip: str) -> tuple[Path, str, list[Entry], list[str]]:
    """
    Resolves the options of a step into the repo, its service, the entries to act on and the lines of its .env.
    """
    root = repo.resolve()
    path = root / ".env"
    if not path.is_file():
        raise click.ClickException(f"No .env in {root}")
    lines = read_lines(path)
    return root, service or root.name.lower(), chosen(parse_env(lines), split_names(only), split_names(skip)), lines


def common_options(function: Any) -> Any:
    """
    Adds the arguments every step shares.
    """
    decorators = (
        click.argument("repo", type=click.Path(path_type=Path, file_okay=False, exists=True), default="."),
        click.option("--service", help="Keyring service name, by default the folder name in lower case."),
        click.option("--only", default="", help="Comma-separated names, instead of the likely secrets."),
        click.option("--skip", default="", help="Comma-separated names to leave alone."),
    )
    for decorator in reversed(decorators):
        function = decorator(function)
    return function


@group("keyring", help="Moves .env secrets into the keyring. Prints names, never values.")
def keyring_command() -> None:
    """
    Groups the steps of the move.
    """


@keyring_command.command("plan")
@common_options
@click.pass_context
def plan_command(ctx: click.Context, repo: Path, service: str | None, only: str, skip: str) -> None:
    """
    Lists what would move, and changes nothing.
    """
    root, name, picks, lines = open_repo(repo, service, only, skip)
    ctx.exit(plan(root, name, picks, lines))


@keyring_command.command("copy")
@common_options
@click.option("--overwrite", is_flag=True, help="Replaces a different value in the keyring.")
@click.pass_context
def copy_command(ctx: click.Context, repo: Path, service: str | None, only: str, skip: str, overwrite: bool) -> None:
    """
    Stores the secrets in the keyring and verifies each one, leaving .env alone.
    """
    _, name, picks, _ = open_repo(repo, service, only, skip)
    ctx.exit(copy(name, picks, overwrite))


@keyring_command.command("strip")
@common_options
@click.pass_context
def strip_command(ctx: click.Context, repo: Path, service: str | None, only: str, skip: str) -> None:
    """
    Replaces each verified secret in .env with a marker.
    """
    root, name, picks, lines = open_repo(repo, service, only, skip)
    ctx.exit(strip(root, name, picks, lines))


@keyring_command.command("restore")
@common_options
@click.pass_context
def restore_command(ctx: click.Context, repo: Path, service: str | None, only: str, skip: str) -> None:
    """
    Writes marked secrets back into .env, which undoes strip.
    """
    root, name, _, lines = open_repo(repo, service, only, skip)
    ctx.exit(restore(root, name, lines))
