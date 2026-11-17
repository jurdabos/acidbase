"""
Canonical Rich-backed Click help formatting for the acidbase ecosystem.

The default Click group listing truncates each command's short description to
a fixed width (``get_short_help_str(limit=45)``), so longer help strings end
with an ellipsis and the user has to run ``<cmd> --help`` to read the rest.
:class:`RichGroup` replaces that with a Quarto-style two-column layout: the
command name in bold, the full first paragraph of its help wrapped onto
aligned continuation lines, no truncation.

Adoption:

* acidbase itself: ``@click.group(cls=RichGroup, ...)`` on the top-level group
  (``src/acidbase/cli.py``).
* Consumer repos that build their own Click group and mount
  ``acidbase.push.push_command`` (tcnvsrnn, transcriber, ratemyhuman, ...):
  import and pass ``cls=RichGroup`` so the whole CLI inherits the same look.
  Typer-based repos (uteal) already render help through Rich and are
  unaffected; they only need this if they expose a bare-Click subgroup.
"""

from __future__ import annotations

import io
from typing import Any, Callable, Optional, Sequence, cast

import click
from rich.console import Console
from rich.table import Table

from acidbase.push import ensure_unicode_safe_streams


def _command_short_help(command: click.Command) -> str:
    """Returns the full first paragraph of a command's help, without truncation.

    Click's ``get_short_help_str(limit=45)`` chops the description to fit the
    group listing; we want the whole first paragraph so :class:`RichGroup` can
    wrap it to the terminal width instead. Falls back to the empty string when
    the command carries neither ``short_help`` nor ``help``.
    """
    text = command.short_help or command.help or ""
    return text.strip().split("\n\n")[0].strip()


def _render_commands_block(commands: Sequence[tuple[str, click.Command]], width: int) -> str:
    """Returns a Rich-rendered, non-truncating two-column command listing as text.

    The string carries ANSI codes (``force_terminal=True``); Click's ``echo``
    strips them when the output is piped, so the block is coloured on a
    terminal and plain text when redirected — matching Click's own behaviour
    for the rest of the help.
    """
    table = Table(show_header=False, box=None, padding=(0, 2), width=width)
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(overflow="fold", ratio=1)
    for name, command in commands:
        table.add_row(name, _command_short_help(command))
    buf = io.StringIO()
    console = Console(
        file=buf,
        force_terminal=True,
        width=width,
        color_system="auto",
        legacy_windows=False,
        highlight=False,
        soft_wrap=False,
    )
    console.print(table)
    return buf.getvalue().rstrip("\n")


class RichGroup(click.Group):
    """A :class:`click.Group` whose ``--help`` command listing wraps instead of truncating.

    Only ``format_commands`` and ``main`` are overridden; every other help
    section (options, description, epilog) keeps Click's default rendering, so
    the change stays local to the one place that was lossy.
    """

    def main(self, *args: Any, **kwargs: Any) -> Any:
        """Reconfigures the output streams to UTF-8, then dispatches normally.

        Windows consoles and pipes default to a legacy code page (cp1250 here),
        which cannot encode the non-ASCII characters that routinely appear in
        command docstrings (em dashes, arrows, accented words) or in a
        command's own output (the check-mark/circled-digit progress glyphs).
        Click's old 45-char truncation hid this by cutting most lines before
        the first such character; now that the full first paragraph is shown,
        an unreconfigured stream renders them as ``?``/replacement chars.
        Routing every adopting CLI through the same guard that
        :func:`acidbase.push.run_push` already uses means consumer ``main()``
        functions do not each have to remember to call it.
        """
        ensure_unicode_safe_streams()
        return super().main(*args, **kwargs)

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        commands: list[tuple[str, click.Command]] = []
        for subcommand in self.list_commands(ctx):
            cmd = self.get_command(ctx, subcommand)
            if cmd is None or cmd.hidden:
                continue
            commands.append((subcommand, cmd))
        if not commands:
            return
        # The table's own 2-char left cell padding mirrors the section indent
        # Click applies to write_dl, so the block lines up under the heading.
        rendered = _render_commands_block(commands, width=formatter.width)
        with formatter.section("Commands"):
            formatter.write(rendered)
            formatter.write("\n")


def group(name: Optional[str] = None, **attrs: Any) -> Callable[..., click.Group]:
    """Decorator wrapper mirroring :func:`click.group` but defaulting to :class:`RichGroup`.

    Passes through every keyword (``help``, ``invoke_without_command``, etc.);
    ``cls`` is forced to :class:`RichGroup` unless the caller overrides it, so
    consumer repos can drop in ``from acidbase.cli_utils import group`` and get
    the nicer help without remembering the ``cls=`` argument.
    """
    attrs.setdefault("cls", RichGroup)
    return cast("Callable[..., click.Group]", click.group(name, **attrs))
