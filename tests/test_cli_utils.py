"""Unit tests for the canonical Rich-backed CLI help formatting."""

from __future__ import annotations

import click
from click.testing import CliRunner

from acidbase import cli_utils
from acidbase.cli_utils import RichGroup, _command_short_help, group


def _long_help_command() -> click.Command:
    """Returns a command whose help is long enough that Click's default 45-char truncation would cut it."""
    return click.Command(
        name="patch",
        help="Find vulnerable repos owner-wide, patch each, and verify alerts clear afterwards.",
        callback=lambda: None,
    )


class TestCommandShortHelp:
    """Tests for the non-truncating short-help extractor."""

    def test_returns_full_first_paragraph(self) -> None:
        """Verifies the whole first paragraph survives, not just the first 45 chars."""
        cmd = _long_help_command()
        help_text = _command_short_help(cmd)
        assert help_text == "Find vulnerable repos owner-wide, patch each, and verify alerts clear afterwards."
        # The word Click's default truncation would have cut after.
        assert "afterwards." in help_text

    def test_stops_at_first_paragraph_break(self) -> None:
        """Verifies only the first paragraph is kept when help has multiple paragraphs."""
        cmd = click.Command(
            name="x",
            help="First paragraph summary.\n\nSecond paragraph with details that must not appear in the listing.",
            callback=lambda: None,
        )
        assert _command_short_help(cmd) == "First paragraph summary."

    def test_empty_when_no_help(self) -> None:
        """Verifies the empty string when a command carries no help text."""
        cmd = click.Command(name="x", callback=lambda: None)
        assert _command_short_help(cmd) == ""


class TestRichGroupHelp:
    """Tests for the non-truncating group help rendering."""

    def test_group_help_does_not_truncate_command_descriptions(self) -> None:
        """The full command description appears in `--help`, with no trailing ellipsis.

        Regression for the Click default that chopped each command's short help
        to 45 chars (``patch ... verify...``); the Quarto-style RichGroup wraps
        the whole first paragraph instead.
        """
        cmd = _long_help_command()

        @click.group(cls=RichGroup, help="Demo CLI.")
        def demo() -> None:
            """Demo group."""

        demo.add_command(cmd)

        result = CliRunner().invoke(demo, ["--help"])
        assert result.exit_code == 0, result.output
        # Rich wraps the description across lines; collapsing whitespace lets us
        # assert the full sentence survived without caring where it broke.
        flat = " ".join(result.output.split())
        assert "verify alerts clear afterwards." in flat
        # No ellipsis-truncation marker on the patched command's line.
        assert "verify..." not in flat

    def test_group_help_lists_every_command(self) -> None:
        """Every non-hidden command shows up in the listing."""
        a = click.Command(name="alpha", help="Alpha summary.", callback=lambda: None)
        b = click.Command(name="beta", help="Beta summary.", callback=lambda: None)
        hidden = click.Command(name="ghost", help="Hidden.", hidden=True, callback=lambda: None)

        @click.group(cls=RichGroup)
        def demo() -> None:
            """Demo group."""

        demo.add_command(a)
        demo.add_command(b)
        demo.add_command(hidden)

        result = CliRunner().invoke(demo, ["--help"])
        assert result.exit_code == 0, result.output
        assert "alpha" in result.output
        assert "Alpha summary." in result.output
        assert "beta" in result.output
        assert "Beta summary." in result.output
        # Hidden commands stay out of the listing.
        assert "ghost" not in result.output


class TestUnicodeSafety:
    """Tests for the UTF-8 stream guard on the shared group."""

    def test_main_reconfigures_streams_before_dispatch(self, monkeypatch) -> None:
        """RichGroup.main calls ensure_unicode_safe_streams so non-ASCII help survives.
        On Windows the legacy console code page cannot encode em dashes and the
        like; consumer CLIs used to be saved only by Click truncating the line
        before the first such character.
        """
        called: list[bool] = []
        monkeypatch.setattr(cli_utils, "ensure_unicode_safe_streams", lambda: called.append(True))

        @click.group(cls=RichGroup)
        def demo() -> None:
            """Demo group."""

        demo.add_command(click.Command(name="x", help="Dash \u2014 here.", callback=lambda: None))
        result = CliRunner().invoke(demo, ["--help"], standalone_mode=False)
        assert result.exit_code == 0, result.output
        assert called, "ensure_unicode_safe_streams was not called by RichGroup.main"

    def test_non_ascii_help_survives_rendering(self) -> None:
        """An em dash in a command's help reaches the rendered listing intact."""

        @click.group(cls=RichGroup)
        def demo() -> None:
            """Demo group."""

        demo.add_command(
            click.Command(name="dashy", help="Prompts for input \u2014 no flags needed.", callback=lambda: None)
        )
        result = CliRunner().invoke(demo, ["--help"])
        assert result.exit_code == 0, result.output
        assert "\u2014" in result.output


class TestGroupDecorator:
    """Tests for the ergonomic group() decorator wrapper."""

    def test_decorator_defaults_to_rich_group(self) -> None:
        """`group()` produces a RichGroup so consumer repos get the nicer help for free."""

        # The decorator must be applied to a function to yield the Group instance.
        @group(help="Wrapped.")
        def decorated() -> None:
            """Wrapped group."""

        assert isinstance(decorated, click.Group)
        assert decorated.__class__ is RichGroup
        # The help text and a registered command render without truncation.
        decorated.add_command(_long_help_command())
        result = CliRunner().invoke(decorated, ["--help"])
        assert result.exit_code == 0, result.output
        flat = " ".join(result.output.split())
        assert "verify alerts clear afterwards." in flat
