"""
Command-line interface for this project.

Scaffolded from ``acidbase/templates/cli.py``. Two things come from acidbase
so every repo in the ecosystem behaves identically and none of it is forked
per repo:

* :func:`acidbase.cli_utils.group` builds the command group. It is a
  ``click.Group`` subclass whose ``--help`` wraps each command's full
  description instead of truncating it at 45 characters, and which routes
  output through UTF-8-safe streams so non-ASCII help survives on Windows
  consoles using a legacy code page.
* :data:`acidbase.versioning.bump_command` provides ``bump`` — the canonical
  static project-version workflow for uv-managed repositories.
* :data:`acidbase.push.push_command` provides ``push`` — the canonical
  commit-and-push workflow (pre-commit-hook-aware, optional
  dual private/public publish).
* :class:`acidbase.workflow.ProjectRunner` supplies strict root discovery,
  executable lookup, argv-only command composition, project-local working
  directories, and subprocess exit-code propagation for commands implemented
  by this project.

Add project-specific commands below with ``@cli.command(...)``. Import
``click`` for its option and argument decorators, and import ``ProjectRunner``
when a command needs to invoke an external tool. Keep the command inventory
ASCII-ordered in source; keep procedures in their execution order.
"""

from __future__ import annotations

from acidbase.cli_utils import group
from acidbase.push import push_command
from acidbase.versioning import bump_command


@group()
def cli() -> None:
    """CLI tools for this project."""


cli.add_command(bump_command)
cli.add_command(push_command)


def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":  # pragma: no cover - module-as-script convenience
    main()
