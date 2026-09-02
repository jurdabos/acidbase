"""
Top-level entry point for the ``acidbase`` CLI.

Exposes the public commands as a click group so each tool lives under
a stable subcommand:

* ``acidbase alerts`` wraps :func:`acidbase.security.cli.alerts_command` to
  list Dependabot alerts for one repo or every non-archived repo of an owner.
* ``acidbase bump`` wraps :func:`acidbase.versioning.bump_command` so uv-based
  projects share one project-version workflow.
* ``acidbase dismiss-alert`` wraps
  :func:`acidbase.security.cli.dismiss_alert_command` to dismiss one or more
  Dependabot alerts on a repo (e.g. false positives) with a recorded reason.
* ``acidbase enable-alerts`` wraps
  :func:`acidbase.security.cli.enable_alerts_command` to idempotently turn on
  Dependabot vulnerability alerts on a single repo. Used by repo-creation
  scaffolders so every freshly-created repo has alerts enabled out of the box.
* ``acidbase enable-fixes`` wraps
  :func:`acidbase.security.cli.enable_fixes_command` to idempotently turn on
  Dependabot automated security fix PRs on a single repo (requires alerts).
* ``acidbase patch`` wraps :func:`acidbase.security.cli.patch_command` to drive
  the cross-platform dependency-patch flow described in
  ``docs/guidelines/security_patching.md``.
* ``acidbase push`` wraps :func:`acidbase.push.push_command` so the canonical
  commit-and-push workflow can be exercised directly on this repo and is
  also importable from any consumer repo.
* ``acidbase reopen-alert`` wraps
  :func:`acidbase.security.cli.reopen_alert_command` to reverse a dismissal,
  so the dismiss flow is never one-way.
* ``acidbase scaffold`` plans or safely applies the shared CLI, lint, CI, and
  secret-scan baseline to an initialized Python repository.
"""

from __future__ import annotations

import click

from acidbase.cli_utils import RichGroup
from acidbase.push import ensure_unicode_safe_streams, push_command
from acidbase.scaffold import scaffold_command
from acidbase.security.cli import (
    alerts_command,
    dismiss_alert_command,
    enable_alerts_command,
    enable_fixes_command,
    patch_command,
    reopen_alert_command,
)
from acidbase.versioning import bump_command


@click.group(
    cls=RichGroup, help="Acidbase tooling: safe scaffolding, shared Git workflows, and dependency maintenance."
)
@click.version_option(package_name="acidbase")
def main() -> None:
    """Top-level click group; subcommands live under :func:`acidbase.cli.main`."""
    ensure_unicode_safe_streams()


main.add_command(alerts_command, name="alerts")
main.add_command(bump_command, name="bump")
main.add_command(dismiss_alert_command, name="dismiss-alert")
main.add_command(enable_alerts_command, name="enable-alerts")
main.add_command(enable_fixes_command, name="enable-fixes")
main.add_command(patch_command, name="patch")
main.add_command(push_command, name="push")
main.add_command(reopen_alert_command, name="reopen-alert")
main.add_command(scaffold_command, name="scaffold")


if __name__ == "__main__":  # pragma: no cover - module-as-script convenience
    main()
