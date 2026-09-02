# Project-version bumps

`acidbase bump` advances the current uv-managed project's own static
`[project].version`. It is deliberately independent of `acidbase patch`, which
updates vulnerable dependency requirements across repositories.

## What the version means

Python's PEP 440 version scheme defines valid spelling and ordering. It does
not certify software quality or impose a compatibility policy. In particular,
the familiar `major.minor.patch` interpretation is a useful project convention:
use a major change for a breaking public interface, a minor change for a
backward-compatible feature, and a patch change for a backward-compatible fix.
Acidbase and uv perform the requested version operation; they do not inspect
the code to decide whether that convention was followed.

For the same release number, the usual phase order is:

```text
1.0.dev1 < 1.0a1 < 1.0b1 < 1.0rc1 < 1.0 < 1.0.post1
```

The numbers following `a`, `b`, `rc`, `.dev`, and `.post` count releases within
that phase. Alpha, beta, and release-candidate labels communicate progressively
later testing stages; their exact readiness criteria belong to the project.
Development releases are also prereleases for dependency resolution. Installers
usually exclude prereleases unless their selection rules explicitly allow them.
See the [PyPA versioning discussion](https://packaging.python.org/en/latest/discussions/versioning/)
and [version-specifier specification](https://packaging.python.org/en/latest/specifications/version-specifiers/).

## Choosing a bump

The inventory below is ASCII-ordered. Examples show the current version on the
left and uv's resulting version on the right.

| Input | Meaning and intended use | Example |
| --- | --- | --- |
| `alpha` | An early named prerelease, written `aN`. Increment an existing alpha or combine it with a release-number change to begin a new series. | `0.3.0a1` to `0.3.0a2` |
| `beta` | A later prerelease, written `bN`, commonly used for wider testing. It can move an alpha to beta or increment an existing beta. | `0.3.0a1` to `0.3.0b1`; `0.3.0b1` to `0.3.0b2` |
| `dev` | A development snapshot, written `.devN`, such as a nightly build. It sorts before the corresponding release or prerelease. | `0.3.0.dev1` to `0.3.0.dev2` |
| `major` | Increase the first release component and reset the following release components. Conventionally used for incompatible public-interface changes. | `1.2.3` to `2.0.0` |
| `minor` | Increase the second release component and reset the patch component. Conventionally used for compatible new functionality. | `1.2.3` to `1.3.0` |
| `patch` | Increase the third release component. Conventionally used for compatible fixes. | `1.2.3` to `1.2.4` |
| `post` | A correction after the same release, written `.postN`, primarily for release notes or distribution metadata. Use a patch release for software bug fixes. | `1.2.3` to `1.2.3.post1`; then to `1.2.3.post2` |
| `rc` | A release candidate, written `rcN`: a candidate for the final release, still explicitly a prerelease. | `0.3.0a1` to `0.3.0rc1`; `0.3.0rc1` to `0.3.0rc2` |
| `stable` | Remove prerelease, development, and post-release qualifiers to reach the unqualified final version. Intended for completing a prerelease series. | `0.3.0b2` to `0.3.0` |

An **explicit PEP 440 version** sets a chosen value instead of calculating
components. Examples include `1.0.0`, `1.1.0rc2`, and `1.1.0.dev5`. This can
select a lower version as well as a higher one, so preview it deliberately.
Prefer the canonical `a`, `b`, `rc`, `.dev`, and `.post` spellings even where
PEP 440 permits an alternative spelling that uv can normalize.

The numeric transformations are delegated to
[uv's version command](https://docs.astral.sh/uv/reference/cli/#uv-version).
The alpha/beta/rc transitions above were also checked with local uv dry runs.
Release-number bumps also clear suffixes: for example,
`1.2.3b4.post5.dev6` with `patch` becomes `1.2.4`. Incrementing `post` on
that version produces `1.2.3b4.post6`, while `stable` produces `1.2.3`.
These complex combinations are legal but rarely helpful for a human-maintained
release scheme; prefer a simple phase sequence and preview unusual cases.

## Usage and prerelease transitions

The command accepts one or more bump kinds, or one explicit version:

```powershell
uv run acidbase bump patch
uv run hadoop bump minor
uv run hadoop bump major
uv run hadoop bump 1.0.0
uv run hadoop bump patch --dry-run
```

Starting a prerelease of the next version needs a release-number increase too.
For example, from stable `0.2.0`:

```powershell
uv run hadoop bump patch beta --dry-run
# 0.2.0 -> 0.2.1b1

uv run hadoop bump minor alpha --dry-run
# 0.2.0 -> 0.3.0a1

uv run hadoop bump patch dev --dry-run
# 0.2.0 -> 0.2.1.dev1
```

Plain `bump beta` from `0.2.0` would produce the earlier `0.2.0b1`, so uv
refuses it. Once a project is already at `0.2.1b1`, `bump beta` produces
`0.2.1b2`, and `bump stable` produces `0.2.1`. The same principle applies when
starting a development phase: its target release or prerelease must advance.
uv applies combined components in its defined largest-to-smallest order; the
wrapper passes them through without inventing separate arithmetic. See
[uv's packaging guide](https://docs.astral.sh/uv/guides/package/#updating-your-version).

An explicit version cannot be mixed with bump kinds, and repeated kinds are
rejected. Always use `--dry-run` when a transition is unfamiliar. A dry run
does not reserve, publish, or release that version.

## Safety contract

Before invoking uv, the command:

1. discovers the nearest project root containing `pyproject.toml`;
2. verifies that `[project].version` is a static PEP 440 value; and
3. refuses to proceed if `pyproject.toml` or `uv.lock` has staged, unstaged, or
   untracked changes.

Other working-tree changes do not block the operation. The guard is limited to
the two files that `uv version` owns, so a prepared changelog or source change
can remain in the same release commit.

Acidbase delegates the update to `uv version ... --no-sync`. uv updates
`pyproject.toml` and the lockfile without rebuilding or synchronizing the
project environment. `--dry-run` asks uv to calculate the next version without
writing either file. Acidbase reports the old and new versions and propagates
uv's exit code.

The command does not commit, tag, publish, or push. Those are release-policy
operations and remain separate from the metadata update.

## Child-CLI integration

Acidbase exports the complete Click command. Child projects import it unchanged:

```python
from acidbase.push import push_command
from acidbase.versioning import bump_command

cli.add_command(bump_command)
cli.add_command(push_command)
```

Dynamic-version projects must use the tool that owns their version. Acidbase
refuses to replace that policy with a static value.

## Reaching every existing child

Newly scaffolded CLIs receive the imports and registrations above. Existing
CLIs do not change merely because Acidbase's template or dependency changes:
the scaffolder intentionally preserves their local source.

A complete rollout therefore has four separate checks:

1. Publish the Acidbase module and updated template to the remote used by
   children. A local Acidbase commit alone is not a downstream release.
2. Upgrade each child's Acidbase lockfile pin and synchronize its native
   environment. Verify that `acidbase.versioning.bump_command` imports there.
3. Register that exact command object in the child's real top-level Click
   group, including any framework adapter. Preserve the child's own commands.
4. Run `uv run <child-cli> bump --help` for every fleet entry and collect all
   failures. A skipped or unavailable child remains an explicit rollout item.

After the rollout changes have been committed, `bump patch --dry-run` provides
an additional end-to-end check. Use `bump --help` before that point, because the
intentional `uv.lock` edit would correctly trigger the dirty-metadata guard.

A child regression test should also assert identity, not merely a matching
help label:

```python
from acidbase.versioning import bump_command

assert cli.commands["bump"] is bump_command
```

The private `docs/guidelines/metarepo_rollout.md` runbook contains the fleet
inventory and executable audit loops. Publication and fleet-wide mutation are
separate, explicit operations; documentation updates do not perform them.
