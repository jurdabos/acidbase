# Scaffolding and command ownership

Acidbase provides a small shared layer for repositories whose actual workflows
differ. A child project should import stable mechanics and define its own
meaning for project lifecycle commands. This keeps a command name consistent
without smuggling one framework's assumptions into every repository.

## The shared contract

Acidbase owns six reusable surfaces:

- `acidbase.clean.clean_command` supplies the common development-cache
  cleaner.
- `acidbase.cli_utils.group` supplies non-truncating Rich help and UTF-8-safe
  command dispatch.
- `acidbase.push.push_command` supplies the common Git commit-and-push
  workflow.
- `acidbase scaffold` plans and applies the canonical CLI, CI, lint, and
  secret-scan baseline.
- `acidbase.versioning.bump_command` supplies the common static
  project-version workflow.
- `acidbase.workflow.ProjectRunner` supplies strict project-root discovery,
  executable lookup, argv-only command composition, project-local working
  directories, and subprocess exit-code propagation.

The child repository owns the commands whose inputs, generated files, or tools
depend on that project. Its command inventory should stay ASCII-ordered because
it is an index. Steps inside a command remain in procedural order.

| Command | Ownership and inclusion rule |
| --- | --- |
| `bump` | Acidbase-owned and imported unchanged for uv projects with a static `[project].version`. |
| `clean` | Acidbase-owned and imported unchanged. A project with more reproducible output wraps `run_clean` in its own command. |
| `css-dev` | Project-owned. Include only when the project has a separate CSS build pipeline. |
| `dev` | Project-owned. Start the project's actual preview, watcher, or development server. |
| `doctor` | Project-owned checks built from shared discovery helpers; verify only tools and configuration the project requires. |
| `format` | Project-owned. Add with `format-check`, using identical scope and configuration. |
| `format-check` | Project-owned, read-only counterpart to `format`. |
| `install` | Project-owned orchestration of the package managers and external-tool checks the repository really uses. |
| `lint` | Project-owned aggregation of relevant static checks. |
| `migrate` | Project-owned. Include only when a versioned data or configuration schema exists. |
| `push` | Acidbase-owned and imported unchanged. |
| `render` | Project-owned. Include when the repository produces a document, site, or other rendered artifact. |
| `test` | Project-owned aggregation of deterministic checks and any appropriate smoke tests. |
| `type-check` | Project-owned. Include when substantive typed code makes it useful. |

`command` is deliberately absent. It does not name a stable behaviour, so it
should enter the contract only after a concrete, repeated meaning emerges.
Framework-specific commands remain in the project that needs them. For
example, a Tailwind watcher, a FastAPI development server, npm installation,
and Alembic migrations belong in a web application, not in acidbase.

## Plan-first adoption

The target must already be an initialized Python repository containing
`pyproject.toml`. Run the command without `--apply` first:

```powershell
uv run acidbase scaffold C:\path\to\project
```

The file report has six states:

- `add`: the path is missing and can be created.
- `extend`: `pyproject.toml` lacks ruff configuration, so the canonical ruff
  tables can be appended without rewriting its existing content; or an existing
  `.gitignore` lacks canonical ecosystem rules, so missing rules can be appended
  without disturbing local project-specific rules.
- `keep`: the file already matches the baseline, or the project already owns
  the relevant configuration.
- `preserve`: a local file differs from the template and will remain untouched.
- `stale`: the local file is a verbatim copy of a *previous* acidbase
  template (listed in `templates/superseded.txt`). It is an old baseline, not
  local policy, but a plain apply still leaves it alone.
- `refresh`: the same file under `--refresh-baseline`; it will be replaced by
  the current template.

Apply exactly that plan with:

```powershell
uv run acidbase scaffold C:\path\to\project --apply
```

Refresh stale baseline copies as well with:

```powershell
uv run acidbase scaffold C:\path\to\project --refresh-baseline --apply
```

`stale` exists because `preserve` used to hide it. Ten children kept the
2026-05 `.pre-commit-config.yaml` (remote ruff hook pinned at `v0.8.0`)
for over a year while their lockfiles moved ruff to 0.12-0.16; every census
reported those files as "divergent local content" and nothing distinguished
an untouched old template from a deliberate local edit. The registry makes
that distinction mechanical, and `tests/test_scaffold.py` walks git history
to fail when a template changes without its previous digest being recorded.

The apply phase rechecks every destination before writing. It refuses symbolic
link traversal, path escape, and a `pyproject.toml` changed after planning. New
content is staged beside its destination and atomically installed. Divergent
local CI, secret-scan, hook, and CLI files are always preserved for manual
comparison.

Ordinary adoption does not invent a CLI when `[project.scripts]` has no
acidbase-style entry point. To create an installable CLI as one explicit,
coupled operation, inspect the wired plan:

```powershell
uv run acidbase scaffold C:\path\to\project --wire-cli
```

The wired plan adds the following only when it can do so without reinterpreting
local build policy:

- the canonical acidbase Git dependency;
- `[project.scripts]` pointing the project command to `<package>.cli:main`;
- `src/<package>/__init__.py` and `src/<package>/cli.py` for a new src layout,
  or the equivalent files in an established flat package;
- Hatchling build metadata and explicit wheel package discovery.

Apply and materialize the new entry point with:

```powershell
uv run acidbase scaffold C:\path\to\project --wire-cli --apply
Set-Location C:\path\to\project
uv lock
uv sync --frozen
uv run <project-command> --help
```

`--command-name NAME` selects a command name different from `[project].name`.
The wiring operation refuses to replace an existing command, add a parallel
CLI beside an established project interface, reinterpret a non-Hatch build
backend, or change an existing Hatch package inventory.

Without `--wire-cli`, scaffolding deliberately does not choose a dependency
source, build backend, or executable name. The report identifies missing
project-owned wiring:

- declare `acidbase` as a dependency;
- map the desired executable under `[project.scripts]` to
  `<package>.cli:main`.

If `[project.scripts]` already exposes another CLI shape, acidbase treats that
interface as locally owned and does not create a parallel `src/<package>/cli.py`.
The report records this decision so a Typer application, framework CLI, or
other established entry point remains authoritative.

Repository-creation wrappers may invoke `acidbase scaffold ... --wire-cli
--apply` and then lock and synchronize the child. Existing repositories can
keep their own interface or opt into the same wiring after reviewing the plan.

## Hosting off GitHub

`--hosting mirror` prepares a repository whose code stays off GitHub (mirror
mode, see [Dual-publish workflow](./dual_push.md#mirror-mode)). Against the
default `--hosting github`, the plan:

- leaves out `.github/workflows/lint.yml`, because GitHub Actions never sees the
  code, and asks in a note to delete an existing copy, since scaffolding never
  deletes; the pre-commit hooks still run ruff and gitleaks on every commit;
- appends the mirror-mode `[tool.acidbase.push]` table when the project has
  none, and refuses to touch an existing table that is not in mirror mode;
- adds a note naming the two remotes to create.

With `--apply`, it also writes the GitHub push guard into `.git/config`, or
reports that the first `acidbase push` will, when the folder is not a
repository yet.

## The shared clean command

`clean` removes one fixed inventory of Python development caches, wherever it
finds them in the project:

- bytecode: `__pycache__` folders and stray `*.pyc` and `*.pyo` files;
- tool caches: `.hypothesis`, `.mypy_cache`, `.pytest_cache` and `.ruff_cache`;
- coverage output: `.coverage`, `.coverage.*`, `coverage.xml` and `htmlcov`.

`uv run REALCLI clean --dry-run` lists each item with its size and removes
nothing. The command finds the project root as `bump` does, from the working
directory upwards.

The inventory names what may go, so `.gitignore` never decides it. An ignored
path can be a `.env`, run state, a log or data that a backup still needs, so
the command never runs `git clean` either.

- **Tracked paths:** a cache-named path that Git tracks, such as a test fixture
  or a published coverage report, stays and is reported. Inside a work tree, a
  failing `git ls-files` stops the command before anything is removed.
- **Foreign trees:** the walk does not enter links, junctions, virtual
  environments (any folder holding `pyvenv.cfg`, and `.venv`), `node_modules`
  or nested repositories.
- **Failures:** a cache held open by another process is reported and skipped.
  The command fails only when every removal fails.

A project with more reproducible output, such as a frontend build, defines its
own `clean` that calls `acidbase.clean.run_clean` and then removes its extra
paths, rather than forking the inventory.

## Child command pattern

The generated `cli.py` mounts the shared `bump`, `clean` and `push` commands.
A child command can use `ProjectRunner` for external processes while retaining its own
semantics:

```python
import click

from acidbase.workflow import ProjectRunner


@cli.command("render")
def render_cmd() -> None:
    """Render this project's declared output."""
    ProjectRunner.discover(__file__).run("quarto", "render")
```

Arguments remain separate argv tokens and no shell is involved. If Quarto is
missing, discovery fails with a named tool error; if rendering fails, its exit
code becomes the CLI exit code.
